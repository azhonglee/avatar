import fs from "node:fs";
import path from "node:path";
import type { Board, BoardTask } from "../board.ts";
import type { Config } from "../config.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import type { Store } from "../store.ts";
import { errMsg, expandHome, log, render, runProcess, truncate } from "../util.ts";

const COMMENT_MAX = 2800;

/** 从任务标题前缀 `[codex]` 或描述里的 `harness: codex` 行解析执行者。 */
export function parseHarness(t: BoardTask, known: string[]): string | undefined {
  const m = t.summary.match(/^\s*\[([\w-]+)\]/) ?? t.description.match(/^\s*harness\s*[:：]\s*([\w-]+)\s*$/im);
  return m && known.includes(m[1]) ? m[1] : undefined;
}

/** 描述里的 `repo: 别名或路径` 行。 */
export function parseRepo(t: BoardTask): string | undefined {
  return t.description.match(/^\s*repo\s*[:：]\s*(\S+)\s*$/im)?.[1];
}

/** 交叉审查必须换一个 harness：执行者正好是 reviewer 时改由 brain 审；都相同则不审。 */
export function pickReviewer(roles: { brain: string; reviewer: string }, worker: string): string {
  if (!roles.reviewer) return "";
  if (roles.reviewer !== worker) return roles.reviewer;
  return roles.brain !== worker ? roles.brain : "";
}

export function parseVerdict(review: string): "approve" | "changes" {
  return /VERDICT\s*[:：]\s*APPROVE/i.test(review) ? "approve" : "changes";
}

/**
 * 派单：看板“派给Agent”列里的任务 → 按标题前缀选 harness → 在独立 worktree/工作目录执行 →
 * （可选）另一个 harness 交叉审查并返工一轮 → 结果写成任务评论 → 移到“待验收”。
 * worker 不拿飞书权限，飞书只由守护进程写。
 */
export class Dispatcher {
  cfg: Config;
  store: Store;
  board: Board;
  private active = new Set<Promise<void>>();
  private scanning = false;

  constructor(cfg: Config, store: Store, board: Board) {
    this.cfg = cfg;
    this.store = store;
    this.board = board;
  }

  async scan(): Promise<number> {
    if (this.scanning) return 0;
    this.scanning = true;
    let started = 0;
    try {
      const tasks = await this.board.listSection("dispatch");
      for (const t of tasks) {
        if (this.store.runningCount() >= this.cfg.dispatch.max_parallel) break;
        if (this.store.isRunning(t.guid)) continue;
        const p = this.execute(t).catch((e) => log("error", "派单执行异常", { task: t.guid, err: errMsg(e) }));
        this.active.add(p);
        p.finally(() => this.active.delete(p));
        started++;
      }
    } finally {
      this.scanning = false;
    }
    return started;
  }

  /** 等所有进行中的派单结束（命令行单次运行时用）。 */
  async drain(): Promise<void> {
    while (this.active.size) await Promise.all([...this.active]);
  }

  async execute(brief: BoardTask): Promise<void> {
    const short = brief.guid.slice(0, 8);
    const logDir = path.join(this.cfg.dataDir, "runs", short);
    fs.mkdirSync(logDir, { recursive: true });
    // 第一个 await 之前同步占位，scan 的并发上限和防重复领取才可靠
    const runId = this.store.startRun({ task_guid: brief.guid, harness: "", role: "worker", cwd: "", log: logDir });
    let t = brief;
    let harness = "";
    try {
      t = { ...brief, ...(await this.board.getTask(brief.guid)) };
      harness = parseHarness(t, Object.keys(this.cfg.harnesses)) ?? (this.cfg.dispatch.default_harness || this.cfg.roles.brain);
      await this.board.move(t.guid, "running");
      const ws = await this.prepareWorkspace(t);
      this.store.updateRun(runId, harness, ws.cwd);
      await this.board.comment(t.guid, `🤖 ${harness} 开始执行\n工作目录：${ws.cwd}${ws.branch ? `\n分支：${ws.branch}` : ""}`);

      const reviewer = pickReviewer(this.cfg.roles, harness);
      let feedback = "";
      let report = "";
      let reviewNote = "";
      const rounds = 1 + (reviewer ? this.cfg.dispatch.fix_rounds : 0);
      for (let round = 1; round <= rounds; round++) {
        const r = await runHarness(this.cfg, {
          harness,
          prompt: render(loadPrompt("worker.md"), {
            summary: t.summary.replace(/^\s*\[[\w-]+\]\s*/, ""),
            description: t.description,
            cwd: ws.cwd,
            feedback: feedback || "（无）",
          }),
          cwd: ws.cwd,
          tools: "write",
          lark: "none",
          timeoutSec: this.cfg.dispatch.timeout_sec,
          logFile: path.join(logDir, `worker-${round}.log`),
        });
        report = r.text || "（无输出）";
        if (!r.ok) throw new Error(`${harness} 执行失败（exit ${r.exitCode}${r.timedOut ? "，超时" : ""}）：${truncate(report, 800)}`);
        if (!reviewer) break;

        const diff = ws.base ? await gitDiff(ws.cwd, ws.base) : "";
        const rv = await runHarness(this.cfg, {
          harness: reviewer,
          prompt: render(loadPrompt("review.md"), {
            summary: t.summary,
            description: t.description,
            report: truncate(report, 8000),
            diff: diff ? truncate(diff, 30000) : "（非代码任务，无 diff）",
          }),
          cwd: ws.cwd,
          tools: "read",
          lark: "none",
          timeoutSec: 1200,
          logFile: path.join(logDir, `review-${round}.log`),
        });
        const verdict = rv.text ? parseVerdict(rv.text) : "changes";
        reviewNote = `🔍 ${reviewer} 审查（第 ${round} 轮）：${verdict === "approve" ? "通过" : "需修改"}\n${truncate(rv.text, 1500)}`;
        await this.board.comment(t.guid, truncate(reviewNote, COMMENT_MAX));
        if (verdict === "approve") break;
        feedback = rv.text;
      }

      const stat = ws.base ? await gitDiffStat(ws.cwd, ws.base) : "";
      const final = [`✅ ${harness} 完成`, truncate(report, 2000), stat ? `\n变更：\n${stat}` : "", ws.branch ? `分支：${ws.branch}（worktree：${ws.cwd}）` : ""]
        .filter(Boolean)
        .join("\n");
      await this.board.comment(t.guid, truncate(final, COMMENT_MAX));
      await this.board.move(t.guid, "review");
      this.store.endRun(runId, "ok", truncate(report, 500));
      log("info", "派单完成", { task: t.summary, harness });
    } catch (e) {
      const msg = errMsg(e);
      this.store.endRun(runId, "failed", msg);
      log("error", "派单失败", { task: t.summary, harness, err: msg });
      await this.board.comment(t.guid, truncate(`❌ 执行失败：${msg}\n日志：${logDir}`, COMMENT_MAX)).catch(() => undefined);
      await this.board.move(t.guid, "review").catch(() => undefined);
    }
  }

  /** 指定了仓库就在该仓库的独立 git worktree 里干活；否则给一个独立的空工作目录。 */
  async prepareWorkspace(t: BoardTask): Promise<{ cwd: string; branch: string; base: string }> {
    const repoRef = parseRepo(t);
    const short = t.guid.slice(0, 8);
    if (!repoRef) {
      const cwd = path.join(this.cfg.dataDir, "workspace", short);
      fs.mkdirSync(cwd, { recursive: true });
      return { cwd, branch: "", base: "" };
    }
    const repo = path.resolve(expandHome(this.cfg.dispatch.repos[repoRef] ?? repoRef));
    const cwd = path.join(this.cfg.dataDir, "worktrees", short);
    const branch = `pa/${short}`;
    const baseKey = `worktree.${t.guid}.base`;
    if (!fs.existsSync(cwd)) {
      const head = await git(repo, ["rev-parse", "HEAD"]);
      const hasBranch = (await runProcess("git", ["-C", repo, "rev-parse", "--verify", "--quiet", branch])).code === 0;
      await git(repo, hasBranch ? ["worktree", "add", cwd, branch] : ["worktree", "add", "-b", branch, cwd]);
      this.store.set(baseKey, head.trim());
    }
    return { cwd, branch, base: this.store.get(baseKey) ?? "" };
  }
}

async function git(cwd: string, args: string[]): Promise<string> {
  const r = await runProcess("git", ["-C", cwd, ...args]);
  if (r.code !== 0) throw new Error(`git ${args.join(" ")} 失败：${r.stderr.trim()}`);
  return r.stdout;
}

/** 相对创建 worktree 时的基线（含未提交和新文件）。 */
async function gitDiff(cwd: string, base: string): Promise<string> {
  await runProcess("git", ["-C", cwd, "add", "-A", "--intent-to-add"]);
  return (await runProcess("git", ["-C", cwd, "diff", base])).stdout;
}

async function gitDiffStat(cwd: string, base: string): Promise<string> {
  await runProcess("git", ["-C", cwd, "add", "-A", "--intent-to-add"]);
  return (await runProcess("git", ["-C", cwd, "diff", "--stat", base])).stdout.trim();
}
