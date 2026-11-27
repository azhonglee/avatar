import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { App } from "../app.ts";
import { deliveryOf, isContextDerivedDispatchBlocked, taskUrl } from "../api/queries.ts";
import type { DeliveryStatus } from "../api/types.ts";
import { CommandError } from "../commands.ts";
import { repoSpec, type Config, type RepoSpec } from "../config.ts";
import { comment } from "../effects.ts";
import type { Handler } from "../engine.ts";
import type { Effect, Ledger, WorkItem } from "../ledger.ts";
import { errMsg, log, truncate } from "../util.ts";
import { parseRepo, type DispatchPayload } from "../workflows/dispatch.ts";
import { denyReason, prBody, prTitle, retentionText, type DeliveryAction, type DeliveryPayload } from "./body.ts";
import {
  branchExists,
  commitAll,
  currentBranch,
  diffStat,
  git,
  isAncestor,
  isClean,
  parseRemote,
  pushBranch,
  remoteDefaultBranch,
  remoteUrl,
  revParse,
  tryGit,
} from "./git.ts";
import { DeliveryError, HttpError, makeProvider, openOrReuse, type ProviderCfg } from "./providers.ts";

/**
 * 交付：把派单结果变成 PR/MR、快进合并到本地分支、放弃（延迟清理 worktree 与分支）、恢复。
 *
 * 命令只校验前置条件并把意图写进账本（kind = "delivery"，ref = 派单 id）；真正的 git / 平台操作由引擎领取执行，
 * 每个动作都设计成可重入：推送幂等、创建 PR 前先查已有的、快进合并前先比较提交，崩溃重试不会重复交付。
 */

const DAY = 86_400_000;
const MAX_ATTEMPTS = 3;
const COMMENT_MAX = 2800;

const ACTION_TEXT: Record<DeliveryPayload["action"], string> = {
  create_pr: "创建 PR",
  merge_local: "合并到本地分支",
  discard: "放弃",
  restore: "恢复",
  cleanup: "清理",
};

type Dispatch = WorkItem<DispatchPayload>;
type Item = WorkItem<DeliveryPayload>;

/** 最新一项非清理的交付工作（清理是放弃的附属动作，不改变交付状态）。 */
export function latestDelivery(ledger: Ledger, dispatchId: string): Item | undefined {
  return ledger.list<DeliveryPayload>({ kinds: ["delivery"], ref: dispatchId, limit: 50 }).find((d) => d.payload.action !== "cleanup");
}

/** 派单所在仓库（任务描述里的 `repo:`）。 */
function repoOf(cfg: Config, d: DispatchPayload): RepoSpec | undefined {
  const ref = parseRepo({ description: d.description ?? "" });
  return ref ? repoSpec(cfg, ref) : undefined;
}

/** 交付平台：仓库的 provider → delivery.default_provider → 只配置了一个时用它。 */
export function resolveProvider(cfg: Config, spec: RepoSpec): { name: string; cfg: ProviderCfg } | { error: string } {
  const all = cfg.delivery.providers;
  const names = Object.keys(all);
  const name = spec.provider || cfg.delivery.default_provider || (names.length === 1 ? names[0] : "");
  if (!name) return { error: names.length ? "没有指定交付平台：请设置 delivery.default_provider 或仓库的 provider" : "没有配置交付平台（delivery.providers）" };
  if (!all[name]) return { error: `未定义的交付平台：${name}` };
  return { name, cfg: all[name] };
}

/** 去掉文本里 URL 的账号密码（remote 地址可能内嵌令牌，git 的报错会原样带出）。 */
export function maskUrl(text: string): string {
  return text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^@\s/]+@/gi, "$1***@");
}

function isPermanent(e: unknown): boolean {
  return e instanceof DeliveryError || (e instanceof HttpError && e.permanent);
}

export function registerDelivery(app: App): void {
  const { cfg, ledger, engine, commands } = app;
  const deps = { bytedcli: cfg.bins.bytedcli };

  // ───────────────────────── 命令：校验并入队 ─────────────────────────

  /** 派单存在、已结束、是这张卡片最新的一次、有分支，且当前交付状态允许这个动作。 */
  function checkTarget(id: string, action: DeliveryAction): { w: Dispatch; status: DeliveryStatus } {
    if (isContextDerivedDispatchBlocked(app, id)) {
      throw new CommandError("conflict", "该派单源自旧工作区主人的工作上下文，已按主人隔离阻断操作");
    }
    const w = ledger.get<DispatchPayload>(id);
    if (!w || w.kind !== "dispatch") throw new CommandError("not_found", `没有这项派单：${id}`);
    if (!w.terminal) throw new CommandError("conflict", "派单还在进行中，结束后才能交付");
    const latest = ledger.latest("dispatch", w.ref);
    if (latest && latest.id !== w.id) throw new CommandError("conflict", "这张卡片已经有更新的派单，请操作最新的一次");
    if (!w.payload.branch) throw new CommandError("conflict", "这次派单没有在 git worktree 中执行（任务描述里没有 repo:），没有可交付的分支");
    const { status } = deliveryOf(app, id);
    const why = denyReason(action, w.state, status);
    if (why) throw new CommandError("conflict", why);
    if (action !== "discard" && !fs.existsSync(w.payload.cwd)) throw new CommandError("conflict", `worktree 已不存在：${w.payload.cwd}`);
    if (!repoOf(cfg, w.payload)) throw new CommandError("conflict", "找不到派单所在的仓库（任务描述里的 repo:）");
    return { w, status };
  }

  function enqueue(w: Dispatch, action: DeliveryAction, extra: Partial<DeliveryPayload> = {}): string {
    const id = `delivery:${w.id}:${action}:${Date.now()}`;
    const payload: DeliveryPayload = { action, dispatch_id: w.id, guid: w.ref || w.payload.guid || "", ...extra };
    if (!ledger.enqueue({ id, kind: "delivery", ref: w.id, state: "pending", payload })) throw new CommandError("conflict", "操作太频繁，请稍后再试");
    return id;
  }

  const Id = z.string().min(1);

  commands.register({
    name: "delivery.create_pr",
    title: "推送分支并创建 PR / MR",
    schema: z.object({ id: Id, title: z.string().trim().max(250).optional(), draft: z.boolean().optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const { w } = checkTarget(a.id, "create_pr");
      const p = resolveProvider(cfg, repoOf(cfg, w.payload)!);
      if ("error" in p) throw new CommandError("conflict", p.error);
      enqueue(w, "create_pr", { title: a.title || undefined, draft: a.draft ?? false, provider: p.name });
      return { ok: true, message: `正在推送分支并创建${a.draft ? "草稿 " : " "}${prLabel(p.cfg.type)}，完成后会在任务里评论链接`, target: w.id };
    },
  });

  commands.register({
    name: "delivery.merge_local",
    title: "快进合并到本地分支",
    schema: z.object({ id: Id, target_branch: z.string().trim().min(1).max(200).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const { w } = checkTarget(a.id, "merge_local");
      if (a.target_branch && (await tryGit(w.payload.cwd, ["check-ref-format", "--branch", a.target_branch], { cfg, readOnly: true })).code !== 0)
        throw new CommandError("invalid", `分支名不合法：${a.target_branch}`);
      enqueue(w, "merge_local", { target_branch: a.target_branch });
      return { ok: true, message: `正在快进合并到本地分支${a.target_branch ? ` ${a.target_branch}` : ""}`, target: w.id };
    },
  });

  commands.register({
    name: "delivery.discard",
    title: "放弃（保留一段时间后清理）",
    schema: z.object({ id: Id }),
    target: (a) => a.id,
    run: async (a) => {
      const { w } = checkTarget(a.id, "discard");
      enqueue(w, "discard");
      const days = cfg.delivery.discard_retention_days;
      return { ok: true, message: days ? `已放弃，worktree 与分支保留 ${days} 天，期间可以恢复` : "已放弃，worktree 与分支将立即清理", target: w.id };
    },
  });

  commands.register({
    name: "delivery.restore",
    title: "恢复已放弃的派单",
    schema: z.object({ id: Id }),
    target: (a) => a.id,
    run: async (a) => {
      const { w } = checkTarget(a.id, "restore");
      const cleanup = pendingCleanup(w.id);
      if (!cleanup) throw new CommandError("conflict", "已超过保留期，worktree 和分支已经清理，无法恢复");
      ledger.requestCancel(cleanup.id); // 先取消清理，再记恢复（清理执行前还会再核对一次）
      enqueue(w, "restore", { cleanup_id: cleanup.id });
      return { ok: true, message: "已恢复，可以重新创建 PR 或合并", target: w.id };
    },
  });

  /** 还没执行的清理（放弃后保留期内）。 */
  function pendingCleanup(dispatchId: string): Item | undefined {
    const discard = latestDelivery(ledger, dispatchId);
    if (discard?.payload.action !== "discard" || discard.state !== "done") return undefined;
    const c = discard.payload.cleanup_id ? ledger.get<DeliveryPayload>(discard.payload.cleanup_id) : undefined;
    return c && !c.terminal ? c : undefined;
  }

  // ───────────────────────── 执行 ─────────────────────────

  function loadDispatch(id: string): Dispatch {
    const w = ledger.get<DispatchPayload>(id);
    if (!w || w.kind !== "dispatch") throw new DeliveryError(`派单不存在：${id}`);
    return w;
  }

  function needWorktree(d: DispatchPayload): RepoSpec {
    if (!d.branch || !d.cwd || !fs.existsSync(d.cwd)) throw new DeliveryError(`worktree 不存在：${d.cwd || "（无）"}`);
    const spec = repoOf(cfg, d);
    if (!spec) throw new DeliveryError("找不到派单所在的仓库（任务描述里的 repo:）");
    return spec;
  }

  const say = (guid: string, text: string): Effect[] => (guid ? [comment(guid, truncate(text, COMMENT_MAX))] : []);

  function finish(item: Item, payload: DeliveryPayload, effects: Effect[], state = "done"): void {
    ledger.transition(item, { state, terminal: true, outcome: state, payload }, effects);
    log("info", "交付完成", { work: item.id, action: payload.action, state });
  }

  async function createPr(item: Item): Promise<void> {
    const p = item.payload;
    const w = loadDispatch(p.dispatch_id);
    const d = w.payload;
    const spec = needWorktree(d);
    const prov = resolveProvider(cfg, spec);
    if ("error" in prov) throw new DeliveryError(prov.error);
    const raw = await remoteUrl(d.cwd, prov.cfg.remote, { cfg }).catch((e) => {
      throw new DeliveryError(errMsg(e));
    });
    const remote = parseRemote(raw);
    if (!remote) throw new DeliveryError(`无法从 remote ${prov.cfg.remote} 的地址识别仓库：${maskUrl(raw)}`);
    const provider = makeProvider(prov.cfg, remote, deps);

    await commitAll(d.cwd, "pa: 交付前提交未提交的改动", { cfg });
    const target =
      spec.target_branch ||
      (await remoteDefaultBranch(d.cwd, prov.cfg.remote, { cfg })) ||
      (await currentBranch(spec.path, { cfg })) ||
      "main";
    if (target === d.branch) throw new DeliveryError(`目标分支与源分支相同（${target}）`);
    const pushed = await pushBranch(d.cwd, prov.cfg.remote, d.branch, { cfg });
    if (!pushed.ok) {
      const msg = `推送 ${d.branch} 到 ${prov.cfg.remote} 失败：${maskUrl(pushed.message)}`;
      throw pushed.rejected ? new DeliveryError(`${msg}\n远端分支有本地没有的提交，请检查后重试。`) : new Error(msg);
    }
    const body = prBody(d, { taskUrl: taskUrl(app, w.ref), dispatchId: w.id, diffStat: await diffStat(d.cwd, d.base, { cfg }) });
    const pr = await openOrReuse(provider, { source: d.branch, target, title: prTitle(d.summary, p.title), body, draft: !!p.draft });
    const label = prLabel(prov.cfg.type);
    const message = `已${pr.reused ? "复用已有的" : "创建"} ${label}${p.draft && !pr.reused ? "（草稿）" : ""}：${pr.url}`;
    finish(item, { ...p, provider: prov.name, url: pr.url, number: pr.number, reused: pr.reused, target_branch: target, message }, say(p.guid, `🔗 ${message}\n分支：${d.branch} → ${target}`));
  }

  async function mergeLocal(item: Item): Promise<void> {
    const p = item.payload;
    const d = loadDispatch(p.dispatch_id).payload;
    const spec = needWorktree(d);
    const repo = spec.path;
    const target = p.target_branch || spec.target_branch || (await currentBranch(repo, { cfg }));
    if (!target) throw new DeliveryError(`主仓库 ${repo} 处于游离 HEAD，请指定目标分支`);
    if (target === d.branch) throw new DeliveryError(`目标分支与源分支相同（${target}）`);
    if (!(await branchExists(repo, target, { cfg }))) throw new DeliveryError(`主仓库 ${repo} 没有本地分支 ${target}`);
    await commitAll(d.cwd, "pa: 交付前提交未提交的改动", { cfg });
    const from = await revParse(repo, `refs/heads/${target}`, { cfg });
    const to = await revParse(repo, `refs/heads/${d.branch}`, { cfg });
    const range = `${from.slice(0, 7)}..${to.slice(0, 7)}`;
    if (from !== to) {
      if (!(await isAncestor(repo, from, to, { cfg })))
        throw new DeliveryError(
          `无法快进：${target} 上有 ${d.branch} 没有的新提交。可以改用“创建 PR”，或在 worktree（${d.cwd}）里 rebase 到 ${target} 后再合并。`,
        );
      try {
        if ((await currentBranch(repo, { cfg })) === target) {
          // 目标分支正检出在主仓库：只有工作区干净时才合并，且只允许快进
          if (!(await isClean(repo, { cfg }))) throw new DeliveryError(`主仓库 ${repo} 当前检出了 ${target} 且有未提交的改动，为避免覆盖没有合并。请先提交或暂存后重试。`);
          await git(repo, ["merge", "--ff-only", "-q", `refs/heads/${d.branch}`], { cfg });
        } else {
          // 没检出：直接更新分支引用（不带 + 的 refspec 只允许快进；目标分支在别的 worktree 检出时 git 会拒绝）
          await git(repo, ["fetch", "-q", ".", `refs/heads/${d.branch}:refs/heads/${target}`], { cfg });
        }
      } catch (e) {
        if (e instanceof DeliveryError) throw e;
        throw new DeliveryError(`合并到 ${target} 失败：${errMsg(e)}`);
      }
    }
    const message = from === to ? `本地分支 ${target} 已包含这些改动` : `已快进合并到本地分支 ${target}（${range}）`;
    finish(item, { ...p, target_branch: target, from, to, message }, say(p.guid, `✅ ${message}\n仓库：${repo}`));
  }

  async function discard(item: Item): Promise<void> {
    const p = item.payload;
    const d = loadDispatch(p.dispatch_id).payload;
    // 清理时间与清理工作 id 都由放弃工作本身确定：重试时不会重复排清理
    const cleanupAt = item.created + cfg.delivery.discard_retention_days * DAY;
    const cleanupId = `delivery:${p.dispatch_id}:cleanup:${item.created}`;
    ledger.enqueue({
      id: cleanupId,
      kind: "delivery",
      ref: p.dispatch_id,
      state: "pending",
      next_at: cleanupAt,
      payload: { action: "cleanup", dispatch_id: p.dispatch_id, guid: p.guid, discard_id: item.id } satisfies DeliveryPayload,
    });
    const pr = ledger
      .list<DeliveryPayload>({ kinds: ["delivery"], ref: p.dispatch_id, limit: 50 })
      .find((x) => x.payload.action === "create_pr" && x.state === "done" && x.payload.url);
    const keep = cfg.delivery.discard_retention_days
      ? `worktree（${d.cwd}）和分支 ${d.branch} 保留到 ${retentionText(cleanupAt, cfg.owner.timezone)}，期间可以“恢复”。`
      : `worktree 和分支 ${d.branch} 将立即清理。`;
    const prNote = pr ? `\n已创建的 PR/MR 不会自动关闭，请到平台上处理：${pr.payload.url}` : "";
    const message = `已放弃这次派单的结果。${keep}`;
    finish(item, { ...p, cleanup_id: cleanupId, cleanup_at: cleanupAt, message }, say(p.guid, `🗑️ ${message}${prNote}`));
  }

  async function restore(item: Item): Promise<void> {
    const p = item.payload;
    const d = loadDispatch(p.dispatch_id).payload;
    const c = p.cleanup_id ? ledger.get<DeliveryPayload>(p.cleanup_id) : undefined;
    if (c?.state === "done") throw new DeliveryError("已超过保留期，worktree 和分支已经清理，无法恢复");
    if (c && !c.terminal) ledger.requestCancel(c.id);
    const message = `已恢复：worktree（${d.cwd}）和分支 ${d.branch} 继续保留，可以重新创建 PR 或合并。`;
    finish(item, { ...p, message }, say(p.guid, `↩️ ${message}`));
  }

  async function cleanup(item: Item): Promise<void> {
    const p = item.payload;
    const skip = (why: string) => finish(item, { ...p, message: why }, [], "cancelled");
    if (ledger.isCancelled(item.id)) return skip("已恢复，取消清理");
    const latest = latestDelivery(ledger, p.dispatch_id);
    if (!latest || latest.id !== p.discard_id || latest.state !== "done") return skip("放弃已被撤销，不清理");
    const w = ledger.get<DispatchPayload>(p.dispatch_id);
    if (!w) return skip("派单记录已不存在");
    const newest = ledger.latest("dispatch", w.ref);
    if (newest && newest.id !== w.id) return skip("这张卡片已重新派单，worktree 继续使用，不清理");
    const d = w.payload;
    const spec = repoOf(cfg, d);
    const removed: string[] = [];
    if (spec && fs.existsSync(spec.path)) {
      const wtParent = path.join(cfg.dataDir, "worktrees");
      if (d.cwd && fs.existsSync(d.cwd)) {
        await git(spec.path, ["worktree", "remove", "--force", d.cwd], { cfg, extraWritablePaths: [wtParent] });
        removed.push(`worktree ${d.cwd}`);
      }
      await tryGit(spec.path, ["worktree", "prune"], { cfg, extraWritablePaths: [wtParent] });
      if (d.branch.startsWith("pa/") && (await branchExists(spec.path, d.branch, { cfg }))) {
        await git(spec.path, ["branch", "-D", d.branch], { cfg });
        removed.push(`本地分支 ${d.branch}`);
      }
    }
    // 之后再派这张卡片时重新记录基线
    if (w.ref) app.store.set(`worktree.${w.ref}.base`, "");
    const message = removed.length ? `已清理放弃的派单：删除${removed.join("、")}` : "放弃的派单没有需要清理的 worktree 或分支";
    finish(item, { ...p, message }, removed.length ? say(p.guid, `🧹 ${message}`) : []);
  }

  const handler: Handler<DeliveryPayload> = {
    kind: "delivery",
    concurrency: 1,
    maxAttempts: MAX_ATTEMPTS,
    async run(item) {
      const p = item.payload;
      if (
        isContextDerivedDispatchBlocked(app, p.dispatch_id) ||
        (!!p.guid && isContextDerivedDispatchBlocked(app, p.guid))
      ) {
        const msg = "该派单源自旧工作区主人的工作上下文，已按主人隔离中止交付";
        ledger.transition(item, { state: "errored", terminal: true, outcome: "errored", error: msg, payload: { ...p, message: msg } });
        log("warn", "主人隔离中止交付", { work: item.id, dispatch: p.dispatch_id, action: p.action });
        return;
      }
      try {
        switch (p.action) {
          case "create_pr":
            return await createPr(item);
          case "merge_local":
            return await mergeLocal(item);
          case "discard":
            return await discard(item);
          case "restore":
            return await restore(item);
          case "cleanup":
            return await cleanup(item);
          default:
            throw new DeliveryError(`未知的交付动作：${String((p as { action?: unknown }).action)}`);
        }
      } catch (e) {
        if (!isPermanent(e)) throw e; // 网络等暂时性错误：交给引擎退避重试
        const msg = maskUrl(errMsg(e));
        ledger.transition(item, { state: "errored", terminal: true, outcome: "errored", error: msg, payload: { ...p, message: msg } }, say(p.guid, `❌ ${ACTION_TEXT[p.action] ?? "交付"}失败：${msg}`));
        log("warn", "交付失败", { work: item.id, action: p.action, err: msg });
      }
    },
    onExhausted: (item, err) => ({
      patch: { state: "errored", outcome: "errored", payload: { ...item.payload, message: maskUrl(err) } },
      effects: say(item.payload.guid, `❌ ${ACTION_TEXT[item.payload.action] ?? "交付"}失败（已尝试 ${MAX_ATTEMPTS} 次）：${maskUrl(err)}`),
    }),
  };
  engine.register(handler);
}

function prLabel(type: ProviderCfg["type"]): string {
  return type === "github" ? "PR" : "MR";
}
