import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";
import type { App } from "./app.ts";
import type { DoctorCheck, DoctorReport } from "./api/types.ts";
import { repoSpec } from "./config.ts";
import { WebLoginStore } from "./context/feishu-web/index.ts";
import { buildWorkspaceIsolation, prepareHarnessEnv, resolveBin, wrapCredentialIsolatedCommand } from "./harness.ts";
import { consoleBaseUrl, isLoopbackHost } from "./server/index.ts";
import { validateConfig } from "./settings.ts";
import { deepFind, errMsg, runProcess, truncate } from "./util.ts";

/**
 * 体检：把依赖、登录、初始化、配置逐项检查成结构化结果，给 `pa doctor`、控制台的初始化向导和健康页用。
 *
 *   - 每项相互隔离：抛错即记为 fail（附错误信息），不影响其他项
 *   - 总耗时有上限：外部命令带超时，每项检查另有整体超时
 *   - 不调用模型、不打印任何令牌的值（只检查环境变量是否设置）
 *   - ready = 没有 fail（warn 表示能跑但有功能受限或风险）
 */

export interface DoctorOptions {
  /** 每条外部命令的超时（默认 10 秒） */
  commandTimeoutMs?: number;
  /** 每项检查的整体超时（默认 20 秒） */
  checkTimeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  home?: string;
  now?: () => number;
}

type Result = Omit<DoctorCheck, "id" | "title"> & { title?: string };
interface CheckDef {
  id: string;
  title: string;
  run: () => Promise<Result>;
}

const ok = (detail: string, fix = ""): Result => ({ status: "ok", detail, fix });
const warn = (detail: string, fix: string): Result => ({ status: "warn", detail, fix });
const fail = (detail: string, fix: string): Result => ({ status: "fail", detail, fix });
const skip = (detail: string, fix = ""): Result => ({ status: "skip", detail, fix });

/** 飞书事件（配置开关 → 事件 key → 用途） */
const EVENTS: { flag: "bot_messages" | "task_updates" | "doc_comments" | "minutes" | "card_actions"; key: string; what: string }[] = [
  { flag: "bot_messages", key: "im.message.receive_v1", what: "私聊机器人发指令" },
  { flag: "task_updates", key: "task.task.update_user_access_v2", what: "任务变更后尽快对账派单列" },
  { flag: "doc_comments", key: "drive.notice.comment_add_v1", what: "文档评论 @我 → 识别任务" },
  { flag: "minutes", key: "minutes.minute.generated_v1", what: "妙记生成 → 识别待办、写会议纪要" },
  { flag: "card_actions", key: "card.action.trigger", what: "卡片上的按钮 / 表单（回调）" },
];

/** 卡片原地更新与回调需要的最低 lark-cli 版本 */
const MIN_LARK_FOR_CARDS = [1, 0, 100];

function cmpVersion(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    t = setTimeout(() => reject(new Error(`${what}超时（${Math.round(ms / 1000)} 秒）`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

const code = (s: string) => "`" + s + "`";

export async function runDoctor(app: App, o: DoctorOptions = {}): Promise<DoctorReport> {
  const { cfg, store } = app;
  const cmdTimeout = o.commandTimeoutMs ?? 10_000;
  const checkTimeout = o.checkTimeoutMs ?? 20_000;
  const env = o.env ?? process.env;
  const home = o.home ?? os.homedir();
  const now = o.now ?? (() => Date.now());

  /** 找到可执行文件并取版本（同一个程序只查一次） */
  const memo = new Map<string, Promise<{ path: string; version: string }>>();
  const probe = (bin: string, args = ["--version"]) => {
    const key = `${bin} ${args.join(" ")}`;
    let p = memo.get(key);
    if (!p) {
      p = (async () => {
        const full = resolveBin(bin);
        const baseEnv = prepareHarnessEnv();
        let r: Awaited<ReturnType<typeof runProcess>>;
        try {
          r = await runProcess(full, args, { env: baseEnv.env, timeoutMs: cmdTimeout });
        } finally {
          baseEnv.cleanup();
        }
        if (r.timedOut) throw new Error(`${bin} ${args.join(" ")} 超时`);
        if (r.code !== 0) throw new Error(`${bin} ${args.join(" ")} 退出码 ${r.code}：${truncate((r.stderr || r.stdout).trim(), 200)}`);
        return { path: full, version: (r.stdout.trim() || r.stderr.trim()).split("\n")[0] };
      })();
      memo.set(key, p);
    }
    return p;
  };
  const probeOk = async (bin: string) => {
    try {
      await probe(bin);
      return true;
    } catch {
      return false;
    }
  };

  const checks: CheckDef[] = [];
  const add = (id: string, title: string, run: () => Promise<Result>) => checks.push({ id, title, run });

  add("node", "Node.js 版本", async () => {
    const [major, minor] = process.versions.node.split(".").map(Number);
    return major > 22 || (major === 22 && minor >= 13)
      ? ok(`Node ${process.versions.node}`)
      : fail(`当前 Node ${process.versions.node}，需要 ≥ 22.13`, `安装新版 Node，例如：\n\n${code("nvm install 22 && nvm use 22")}`);
  });

  add("config", "配置文件", async () => {
    if (!cfg.file || !fs.existsSync(cfg.file)) return warn("没有找到配置文件（使用内存中的配置）", `${code("cp config.example.yaml config.yaml")} 后按需修改`);
    const v = validateConfig(YAML.parse(fs.readFileSync(cfg.file, "utf8")));
    if (!v.ok)
      return fail(
        `${cfg.file} 有 ${v.errors.length} 处问题：${v.errors.map((e) => `${e.path || "（根）"}：${e.message}`).join("；")}`,
        `在控制台“设置”页修改，或直接编辑 ${code(cfg.file)} 后重启常驻进程`,
      );
    return ok(cfg.file);
  });

  add("lark_cli", "lark-cli", async () => {
    const fix = `安装或升级：\n\n${code("npm i -g @larksuite/cli")}\n\n如果装在非默认位置，在配置里设置 ${code("bins.lark")}`;
    try {
      const v = await probe(cfg.bins.lark);
      const m = v.version.match(/(\d+)\.(\d+)\.(\d+)/);
      if (cfg.cards.enabled && m && cmpVersion(m.slice(1).map(Number), MIN_LARK_FOR_CARDS) < 0)
        return warn(`${v.path}（${v.version}）：交互卡片需要 ≥ ${MIN_LARK_FOR_CARDS.join(".")}`, fix);
      return ok(`${v.path}（${v.version}）`);
    } catch (e) {
      return fail(errMsg(e), fix);
    }
  });

  add("lark_auth", "飞书登录", async () => {
    if (!(await probeOk(cfg.bins.lark))) return skip("lark-cli 不可用，跳过");
    const fix = `按提示在浏览器完成：\n\n${code("lark-cli config init --new")}\n\n${code("lark-cli auth login --recommend")}\n\n开发者后台需开启“刷新 user_access_token”`;
    // 直接解析 auth status：新版 lark-cli 输出的是裸 JSON（没有 ok/data 信封），也兼容信封格式
    const r = await runProcess(resolveBin(cfg.bins.lark), ["auth", "status", "--json"], { timeoutMs: cmdTimeout, cwd: cfg.dataDir });
    if (r.timedOut) return fail("lark-cli auth status 超时", fix);
    let s: Record<string, unknown>;
    try {
      s = JSON.parse(r.stdout.trim() || r.stderr.trim());
    } catch {
      return r.code === 0 ? ok(truncate(r.stdout.trim(), 200)) : fail(`未登录或登录已失效：${truncate((r.stderr || r.stdout).trim(), 300)}`, fix);
    }
    if (s.ok === false || r.code !== 0) {
      const msg = (deepFind(s, "message") as string | undefined) ?? (r.stderr || r.stdout).trim();
      return fail(`未登录或登录已失效：${truncate(String(msg), 300)}`, fix);
    }
    if (s.ok === true && s.data !== undefined) s = s.data as Record<string, unknown>;
    const ids = (s.identities ?? {}) as Record<string, { available?: boolean; status?: string; userName?: string; openId?: string; refreshExpiresAt?: string } | undefined>;
    const name = ids.user?.userName ?? deepFind(s, "name") ?? deepFind(s, "user_name");
    const id = ids.user?.openId ?? deepFind(s, "open_id") ?? deepFind(s, "user_open_id");
    const who = `${name ? String(name) : "已登录"}${id ? `（${String(id)}）` : ""}`;
    const problems: string[] = [];
    if (ids.user && ids.user.available === false) problems.push(`用户身份不可用（${ids.user.status ?? "未知"}）`);
    if (ids.bot && ids.bot.available === false) problems.push(`机器人身份不可用（${ids.bot.status ?? "未知"}），无法给你发私信和卡片`);
    if (problems.length) return fail(`${who}：${problems.join("；")}`, fix);
    const refresh = Date.parse(ids.user?.refreshExpiresAt ?? "");
    if (Number.isFinite(refresh) && refresh < now()) return fail(`${who}：登录已过期`, fix);
    if (Number.isFinite(refresh) && refresh - now() < 24 * 3600_000)
      return warn(`${who}：登录将在 24 小时内过期（${ids.user?.refreshExpiresAt}）`, `重新登录：${code("lark-cli auth login --recommend")}`);
    return ok(`${who}${ids.bot ? "，机器人身份可用" : ""}`);
  });

  add("owner", "主人身份", async () =>
    cfg.owner.open_id
      ? ok(`open_id：${cfg.owner.open_id}`)
      : fail("还不知道你的 open_id", `登录飞书后运行 ${code("bin/pa init")}（自动从登录信息获取），或在配置里填写 ${code("owner.open_id")}`),
  );

  add("board", "Agent 看板", async () => {
    const tl = store.get("board.tasklist");
    if (!tl) return fail("看板任务清单尚未创建", `运行 ${code("bin/pa init")}`);
    const missing = Object.entries(cfg.board.sections)
      .filter(([k]) => !store.get(`board.section.${k}`))
      .map(([, name]) => name);
    if (missing.length) return warn(`缺少分组：${missing.join("、")}`, `运行 ${code("bin/pa init")} 补建（常驻进程启动时也会自动补建）`);
    return ok(`「${cfg.board.name}」（${tl}），${Object.keys(cfg.board.sections).length} 个分组齐全`);
  });

  add("kb", "个人知识库", async () => {
    if (!cfg.kb.enabled) return skip("知识库未启用（kb.enabled = false）");
    const space = store.get("kb.space");
    if (!space) return warn("知识空间尚未创建：会议纪要整理、知识库作业会失败", `运行 ${code("bin/pa init")}`);
    const missing = cfg.kb.nodes.filter((n) => !store.get(`kb.node.${n}`));
    if (missing.length) return warn(`缺少节点：${missing.join("、")}`, `运行 ${code("bin/pa init")} 补建`);
    const root = store.get("kb.root");
    return ok(root ? `「${cfg.kb.space_name}」（我的文档库 ${space} / 节点 ${root}）` : `「${cfg.kb.space_name}」（${space}）`);
  });

  add("acpx", "acpx（调用各 harness）", async () => {
    const needsAcpx = Object.values(cfg.harnesses).some((h) => h.type === "acpx");
    try {
      const v = await probe(cfg.bins.acpx);
      return ok(`${v.path}（${v.version}）`);
    } catch (e) {
      if (!needsAcpx) return skip("未安装 acpx；当前配置未用到 acpx 类型的执行者");
      return fail(errMsg(e), `安装：\n\n${code("npm i -g acpx")}\n\n如果装在非默认位置，在配置里设置 ${code("bins.acpx")}`);
    }
  });

  const acpxAgents = (): Set<string> => {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(home, ".acpx", "config.json"), "utf8"));
      return new Set(Object.keys((j?.agents as Record<string, unknown>) ?? {}));
    } catch {
      return new Set();
    }
  };
  for (const [name, h] of Object.entries(cfg.harnesses)) {
    add(`harness:${name}`, `执行者 ${name}`, async () => {
      const roles = [
        cfg.roles.brain === name && "brain",
        cfg.roles.reviewer === name && "reviewer",
        (cfg.dispatch.default_harness || cfg.roles.brain) === name && "默认执行者",
        cfg.context.enabled && (cfg.context.harness || cfg.roles.brain) === name && "工作上下文",
      ].filter(Boolean);
      const problems: string[] = [];
      const fixes: string[] = [];
      const refs = [...new Set(Object.values(h.env).flatMap((v) => [...v.matchAll(/\$\{(\w+)\}/g)].map((m) => m[1])))];
      const unset = refs.filter((r) => !env[r]);
      if (unset.length) {
        problems.push(`环境变量未设置：${unset.join("、")}`);
        fixes.push(`在常驻进程的环境里设置 ${unset.map(code).join("、")}（systemd 用 ${code("Environment=")} 或 ${code("EnvironmentFile=")}）`);
      }
      if (h.type === "codex-exec" || h.type === "doubao-cli") {
        const bin = h.cmd || (h.type === "doubao-cli" ? "doubao" : "codex");
        let cmdPath = "";
        try {
          cmdPath = resolveBin(bin);
          fs.accessSync(cmdPath, fs.constants.X_OK);
        } catch {
          return fail(
            `找不到启动命令 ${bin}`,
            h.type === "doubao-cli"
              ? `安装豆包 CLI（doubao）或在 ${code(`harnesses.${name}.cmd`)} 里写绝对路径`
              : `安装 Codex CLI 或在 ${code(`harnesses.${name}.cmd`)} 里写绝对路径`,
          );
        }
        const how = h.type === "doubao-cli" ? `${cmdPath} -p（豆包 CLI）` : `${cmdPath} exec（只读）`;
        const detail = `${how}${h.model ? `，模型 ${h.model}` : ""}${roles.length ? `，角色：${roles.join("、")}` : ""}（未实际调用模型）`;
        return problems.length ? warn(`${detail}；${problems.join("；")}`, fixes.join("\n\n")) : ok(detail);
      }
      if (!h.agent === !h.agentCommand) return fail("必须且只能设置 agent 或 agentCommand 之一", `在设置页或配置文件的 ${code(`harnesses.${name}`)} 里修正`);
      const how = h.agent ? `acpx ${h.agent}${acpxAgents().has(h.agent) ? "（~/.acpx/config.json 自定义）" : ""}` : `acpx --agent '${h.agentCommand}'`;
      const detail = `${how}${h.model ? `，模型 ${h.model}` : ""}${roles.length ? `，角色：${roles.join("、")}` : ""}（未实际调用模型）`;
      if (!(await probeOk(cfg.bins.acpx))) return skip(`acpx 不可用，跳过：${detail}`);
      if (h.agentCommand) {
        const bin = h.agentCommand.trim().split(/\s+/)[0];
        try {
          resolveBin(bin);
        } catch {
          problems.push(`找不到启动命令 ${bin}`);
          fixes.push(`安装 ${code(bin)} 或在 ${code("agentCommand")} 里写绝对路径`);
        }
      }
      return problems.length ? warn(`${detail}；${problems.join("；")}`, fixes.join("\n\n")) : ok(detail);
    });
  }

  add("git", "git", async () => {
    try {
      const v = await probe("git");
      return ok(v.version);
    } catch (e) {
      return fail(errMsg(e), "安装 git（派单在独立 git worktree 中执行），例如 `sudo apt install git`");
    }
  });

  const repos = Object.keys(cfg.dispatch.repos);
  if (!repos.length)
    add("repos", "仓库", async () =>
      skip("没有配置仓库别名：派单只能在默认工作目录执行", `在设置页或配置文件的 ${code("dispatch.repos")} 里添加，如 ${code("web: ~/code/web")}`),
    );
  for (const alias of repos) {
    add(`repo:${alias}`, `仓库 ${alias}`, async () => {
      const spec = repoSpec(cfg, alias);
      const fixPath = `检查 ${code(`dispatch.repos.${alias}`)} 的路径是否正确`;
      if (!fs.existsSync(spec.path)) return fail(`路径不存在：${spec.path}`, fixPath);
      if (!(await probeOk("git"))) return skip(`git 不可用，跳过：${spec.path}`);
      const baseEnv = prepareHarnessEnv();
      let r: Awaited<ReturnType<typeof runProcess>>;
      try {
        const wrapped = wrapCredentialIsolatedCommand(
          resolveBin("git"),
          [
            "-C",
            spec.path,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "rev-parse",
            "--is-inside-work-tree",
          ],
          process.env,
          buildWorkspaceIsolation(cfg, {
            mode: "git-ro",
            cwd: spec.path,
            trustedRepoRoot: spec.path,
            extraReadOnlyPaths: baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : [],
          }),
        );
        r = await runProcess(wrapped.cmd, wrapped.args, { env: baseEnv.env, timeoutMs: cmdTimeout });
      } finally {
        baseEnv.cleanup();
      }
      if (r.code !== 0 || r.stdout.trim() !== "true") return fail(`${spec.path} 不是 git 仓库`, `${fixPath}，或在该目录运行 ${code("git init")}`);
      return ok(`${spec.path}${spec.verify ? `，校验命令：${code(spec.verify)}` : "，未配置校验命令"}`);
    });
  }

  add("acceptance", "验收方式", async () => {
    const verified = Object.entries(cfg.dispatch.repos)
      .filter(([, v]) => typeof v !== "string" && v.verify)
      .map(([k]) => k);
    const policy = cfg.acceptance.on_unverified === "needs_human" ? "需人工介入" : "标为未验证进待验收";
    const detail = `审查者：${cfg.roles.reviewer || "无"}；带校验命令的仓库：${verified.join("、") || "无"}；无任何校验时 → ${policy}`;
    if (!cfg.roles.reviewer && !verified.length && cfg.acceptance.on_unverified === "needs_human")
      return warn(
        `${detail}。所有派单结果都会进“需人工介入”`,
        `配置 ${code("roles.reviewer")}（交叉审查），或给仓库加 ${code("verify")} 校验命令，或把 ${code("acceptance.on_unverified")} 改为 ${code("review")}`,
      );
    return ok(detail);
  });

  const providers = Object.entries(cfg.delivery.providers);
  if (!providers.length)
    add("delivery", "交付平台", async () => skip("没有配置 PR 平台（可选）：仍可合并到本地分支或放弃", `在 ${code("delivery.providers")} 里添加 github / gitlab / codebase`));
  for (const [name, p] of providers) {
    add(`provider:${name}`, `交付平台 ${name}（${p.type}）`, async () => {
      if (p.type === "codebase") {
        try {
          const v = await probe("bytedcli");
          return ok(`${v.path}（${v.version}），使用 bytedcli 的登录态`);
        } catch (e) {
          return warn(`bytedcli 不可用：${errMsg(e)}`, "安装 bytedcli 并完成登录（创建 MR 走 bytedcli 的登录态）");
        }
      }
      const def = p.type === "github" ? "GITHUB_TOKEN" : "GITLAB_TOKEN";
      if (!p.token_env) return warn("没有配置 token_env（存放访问令牌的环境变量名）", `在 ${code(`delivery.providers.${name}.token_env`)} 填写环境变量名，如 ${code(def)}，并在常驻进程环境里设置它`);
      if (!env[p.token_env]) return warn(`环境变量 ${p.token_env} 未设置：无法创建 PR/MR`, `在常驻进程的环境里设置 ${code(p.token_env)}（不要写进配置文件）`);
      return ok(`令牌来自环境变量 ${p.token_env}（已设置）${p.base_url ? `，${p.base_url}` : ""}`);
    });
  }

  add("server", "Web 控制台", async () => {
    const s = cfg.server;
    if (!s.enabled) return skip("server.enabled 为 false：常驻进程不会启动控制台", `把 ${code("server.enabled")} 改为 true 后重启常驻进程`);
    const url = consoleBaseUrl(s.host, s.port);
    if (isLoopbackHost(s.host)) {
      return ok(`监听 ${s.host}:${s.port}（仅本机）`, `运行 ${code("bin/pa console")} 获取登录链接；远程开发机先转发端口：${code(`ssh -L ${s.port}:127.0.0.1:${s.port} <开发机>`)}`);
    }
    return ok(`监听 ${s.host}:${s.port}（访问地址 ${url}，令牌鉴权）`, `运行 ${code("bin/pa console")} 获取登录链接；如需仅限本机访问，可把 ${code("server.host")} 设为 ${code("127.0.0.1")}`);
  });

  add("events", "飞书事件订阅", async () => {
    const wanted = EVENTS.filter((e) => cfg.events[e.flag] && (e.flag !== "card_actions" || cfg.cards.enabled));
    const list = wanted.map((e) => `- ${code(e.key)}：${e.what}`).join("\n");
    const fix =
      `在飞书开发者后台（你的应用 → 事件与回调）选择“使用长连接接收”，开启以下事件${wanted.some((e) => e.flag === "card_actions") ? `；${code("card.action.trigger")} 在“回调配置”里开启` : ""}，然后**发布新版本**：\n\n${list}` +
      "\n\n订阅是否生效无法在本机检测；如果私聊指令或卡片按钮没反应，先检查这里。";
    const detail = wanted.length ? `需要开启 ${wanted.length} 个：${wanted.map((e) => e.key).join("、")}` : "没有开启任何事件（只靠定时轮询）";
    if (cfg.cards.enabled && !cfg.events.card_actions)
      return warn(`${detail}；卡片已启用但 events.card_actions 为 false：卡片上的按钮不会生效`, `把 ${code("events.card_actions")} 改为 true 并重启常驻进程。\n\n${fix}`);
    if (cfg.cards.enabled && cfg.events.card_actions && !app.ext.cards) return ok(`${detail}（卡片模块未启用，暂不订阅 card.action.trigger）`, fix);
    return ok(detail, fix);
  });

  add("personal_web", "个人 Web 实时通道", async () => {
    if (!cfg.context.enabled || !cfg.context.personal_web.enabled) {
      return skip(
        "未启用（当前仅走 lark-cli 定时采集）",
        `如需秒级响应任意群 @我 与私聊，先运行 ${code("bin/pa context web-login")} 扫码，再把 ${code("context.personal_web.enabled")} 设为 true`,
      );
    }
    const inspected = new WebLoginStore(cfg.dataDir).inspect();
    const pw = app.ext.context?.status().personal_web;
    if (inspected.status === "missing_key") {
      if (pw && pw.logged_in && pw.state === "listening") {
        return ok(`${pw.owner_name || pw.owner_id}（常驻进程在线监听中；当前 shell 未注入解密密钥，未在本地解密凭据文件）`);
      }
      return warn(
        `检测到已加密的个人 Web 凭据，但当前环境缺少解密密钥（常驻状态：${pw?.state ?? "未知"}）`,
        "请在常驻服务环境中提供 PA_FEISHU_WEB_KEY 或通过 systemd LoadCredential 配置 feishu-web-key",
      );
    }
    if (inspected.status === "plaintext_rejected") {
      return warn(
        "检测到未加密的明文个人 Web 凭据，已按安全策略拒绝加载",
        `配置加密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）后运行 ${code("bin/pa context web-login --allow-unverified-owner")} 重新扫码加密保存`,
      );
    }
    const login = inspected.status === "ok" ? inspected.login : undefined;
    if (!login) {
      if (inspected.status === "missing" && pw && pw.logged_in && pw.state === "listening") {
        return ok(`${pw.owner_name || pw.owner_id}（常驻进程在线监听中；当前默认路径无本地凭据文件，常驻服务可能使用了自定义 PA_FEISHU_WEB_CRED_FILE）`);
      }
      return warn(
        "已启用但尚未扫码登录（期间仍由每 10 分钟的飞书轮询兜底）",
        `配置加密密钥后运行 ${code("bin/pa context web-login --allow-unverified-owner")} 使用本人飞书 App 扫码登录`,
      );
    }
    const state = pw?.state ?? "idle";
    const lastError = pw?.last_error ?? "";
    if (state === "needs_login") {
      return warn(
        `会话已失效（${lastError || "需要重新扫码"}）`,
        `运行 ${code("bin/pa context web-login")} 重新扫码登录`,
      );
    }
    if (state === "publication_blocked") {
      return warn(
        `消息入库受阻，已暂缓确认推送（${lastError || "请检查数据库或排除规则"}）`,
        "检查常驻进程日志确认数据库写入与排除规则解析是否正常",
      );
    }
    return ok(`${login.owner_name || login.owner_id}（已登录，当前状态：${state}）`);
  });

  add("data_dir", "数据目录", async () => {
    const probeFile = path.join(cfg.dataDir, `.doctor-${process.pid}-${now()}`);
    try {
      fs.writeFileSync(probeFile, "ok");
      fs.rmSync(probeFile, { force: true });
      return ok(cfg.dataDir);
    } catch (e) {
      return fail(`${cfg.dataDir} 不可写：${errMsg(e)}`, `检查目录权限，或在配置文件里把 ${code("data_dir")} 改到可写的位置`);
    }
  });

  add("daemon", "常驻进程", async () => {
    const hb = store.get("daemon.heartbeat");
    const fix = `前台试跑：${code("bin/pa run")}；长期运行见 ${code("deploy/")}（systemd 单元或守护脚本）`;
    if (!hb) return warn("从未运行过", fix);
    const [owner, ms] = [hb.slice(0, hb.lastIndexOf("|")), Number(hb.slice(hb.lastIndexOf("|") + 1))];
    const age = now() - ms;
    if (Number.isFinite(age) && age < 60_000) return ok(`运行中（${owner}，${Math.max(0, Math.round(age / 1000))} 秒前心跳）`);
    const when = Number.isFinite(ms) ? new Date(ms).toLocaleString("zh-CN", { timeZone: cfg.owner.timezone, hour12: false }) : "未知";
    return warn(`没有在运行（最后心跳：${when}）`, fix);
  });

  const results = await Promise.all(
    checks.map(async (c): Promise<DoctorCheck> => {
      try {
        const r = await withTimeout(c.run(), checkTimeout, "检查");
        return { id: c.id, title: r.title ?? c.title, status: r.status, detail: r.detail, fix: r.fix };
      } catch (e) {
        return { id: c.id, title: c.title, status: "fail", detail: `检查出错：${errMsg(e)}`, fix: "" };
      }
    }),
  );
  return { checks: results, ready: !results.some((r) => r.status === "fail") };
}

const ICON: Record<DoctorCheck["status"], string> = { ok: "✅", warn: "⚠️ ", fail: "❌", skip: "⏭️ " };

/** 命令行输出：每项一行，非通过项附修复指引 */
export function formatReport(r: DoctorReport): string {
  const lines: string[] = [];
  for (const c of r.checks) {
    lines.push(`${ICON[c.status]} ${c.title}：${c.detail}`);
    if (c.fix && (c.status === "warn" || c.status === "fail")) for (const l of c.fix.split("\n")) if (l.trim()) lines.push(`     ${l}`);
  }
  const n = (s: DoctorCheck["status"]) => r.checks.filter((c) => c.status === s).length;
  lines.push("");
  lines.push(r.ready ? `✅ 可以运行（${n("warn")} 项提醒）` : `❌ 还有 ${n("fail")} 项需要处理（${n("warn")} 项提醒）`);
  return lines.join("\n");
}

export function registerDoctor(app: App): void {
  app.ext.doctor = { run: () => runDoctor(app) };
}
