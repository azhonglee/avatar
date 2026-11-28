import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";
import type { App } from "./app.ts";
import type { DoctorCheck, DoctorReport } from "./api/types.ts";
import { repoSpec } from "./config.ts";
import { createGatewayClientForConfig, legacyPersonalWebArtifacts, resolveGatewayClientConfig, verifyGatewayOwnerForWorkspace } from "./context/personal-web.ts";
import { GatewayHttpError } from "./gateway/protocol.ts";
import { resolveBin } from "./harness.ts";
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
        const r = await runProcess(full, args, { timeoutMs: cmdTimeout });
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
      const r = await runProcess(resolveBin("git"), ["-C", spec.path, "rev-parse", "--is-inside-work-tree"], { timeoutMs: cmdTimeout });
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

  add("personal_web_legacy", "旧版个人 Web 凭据残留", async () => {
    const legacy = legacyPersonalWebArtifacts(cfg, env);
    if (!legacy.files.length && !legacy.externalFiles.length && !legacy.envKeys.length) return ok("未发现旧版遗留的个人 Web 会话凭据");
    const parts = [
      ...(legacy.files.length ? [`数据目录中仍有会话凭据文件 ${legacy.files.join("、")}`] : []),
      ...(legacy.externalFiles.length ? [`环境变量指向外部凭据文件 ${legacy.externalFiles.join("、")}`] : []),
      ...(legacy.envKeys.length ? [`运行环境中仍设置了 ${legacy.envKeys.join("、")}`] : []),
    ];
    const fixes = [
      ...(legacy.files.length ? [`运行 ${code("pa context web-logout")} 删除数据目录内的残留文件`] : []),
      ...(legacy.externalFiles.length ? [`核实外部凭据文件是否仍被新网关使用后再决定是否手动删除`] : []),
      ...(legacy.envKeys.length ? [`从 Avatar 运行环境移除 ${legacy.envKeys.map((k) => code(k)).join("、")}`] : []),
    ];
    return warn(
      `${parts.join("；")}：同一系统用户下的 worker 仍可能读到个人飞书会话`,
      `${fixes.join("，")}；登录态只保留在独立网关`,
    );
  });

  add("personal_web", "个人 Web 独立网关", async () => {
    const pwCfg = cfg.context.personal_web;
    if (!cfg.context.enabled || !pwCfg.enabled) {
      return skip(
        "未启用（当前仅走 lark-cli 定时采集）",
        `如需秒级响应任意群 @我 与私聊，请先以独立进程/用户部署 ${code("bin/feishu-gateway")}（${code("feishu-gateway login")} + ${code("feishu-gateway run")}），再在 ${code("config.yaml")} 中配置 ${code("context.personal_web.gateway_socket")}（或 ${code("gateway_url")}）并将 ${code("enabled")} 设为 true`,
      );
    }
    const resolved = resolveGatewayClientConfig(pwCfg, env);
    if (!resolved.socketPath && !resolved.baseUrl) {
      return fail(
        "已启用个人 Web 通道但未配置网关地址",
        `在 ${code("config.yaml")} 中配置 ${code("context.personal_web.gateway_socket")} 或回环 ${code("gateway_url")}`,
      );
    }
    if (!resolved.readToken) {
      return fail(
        `缺少网关只读令牌（环境变量 ${pwCfg.read_token_env || "FEISHU_GW_READ_TOKEN"} 未设置）`,
        `非 systemd 部署请在网关侧运行 ${code("bin/feishu-gateway tokens")} 获取 read_token；systemd ${code("LoadCredential")} 部署请查看 ${code("/etc/feishu-gateway/secrets/read-token")}，并在运行 Avatar 前导出环境变量 ${code(pwCfg.read_token_env || "FEISHU_GW_READ_TOKEN")}`,
      );
    }
    if (resolved.replyToken && resolved.readToken === resolved.replyToken) {
      return fail(
        "安全约束违规：read_token 与 reply_token 相同",
        `为 ${code(pwCfg.read_token_env)} 与 ${code(pwCfg.reply_token_env)} 配置各自独立的令牌`,
      );
    }
    if (pwCfg.send_replies && !resolved.replyToken) {
      return fail(
        `已开启 send_replies 但缺少回复令牌（环境变量 ${pwCfg.reply_token_env || "FEISHU_GW_REPLY_TOKEN"} 未设置）`,
        `在运行 Avatar 前导出 ${code(pwCfg.reply_token_env || "FEISHU_GW_REPLY_TOKEN")}（文件模式来自 ${code("bin/feishu-gateway tokens")}，systemd 部署见 ${code("/etc/feishu-gateway/secrets/reply-token")}），或关闭 ${code("context.personal_web.send_replies")}`,
      );
    }
    let client;
    try {
      client = createGatewayClientForConfig(pwCfg, env);
    } catch (e) {
      return fail(`个人 Web 网关配置无效：${errMsg(e)}`, `检查 ${code("config.yaml")} 中的 ${code("context.personal_web")} 地址与令牌配置`);
    }
    try {
      const st = await client.status({ timeoutMs: 3_000 });
      if (st.owner_id) {
        try {
          verifyGatewayOwnerForWorkspace(app, st.owner_id);
        } catch (e) {
          return fail(
            errMsg(e),
            `确认 ${resolved.endpointLabel} 指向正确的网关实例；如网关已通过 ${code("--force-switch-account")} 切换账号，请运行 ${code("pa context web-unbind")} 解除当前工作区旧绑定`,
          );
        }
      }
      if (st.credential_status === "missing_key") {
        return fail(
          `网关缺少凭据解密密钥（${resolved.endpointLabel}）`,
          `在网关侧配置 ${code("FEISHU_GW_KEY")}（或 systemd ${code("LoadCredential=feishu-gw-key:...")}）并重启网关`,
        );
      }
      if (st.credential_status === "plaintext_rejected" || st.credential_status === "invalid") {
        return fail(
          `网关凭据异常（${st.credential_status}）：${st.last_error || "解密失败"}`,
          `在网关侧核对 ${code("FEISHU_GW_KEY")} 或重新运行 ${code("bin/feishu-gateway login")}`,
        );
      }
      if (!st.logged_in || st.state === "needs_login") {
        return warn(
          `网关在线但尚未登录或会话已失效（${st.last_error || st.credential_status}）`,
          `在网关侧运行 ${code("bin/feishu-gateway login")} 使用本人飞书 App 扫码登录`,
        );
      }
      if (pwCfg.send_replies && !st.allow_reply) {
        return warn(
          `网关已连接（${st.owner_name || st.owner_id}，${st.state}），但网关侧 allow_reply 为 false，无法发送回复`,
          `如需走个人 Web 发送回复，请在网关 ${code("gateway.yaml")} 中显式设置 ${code("allow_reply: true")} 并重启网关`,
        );
      }
      return ok(`${st.owner_name || st.owner_id}（${resolved.endpointLabel}，状态：${st.state}，缓存 seq ${st.latest_seq}）`);
    } catch (e) {
      if (e instanceof GatewayHttpError && (e.statusCode === 401 || e.statusCode === 403)) {
        return fail(
          `网关鉴权失败（${e.code}）：${e.message}`,
          `核对 ${code(pwCfg.read_token_env || "FEISHU_GW_READ_TOKEN")} 是否与网关当前生效的 read_token 一致（文件模式运行 ${code("bin/feishu-gateway tokens")}，systemd ${code("LoadCredential")} 部署请核对 ${code("/etc/feishu-gateway/secrets/read-token")}）`,
        );
      }
      return warn(
        `无法连接到个人 Web 网关 ${resolved.endpointLabel}：${errMsg(e)}（期间由每 10 分钟的飞书轮询兜底）`,
        `确认独立网关正在运行（${code("bin/feishu-gateway run")}）且当前用户对 socket 有访问权限`,
      );
    }
  });

  add("personal_web_boundary", "个人 Web 令牌隔离边界", async () => {
    const pwCfg = cfg.context.personal_web;
    if (!cfg.context.enabled || !pwCfg.enabled) {
      return skip("个人 Web 通道未启用");
    }
    const resolved = resolveGatewayClientConfig(pwCfg, env);
    if (pwCfg.send_replies) {
      return warn(
        "已开启 context.personal_web.send_replies：与 Avatar 同 OS 用户运行的 --approve-all worker 可从 /proc/<pid>/environ 或 $CREDENTIALS_DIRECTORY 读取 reply_token，在网关 allow_reply=true 时能以本人身份回复消息",
        `如不需要经个人 Web 自动发送回复，将 ${code("context.personal_web.send_replies")} 设为 false 并从 Avatar 运行环境/凭据目录移除 ${code(pwCfg.reply_token_env || "FEISHU_GW_REPLY_TOKEN")}；如需保留，请将派单 worker 隔离在独立 OS 用户或容器中运行`,
      );
    }
    if (resolved.replyToken) {
      return warn(
        `context.personal_web.send_replies 已关闭，但 Avatar 进程环境或 $CREDENTIALS_DIRECTORY 中仍存在 reply_token（${pwCfg.reply_token_env || "FEISHU_GW_REPLY_TOKEN"}）：同 OS 用户的 --approve-all worker 仍可读取该令牌并在网关 allow_reply=true 时直接调用回复接口`,
        `从 Avatar 运行环境或 systemd LoadCredential 中移除 ${code(pwCfg.reply_token_env || "FEISHU_GW_REPLY_TOKEN")}（reply-token），仅保留只读令牌`,
      );
    }
    return ok("个人 Web 回复已关闭且未向 Avatar 暴露 reply_token（仅使用只读通道；如需对 read_token 做强隔离，仍建议以独立 OS 用户或容器运行 worker）");
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
