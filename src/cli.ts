import fs from "node:fs";
import { parseArgs } from "node:util";
import { createApp, initApp, runConfiguredJob, runDaemon, runDispatchOnce, sendBrief } from "./app.ts";
import { loadConfig } from "./config.ts";
import {
  createGatewayClientForConfig,
  formatTokenSourceLabel,
  inspectPersonalWebGateway,
  legacyPersonalWebArtifacts,
  resolveGatewayClientConfig,
  unbindPersonalWebAccount,
  verifyGatewayOwnerForWorkspace,
} from "./context/personal-web.ts";
import { runPersonalWebSetup, type SetupTokenOrigin } from "./context/personal-web-setup.ts";
import { decide, type Profile } from "./guard.ts";
import { consoleBaseUrl, isLoopbackHost, resolveConsoleHost, serverToken } from "./server/index.ts";
import { formatReport, runDoctor } from "./doctor.ts";
import { errMsg } from "./util.ts";
import { runAgentJob, statusText } from "./workflows/agent.ts";
import { buildBrief } from "./workflows/brief.ts";

const USAGE = `用法：pa <命令>

  doctor                      检查依赖、登录状态和初始化情况
  init                        建看板清单/分组、知识空间/节点，记录你的 open_id（可重复执行）
  run                         常驻运行（事件长连接 + 定时任务）
  brief [morning|evening]     生成概览并私信给你（--print 只打印不发送）
  capture                     立即识别一轮任务
  dispatch                    立即对账“派给Agent”列并执行派单（含崩溃后未完成的），等待完成
  context run                 立即采集并理解一轮（Meego / 飞书任务 / 消息 / 妙记 / 日历），打印结果
  context today               打印「今天」：最该处理的事、冲突、草稿、今天的会
  context digest [morning|evening]   发送晨间卡 / 收尾卡（--print 只打印不发送）
  context split <项目>        把一个大项目拆成子项目（模型归类，可重复执行）
  context web-setup [选项]           自动配置个人 Web 网关地址并同步只读令牌到 <data_dir>/gateway.env（0600）
  context web-status [--verify]      查询独立飞书个人 Web 网关的连接与缓存状态（登录/登出请使用 feishu-gateway）
  context web-unbind          解除当前工作区与个人 Web 账号的绑定并重置本地网关游标（切换网关账号时使用）
  context web-logout          删除旧版残留在本机数据目录的个人 Web 会话凭据（feishu-web.json）
  status                      最近 24 小时的派单、作业，以及重试中/失败的事件和飞书写入
  console [--rotate]          打印控制台登录链接（--rotate 作废旧链接）；常驻进程运行时可用
  command <名称> [JSON 参数]   执行一条命令（与控制台/卡片按钮相同），如 pa command dispatch.cancel '{"id":"…"}'
  job <名称>                  立即执行 config.yaml 里定义的 agent 作业
  ask <文字>                  让 superagent 处理一句话并打印回复
  publish-doc <file.md>       把 Markdown 发布为飞书文档（--title 标题，--parent 知识库节点名，缺省放“我的文档库”）
  guard-check <profile> -- <lark-cli 参数…>   查看守卫对一条命令的判定
`;

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "help" || cmd === "--help") return void process.stdout.write(USAGE);

  if (cmd === "guard-check") {
    const [profile, ...args] = rest.filter((a, i) => !(a === "--" && i === 1));
    const d = decide(args, profile as Profile, process.env.PA_OWNER_OPEN_ID ?? "ou_owner");
    return void console.log(`${d.allow ? "ALLOW" : "DENY "} ${d.reason}`);
  }

  const cfg = loadConfig();
  const app = createApp(cfg);

  switch (cmd) {
    case "doctor":
      return doctor(app);
    case "init": {
      await initApp(app);
      const kbSpace = app.store.get("kb.space");
      const kbRoot = app.store.get("kb.root");
      const kbInfo = !cfg.kb.enabled ? "已关闭" : kbRoot ? `${kbSpace}（我的文档库 / 根节点 ${kbRoot}）` : (kbSpace ?? "未初始化");
      console.log(`✅ 初始化完成\n主人 open_id：${cfg.owner.open_id}\n看板清单：${app.store.get("board.tasklist")}\n知识空间：${kbInfo}`);
      if (cfg.context.enabled && cfg.context.personal_web.enabled) {
        const icon: Record<string, string> = { ok: "✅", warn: "⚠️ ", fail: "❌", skip: "⏭️ " };
        try {
          const pw = await inspectPersonalWebGateway(app, { timeoutMs: 3_000 });
          console.log(`个人 Web 网关：${icon[pw.personalWeb.status]} ${pw.personalWeb.detail}`);
          if ((pw.personalWeb.status === "warn" || pw.personalWeb.status === "fail") && pw.personalWeb.fix) {
            console.log(`  指引：${pw.personalWeb.fix}`);
          }
          if (pw.boundary.status === "warn" || pw.boundary.status === "fail") {
            console.log(`个人 Web 边界提醒：${icon[pw.boundary.status]} ${pw.boundary.detail}`);
            if (pw.boundary.fix) console.log(`  指引：${pw.boundary.fix}`);
          }
        } catch (e) {
          console.log(`个人 Web 网关：⚠️  只读检测异常（${errMsg(e)}），可稍后运行 bin/pa doctor 核查`);
        }
      } else if (cfg.context.enabled) {
        console.log("个人 Web 网关：未启用（可选：部署独立网关后运行 bin/pa context web-setup 接入）");
      }
      return;
    }
    case "run":
      return runDaemon(app);
    case "brief": {
      const { values, positionals } = parseArgs({ args: rest, options: { print: { type: "boolean" } }, allowPositionals: true });
      const mode = positionals[0] === "evening" ? "evening" : "morning";
      if (values.print) console.log(await buildBrief(cfg, app.lark, app.store, app.ledger, app.board, mode));
      else {
        await sendBrief(app, mode);
        await app.engine.drain(["effect"]);
      }
      return;
    }
    case "capture":
      return void console.log(await app.capture.run());
    case "dispatch": {
      const r = await runDispatchOnce(app);
      console.log(`新派单 ${r.enqueued} 个`);
      for (const w of r.items) if (w) console.log(`- ${w.state}${w.terminal ? "" : "（未完成，常驻进程会继续）"} ${String(w.payload.summary ?? w.ref)}`);
      const pending = app.ledger.active("effect").length;
      if (pending) console.log(`⚠️ 还有 ${pending} 条飞书写入待重试，常驻进程会继续投递`);
      return;
    }
    case "context":
      return context(app, rest);
    case "status":
      return void console.log(statusText(app.ledger));
    case "console": {
      const token = serverToken(app, rest.includes("--rotate"));
      const displayHost = resolveConsoleHost(cfg.server.host);
      const base = consoleBaseUrl(displayHost, cfg.server.port);
      if (isLoopbackHost(cfg.server.host)) {
        console.log(`控制台登录链接（仅本机监听；远程开发机请先转发端口 ${cfg.server.port}）：\n${base}/login?token=${token}`);
        console.log(`\n端口转发示例：ssh -L ${cfg.server.port}:127.0.0.1:${cfg.server.port} <开发机>   （VS Code Remote 会自动转发）`);
      } else if (isLoopbackHost(displayHost)) {
        console.log(`控制台登录链接（未检测到局域网 IP，已回退到本机地址）：\n${base}/login?token=${token}`);
      } else {
        console.log(`控制台登录链接（同局域网浏览器可直接打开）：\n${base}/login?token=${token}`);
      }
      if (!cfg.server.enabled) console.log("⚠️  config.yaml 里 server.enabled 为 false，常驻进程不会启动控制台");
      return;
    }
    case "command": {
      const [name, json] = rest;
      if (!name) return void console.log(`可用命令：\n${app.commands.names().map((n) => `  ${n}`).join("\n")}`);
      const r = await app.commands.exec(name, json ? JSON.parse(json) : {}, { source: "cli", actor: "owner" });
      console.log(`${r.ok ? "✅" : "❌"} ${r.message}${r.target ? `（${r.target}）` : ""}${r.url ? `\n${r.url}` : ""}`);
      await app.engine.drain(["effect"]);
      return;
    }
    case "job":
      if (!rest[0]) throw new Error("用法：pa job <名称>");
      return void console.log(await runConfiguredJob(app, rest[0]));
    case "ask": {
      const r = await runAgentJob(cfg, app.store, app.ledger, { name: "ask", task: rest.join(" ") });
      return void console.log(r.text);
    }
    case "publish-doc": {
      const { values, positionals } = parseArgs({
        args: rest,
        options: { title: { type: "string" }, parent: { type: "string" } },
        allowPositionals: true,
      });
      const file = positionals[0];
      if (!file) throw new Error("用法：pa publish-doc <file.md> [--title 标题] [--parent 知识库节点名]");
      const md = fs.readFileSync(file, "utf8");
      const title = values.title ?? md.match(/^#\s+(.+)$/m)?.[1] ?? file;
      if (values.parent) return void console.log(await app.kb.createDoc(values.parent, title, md));
      const out = await app.lark.run(
        ["docs", "+create", "--doc-format", "markdown", "--title", title, "--parent-position", "my_library", "--content", "-"],
        { as: "user", input: md },
      );
      return void console.log(JSON.stringify(out, null, 2));
    }
    default:
      process.stdout.write(USAGE);
      process.exitCode = 2;
  }
}

async function context(app: ReturnType<typeof createApp>, rest: string[]): Promise<void> {
  const [sub, ...more] = rest;

  // 清理旧版（进程内个人 Web）遗留在 Avatar 数据目录内的会话凭据；外部 PA_FEISHU_WEB_CRED_FILE 仅提示不自动删（避免误删新网关凭据）
  if (sub === "web-logout") {
    const legacy = legacyPersonalWebArtifacts(app.cfg);
    const removed: string[] = [];
    const failed: string[] = [];
    for (const f of legacy.files) {
      try {
        fs.rmSync(f, { force: true });
        removed.push(f);
      } catch (e) {
        failed.push(`${f}（${errMsg(e)}）`);
      }
    }
    console.log(removed.length ? `已删除数据目录内的旧版个人 Web 凭据：\n${removed.map((f) => `  ${f}`).join("\n")}` : "数据目录内未发现旧版个人 Web 凭据文件。");
    if (failed.length) {
      console.log(`⚠️ 以下文件删除失败，请检查权限后手动删除：\n${failed.map((f) => `  ${f}`).join("\n")}`);
    }
    if (legacy.externalFiles.length) {
      console.log(
        `⚠️ 检测到数据目录外的 PA_FEISHU_WEB_CRED_FILE 文件（为避免误删独立网关凭据未自动删除，请核实后再手动处理）：\n${legacy.externalFiles.map((f) => `  ${f}`).join("\n")}`,
      );
    }
    if (legacy.envKeys.length) {
      console.log(`请从 Avatar 的运行环境（shell / systemd 单元）中移除：${legacy.envKeys.join("、")}，然后重启 pa run。`);
    }
    console.log("旧会话在飞书侧仍可能有效：请在飞书 App 的登录设备管理中移除对应的网页登录；网关的登录/登出请使用 feishu-gateway login / logout。");
    return;
  }
  // 解除当前工作区绑定的个人 Web 账号并清空网关游标/db_epoch/状态缓存（供切换网关账号时使用）
  if (sub === "web-unbind") {
    const { previousOwnerId } = unbindPersonalWebAccount(app);
    console.log(
      previousOwnerId
        ? `已解除当前工作区与个人 Web 账号 ${previousOwnerId} 的绑定，并重置网关游标与状态缓存。`
        : "当前工作区尚未绑定个人 Web 账号，已重置网关游标与状态缓存。",
    );
    console.log("下次连接个人 Web 网关时将自动绑定网关当前账号并从新事件库重新同步（历史观测不会被删除）。");
    return;
  }
  // 自动配置个人 Web 网关地址并同步/更新只读令牌到 <data_dir>/gateway.env（0600，不依赖 context.enabled）
  if (sub === "web-setup") {
    if (more.includes("--help") || more.includes("-h")) {
      console.log(
        `用法：pa context web-setup [选项]

  --gateway-config <file>    指定网关 gateway.yaml 路径（缺省查找 FEISHU_GW_CONFIG 或仓库根目录 gateway.yaml）
  --socket <path>            显式指定网关 Unix Socket 路径（与 --url 二选一）
  --url <http://127.0.0.1:…> 显式指定网关回环 HTTP 地址（与 --socket 二选一）
  --read-token-file <path>   从文件读取只读令牌（如 /etc/feishu-gateway/secrets/read-token，推荐用于跨用户部署）
  --read-token <token>       显式传入只读令牌
  --with-reply               显式开启 send_replies 并同步回复令牌（需网关侧同时开启 allow_reply）
  --reply-token-file <path>  配合 --with-reply 从文件读取回复令牌
  --reply-token <token>      配合 --with-reply 显式传入回复令牌
  --no-reply                 显式关闭 send_replies 并从 gateway.env 清理回复令牌
  --verify                   额外执行飞书在线会话核验（GET /v1/status?verify=1）
  --no-verify                跳过网关连通性与鉴权探测，仅校验格式并写入文件`,
      );
      return;
    }
    const { values } = parseArgs({
      args: more,
      options: {
        "gateway-config": { type: "string" },
        socket: { type: "string" },
        url: { type: "string" },
        "read-token": { type: "string" },
        "read-token-file": { type: "string" },
        "with-reply": { type: "boolean" },
        "no-reply": { type: "boolean" },
        "reply-token": { type: "string" },
        "reply-token-file": { type: "string" },
        verify: { type: "boolean" },
        "no-verify": { type: "boolean" },
      },
      allowPositionals: false,
    });
    const res = await runPersonalWebSetup(app, {
      gatewayConfig: values["gateway-config"],
      socket: values.socket,
      url: values.url,
      readToken: values["read-token"],
      readTokenFile: values["read-token-file"],
      withReply: values["with-reply"],
      noReply: values["no-reply"],
      replyToken: values["reply-token"],
      replyTokenFile: values["reply-token-file"],
      verify: values.verify,
      noVerify: values["no-verify"],
    });
    const originLabel = (o: SetupTokenOrigin): string => {
      switch (o) {
        case "gateway_tokens":
          return "本地网关 tokens.json";
        case "file":
          return "指定令牌文件";
        case "arg":
          return "命令行参数";
        case "env":
          return "环境变量";
        case "credential":
          return "systemd 凭据";
        case "env_file":
          return "已有 gateway.env";
      }
    };
    console.log(`✅ 个人 Web 网关配置已完成`);
    console.log(`配置文件：${res.configFile}${res.configChanged ? "（已更新，原文件备份为 .bak）" : "（无变化）"}`);
    console.log(`凭据文件：${res.envFile}（权限 0600）`);
    console.log(`网关地址：${res.endpointLabel}`);
    console.log(`只读令牌：${res.readTokenEnv}（来源：${originLabel(res.readTokenOrigin)}）`);
    console.log(
      `回复通道：${res.sendReplies ? "已开启" : "已关闭"}（回复令牌：${res.replyTokenStored ? `${res.replyTokenEnv} 已同步` : res.removedReplyTokenFromEnvFile ? "已从 gateway.env 清理" : "未写入"}）`,
    );
    if (res.reachable && res.gatewayStatus) {
      const st = res.gatewayStatus;
      console.log(
        `网关状态：${st.logged_in ? `${st.owner_name || st.owner_id}（ID: ${st.owner_id}）` : `未登录（${st.credential_status}）`}，state=${st.state}，allow_reply=${st.allow_reply}，缓存事件 ${st.cached_events} 条（seq ${st.min_seq}..${st.latest_seq}）`,
      );
      if (res.verifiedOnline) {
        console.log(`✅ 飞书在线会话核验通过：${st.owner_name || st.owner_id}（ID: ${st.owner_id}）`);
      }
    }
    for (const w of res.warnings) console.log(`⚠️  ${w}`);
    if (res.daemonRunning) {
      console.log("提示：检测到 Avatar 常驻进程正在运行，请重启 `bin/pa run` 使新配置生效。");
    }
    return;
  }

  // 查询独立个人 Web 网关状态（只读，不依赖 context.enabled）
  if (sub === "web-status") {
    const verify = more.includes("--verify");
    const pwCfg = app.cfg.context.personal_web;
    const resolved = resolveGatewayClientConfig(pwCfg, process.env, { dataDir: app.cfg.dataDir });
    const fmtTok = (has: boolean, src: typeof resolved.readTokenSource) => (has ? `已配置（${formatTokenSourceLabel(src)}）` : "未配置");
    console.log(
      `启用状态：${pwCfg.enabled ? "已启用" : "未启用"}（fast_lane=${pwCfg.fast_lane}，debounce_ms=${pwCfg.debounce_ms}，pre_draft=${pwCfg.pre_draft}，send_replies=${pwCfg.send_replies}）`,
    );
    console.log(`网关地址：${resolved.endpointLabel}（只读令牌：${fmtTok(!!resolved.readToken, resolved.readTokenSource)}，回复令牌：${fmtTok(!!resolved.replyToken, resolved.replyTokenSource)}）`);
    if (resolved.envFileError) console.log(`⚠️  凭据文件异常：${resolved.envFileError}`);
    if (!resolved.socketPath && !resolved.baseUrl) {
      if (verify) throw new Error("未配置 context.personal_web.gateway_socket 或 gateway_url");
      return;
    }
    const client = createGatewayClientForConfig(pwCfg, process.env, { dataDir: app.cfg.dataDir });
    const st = await client.status({ verify });
    if (st.owner_id) verifyGatewayOwnerForWorkspace(app, st.owner_id);
    console.log(`网关账号：${st.logged_in ? `${st.owner_name || st.owner_id}（ID: ${st.owner_id}）` : `未登录（${st.credential_status}）`}`);
    console.log(`运行状态：${st.state}，网关回复开关 allow_reply=${st.allow_reply}，缓存事件 ${st.cached_events} 条（seq ${st.min_seq}..${st.latest_seq}）`);
    console.log(`本地游标：seq=${app.store.get("ctx.pw_gateway.cursor") ?? "0"}`);
    if (st.last_message_at) {
      console.log(`最近消息：${new Date(st.last_message_at).toLocaleString("zh-CN", { timeZone: app.cfg.owner.timezone, hour12: false })}`);
    }
    if (st.last_error) console.log(`最近错误：${st.last_error}`);
    if (verify) {
      console.log(`✅ 网关在线核验通过：${st.owner_name || st.owner_id}（ID: ${st.owner_id}）`);
    }
    return;
  }

  const ctx = app.ext.context;
  if (!ctx) throw new Error("工作上下文未启用（config.yaml 里 context.enabled）");
  if (sub === "run") {
    const r = await ctx.runOnce();
    for (const s of r.sources) console.log(`${s.error ? "⚠️" : "✅"} ${s.source}：${s.error || `${s.count} 条`}`);
    console.log(`理解 ${r.convs} 个会话：新事项 ${r.created}，关闭 ${r.closed}，知识 ${r.knowledge}，动态 ${r.updates}，冲突 ${r.conflicts}，丢弃无证据 ${r.rejected}，提醒 ${r.nudged}`);
    for (const e of r.errors) console.log(`⚠️ ${e}`);
    return;
  }
  if (sub === "today") {
    const t = ctx.today();
    const line = (i: { title: string; project_name: string; why: string[]; kind: string }) => `- ${i.title}${i.project_name ? `（${i.project_name}）` : ""}  [${i.why.join(" · ")}]`;
    console.log(`今天 ${t.date}\n\n先做这几件：\n${t.focus.map(line).join("\n") || "（无）"}`);
    if (t.conflicts.length) console.log(`\n需要你判断：\n${t.conflicts.map((c) => `- ${c.topic}：${c.claims.map((x) => x.claim).join(" / ")}`).join("\n")}`);
    if (t.drafts.length) console.log(`\n待确认草稿：\n${t.drafts.map((d) => `- ${d.target_label}`).join("\n")}`);
    if (t.needs_review.length) console.log(`\n待确认识别：${t.needs_review.length} 件`);
    console.log(`\n共 ${t.status.totals.projects} 个项目、${t.status.totals.open_items} 件未完成、${t.status.totals.knowledge} 条知识`);
    return;
  }
  if (sub === "split") {
    if (!more[0]) throw new Error("用法：pa context split <项目名或 ID>");
    const r = await ctx.split(more.join(" "));
    console.log(`「${r.project}」拆成 ${r.subprojects.length} 个子项目：`);
    for (const s of r.subprojects) console.log(`- ${s.name}（${s.moved} 条）`);
    console.log(`留在原项目：${r.left} 条`);
    return;
  }
  if (sub === "digest") {
    const { values, positionals } = parseArgs({ args: more, options: { print: { type: "boolean" } }, allowPositionals: true });
    const mode = positionals[0] === "evening" ? "evening" : "morning";
    if (values.print) return void console.log(JSON.stringify(ctx.today(), null, 2));
    ctx.sendDigest(mode);
    await app.engine.drain(["effect"]);
    return;
  }
  throw new Error("用法：pa context run | today | split <项目> | digest [morning|evening] [--print] | web-setup [选项] | web-status [--verify] | web-unbind | web-logout（个人 Web 扫码登录/登出请使用独立网关命令 feishu-gateway login / logout）");
}

async function doctor(app: ReturnType<typeof createApp>): Promise<void> {
  const report = await runDoctor(app);
  console.log(formatReport(report));
  if (!report.ready) process.exitCode = 1;
}

main().catch((e) => {
  console.error(`错误：${errMsg(e)}`);
  process.exit(1);
});
