import fs from "node:fs";
import { parseArgs } from "node:util";
import { createApp, initApp, runConfiguredJob, runDaemon, runDispatchOnce, sendBrief } from "./app.ts";
import { loadConfig } from "./config.ts";
import { beginLogin, FeishuWebClient, pollLogin, renderQrSvg, renderQrTerminal, WebLoginStore } from "./context/feishu-web/index.ts";
import {
  assertLoginAuthorizedForWorkspace,
  BOUND_OWNER_KV_KEY,
  BOUND_WORKSPACE_OWNER_KV_KEY,
  commitWorkspaceLogin,
  PENDING_CRED_COMMIT_KV_KEY,
  revokeWorkspacePersonalWebSession,
  verifyWorkspaceOwnerBinding,
} from "./context/personal-web.ts";
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
  context web-login [--out qr.svg]   飞书个人 Web 协议扫码登录（用于秒级实时接收任意群 @我 与私聊）
  context web-status [--verify]      查看个人 Web 协议登录与长连接状态（--verify 实时向飞书核验凭据）
  context web-logout          清除本地保存的个人 Web 协议登录凭据
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
      return void console.log(statusText(app.ledger, { cfg: app.cfg, store: app.store }));
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
  // 个人 Web 凭据管理不依赖 context.enabled（关闭模块后仍必须能 web-logout / 查看状态 / 重新登录）
  if (sub === "web-logout") {
    const { fileRemoved, fileRetained, credFile, fileError } = revokeWorkspacePersonalWebSession(app);
    if (fileError) {
      console.log("已写入工作区个人 Web 会话吊销标记，正在运行的常驻监听与回复发送将立即中止。");
      console.error(`⚠️ 清理本地凭据文件失败（${credFile}）：${fileError}；请手动删除该文件。`);
      process.exitCode = 1;
    } else if (fileRemoved) {
      console.log(`已清除个人 Web 登录凭据（${credFile}）并写入工作区吊销标记。若 pa run 正在运行，将在数秒内自动断开会话且不会回写旧凭据。`);
    } else if (fileRetained) {
      console.log(
        `已写入本工作区个人 Web 会话吊销标记，正在运行的常驻监听与回复发送将立即中止；检测到共享/未核验归属的凭据文件（${credFile}），为避免影响其他工作区已原样保留未删除。`,
      );
    } else {
      console.log(
        `已写入工作区个人 Web 会话吊销标记，正在运行的常驻监听与回复发送将立即中止（当前默认路径 ${credFile} 无本地文件；如常驻进程使用了自定义 PA_FEISHU_WEB_CRED_FILE，请核实归属后按需处理）。`,
      );
    }
    return;
  }
  if (sub === "web-status") {
    const verify = more.includes("--verify");
    const store = new WebLoginStore(app.cfg.dataDir);
    store.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
    const inspected = store.inspect();
    const login = inspected.status === "ok" ? inspected.login : undefined;
    let loginAuthErr: Error | undefined;
    if (login) {
      try {
        assertLoginAuthorizedForWorkspace(app, login);
      } catch (err) {
        loginAuthErr = err instanceof Error ? err : new Error(errMsg(err));
      }
    }
    const ctx = app.ext.context;
    const st = ctx?.status().personal_web;
    const pwCfg = app.cfg.context.personal_web;
    console.log(`启用状态：${app.cfg.context.enabled && pwCfg.enabled ? "已启用" : "未启用"}（context.enabled=${app.cfg.context.enabled}，fast_lane=${pwCfg.fast_lane}，debounce_ms=${pwCfg.debounce_ms}，pre_draft=${pwCfg.pre_draft}，send_replies=${pwCfg.send_replies}）`);
    const fileNote = login
      ? loginAuthErr
        ? `本地凭据不可用于当前工作区（${loginAuthErr.message}）`
        : `已登录 ${login.owner_name || login.owner_id}，更新于 ${login.updated_at ?? "未知"}`
      : inspected.status === "missing_key"
        ? "凭据已加密但当前环境缺少密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）"
        : inspected.status === "plaintext_rejected"
          ? "检测到未加密明文凭据（已拒绝加载，请配置密钥后重新 web-login）"
          : st?.logged_in
            ? `当前路径无本地文件（常驻进程正以其他凭据路径运行，状态：${st.state}）`
            : "未登录";
    console.log(`凭据文件：${store.file}（${fileNote}）`);
    if (st) {
      console.log(`常驻状态：${st.state}${st.last_message_at ? `，最近消息 ${new Date(st.last_message_at).toLocaleString("zh-CN", { timeZone: app.cfg.owner.timezone, hour12: false })}` : ""}`);
      if (st.last_error) console.log(`最近错误：${st.last_error}`);
    }
    if (verify) {
      if (!login) {
        if (inspected.status === "missing_key") {
          throw new Error("凭据已加密但当前环境缺少解密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）");
        }
        throw new Error("尚未登录，请先运行 `pa context web-login`");
      }
      if (loginAuthErr) throw loginAuthErr;
      const client = await FeishuWebClient.connect(login, {
        onSessionConfirmed: (u, d) => {
          try {
            assertLoginAuthorizedForWorkspace(app, u);
          } catch {
            return null;
          }
          return store.saveIfSessionMatches(u, d);
        },
      });
      console.log(`✅ 在线核验通过：${client.owner().name}（ID: ${client.owner().id}）`);
    }
    return;
  }
  if (sub === "web-login") {
    const { values } = parseArgs({
      args: more,
      options: {
        out: { type: "string" },
        "force-switch-account": { type: "boolean" },
        "allow-name-mismatch": { type: "boolean" },
        "allow-unverified-owner": { type: "boolean" },
      },
      allowPositionals: true,
    });
    if (!WebLoginStore.hasEncryptionKey()) {
      throw new Error(
        "执行 pa context web-login 前必须配置静态加密密钥（设置环境变量 PA_FEISHU_WEB_KEY 或通过 systemd LoadCredential 提供 CREDENTIALS_DIRECTORY/feishu-web-key），拒绝明文写入会话 Cookie",
      );
    }
    // 扫码前预检首次绑定 / 工作区主人变更确认参数，避免用户扫码批准后才被告知缺少 --allow-unverified-owner 而重复登录
    const boundNative = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
    const boundWs = (app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    const cfgWs = app.cfg.owner.open_id.trim();
    const needsFirstBindConfirm = !boundNative || (!!cfgWs && boundWs !== cfgWs) || (!!boundWs && boundWs !== cfgWs);
    if (needsFirstBindConfirm && !values["allow-unverified-owner"]) {
      throw new Error(
        `当前工作区尚未完成个人 Web 账号绑定或 owner.open_id 已变更（配置: ${cfgWs || "未配置"}，已绑定: ${boundWs || "未绑定"}）。` +
          "由于飞书网页原生账号 ID 与开放平台 open_id 无法跨应用强校验，请确认将使用本人飞书 App 扫码后，追加 --allow-unverified-owner 重新执行：pa context web-login --allow-unverified-owner",
      );
    }
    console.log("正在向飞书申请个人 Web 登录二维码…");
    const challenge = await beginLogin();
    console.log("\n" + renderQrTerminal(challenge.qrCode) + "\n");
    if (values.out) {
      fs.writeFileSync(values.out, renderQrSvg(challenge.qrCode), "utf8");
      console.log(`已将二维码写入：${values.out}`);
    }
    const deadline = new Date(challenge.expiresAtMs).toLocaleTimeString("zh-CN", { timeZone: app.cfg.owner.timezone, hour12: false });
    console.log(`请用本人飞书 App 扫码确认（有效期至 ${deadline}，按 Ctrl+C 取消）…`);
    const ctrl = new AbortController();
    const onSig = () => ctrl.abort();
    process.once("SIGINT", onSig);
    process.once("SIGTERM", onSig);
    try {
      const login = await pollLogin(challenge, {
        signal: ctrl.signal,
        onProgress: (st) => {
          if (st === "scanned") console.log("📱 已扫码，请在手机飞书上点击「确认登录」…");
          if (st === "approved") console.log("✅ 已确认，正在验证账号并保存凭据…");
        },
      });
      await verifyWorkspaceOwnerBinding(app, login, {
        forceSwitch: !!values["force-switch-account"],
        allowNameMismatch: !!values["allow-name-mismatch"],
        allowUnverifiedOwner: !!values["allow-unverified-owner"],
      });
      const store = new WebLoginStore(app.cfg.dataDir);
      const saved = commitWorkspaceLogin(app, login, {
        forceSwitch: !!values["force-switch-account"],
        allowUnverifiedOwner: !!values["allow-unverified-owner"],
        signal: ctrl.signal,
      });
      console.log(`✅ 个人 Web 登录成功：${saved.owner_name || "(无昵称)"}（ID: ${saved.owner_id}）`);
      console.log(`凭据已以 AES-256-GCM (0600) 保存到：${store.file}`);
      if (!app.cfg.context.enabled || !app.cfg.context.personal_web.enabled) {
        console.log("提示：在 config.yaml 里把 context.enabled 与 context.personal_web.enabled 设为 true 并重启 `pa run` 即可开启秒级实时接收。");
      } else {
        console.log("提示：若 `pa run` 正在运行，将在数秒内自动加载新凭据并重连。");
      }
    } finally {
      process.off("SIGINT", onSig);
      process.off("SIGTERM", onSig);
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
  throw new Error("用法：pa context run | today | split <项目> | digest [morning|evening] [--print] | web-login [--out qr.svg] | web-status [--verify] | web-logout");
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
