import fs from "node:fs";
import { parseArgs } from "node:util";
import { createApp, initApp, runConfiguredJob, runDaemon, runDispatchOnce, sendBrief } from "./app.ts";
import { loadConfig } from "./config.ts";
import { decide, type Profile } from "./guard.ts";
import { serverToken } from "./server/index.ts";
import { resolveBin } from "./harness.ts";
import { errMsg, runProcess } from "./util.ts";
import { runAgentJob, statusText } from "./workflows/agent.ts";
import { buildBrief } from "./workflows/brief.ts";

const USAGE = `用法：pa <命令>

  doctor                      检查依赖、登录状态和初始化情况
  init                        建看板清单/分组、知识空间/节点，记录你的 open_id（可重复执行）
  run                         常驻运行（事件长连接 + 定时任务）
  brief [morning|evening]     生成概览并私信给你（--print 只打印不发送）
  capture                     立即识别一轮任务
  dispatch                    立即对账“派给Agent”列并执行派单（含崩溃后未完成的），等待完成
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
    case "init":
      await initApp(app);
      console.log(`✅ 初始化完成\n主人 open_id：${cfg.owner.open_id}\n看板清单：${app.store.get("board.tasklist")}\n知识空间：${app.store.get("kb.space")}`);
      return;
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
    case "status":
      return void console.log(statusText(app.ledger));
    case "console": {
      const token = serverToken(app, rest.includes("--rotate"));
      const base = `http://${cfg.server.host === "0.0.0.0" ? "127.0.0.1" : cfg.server.host}:${cfg.server.port}`;
      console.log(`控制台登录链接（在本机浏览器打开；远程开发机请先转发端口 ${cfg.server.port}）：\n${base}/login?token=${token}`);
      console.log(`\n端口转发示例：ssh -L ${cfg.server.port}:127.0.0.1:${cfg.server.port} <开发机>   （VS Code Remote 会自动转发）`);
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

async function doctor(app: ReturnType<typeof createApp>): Promise<void> {
  const { cfg, store } = app;
  const line = (ok: boolean, msg: string) => console.log(`${ok ? "✅" : "❌"} ${msg}`);
  const [major, minor] = process.versions.node.split(".").map(Number);
  line(major > 22 || (major === 22 && minor >= 13), `Node ${process.versions.node}（需要 ≥ 22.13）`);
  for (const [name, bin] of [["lark-cli", cfg.bins.lark], ["acpx", cfg.bins.acpx]] as const) {
    try {
      const p = resolveBin(bin);
      const v = await runProcess(p, ["--version"], { timeoutMs: 15_000 });
      line(v.code === 0, `${name}: ${p} ${v.stdout.trim()}`);
    } catch (e) {
      line(false, `${name}: ${errMsg(e)}`);
    }
  }
  try {
    const s = await app.lark.run(["auth", "status", "--json"]);
    line(true, `lark-cli 已登录：${JSON.stringify(s).slice(0, 200)}`);
  } catch (e) {
    line(false, `lark-cli 未就绪：${errMsg(e)}（运行 lark-cli config init --new 和 lark-cli auth login --recommend）`);
  }
  line(!!cfg.owner.open_id, `主人 open_id：${cfg.owner.open_id || "未知（运行 pa init）"}`);
  line(!!store.get("board.tasklist"), `看板清单：${store.get("board.tasklist") ?? "未初始化（运行 pa init）"}`);
  line(!!store.get("kb.space"), `知识空间：${store.get("kb.space") ?? "未初始化（运行 pa init）"}`);
  for (const [name, h] of Object.entries(cfg.harnesses)) {
    console.log(`ℹ️  harness ${name} → ${h.agent ? `acpx ${h.agent}` : `acpx --agent '${h.agentCommand}'`}${h.model ? ` (model ${h.model})` : ""}`);
  }
  console.log(`ℹ️  角色：brain=${cfg.roles.brain} reviewer=${cfg.roles.reviewer || "无"} 默认执行者=${cfg.dispatch.default_harness || cfg.roles.brain}`);
  const verified = Object.entries(cfg.dispatch.repos).filter(([, v]) => typeof v !== "string" && v.verify).map(([k]) => k);
  console.log(`ℹ️  验收：无校验时 → ${cfg.acceptance.on_unverified === "needs_human" ? "需人工介入" : "标为未验证进待验收"}；带 verify 命令的仓库：${verified.join(", ") || "无"}`);
  if (!cfg.roles.reviewer && !verified.length && cfg.acceptance.on_unverified === "needs_human")
    console.log("⚠️  没有配置 reviewer 也没有 verify 命令：所有派单结果都会进“需人工介入”");
  if (store.get("board.tasklist") && !app.board.isInitialized()) console.log("⚠️  看板有新增分组尚未创建，请再运行一次 pa init");
  console.log(`ℹ️  数据目录：${cfg.dataDir}`);
}

main().catch((e) => {
  console.error(`错误：${errMsg(e)}`);
  process.exit(1);
});
