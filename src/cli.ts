import fs from "node:fs";
import { parseArgs } from "node:util";
import { createApp, initApp, runConfiguredJob, runDaemon, sendBrief } from "./app.ts";
import { loadConfig } from "./config.ts";
import { decide, type Profile } from "./guard.ts";
import { resolveBin } from "./harness.ts";
import { errMsg, runProcess } from "./util.ts";
import { runAgentJob } from "./workflows/agent.ts";
import { buildBrief } from "./workflows/brief.ts";

const USAGE = `用法：pa <命令>

  doctor                      检查依赖、登录状态和初始化情况
  init                        建看板清单/分组、知识空间/节点，记录你的 open_id（可重复执行）
  run                         常驻运行（事件长连接 + 定时任务）
  brief [morning|evening]     生成概览并私信给你（--print 只打印不发送）
  capture                     立即识别一轮任务
  dispatch                    立即处理“派给Agent”列，并等待完成
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
      if (values.print) console.log(await buildBrief(cfg, app.lark, app.store, app.board, mode));
      else await sendBrief(app, mode);
      return;
    }
    case "capture":
      return void console.log(await app.capture.run());
    case "dispatch":
      console.log(`领取 ${await app.dispatcher.scan()} 个任务，执行中…`);
      await app.dispatcher.drain();
      return void console.log("完成");
    case "job":
      if (!rest[0]) throw new Error("用法：pa job <名称>");
      return void console.log(await runConfiguredJob(app, rest[0]));
    case "ask": {
      const r = await runAgentJob(cfg, app.store, { name: "ask", task: rest.join(" ") });
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
  console.log(`ℹ️  数据目录：${cfg.dataDir}`);
}

main().catch((e) => {
  console.error(`错误：${errMsg(e)}`);
  process.exit(1);
});
