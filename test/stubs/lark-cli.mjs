// 有状态的 lark-cli 桩：状态存 STUB_STATE（JSON），每次调用记到 STUB_LOG。只实现框架用到的命令。
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const statePath = process.env.STUB_STATE;
// 多个桩进程会并发运行（常驻进程里事件和定时任务并行），读-改-写状态文件前先拿文件锁
const lockPath = statePath && `${statePath}.lock`;
if (lockPath && !(argv[0] === "event" && argv[1] === "consume")) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lockPath, "wx"));
      break;
    } catch {
      if (Date.now() > deadline) fs.rmSync(lockPath, { force: true });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
  process.on("exit", () => fs.rmSync(lockPath, { force: true }));
}
const state = statePath && fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, "utf8")) : { tasks: {}, messages: [], seq: 0, sections: [] };
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const readStdin = () => {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
};
// 原子写：测试会在任意时刻读取状态文件
const save = () => {
  if (!statePath) return;
  fs.writeFileSync(`${statePath}.${process.pid}.tmp`, JSON.stringify(state, null, 2));
  fs.renameSync(`${statePath}.${process.pid}.tmp`, statePath);
};
const ok = (data) => {
  save();
  process.stdout.write(JSON.stringify({ ok: true, identity: flag("--as") ?? "user", data }) + "\n");
  process.exit(0);
};
const fail = (message, code = 1) => {
  process.stderr.write(JSON.stringify({ ok: false, error: { type: "stub", message } }) + "\n");
  process.exit(code);
};
const log = (extra = {}) => process.env.STUB_LOG && fs.appendFileSync(process.env.STUB_LOG, JSON.stringify({ argv, ...extra }) + "\n");

const [domain, cmd, method] = argv;
const key = `${domain} ${cmd}${method && !method.startsWith("-") ? " " + method : ""}`;

if (argv[0] === "--version") {
  process.stdout.write("lark-cli version stub\n");
  process.exit(0);
}

if (key.startsWith("event consume")) {
  const ek = argv[2];
  log();
  process.stderr.write(`[event] ready event_key=${ek}\n`);
  const f = process.env.STUB_EVENTS_DIR && path.join(process.env.STUB_EVENTS_DIR, `${ek}.ndjson`);
  if (f && fs.existsSync(f)) process.stdout.write(fs.readFileSync(f, "utf8"));
  // 和真实 consume 一样：stdin 关闭才退出
  process.stdin.resume();
  process.stdin.on("end", () => {
    process.stderr.write("[event] exited — received 0 event(s) in 1s (reason: signal)\n");
    process.exit(0);
  });
} else {
  const stdin = argv.includes("-") ? readStdin() : "";
  log(stdin ? { stdin } : {});
  const nextId = (p) => `${p}_${++state.seq}`;
  const params = flag("--params") ? JSON.parse(flag("--params")) : {};
  const data = flag("--data") ? JSON.parse(flag("--data")) : {};

  // 故障注入：state.failOnce[命令] = 次数，前 N 次调用失败
  if (state.failOnce?.[key] > 0) {
    state.failOnce[key]--;
    save();
    fail(`注入的临时故障：${key}`);
  }

  switch (key) {
    case "auth status":
      ok({ identity: "user", user: { open_id: "ou_owner", name: "主人" } });
    case "task +tasklist-search":
      ok({ items: [] });
    case "task +tasklist-create":
      ok({ tasklist: { guid: "tl_board", name: flag("--name") } });
    case "task sections list":
      ok({ items: state.sections.length ? state.sections : [{ guid: "sec_default", name: "默认分组", is_default: true }] });
    case "task sections create": {
      const s = { guid: `sec_${data.name}`, name: data.name };
      state.sections.push(s);
      ok({ section: s });
    }
    case "wiki +space-list":
      ok({ items: [] });
    case "wiki +space-create":
      ok({ space: { space_id: "sp_kb", name: flag("--name") } });
    case "wiki +node-list":
      ok({ items: [] });
    case "wiki +node-create":
      ok({ node: { node_token: `nd_${flag("--title")}`, title: flag("--title") } });
    case "im +messages-search": {
      if (argv.includes("--is-at-me"))
        ok({ has_more: false, page_token: "", messages: [{ message_id: "om_1", chat_id: "oc_g1", chat_type: "group", chat_name: "预算群", sender: { id: "ou_alice", name: "Alice" }, content: "@主人 周五前帮忙评审一下 Q4 预算方案", create_time: "2026-11-19 10:00" }] });
      ok({
        has_more: false,
        page_token: "",
        messages: [
          { message_id: "om_2", chat_id: "oc_p1", chat_type: "p2p", sender: { id: "ou_bob", name: "Bob" }, content: "收到，谢谢", create_time: "2026-11-19 10:05" },
          { message_id: "om_3", chat_id: "oc_p1", chat_type: "p2p", sender: { id: "ou_owner", name: "主人" }, content: "我自己发的", create_time: "2026-11-19 10:06" },
        ],
      });
    }
    case "task +create": {
      const guid = nextId("task");
      state.tasks[guid] = { guid, summary: flag("--summary"), description: flag("--description") ?? "", section: "", comments: [], due: flag("--due") ?? null, assignee: flag("--assignee") };
      ok({ task: { guid, summary: flag("--summary"), url: `https://applink.feishu.cn/client/todo/task?guid=${guid}` } });
    }
    case "task +tasklist-task-add": {
      const t = state.tasks[flag("--task-id")];
      if (!t) fail("no such task");
      t.section = flag("--section-guid");
      ok({ guid: t.guid });
    }
    case "task sections tasks":
      ok({ items: Object.values(state.tasks).filter((t) => t.section === params.section_guid && !t.completed).map(({ guid, summary }) => ({ guid, summary })) });
    case "task tasks get": {
      const t = state.tasks[params.task_guid];
      if (!t) fail("no such task");
      ok({ task: { guid: t.guid, summary: t.summary, description: t.description } });
    }
    case "task +comment": {
      const t = state.tasks[flag("--task-id")];
      if (!t) fail("no such task");
      t.comments.push(flag("--content"));
      ok({ comment: { id: nextId("c") } });
    }
    case "task comments list": {
      const t = state.tasks[params.resource_id];
      if (!t) fail("no such task");
      ok({ items: [...t.comments].reverse().map((content, i) => ({ id: `c_${i}`, content })), has_more: false });
    }
    case "task +get-my-tasks":
      ok({
        items: [
          { guid: "t_over", summary: "已经逾期的事", due: { timestamp: String(Date.now() - 3_600_000) }, url: "https://x/over" },
          { guid: "t_none", summary: "没有截止时间的事" },
        ],
      });
    case "im +messages-send":
      state.messages.push({ to: flag("--user-id"), as: flag("--as"), markdown: stdin || flag("--markdown") || flag("--text") });
      ok({ message_id: nextId("om") });
    case "drive +batch-query-comments":
      ok({ items: [{ comment_id: flag("--comment-ids"), reply_list: { replies: [{ content: "@主人 这里请补充一下数据来源" }] } }] });
    case "minutes +detail":
      ok({ minutes: [{ title: "周会", summary: "讨论了上线计划", todos: [{ content: "主人：整理上线清单", owner: "主人" }] }] });
    case "docs +create":
      ok({ document: { document_id: "doc_1", url: "https://feishu.cn/docx/doc_1" } });
    default:
      fail(`stub 不支持：${key}`);
  }
}
