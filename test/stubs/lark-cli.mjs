// 有状态的 lark-cli 桩：状态存 STUB_STATE（JSON），每次调用记到 STUB_LOG。只实现框架用到的命令。
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const statePath = process.env.STUB_STATE;
const rpcUrl = process.env.STUB_RPC_URL;
const useRpc = !!rpcUrl && !!statePath && !fs.existsSync(statePath);
// 多个桩进程会并发运行（常驻进程里事件和定时任务并行），读-改-写状态文件前先拿文件锁
const lockPath = !useRpc && statePath && `${statePath}.lock`;
if (lockPath && !(argv[0] === "event" && argv[1] === "consume")) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lockPath, "wx"));
      break;
    } catch (e) {
      // 目录不存在等非冲突错误直接抛出，避免测试目录已清理时死循环
      if (e && e.code !== "EEXIST") throw e;
      if (Date.now() > deadline) fs.rmSync(lockPath, { force: true });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
  process.on("exit", () => fs.rmSync(lockPath, { force: true }));
}
let state = { tasks: {}, messages: [], seq: 0, sections: [] };
if (useRpc) {
  const r = await fetch(`${rpcUrl}/lark-state`);
  if (r.ok) state = await r.json();
} else if (statePath && fs.existsSync(statePath)) {
  state = JSON.parse(fs.readFileSync(statePath, "utf8"));
}
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
const save = async () => {
  if (useRpc) {
    await fetch(`${rpcUrl}/lark-state`, { method: "POST", body: JSON.stringify(state) });
    return;
  }
  if (!statePath) return;
  fs.writeFileSync(`${statePath}.${process.pid}.tmp`, JSON.stringify(state, null, 2));
  fs.renameSync(`${statePath}.${process.pid}.tmp`, statePath);
};
const ok = async (data) => {
  await save();
  process.stdout.write(JSON.stringify({ ok: true, identity: flag("--as") ?? "user", data }) + "\n");
  process.exit(0);
};
const fail = (message, code = 1) => {
  process.stderr.write(JSON.stringify({ ok: false, error: { type: "stub", message } }) + "\n");
  process.exit(code);
};
const log = async (extra = {}) => {
  const line = JSON.stringify({ argv, ...extra }) + "\n";
  if (useRpc) {
    await fetch(`${rpcUrl}/lark-log`, { method: "POST", body: line });
    return;
  }
  if (process.env.STUB_LOG) fs.appendFileSync(process.env.STUB_LOG, line);
};

const [domain, cmd, method] = argv;
const key = `${domain} ${cmd}${method && !method.startsWith("-") ? " " + method : ""}`;

if (argv[0] === "--version") {
  process.stdout.write("lark-cli version stub\n");
  process.exit(0);
}

if (key.startsWith("event consume")) {
  const ek = argv[2];
  await log();
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
  await log(stdin ? { stdin } : {});
  const nextId = (p) => `${p}_${++state.seq}`;
  const params = flag("--params") ? JSON.parse(flag("--params")) : {};
  const data = flag("--data") ? JSON.parse(flag("--data")) : {};

  // 故障注入：state.failOnce[命令] = 次数，前 N 次调用失败
  if (state.failOnce?.[key] > 0) {
    state.failOnce[key]--;
    await save();
    fail(`注入的临时故障：${key}`);
  }

  await (async () => {
    switch (key) {
      case "auth status":
        return await ok({ identity: "user", user: { open_id: "ou_owner", name: "主人" } });
      case "task +tasklist-search":
        return await ok({ items: [] });
      case "task +tasklist-create":
        return await ok({ tasklist: { guid: "tl_board", name: flag("--name") } });
      case "task sections list":
        return await ok({ items: state.sections.length ? state.sections : [{ guid: "sec_default", name: "默认分组", is_default: true }] });
      case "task sections create": {
        const s = { guid: `sec_${data.name}`, name: data.name };
        state.sections.push(s);
        return await ok({ section: s });
      }
      case "wiki +space-list":
        return await ok({ items: [] });
      case "wiki spaces get":
        return await ok({ space: { space_id: params.space_id === "my_library" ? "sp_my_library" : params.space_id, name: "My Document Library" } });
      case "wiki +space-create":
        return await ok({ space: { space_id: "sp_kb", name: flag("--name") } });
      case "wiki +node-list":
        return await ok({ items: [] });
      case "wiki +node-create":
        return await ok({ node: { node_token: `nd_${flag("--title")}`, title: flag("--title") } });
      case "im +messages-search": {
        if (argv.includes("--is-at-me"))
          return await ok({ has_more: false, page_token: "", messages: [{ message_id: "om_1", chat_id: "oc_g1", chat_type: "group", chat_name: "预算群", sender: { id: "ou_alice", name: "Alice" }, content: "@主人 周五前帮忙评审一下 Q4 预算方案", create_time: "2026-11-19 10:00" }] });
        return await ok({
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
        return await ok({ task: { guid, summary: flag("--summary"), url: `https://applink.feishu.cn/client/todo/task?guid=${guid}` } });
      }
      case "task +tasklist-task-add": {
        const t = state.tasks[flag("--task-id")];
        if (!t) fail("no such task");
        t.section = flag("--section-guid");
        return await ok({ guid: t.guid });
      }
      case "task sections tasks":
        return await ok({ items: Object.values(state.tasks).filter((t) => t.section === params.section_guid && !t.completed).map(({ guid, summary }) => ({ guid, summary })) });
      case "task tasks get": {
        const t = state.tasks[params.task_guid];
        if (!t) fail("no such task");
        // 与真实接口一致：completed_at 为 "0" 表示未完成，tasklists 给出所在清单与分组
        return await ok({
          task: {
            guid: t.guid,
            summary: t.summary,
            description: t.description,
            completed_at: t.completed ? String(Date.now()) : "0",
            tasklists: t.section ? [{ tasklist_guid: "tl_board", section_guid: t.section }] : [],
          },
        });
      }
      case "task +comment": {
        const t = state.tasks[flag("--task-id")];
        if (!t) fail("no such task");
        t.comments.push(flag("--content"));
        return await ok({ comment: { id: nextId("c") } });
      }
      case "task comments list": {
        const t = state.tasks[params.resource_id];
        if (!t) fail("no such task");
        return await ok({ items: [...t.comments].reverse().map((content, i) => ({ id: `c_${i}`, content })), has_more: false });
      }
      case "task +get-my-tasks":
        return await ok({
          items: [
            { guid: "t_over", summary: "已经逾期的事", due: { timestamp: String(Date.now() - 3_600_000) }, url: "https://x/over" },
            { guid: "t_none", summary: "没有截止时间的事" },
          ],
        });
      case "im +messages-send":
        // 交互卡片：记下解析后的卡片 JSON；同一幂等键只发一次（与真实接口一致）
        if (flag("--msg-type") === "interactive") {
          const idem = flag("--idempotency-key");
          const dup = idem && state.messages.find((m) => m.msg_type === "interactive" && m.idem === idem);
          if (dup) return await ok({ message_id: dup.message_id });
          const content = flag("--content") === "-" ? stdin : flag("--content");
          let parsed;
          try {
            parsed = JSON.parse(content);
          } catch {
            fail("卡片内容不是合法 JSON");
          }
          const message_id = nextId("om_card");
          state.messages.push({ to: flag("--user-id"), as: flag("--as"), msg_type: "interactive", card: parsed, message_id, idem, patches: 0 });
          return await ok({ message_id });
        }
        state.messages.push({ to: flag("--user-id"), as: flag("--as"), markdown: stdin || flag("--markdown") || flag("--text") });
        return await ok({ message_id: nextId("om") });
      case "im messages patch": {
        const m = state.messages.find((x) => x.msg_type === "interactive" && x.message_id === params.message_id);
        if (!m) fail(`没有这条卡片消息：${params.message_id}`);
        m.card = JSON.parse(data.content);
        m.patches++;
        return await ok({});
      }
      case "drive +batch-query-comments":
        return await ok({ items: [{ comment_id: flag("--comment-ids"), reply_list: { replies: [{ content: "@主人 这里请补充一下数据来源" }] } }] });
      case "minutes +detail":
        return await ok({ minutes: [{ title: "周会", summary: "讨论了上线计划", todos: [{ content: "主人：整理上线清单", owner: "主人" }] }] });
      case "docs +create":
        return await ok({ document: { document_id: "doc_1", url: "https://feishu.cn/docx/doc_1" } });
      case "task +update": {
        const t = state.tasks[flag("--task-id")];
        if (!t) fail("no such task");
        if (flag("--description") !== undefined) t.description = flag("--description");
        if (flag("--summary") !== undefined) t.summary = flag("--summary");
        return await ok({ task: { guid: t.guid } });
      }
      case "task +complete": {
        const t = state.tasks[flag("--task-id")];
        if (!t) fail("no such task");
        t.completed = true;
        return await ok({ task: { guid: t.guid } });
      }
      default:
        fail(`stub 不支持：${key}`);
    }
  })();
}
