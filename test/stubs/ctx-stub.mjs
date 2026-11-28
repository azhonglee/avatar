// 工作上下文测试桩：一个脚本扮演 lark-cli / bytedcli / codex 三个角色（第一个参数）。
// 数据来自 $CTX_DIR 下的夹具文件，每次调用记到 $CTX_DIR/calls.log。
//   lark.json       { at_me, p2p, mine, chats: {chat_id: [...]}, tasks, minutes, minute_details, calendar, user_name, fail: ["im"] }
//   meego.json      { list: [...], total?: n, fail?: true }
//   understand.json 理解模型的输出（缺省为空图谱）；understand.txt 优先（原样输出，用于模拟乱码）
//   draft.txt       起草模型的输出
import fs from "node:fs";
import path from "node:path";

const [role, ...argv] = process.argv.slice(2);
const dir = process.env.CTX_DIR ?? ".";
const read = (f, d) => {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  } catch {
    return d;
  }
};
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const stdin = () => {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
};
const logCall = (extra = {}) => fs.appendFileSync(path.join(dir, "calls.log"), JSON.stringify({ role, argv, ...extra }) + "\n");
const ok = (data) => {
  process.stdout.write(JSON.stringify({ ok: true, data }) + "\n");
  process.exit(0);
};
const fail = (message) => {
  process.stderr.write(JSON.stringify({ ok: false, error: { type: "stub", message } }) + "\n");
  process.exit(1);
};

if (role === "lark") {
  const fx = read("lark.json", {});
  const key = `${argv[0]} ${argv[1]}`;
  const writes = ["im +messages-reply", "im +messages-send", "docs +create", "task +create"];
  logCall(writes.includes(key) || key === "im +messages-send" ? { input: stdin() } : {});
  if ((fx.fail ?? []).includes(argv[0])) fail(`${argv[0]} 故障`);
  if (key === "auth status") {
    process.stdout.write(JSON.stringify({ identities: { user: { openId: "ou_owner", userName: fx.user_name ?? "张三" } } }) + "\n");
    process.exit(0);
  }
  const paged = (val, listKey, fallback = {}) => {
    if (val && typeof val === "object" && !Array.isArray(val) && val.pages) {
      const token = flag("--page-token") ?? "";
      return val.pages[token] ?? { [listKey]: [], has_more: false };
    }
    return { [listKey]: val ?? [], ...fallback };
  };
  switch (key) {
    case "im +messages-search":
      if (argv.includes("--is-at-me")) ok(paged(fx.at_me, "messages"));
      if (flag("--chat-type") === "p2p") ok(paged(fx.p2p, "messages"));
      if (flag("--sender")) ok(paged(fx.mine, "messages"));
      ok({ messages: [] });
    case "im +chat-messages-list":
      ok(paged((fx.chats ?? {})[flag("--chat-id")], "messages"));
    case "task +get-my-tasks":
      ok({ items: fx.tasks ?? [] });
    case "minutes +search":
      ok(paged(fx.minutes, "items", { has_more: false }));
    case "minutes +detail":
      ok({ minutes: fx.minute_details ?? [] });
    case "calendar +agenda":
      ok({ items: fx.calendar ?? [] });
    case "im +messages-reply":
    case "im +messages-send":
      ok({ message_id: `om_sent_${Date.now()}` });
    case "docs +create":
      ok({ document: { url: "https://example.feishu.cn/docx/weekly123" } });
    case "task +create":
      ok({ task: { guid: "t_own_1" } });
    default:
      fail(`桩未实现：${key}`);
  }
}

if (role === "bytedcli") {
  logCall();
  const fx = read("meego.json", { list: [] });
  if (argv[0] === "meego" && argv[1] === "todo") {
    if (fx.fail) fail("meego 故障");
    const page = Number(flag("--page") ?? 1);
    const list = page === 1 ? fx.list : [];
    process.stdout.write(JSON.stringify({ status: "success", data: { result: { structuredContent: { list, total: fx.total ?? fx.list.length } } } }) + "\n");
    process.exit(0);
  }
  if (argv[0] === "meego" && argv[1] === "comment") {
    process.stdout.write(JSON.stringify({ status: "success", data: { comment_id: 1 } }) + "\n");
    process.exit(0);
  }
  fail(`桩未实现：${argv.slice(0, 3).join(" ")}`);
}

if (role === "codex") {
  const prompt = stdin();
  const out = flag("-o");
  const kind = prompt.includes("维护个人工作上下文") ? "understand" : prompt.includes("整理工作上下文里的项目结构") ? "split" : "draft";
  logCall({ kind, prompt });
  let text;
  if (kind === "understand") {
    const raw = path.join(dir, "understand.txt");
    text = fs.existsSync(raw) ? fs.readFileSync(raw, "utf8") : "```json\n" + JSON.stringify(read("understand.json", {})) + "\n```";
  } else if (kind === "split") {
    text = "```json\n" + JSON.stringify(read("split.json", { subprojects: [] })) + "\n```";
  } else {
    const f = path.join(dir, "draft.txt");
    text = fs.existsSync(f) ? fs.readFileSync(f, "utf8") : "好的，今天下班前给你结论。";
  }
  if (out) fs.writeFileSync(out, text);
  process.stdout.write("codex stub done\n");
  process.exit(0);
}

fail(`未知角色：${role}`);
