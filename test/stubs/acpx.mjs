// acpx 桩：按提示词内容模拟不同角色的 harness 回复，并把调用记到 STUB_ACPX_LOG。
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
if (argv[0] === "--version") {
  process.stdout.write("0.0.0-stub\n");
  process.exit(0);
}
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const prompt = fs.readFileSync(0, "utf8");
const cwd = flag("--cwd");
const agent = argv[argv.indexOf("exec") - 1];
const perm = argv.find((a) => ["--approve-all", "--approve-reads", "--deny-all"].includes(a));
if (process.env.STUB_ACPX_LOG) fs.appendFileSync(process.env.STUB_ACPX_LOG, JSON.stringify({ agent, perm, cwd, head: prompt.slice(0, 60) }) + "\n");

if (prompt.includes("<signal id=")) {
  // 分诊：含“评审/补充/整理”的算任务
  const out = [...prompt.matchAll(/<signal id="([^"]+)"[^>]*>\n([\s\S]*?)\n<\/signal>/g)].map(([, id, text]) => {
    const isTask = /评审|补充|整理/.test(text);
    return { signal_id: id, is_task: isTask, summary: isTask ? `处理：${text.slice(-12)}` : "", due: null, confidence: isTask ? 0.8 : 0.1, reason: "stub" };
  });
  process.stdout.write("好的，结果如下：\n```json\n" + JSON.stringify(out) + "\n```\n");
} else if (prompt.includes("你是代码与交付审查者")) {
  // 审查：标题含“总是打回”的一律要求修改；含“审查乱码”的输出无法解析的内容（模拟审查器故障）
  if (prompt.includes("审查乱码")) process.stdout.write("嗯……我看了一下。\n");
  else if (prompt.includes("总是打回"))
    process.stdout.write('```json\n{"verdict":"changes","summary":"还不够好","issues":[{"severity":"high","location":"hello.txt","problem":"内容不对","suggestion":"重写"}]}\n```\n');
  else process.stdout.write('改动符合要求，没有发现问题。\n```json\n{"verdict":"approve","summary":"改动符合要求","issues":[]}\n```\n');
} else if (prompt.includes("你是一名执行者")) {
  // 崩溃测试：STUB_HANG_FILE 内容为 armed 时，先留下一个未提交的半成品，再记下自己的 pid 并卡住
  const hang = process.env.STUB_HANG_FILE;
  if (hang && fs.existsSync(hang) && fs.readFileSync(hang, "utf8") === "armed") {
    fs.writeFileSync(path.join(cwd, "partial.txt"), "half done\n");
    fs.writeFileSync(hang, String(process.pid));
    setInterval(() => undefined, 1 << 30);
  } else {
  fs.writeFileSync(path.join(cwd, "hello.txt"), "hello from " + agent + "\n");
  if (fs.existsSync(path.join(cwd, ".git"))) {
    execFileSync("git", ["-C", cwd, "add", "-A"]);
    execFileSync("git", ["-C", cwd, "-c", "user.name=stub", "-c", "user.email=stub@x", "commit", "-q", "--allow-empty", "-m", "add hello"]);
  }
  process.stdout.write(`已完成：新增 hello.txt（${agent}）\n`);
  }
} else {
  // agent 作业：通过 PATH 上的守卫调用 lark-cli，一次越权、一次正常读取
  const bad = spawnSync("lark-cli", ["im", "+messages-send", "--as", "bot", "--user-id", "ou_someone_else", "--text", "hi"], { encoding: "utf8" });
  const good = spawnSync("lark-cli", ["task", "+get-my-tasks", "--as", "user"], { encoding: "utf8" });
  process.stdout.write(`越权发消息 exit=${bad.status}；读取任务 exit=${good.status}\n`);
}
