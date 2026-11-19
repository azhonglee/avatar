/**
 * bin/guard/lark-cli 的实现：agent 调用 lark-cli 时先经过这里。
 * 环境变量由 harness.ts 注入：PA_GUARD_PROFILE、PA_OWNER_OPEN_ID、PA_LARK_REAL、PA_GUARD_LOG。
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import { decide, type Profile } from "./guard.ts";

const argv = process.argv.slice(2);
const profile = (process.env.PA_GUARD_PROFILE ?? "none") as Profile;
const d = decide(argv, profile, process.env.PA_OWNER_OPEN_ID ?? "");

if (process.env.PA_GUARD_LOG) {
  const line = JSON.stringify({ t: new Date().toISOString(), profile, allow: d.allow, reason: d.reason, argv });
  try {
    fs.appendFileSync(process.env.PA_GUARD_LOG, line + "\n");
  } catch {
    // 审计日志写失败不影响决策
  }
}

if (!d.allow) {
  const env = { ok: false, error: { type: "guard", subtype: "denied", message: `personal-agent 守卫拒绝：${d.reason}`, hint: "该操作需要主人亲自执行，或在 src/guard.ts 中调整策略" } };
  process.stderr.write(JSON.stringify(env) + "\n");
  process.exit(13);
}

const real = process.env.PA_LARK_REAL;
if (!real) {
  process.stderr.write('{"ok":false,"error":{"type":"guard","message":"PA_LARK_REAL 未设置"}}\n');
  process.exit(13);
}
const child = spawn(real, argv, { stdio: "inherit" });
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
child.on("error", (e) => {
  process.stderr.write(JSON.stringify({ ok: false, error: { type: "guard", message: String(e) } }) + "\n");
  process.exit(13);
});
