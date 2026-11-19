import type { Config } from "./config.ts";
import { runProcess } from "./util.ts";

export class LarkError extends Error {
  exitCode: number;
  type: string;
  subtype: string;
  hint: string;
  constructor(message: string, exitCode: number, type = "", subtype = "", hint = "") {
    super(message);
    this.exitCode = exitCode;
    this.type = type;
    this.subtype = subtype;
    this.hint = hint;
  }
  /** 退出码 10 是 lark-cli 的高风险写操作确认关卡：必须交给人确认，不能自动加确认参数绕过。 */
  get isHighRisk(): boolean {
    return this.exitCode === 10;
  }
}

export type Identity = "user" | "bot";

/** lark-cli 的薄封装：统一身份、JSON 信封解析和错误处理。只有守护进程（superagent）用它写飞书。 */
export class Lark {
  cfg: Config;
  constructor(cfg: Config) {
    this.cfg = cfg;
  }

  /**
   * 执行一条 lark-cli 命令并返回信封里的 data。
   * 长文本内容请放到 input（配合命令里的 `-` 参数走 stdin），lark-cli 只接受相对路径的 @file。
   */
  async run(args: string[], opts: { as?: Identity; input?: string; timeoutMs?: number } = {}): Promise<unknown> {
    const full = opts.as ? [...args, "--as", opts.as] : args;
    const r = await runProcess(this.cfg.bins.lark, full, {
      cwd: this.cfg.dataDir,
      input: opts.input,
      timeoutMs: opts.timeoutMs ?? 120_000,
    });
    const env = parseEnvelope(r.stdout) ?? parseEnvelope(r.stderr);
    if (r.code === 0 && env?.ok === true) return env.data ?? env;
    if (r.code === 0 && env === undefined && r.stdout.trim()) return r.stdout;
    const e = (env?.error ?? {}) as Record<string, string>;
    throw new LarkError(
      `lark-cli ${args.slice(0, 2).join(" ")} 失败：${e.message ?? (r.stderr.trim() || r.stdout.trim() || `exit ${r.code}`)}`,
      r.code === 0 ? 1 : r.code,
      e.type,
      e.subtype,
      e.hint,
    );
  }

  /** 以机器人身份给本人发 Markdown 私信（机器人只给主人发消息）。 */
  async notifyOwner(markdown: string, idempotencyKey?: string): Promise<void> {
    const args = ["im", "+messages-send", "--user-id", this.cfg.owner.open_id, "--markdown", "-"];
    if (idempotencyKey) args.push("--idempotency-key", idempotencyKey.slice(0, 50));
    await this.run(args, { as: "bot", input: markdown });
  }
}

function parseEnvelope(text: string): { ok?: boolean; data?: unknown; error?: unknown } | undefined {
  const t = text.trim();
  if (!t.startsWith("{")) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}
