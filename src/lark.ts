import type { Config } from "./config.ts";
import { deepFind, runProcess } from "./util.ts";

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

  /**
   * 读取 lark-cli auth status：新版输出裸 JSON（无 ok/data 信封），旧版与测试桩带信封，两者都兼容。
   */
  async authStatus(): Promise<Record<string, unknown>> {
    const r = await runProcess(this.cfg.bins.lark, ["auth", "status", "--json"], {
      cwd: this.cfg.dataDir,
      timeoutMs: 30_000,
    });
    if (r.timedOut) throw new LarkError("lark-cli auth status 超时", 1);
    const s = parseEnvelope(r.stdout) ?? parseEnvelope(r.stderr);
    if (r.code !== 0 || !s || s.ok === false) {
      const e = (s?.error ?? {}) as Record<string, string>;
      const topMsg = typeof (s as Record<string, unknown> | undefined)?.message === "string" ? String((s as Record<string, unknown>).message) : undefined;
      const msg = e.message ?? topMsg ?? (r.stderr.trim() || r.stdout.trim() || `exit ${r.code}`);
      throw new LarkError(`lark-cli auth status 失败：${msg}`, r.code === 0 ? 1 : r.code, e.type, e.subtype, e.hint);
    }
    return (s.ok === true && s.data !== undefined && typeof s.data === "object" && s.data !== null ? s.data : s) as Record<string, unknown>;
  }

  /** 以机器人身份给本人发 Markdown 私信（机器人只给主人发消息）。 */
  async notifyOwner(markdown: string, idempotencyKey?: string): Promise<void> {
    const args = ["im", "+messages-send", "--user-id", this.cfg.owner.open_id, "--markdown", "-"];
    if (idempotencyKey) args.push("--idempotency-key", idempotencyKey.slice(0, 50));
    await this.run(args, { as: "bot", input: markdown });
  }
}

/** 从 lark-cli auth status（裸 JSON 或信封解包后）里提取当前用户的 open_id。 */
export function extractOwnerOpenId(status: Record<string, unknown>): string {
  const ids = (status.identities ?? {}) as Record<string, { openId?: string; open_id?: string } | undefined>;
  const id = ids.user?.openId ?? ids.user?.open_id ?? deepFind(status, "open_id") ?? deepFind(status, "user_open_id") ?? deepFind(status, "openId") ?? "";
  return String(id);
}

/**
 * 实时核验当前 lark-cli 登录用户的 open_id 与预期主人一致，防止切换 CLI 账号后跨账号读写飞书数据。
 */
export async function verifyActiveLarkUser(
  lark: Pick<Lark, "authStatus">,
  expectedOwnerOpenId: string,
  actionLabel: string,
): Promise<{ openId: string; status: Record<string, unknown> }> {
  const expected = expectedOwnerOpenId.trim();
  if (!expected) {
    throw new Error(`未配置 owner.open_id，无法确认${actionLabel}的 lark-cli 账号归属，已按安全策略中止`);
  }
  let status: Record<string, unknown>;
  try {
    status = await lark.authStatus();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`无法核验当前 lark-cli 登录用户身份，已中止${actionLabel}：${msg}`);
  }
  const openId = extractOwnerOpenId(status).trim();
  if (!openId || !openId.startsWith("ou_")) {
    throw new Error(`无法从 lark-cli auth status 解析当前登录用户的 open_id，已中止${actionLabel}`);
  }
  if (openId !== expected) {
    throw new Error(
      `当前 lark-cli 登录用户 (${openId}) 与配置 owner.open_id (${expected}) 不一致，已阻断${actionLabel}以防跨账号读写`,
    );
  }
  return { openId, status };
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
