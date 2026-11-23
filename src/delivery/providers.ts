import type { Config } from "../config.ts";
import { deepFind, errMsg, findItems, runProcess, truncate } from "../util.ts";
import type { RemoteRef } from "./git.ts";

/**
 * PR / MR 平台：GitHub（REST v3）、GitLab（REST v4）、公司 Codebase（bytedcli）。
 * 统一成“先查同一源分支上已打开的 PR/MR，有就复用，没有才创建”，保证重试幂等。
 * 令牌只从环境变量读取，只放在请求头里，不写日志、不进错误信息。
 */

export type ProviderCfg = Config["delivery"]["providers"][string];

/** 永久错误：重试也不会好（令牌无效、仓库不存在、无法快进……），直接落定为失败并告诉用户怎么办。 */
export class DeliveryError extends Error {}

export interface PrRequest {
  source: string;
  target: string;
  title: string;
  body: string;
  draft: boolean;
}

export interface PrRef {
  url: string;
  number: number;
}

export interface Provider {
  type: ProviderCfg["type"];
  /** 同一源分支上已打开的 PR/MR */
  find(source: string): Promise<PrRef | undefined>;
  create(req: PrRequest): Promise<PrRef>;
}

export interface ProviderDeps {
  /** bytedcli 可执行文件（config.bins.bytedcli） */
  bytedcli: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

/** 幂等地打开 PR/MR：已有就复用；创建时撞上“已存在”（并发或上次创建成功但没记下）就再查一次。 */
export async function openOrReuse(p: Provider, req: PrRequest): Promise<PrRef & { reused: boolean }> {
  const existing = await p.find(req.source);
  if (existing) return { ...existing, reused: true };
  try {
    return { ...(await p.create(req)), reused: false };
  } catch (e) {
    if (e instanceof HttpError && e.alreadyExists) {
      const again = await p.find(req.source);
      if (again) return { ...again, reused: true };
    }
    throw e;
  }
}

export function makeProvider(cfg: ProviderCfg, remote: RemoteRef, deps: ProviderDeps): Provider {
  const env = deps.env ?? process.env;
  const token = () => {
    if (!cfg.token_env) throw new DeliveryError(`${cfg.type} 平台没有配置 token_env（存放访问令牌的环境变量名）`);
    const t = env[cfg.token_env];
    if (!t) throw new DeliveryError(`环境变量 ${cfg.token_env} 未设置，无法访问 ${cfg.type}`);
    return t;
  };
  switch (cfg.type) {
    case "github":
      return github(cfg, remote, token(), deps);
    case "gitlab":
      return gitlab(cfg, remote, token(), deps);
    case "codebase":
      return codebase(cfg, remote, deps);
  }
}

// ───────────────────────── HTTP 与错误映射 ─────────────────────────

export class HttpError extends Error {
  status: number;
  permanent: boolean;
  alreadyExists: boolean;
  constructor(message: string, status: number, permanent: boolean, alreadyExists = false) {
    super(message);
    this.status = status;
    this.permanent = permanent;
    this.alreadyExists = alreadyExists;
  }
}

/** 从 GitHub / GitLab 的错误响应里提取可读信息（不含请求头，不会带出令牌）。 */
export function apiMessage(body: unknown): string {
  if (typeof body === "string") return truncate(body.trim(), 300);
  if (!body || typeof body !== "object") return "";
  const b = body as Record<string, unknown>;
  const parts: string[] = [];
  const flat = (v: unknown): string[] =>
    typeof v === "string" ? [v] : Array.isArray(v) ? v.flatMap(flat) : v && typeof v === "object" ? Object.entries(v).flatMap(([k, x]) => flat(x).map((s) => `${k} ${s}`)) : [];
  parts.push(...flat(b.message), ...flat(b.error));
  if (Array.isArray(b.errors)) for (const e of b.errors) parts.push(...flat(typeof e === "object" && e && "message" in e ? (e as { message: unknown }).message : e));
  return truncate([...new Set(parts)].join("；"), 300);
}

/** HTTP 状态 → 中文错误；决定是否值得重试。 */
export function httpError(status: number, body: unknown, ctx: { platform: string; repo: string; tokenEnv?: string }): HttpError {
  const msg = apiMessage(body);
  const tail = msg ? `（${msg}）` : "";
  const exists = /already exists/i.test(msg);
  if (status === 401) return new HttpError(`${ctx.platform} 认证失败：令牌无效或已过期，请检查环境变量 ${ctx.tokenEnv ?? ""}${tail}`, status, true);
  if (status === 403 && /rate limit/i.test(msg)) return new HttpError(`${ctx.platform} 触发限流，稍后重试${tail}`, status, false);
  if (status === 403) return new HttpError(`${ctx.platform} 拒绝访问：令牌对仓库 ${ctx.repo} 没有足够权限${tail}`, status, true);
  if (status === 404) return new HttpError(`${ctx.platform} 找不到仓库 ${ctx.repo}（或令牌无权访问）${tail}`, status, true);
  if (status === 409 || status === 422) return new HttpError(`${ctx.platform} 拒绝了请求${tail}`, status, true, exists);
  if (status === 429 || status >= 500) return new HttpError(`${ctx.platform} 暂时不可用（HTTP ${status}），稍后重试${tail}`, status, false);
  return new HttpError(`${ctx.platform} 请求失败（HTTP ${status}）${tail}`, status, true);
}

async function http(url: string, init: RequestInit, ctx: { platform: string; repo: string; tokenEnv?: string }, timeoutMs = 30_000): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new HttpError(`${ctx.platform} 网络错误：${errMsg(e)}`, 0, false);
  }
  const text = await res.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    // 不是 JSON，保留原文
  }
  if (!res.ok) throw httpError(res.status, body, ctx);
  return body;
}

const trimSlash = (s: string) => s.replace(/\/+$/, "");

// ───────────────────────── GitHub ─────────────────────────

function github(cfg: ProviderCfg, remote: RemoteRef, token: string, deps: ProviderDeps): Provider {
  // github.com 走 api.github.com；GitHub Enterprise 缺省 https://<host>/api/v3
  const base = trimSlash(cfg.base_url || (remote.host === "github.com" ? "https://api.github.com" : `https://${remote.host}/api/v3`));
  const [owner, repo] = remote.path.split("/");
  const ctx = { platform: "GitHub", repo: `${owner}/${repo}`, tokenEnv: cfg.token_env };
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "avatar-personal-agent",
    "Content-Type": "application/json",
  };
  const root = `${base}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`;
  const ref = (pr: Record<string, unknown>): PrRef => ({ url: String(pr.html_url ?? ""), number: Number(pr.number ?? 0) });
  return {
    type: "github",
    async find(source) {
      const q = new URLSearchParams({ state: "open", head: `${owner}:${source}`, per_page: "10" });
      const list = (await http(`${root}?${q}`, { headers }, ctx, deps.timeoutMs)) as Record<string, unknown>[];
      const pr = Array.isArray(list) ? (list.find((p) => (p.head as { ref?: string } | undefined)?.ref === source) ?? list[0]) : undefined;
      return pr ? ref(pr) : undefined;
    },
    async create(r) {
      const pr = await http(
        root,
        { method: "POST", headers, body: JSON.stringify({ title: r.title, head: r.source, base: r.target, body: r.body, draft: r.draft }) },
        ctx,
        deps.timeoutMs,
      );
      return ref(pr as Record<string, unknown>);
    },
  };
}

// ───────────────────────── GitLab ─────────────────────────

function gitlab(cfg: ProviderCfg, remote: RemoteRef, token: string, deps: ProviderDeps): Provider {
  const base = trimSlash(cfg.base_url || `https://${remote.host}`).replace(/\/api\/v4$/, "");
  const ctx = { platform: "GitLab", repo: remote.path, tokenEnv: cfg.token_env };
  const headers = { "PRIVATE-TOKEN": token, "Content-Type": "application/json", "User-Agent": "avatar-personal-agent" };
  const root = `${base}/api/v4/projects/${encodeURIComponent(remote.path)}/merge_requests`;
  const ref = (mr: Record<string, unknown>): PrRef => ({ url: String(mr.web_url ?? ""), number: Number(mr.iid ?? 0) });
  return {
    type: "gitlab",
    async find(source) {
      const q = new URLSearchParams({ state: "opened", source_branch: source, per_page: "10" });
      const list = (await http(`${root}?${q}`, { headers }, ctx, deps.timeoutMs)) as Record<string, unknown>[];
      const mr = Array.isArray(list) ? (list.find((m) => m.source_branch === source) ?? list[0]) : undefined;
      return mr ? ref(mr) : undefined;
    },
    async create(r) {
      // 草稿用标题前缀 "Draft: "，各版本 GitLab 都支持
      const title = r.draft && !/^(draft|wip)\s*:/i.test(r.title) ? `Draft: ${r.title}` : r.title;
      const mr = await http(
        root,
        { method: "POST", headers, body: JSON.stringify({ source_branch: r.source, target_branch: r.target, title, description: r.body }) },
        ctx,
        deps.timeoutMs,
      );
      return ref(mr as Record<string, unknown>);
    },
  };
}

// ───────────────────────── Codebase（bytedcli） ─────────────────────────

/** bytedcli 的失败是否值得重试：认证 / 权限 / 参数问题重试也没用。 */
export function codebasePermanent(msg: string): boolean {
  return /登录|login|auth|unauthori|permission|forbidden|权限|not found|不存在|invalid|required|deny|denied/i.test(msg);
}

/** 从 bytedcli --json 的输出里取 MR 链接与编号（字段名大小写不一，按名字找更稳）。 */
export function parseCodebaseMr(out: unknown, web: string, repoPath: string): PrRef | undefined {
  const str = (k: string) => {
    const v = deepFind(out, k);
    return typeof v === "string" && v ? v : "";
  };
  const num = Number(deepFind(out, "Number") ?? deepFind(out, "number") ?? deepFind(out, "iid") ?? 0) || 0;
  const url = str("URL") || str("url") || str("web_url") || str("WebURL");
  if (/^https?:\/\//.test(url)) return { url, number: num || Number(url.match(/merge_requests\/(\d+)/)?.[1] ?? 0) };
  if (num) return { url: `${web}/${repoPath}/merge_requests/${num}`, number: num };
  const m = JSON.stringify(out ?? "").match(/https?:\/\/[^\s"']+\/merge_requests\/(\d+)/);
  return m ? { url: m[0], number: Number(m[1]) } : undefined;
}

function codebase(cfg: ProviderCfg, remote: RemoteRef, deps: ProviderDeps): Provider {
  const web = trimSlash(cfg.base_url || `https://${remote.host}`);
  const run = async (args: string[], input?: string): Promise<unknown> => {
    let r;
    try {
      r = await runProcess(deps.bytedcli, ["--json", "codebase", "mr", ...args], { input, env: deps.env, timeoutMs: deps.timeoutMs ?? 120_000 });
    } catch (e) {
      throw new DeliveryError(`无法运行 bytedcli（${deps.bytedcli}）：${errMsg(e)}`);
    }
    let out: unknown;
    try {
      out = JSON.parse(r.stdout);
    } catch {
      out = undefined;
    }
    const status = (out as { status?: string } | undefined)?.status;
    if (r.code !== 0 || (status && status !== "success")) {
      const msg = truncate(
        String(deepFind(out, "message") ?? deepFind(out, "error") ?? (r.stderr.trim() || r.stdout.trim() || `退出码 ${r.code}`)),
        500,
      );
      const text = `Codebase：${msg}`;
      if (/already exists|已存在/i.test(msg)) throw new HttpError(text, 409, true, true);
      throw codebasePermanent(msg) ? new DeliveryError(text) : new Error(text);
    }
    return out;
  };
  return {
    type: "codebase",
    async find(source) {
      const out = await run(["list", "-R", remote.path, "-H", source, "-s", "open", "--page-size", "20"]);
      const items = findItems(out, "Number");
      const mr = items.find((m) => m.SourceBranchName === undefined || m.SourceBranchName === source);
      return mr ? parseCodebaseMr(mr, web, remote.path) : undefined;
    },
    async create(r) {
      const args = ["create", "-R", remote.path, "--head", r.source, "--base", r.target, "--title", r.title, "-F", "-"];
      if (r.draft) args.push("--draft");
      const out = await run(args, r.body);
      const mr = parseCodebaseMr(out, web, remote.path);
      if (!mr) throw new Error("Codebase 返回里找不到 MR 链接");
      return mr;
    },
  };
}
