import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { App } from "../app.ts";
import type { ApiError, ServerEvent } from "../api/types.ts";
import * as Q from "../api/queries.ts";
import { CommandError } from "../commands.ts";
import { ROOT } from "../config.ts";
import { errMsg, log } from "../util.ts";

/**
 * 控制台服务：REST API + SSE + 静态页面。
 *
 * 安全：
 *   - 监听 cfg.server.host（默认 0.0.0.0，同局域网可直接访问；如需仅限本机访问可设为 127.0.0.1）
 *   - 令牌鉴权：令牌存在 kv（server.token），`pa console` 打印登录链接；
 *     飞书卡片链接携带短期 HMAC 签名票据（/login?ticket=<exp>.<sig>&next=...），不暴露主令牌，轮换令牌即全部失效；
 *     /login 校验后写入 HttpOnly + SameSite=Lax 的 Cookie 并跳转到站内 next 路径。也接受 Authorization: Bearer
 *   - 写请求要求 JSON 且同源（Origin 与 Host 一致），防 CSRF
 */

const VIRTUAL_IFACE = /^(lo|docker|br-|veth|virbr|cni|flannel|kube|podman|cilium|dummy)/i;
const TUNNEL_IFACE = /^(utun|tun|tap|wg|tailscale|zt)/i;

function isPrivateLanIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function isCgnatIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  return parts.length === 4 && parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127;
}

/** 选一个最合适的局域网 IPv4（优先物理网卡上的私网地址，避开 docker/网桥/link-local）。 */
export function detectLanIp(ifaces?: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string | undefined {
  let map = ifaces;
  if (!map) {
    try {
      map = os.networkInterfaces();
    } catch {
      return undefined;
    }
  }
  let best: { ip: string; score: number } | undefined;
  for (const [name, list] of Object.entries(map)) {
    for (const info of list ?? []) {
      const family = String(info.family);
      if (info.internal || family !== "IPv4" || !info.address || info.address === "0.0.0.0" || info.address.startsWith("169.254.")) continue;
      let score = VIRTUAL_IFACE.test(name) ? 10 : TUNNEL_IFACE.test(name) ? 50 : 100;
      score += isPrivateLanIpv4(info.address) ? 30 : isCgnatIpv4(info.address) ? 20 : 10;
      if (!best || score > best.score) best = { ip: info.address, score };
    }
  }
  return best?.ip;
}

export function isWildcardHost(host: string): boolean {
  const h = host.trim().replace(/^\[|\]$/g, "");
  return !h || h === "0.0.0.0" || h === "::";
}

export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "127.0.0.1" || h === "localhost" || h === "::1";
}

function formatHost(host: string): string {
  const h = host.trim().replace(/^\[|\]$/g, "");
  return h.includes(":") ? `[${h}]` : h;
}

/** 解析对外展示的控制台主机名：监听通配地址（0.0.0.0 / ::）时优先使用本机局域网 IP，无可用网卡时回退 127.0.0.1。 */
export function resolveConsoleHost(host: string, ifaces?: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string {
  return isWildcardHost(host) ? (detectLanIp(ifaces) ?? "127.0.0.1") : host.trim().replace(/^\[|\]$/g, "");
}

/** 构造控制台基址（形如 http://<局域网IP>:7878）。 */
export function consoleBaseUrl(host: string, port: number, ifaces?: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string {
  return `http://${formatHost(resolveConsoleHost(host, ifaces))}:${port}`;
}

const COOKIE = "pa_session";
const LOGIN_TICKET_TTL_MS = 7 * 86_400_000;
const MAX_BODY = 1024 * 1024;
const WEB_DIST = path.join(ROOT, "web", "dist");

export function serverToken(app: App, rotate = false): string {
  let t = app.store.get("server.token");
  if (!t || rotate) {
    t = randomBytes(24).toString("base64url");
    app.store.set("server.token", t);
  }
  return t;
}

/** 用主令牌签发短期无状态登录票据（`<expMs>.<hmac-sha256-base64url>`），供发给本人的飞书卡片链接免登；轮换主令牌即刻失效。 */
export function signLoginTicket(token: string, ttlMs = LOGIN_TICKET_TTL_MS, now = Date.now()): string {
  const exp = String(Math.floor(now + ttlMs));
  const sig = createHmac("sha256", token).update(`login:${exp}`).digest("base64url");
  return `${exp}.${sig}`;
}

export function verifyLoginTicket(token: string, ticket: string, now = Date.now()): boolean {
  if (!token || !ticket) return false;
  const parts = ticket.split(".");
  if (parts.length !== 2) return false;
  const [expStr, sig] = parts;
  if (!/^\d+$/.test(expStr) || !sig) return false;
  const exp = Number(expStr);
  if (!Number.isSafeInteger(exp) || exp < now) return false;
  const expected = createHmac("sha256", token).update(`login:${expStr}`).digest("base64url");
  return safeEqual(sig, expected);
}

/** 校验并规范化登录后跳转的站内相对路径，拦截开放重定向（`//evil`、`/\evil`、外链、控制字符等）。 */
export function safeNextPath(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\") || /[\x00-\x1f\x7f]/.test(raw)) return "/";
  try {
    const u = new URL(raw, "http://local.invalid");
    if (u.origin !== "http://local.invalid") return "/";
    return `${u.pathname}${u.search}${u.hash}`;
  } catch {
    return "/";
  }
}

/** 构造控制台链接；提供 ticket 时经 `/login?ticket=...&next=...` 写入 Cookie 后再跳目标页。 */
export function consoleLinkUrl(base: string, targetPath = "/", ticket?: string): string {
  if (!base) return "";
  const clean = base.replace(/\/+$/, "");
  const next = safeNextPath(targetPath);
  if (!ticket) return `${clean}${next}`;
  const qs = new URLSearchParams({ ticket });
  if (next !== "/") qs.set("next", next);
  return `${clean}/login?${qs.toString()}`;
}

class HttpError extends Error {
  status: number;
  code: ApiError["error"]["code"];
  constructor(status: number, code: ApiError["error"]["code"], message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const STATUS: Record<ApiError["error"]["code"], number> = {
  unauthorized: 401,
  not_found: 404,
  invalid: 400,
  conflict: 409,
  forbidden: 403,
  unavailable: 503,
  internal: 500,
};

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function cookies(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
};

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SECURITY_HEADERS, ...headers });
  res.end(data);
}

async function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const ct = req.headers["content-type"] ?? "";
  if (!ct.startsWith("application/json")) throw new HttpError(415, "invalid", "请求体必须是 JSON");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "invalid", "请求体过大");
    chunks.push(c as Buffer);
  }
  if (!chunks.length) return {};
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "invalid", "请求体不是合法的 JSON 对象");
  }
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".woff2": "font/woff2",
  ".map": "application/json",
};

const NOT_BUILT = `<!doctype html><meta charset="utf-8"><title>Avatar 控制台</title>
<body style="font-family:system-ui;padding:40px;color:#333"><h2>控制台页面尚未构建</h2>
<p>在项目目录运行 <code>npm run build:web</code> 后刷新本页。API 已可用：<code>/api/meta</code>。</p></body>`;

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): void {
  const index = path.join(WEB_DIST, "index.html");
  if (!fs.existsSync(index)) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS });
    res.end(NOT_BUILT);
    return;
  }
  const rel = decodeURIComponent(pathname).replace(/^\/+/, "");
  const file = path.resolve(WEB_DIST, rel);
  const inside = file.startsWith(WEB_DIST + path.sep);
  const target = inside && rel && fs.existsSync(file) && fs.statSync(file).isFile() ? file : index; // SPA 回退
  const ext = path.extname(target);
  const immutable = target !== index && rel.startsWith("assets/");
  res.writeHead(200, {
    "Content-Type": MIME[ext] ?? "application/octet-stream",
    "Cache-Control": immutable ? "public, max-age=31536000, immutable" : "no-cache",
    ...SECURITY_HEADERS,
  });
  if (req.method === "HEAD") return void res.end();
  fs.createReadStream(target).pipe(res);
}

export interface ConsoleServer {
  url: string;
  close(): Promise<void>;
}

export async function startServer(app: App, o: { version: string; port?: number; host?: string }): Promise<ConsoleServer> {
  serverToken(app); // 启动时确保令牌已生成
  const currentToken = () => serverToken(app);
  const host = o.host ?? app.cfg.server.host;
  const clients = new Set<http.ServerResponse>();

  const broadcast = (e: ServerEvent) => {
    const line = `data: ${JSON.stringify(e)}\n\n`;
    for (const c of clients) c.write(line);
  };
  let lastBus = 0;
  const offs = [
    app.bus.on("work.changed", (e) => {
      lastBus = Date.now();
      broadcast({ type: "work", ...e });
    }),
    app.bus.on("candidate.created", (e) => {
      lastBus = Date.now();
      broadcast({ type: "candidate", signal_id: e.signalId });
    }),
    app.bus.on("command.executed", (e) => broadcast({ type: "command", name: e.name, ok: e.ok, target: e.target })),
    // 飞书写入落定（如草稿已发送）：控制台据此刷新对应资源
    app.bus.on("effect.settled", (e) => broadcast({ type: "work", id: e.id, kind: "effect", ref: e.ref, state: e.state, terminal: true })),
  ];
  // 跨进程变化（命令行、另一个进程）：轮询账本的最后更新时间
  let lastMax = 0;
  const poll = setInterval(() => {
    if (!clients.size) return;
    const m = (app.ledger.db.prepare("SELECT COALESCE(MAX(updated), 0) AS m FROM work").get() as { m: number }).m;
    if (lastMax && m > lastMax && Date.now() - lastBus > 2000) broadcast({ type: "refresh" });
    lastMax = m;
  }, 2000);
  const ping = setInterval(() => broadcast({ type: "ping", at: Date.now() }), 15_000);

  const authed = (req: http.IncomingMessage): boolean => {
    const tok = currentToken();
    const bearer = req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    const c = cookies(req)[COOKIE];
    return (!!bearer && safeEqual(bearer, tok)) || (!!c && safeEqual(c, tok));
  };

  const sameOrigin = (req: http.IncomingMessage): boolean => {
    const origin = req.headers.origin;
    if (!origin) return true; // 非浏览器客户端（curl 等）没有 Origin，靠令牌
    try {
      return new URL(origin).host === req.headers.host;
    } catch {
      return false;
    }
  };

  const route = async (req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> => {
    const { pathname } = url;
    const m = req.method ?? "GET";

    if (pathname === "/login" && m === "GET") {
      const tok = currentToken();
      const t = url.searchParams.get("token") ?? "";
      const ticket = url.searchParams.get("ticket") ?? "";
      const next = safeNextPath(url.searchParams.get("next"));
      const valid = (!!t && safeEqual(t, tok)) || (!!ticket && verifyLoginTicket(tok, ticket));
      if (!valid) {
        // 卡片里的短期票据过期后，若当前浏览器/飞书 WebView 仍持有效会话 Cookie，直接放行到目标页
        if (!t && ticket && authed(req)) {
          res.writeHead(302, { Location: next, "Cache-Control": "no-store", ...SECURITY_HEADERS });
          return void res.end();
        }
        res.writeHead(401, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...SECURITY_HEADERS });
        return void res.end("<meta charset=utf-8><p>登录链接无效或已过期。请在开发机上运行 <code>pa console</code> 获取新链接。</p>");
      }
      res.writeHead(302, {
        "Set-Cookie": `${COOKIE}=${encodeURIComponent(tok)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}`,
        Location: next,
        "Cache-Control": "no-store",
        ...SECURITY_HEADERS,
      });
      return void res.end();
    }
    if (pathname === "/logout" && m === "POST") {
      return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` });
    }
    if (pathname === "/api/health/live") return send(res, 200, { ok: true });

    if (!pathname.startsWith("/api/")) return serveStatic(req, res, pathname);
    if (!authed(req)) throw new HttpError(401, "unauthorized", "未登录：请在开发机上运行 pa console 获取登录链接");
    if (m !== "GET" && m !== "HEAD" && !sameOrigin(req)) throw new HttpError(403, "forbidden", "跨站请求被拒绝");

    const seg = pathname.slice(5).split("/").map(decodeURIComponent); // 去掉 /api/
    const need = <T>(v: T | undefined, what: string): T => {
      if (v === undefined) throw new HttpError(404, "not_found", `${what}不存在`);
      return v;
    };
    const ext = <K extends keyof App["ext"]>(k: K): NonNullable<App["ext"][K]> => {
      const v = app.ext[k];
      if (!v) throw new HttpError(501, "unavailable", "该功能未启用");
      return v as NonNullable<App["ext"][K]>;
    };

    if (m === "GET") {
      switch (seg[0]) {
        case "meta":
          return send(res, 200, Q.meta(app, o.version));
        case "overview":
          return send(res, 200, Q.overview(app));
        case "dispatches":
          if (!seg[1])
            return send(
              res,
              200,
              Q.listDispatches(app, {
                filter: (url.searchParams.get("filter") as Q.DispatchFilter) ?? "all",
                q: url.searchParams.get("q") ?? undefined,
                limit: Number(url.searchParams.get("limit") ?? 200),
              }),
            );
          if (seg[2] === "diff") return send(res, 200, need(await Q.dispatchDiff(app, seg[1]), "派单"));
          return send(res, 200, need(await Q.dispatchDetail(app, seg[1]), "派单"));
        case "steps":
          if (seg[2] === "log") return send(res, 200, need(Q.stepLog(app, Number(seg[1]), Number(url.searchParams.get("offset") ?? 0)), "步骤"));
          break;
        case "candidates":
          return send(
            res,
            200,
            ext("candidates").list({
              days: Number(url.searchParams.get("days") ?? 14),
              feedback: (url.searchParams.get("feedback") as "" | "confirmed" | "rejected" | "all") ?? "all",
            }),
          );
        case "jobs":
          return send(res, 200, Q.jobs(app));
        case "health":
          return send(res, 200, Q.health(app));
        case "usage":
          return send(res, 200, ext("usage").summary(Number(url.searchParams.get("days") ?? 14)));
        case "settings":
          return send(res, 200, ext("settings").get());
        case "doctor":
          return send(res, 200, await ext("doctor").run());
        case "audit":
          return send(res, 200, Q.auditViews(app, url.searchParams.get("target") ?? undefined, Number(url.searchParams.get("limit") ?? 100)));
        case "commands":
          return send(res, 200, app.commands.names());
        case "context": {
          const c = ext("context");
          const q = (k: string) => url.searchParams.get(k) ?? undefined;
          switch (seg[1]) {
            case "today":
              return send(res, 200, c.today());
            case "projects":
              if (seg[2]) return send(res, 200, need(c.project(seg[2]), "项目"));
              return send(res, 200, c.projects({ legacy: q("legacy") === "1" }));
            case "items":
              if (seg[2]) return send(res, 200, need(c.item(seg[2]), "事项"));
              return send(res, 200, c.items({ status: q("status"), kind: q("kind"), project: q("project"), q: q("q") }));
            case "knowledge":
              return send(res, 200, c.knowledge({ q: q("q"), project: q("project") }));
            case "updates":
              return send(res, 200, c.updates({ days: Number(q("days") ?? 7) || 7, project: q("project") }));
            case "people":
              return send(res, 200, c.people());
            case "conflicts":
              return send(res, 200, c.conflicts((q("status") as "open" | "resolved" | undefined) ?? undefined));
            case "drafts":
              return send(res, 200, c.drafts(q("status")));
            case "status":
              return send(res, 200, c.status());
          }
          break;
        }
        case "events": {
          res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive", ...SECURITY_HEADERS });
          res.write(`data: ${JSON.stringify({ type: "ping", at: Date.now() } satisfies ServerEvent)}\n\n`);
          clients.add(res);
          req.on("close", () => clients.delete(res));
          return;
        }
      }
    }
    if (m === "POST" && seg[0] === "commands" && seg[1]) {
      const body = await readJson(req);
      return send(res, 200, await app.commands.exec(seg[1], body.args ?? {}, { source: "web", actor: "owner" }));
    }
    if (m === "PUT" && seg[0] === "settings") {
      const body = await readJson(req);
      const r = await ext("settings").put(body);
      return send(res, r.ok ? 200 : 400, r);
    }
    throw new HttpError(404, "not_found", `没有这个接口：${m} ${pathname}`);
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    route(req, res, url).catch((e) => {
      if (res.headersSent) return void res.end();
      if (e instanceof HttpError) return send(res, e.status, { error: { code: e.code, message: e.message } } satisfies ApiError);
      if (e instanceof CommandError) return send(res, STATUS[e.code], { error: { code: e.code, message: e.message } } satisfies ApiError);
      log("error", "控制台请求失败", { path: url.pathname, err: errMsg(e) });
      send(res, 500, { error: { code: "internal", message: errMsg(e) } } satisfies ApiError);
    });
  });
  const bindHost = host.trim().replace(/^\[|\]$/g, "");
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port ?? app.cfg.server.port, bindHost || undefined, () => resolve());
  });
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : app.cfg.server.port;
  const url = consoleBaseUrl(bindHost, port);
  log("info", "控制台已启动", { url, listen: `${formatHost(bindHost || "0.0.0.0")}:${port}` });
  return {
    url,
    close: async () => {
      clearInterval(poll);
      clearInterval(ping);
      offs.forEach((f) => f());
      for (const c of clients) c.end();
      clients.clear();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
