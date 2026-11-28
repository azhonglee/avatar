import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import type { GatewayConfig } from "./config.ts";
import {
  GatewayHttpError,
  MAX_EVENTS_LIMIT,
  type GatewayContextRequest,
  type GatewayErrorBody,
  type GatewayEvent,
  type GatewayReplyRequest,
  type GatewayStatus,
} from "./protocol.ts";
import type { FeishuGatewayService } from "./service.ts";
import type { ResolvedGatewayTokens } from "./store.ts";

/**
 * 飞书个人 Web 独立网关 HTTP/1.1 + SSE 服务。
 *
 * 安全设计：
 *   - 默认监听 Unix Domain Socket（支持 chmod 0660 供同组客户端连接，禁止 world 权限）；
 *   - 可选回环 TCP（仅 127.0.0.1 / localhost / ::1，拒绝通配地址）；
 *   - 严格读写分离鉴权：read_token 仅能访问只读接口，reply_token 仅能访问 POST /v1/replies；
 *   - 启动前先探测已有 Unix Socket 是否存活，绝不误删运行中实例的 socket 或非 socket 文件。
 */

const MAX_JSON_BODY = 64 * 1024;
const MAX_SSE_CLIENTS = 32;
const DEFAULT_SSE_HEARTBEAT_MS = 15_000;

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function bearerToken(req: http.IncomingMessage): string {
  const raw = req.headers.authorization;
  if (typeof raw !== "string") return "";
  const m = raw.match(/^Bearer\s+(\S+)$/i);
  return m ? m[1] : "";
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  if (res.writableEnded) return;
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

function sendError(res: http.ServerResponse, err: GatewayHttpError): void {
  const body: GatewayErrorBody = {
    ok: false,
    code: err.code,
    error: err.message,
    permanent: err.permanent,
    ...(err.gatewayStatus ? { status: err.gatewayStatus } : {}),
  };
  sendJson(res, err.statusCode, body);
}

function readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers["content-type"] ?? "").toLowerCase();
    if (!ct.startsWith("application/json")) {
      return reject(new GatewayHttpError(415, "unsupported_media_type", "请求必须携带 Content-Type: application/json", true));
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > MAX_JSON_BODY) {
        settled = true;
        req.destroy();
        reject(new GatewayHttpError(413, "payload_too_large", `请求体超过上限（${MAX_JSON_BODY} 字节）`, true));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
        resolve(parsed);
      } catch {
        reject(new GatewayHttpError(400, "invalid_json", "请求体不是合法 JSON", true));
      }
    });
    req.on("error", (e) => {
      if (settled) return;
      settled = true;
      reject(new GatewayHttpError(400, "read_error", e.message, false));
    });
  });
}

function probeUnixSocketAlive(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect(socketPath);
    const done = (alive: boolean) => {
      sock.destroy();
      resolve(alive);
    };
    sock.setTimeout(500, () => done(true));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

async function prepareUnixSocket(socketPath: string): Promise<void> {
  fs.mkdirSync(path.dirname(socketPath), { recursive: true });
  let stat: fs.Stats | undefined;
  try {
    stat = fs.lstatSync(socketPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw e;
  }
  if (!stat.isSocket()) {
    throw new Error(`路径 ${socketPath} 已存在且不是 Unix Socket，拒绝覆盖`);
  }
  if (await probeUnixSocketAlive(socketPath)) {
    throw new Error(`Unix Socket ${socketPath} 已被另一个运行中的网关实例占用`);
  }
  fs.unlinkSync(socketPath);
}

export interface GatewayServerHandle {
  readonly address: string;
  readonly socketPath?: string;
  readonly url?: string;
  stop(): Promise<void>;
}

export interface StartGatewayServerOptions {
  heartbeatMs?: number;
}

export async function startGatewayServer(
  cfg: GatewayConfig,
  service: FeishuGatewayService,
  tokens: ResolvedGatewayTokens,
  opts: StartGatewayServerOptions = {},
): Promise<GatewayServerHandle> {
  const sseStreams = new Set<{ close(): void }>();
  const heartbeatMs = opts.heartbeatMs ?? DEFAULT_SSE_HEARTBEAT_MS;

  const authorize = (req: http.IncomingMessage, scope: "read" | "reply"): GatewayHttpError | undefined => {
    const token = bearerToken(req);
    if (!token) {
      return new GatewayHttpError(401, "unauthorized", "缺少 Bearer 鉴权令牌", true);
    }
    const isRead = safeEqual(token, tokens.readToken);
    const isReply = safeEqual(token, tokens.replyToken);
    if (!isRead && !isReply) {
      return new GatewayHttpError(401, "unauthorized", "无效的鉴权令牌", true);
    }
    if (scope === "read" && !isRead) {
      return new GatewayHttpError(403, "insufficient_scope", "reply_token 无权访问只读接口，请使用 read_token", true);
    }
    if (scope === "reply" && !isReply) {
      return new GatewayHttpError(403, "insufficient_scope", "read_token 无权发送回复，请使用独立的 reply_token", true);
    }
    return undefined;
  };

  const handleStream = (req: http.IncomingMessage, res: http.ServerResponse, afterRaw: string | null) => {
    if (sseStreams.size >= MAX_SSE_CLIENTS) {
      return sendError(res, new GatewayHttpError(503, "too_many_streams", "实时订阅连接数已达上限", false));
    }
    const after = Math.max(0, Number.parseInt(afterRaw ?? "0", 10) || 0);
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });

    const writeSse = (event: string, data: unknown, id?: number) => {
      if (res.writableEnded || res.destroyed) return;
      if (id !== undefined) res.write(`id: ${id}\n`);
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    let lastSent = after;
    let catchingUp = true;
    const pending: GatewayEvent[] = [];

    // 先挂订阅再补拉 DB，保证补拉期间到达的新事件零丢失、严格按 seq 递增
    const offEvent = service.onEvent((ev) => {
      if (catchingUp) {
        pending.push(ev);
        return;
      }
      if (ev.seq <= lastSent) return;
      lastSent = ev.seq;
      writeSse("event", ev, ev.seq);
    });
    const offStatus = service.onStatus((st: GatewayStatus) => {
      writeSse("status", st);
    });
    const timer = setInterval(() => {
      if (!res.writableEnded && !res.destroyed) res.write(": ping\n\n");
    }, heartbeatMs);
    timer.unref?.();

    const cleanup = () => {
      clearInterval(timer);
      offEvent();
      offStatus();
      sseStreams.delete(handle);
    };
    const handle = {
      close: () => {
        cleanup();
        if (!res.writableEnded) res.end();
      },
    };
    sseStreams.add(handle);
    req.once("close", cleanup);
    res.once("close", cleanup);

    // 初始状态
    writeSse("status", service.status());

    // 同步补拉游标之后的增量事件
    let cursor = after;
    let gapEmitted = false;
    while (!res.writableEnded && !res.destroyed) {
      const page = service.store.listEvents(cursor, MAX_EVENTS_LIMIT);
      if (page.truncated && !gapEmitted) {
        gapEmitted = true;
        writeSse("gap", { after, min_seq: page.min_seq, latest_seq: page.latest_seq });
      }
      for (const ev of page.events) {
        if (ev.seq <= lastSent) continue;
        lastSent = ev.seq;
        writeSse("event", ev, ev.seq);
      }
      if (!page.has_more || page.events.length === 0) break;
      cursor = page.events[page.events.length - 1].seq;
    }

    catchingUp = false;
    for (const ev of pending) {
      if (ev.seq <= lastSent) continue;
      lastSent = ev.seq;
      writeSse("event", ev, ev.seq);
    }
    pending.length = 0;
  };

  const server = http.createServer(async (req, res) => {
    const method = req.method ?? "GET";
    const parsedUrl = new URL(req.url ?? "/", "http://localhost");
    const pathname = parsedUrl.pathname;

    const reqCtrl = new AbortController();
    const onClose = () => {
      if (!res.writableEnded) reqCtrl.abort();
    };
    res.once("close", onClose);

    try {
      if (method === "GET" && pathname === "/v1/health") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        return sendJson(res, 200, service.health());
      }

      if (method === "GET" && pathname === "/v1/status") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        const verify = parsedUrl.searchParams.get("verify") === "1" || parsedUrl.searchParams.get("verify") === "true";
        const st = verify ? await service.verifyStatus(reqCtrl.signal) : service.status();
        return sendJson(res, 200, st);
      }

      if (method === "GET" && pathname === "/v1/events") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        const after = Number.parseInt(parsedUrl.searchParams.get("after") ?? "0", 10) || 0;
        const limit = Number.parseInt(parsedUrl.searchParams.get("limit") ?? "200", 10) || 200;
        return sendJson(res, 200, service.store.listEvents(after, limit));
      }

      if (method === "GET" && pathname === "/v1/stream") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        handleStream(req, res, parsedUrl.searchParams.get("after"));
        return;
      }

      if (method === "POST" && pathname === "/v1/context") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        const body = await readJsonBody<GatewayContextRequest>(req);
        const out = await service.readContext(body, reqCtrl.signal);
        return sendJson(res, 200, out);
      }

      if (method === "POST" && pathname === "/v1/replies") {
        const authErr = authorize(req, "reply");
        if (authErr) return sendError(res, authErr);
        const body = await readJsonBody<GatewayReplyRequest>(req);
        const result = await service.sendReply(body, reqCtrl.signal);
        return sendJson(res, 200, { ok: true, result });
      }

      return sendError(res, new GatewayHttpError(404, "not_found", `未知接口：${method} ${pathname}`, true));
    } catch (err) {
      if (err instanceof GatewayHttpError) {
        sendError(res, err);
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        sendError(res, new GatewayHttpError(500, "internal_error", msg, false));
      }
    } finally {
      res.off("close", onClose);
    }
  });

  let boundSocketPath: string | undefined;
  let boundUrl: string | undefined;

  if (cfg.socketPath) {
    await prepareUnixSocket(cfg.socketPath);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(cfg.socketPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
    fs.chmodSync(cfg.socketPath, cfg.socketMode);
    boundSocketPath = cfg.socketPath;
  } else {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(cfg.listen.port, cfg.listen.host, () => {
        server.off("error", reject);
        resolve();
      });
    });
    const addr = server.address();
    if (addr && typeof addr === "object") {
      const h = addr.address.includes(":") ? `[${addr.address}]` : addr.address;
      boundUrl = `http://${h}:${addr.port}`;
    } else {
      boundUrl = `http://${cfg.listen.host}:${cfg.listen.port}`;
    }
  }

  let stopped = false;
  return {
    address: boundSocketPath ? `unix://${boundSocketPath}` : (boundUrl ?? ""),
    socketPath: boundSocketPath,
    url: boundUrl,
    async stop() {
      if (stopped) return;
      stopped = true;
      for (const s of [...sseStreams]) s.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (boundSocketPath) {
        try {
          if (fs.lstatSync(boundSocketPath).isSocket()) fs.unlinkSync(boundSocketPath);
        } catch {
          // ignore
        }
      }
    },
  };
}
