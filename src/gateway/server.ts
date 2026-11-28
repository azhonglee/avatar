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
 *   - 默认监听 Unix Domain Socket（bind 前临时收紧 umask(0177) 消除权限窗口，再按需放宽至 0660 供同组连接）；
 *   - 可选回环 TCP（仅 127.0.0.1 / localhost / ::1，拒绝通配地址）；
 *   - 严格读写分离鉴权：read_token 仅能访问只读接口，reply_token 仅能访问 POST /v1/replies；
 *   - 仅当明确收到 ECONNREFUSED 时才清理 stale Unix Socket，绝不误删存活实例或其他错误状态下的 socket；
 *   - SSE 具备慢消费者背压上限保护（超限主动断开，事件保留在 SQLite 供重连按游标无损续传）。
 */

const MAX_JSON_BODY = 64 * 1024;
const MAX_SSE_CLIENTS = 32;
const MAX_SSE_BUFFER_BYTES = 2 * 1024 * 1024;
const MAX_SSE_PENDING = 2_000;
const SSE_DRAIN_TIMEOUT_MS = 10_000;
const DEFAULT_SSE_HEARTBEAT_MS = 15_000;
const MIN_TOKEN_LEN = 16;

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

function sendJson(res: http.ServerResponse, status: number, body: unknown, closeAfter = false): void {
  if (res.writableEnded || res.destroyed || res.headersSent) return;
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(data),
    ...(closeAfter ? { connection: "close" } : {}),
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
  sendJson(res, err.statusCode, body, err.statusCode === 413);
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
        req.pause();
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

type SocketProbeResult = "alive" | "stale" | "missing" | { error: string };

function probeUnixSocketStatus(socketPath: string): Promise<SocketProbeResult> {
  return new Promise((resolve) => {
    const sock = net.connect(socketPath);
    let settled = false;
    const done = (r: SocketProbeResult) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(500, () => done("alive"));
    sock.once("connect", () => done("alive"));
    sock.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED") return done("stale");
      if (err.code === "ENOENT") return done("missing");
      return done({ error: `${err.code ?? "ERR"}: ${err.message}` });
    });
  });
}

async function prepareUnixSocket(socketPath: string): Promise<void> {
  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o750 });
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
  const probe = await probeUnixSocketStatus(socketPath);
  if (probe === "alive") {
    throw new Error(`Unix Socket ${socketPath} 已被另一个运行中的网关实例占用`);
  }
  if (probe === "missing") return;
  if (probe !== "stale") {
    throw new Error(`探测 Unix Socket ${socketPath} 失败，为避免误删拒绝覆盖：${probe.error}`);
  }
  fs.unlinkSync(socketPath);
}

function waitDrain(res: http.ServerResponse, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    if (res.writableEnded || res.destroyed) return resolve(false);
    let settled = false;
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      res.off("drain", onDrain);
      res.off("close", onClose);
      resolve(ok);
    };
    const onDrain = () => done(true);
    const onClose = () => done(false);
    const t = setTimeout(() => done(false), timeoutMs);
    t.unref?.();
    res.once("drain", onDrain);
    res.once("close", onClose);
  });
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
  if (tokens.readToken.length < MIN_TOKEN_LEN || tokens.replyToken.length < MIN_TOKEN_LEN || tokens.readToken === tokens.replyToken) {
    throw new Error("安全约束违规：启动网关服务必须提供两个不同且不少于 16 字符的 read_token 与 reply_token");
  }

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

  const handleStream = async (res: http.ServerResponse, afterRaw: string | null) => {
    if (sseStreams.size >= MAX_SSE_CLIENTS) {
      return sendError(res, new GatewayHttpError(503, "too_many_streams", "实时订阅连接数已达上限", false));
    }
    const requestedAfter = Math.max(0, Number.parseInt(afterRaw ?? "0", 10) || 0);
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });

    let closed = false;
    let lastSent = requestedAfter;
    let streamEpoch = "";
    let catchingUp = true;
    const pending: GatewayEvent[] = [];

    const cleanup = () => {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      offEvent();
      offStatus();
      sseStreams.delete(handle);
    };

    const dropSlowClient = () => {
      cleanup();
      if (!res.destroyed) res.destroy();
    };

    const writeRaw = (chunk: string): boolean => {
      if (closed || res.writableEnded || res.destroyed) return false;
      if (res.writableLength > MAX_SSE_BUFFER_BYTES) {
        dropSlowClient();
        return false;
      }
      return res.write(chunk);
    };

    const writeSse = (event: string, data: unknown, id?: number): boolean => {
      const prefix = id !== undefined ? `id: ${id}\n` : "";
      return writeRaw(`${prefix}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    const offEvent = service.onEvent((ev) => {
      if (closed) return;
      if (catchingUp) {
        if (pending.length >= MAX_SSE_PENDING) {
          dropSlowClient();
          return;
        }
        pending.push(ev);
        return;
      }
      if (ev.seq <= lastSent) return;
      lastSent = ev.seq;
      writeSse("event", ev, ev.seq);
    });
    const offStatus = service.onStatus((st: GatewayStatus) => {
      if (closed) return;
      if (st.db_epoch && streamEpoch && st.db_epoch !== streamEpoch) {
        streamEpoch = st.db_epoch;
        lastSent = 0;
      } else if (st.db_epoch && !streamEpoch) {
        streamEpoch = st.db_epoch;
      }
      writeSse("status", st);
    });
    const timer = setInterval(() => {
      if (closed || res.writableEnded || res.destroyed) return;
      writeRaw(": ping\n\n");
    }, heartbeatMs);
    timer.unref?.();

    const handle = {
      close: () => {
        cleanup();
        if (!res.writableEnded) res.end();
      },
    };
    sseStreams.add(handle);
    res.once("close", cleanup);

    try {
      // 1) 立即推送当前状态
      const initialStatus = service.status();
      if (initialStatus.db_epoch) streamEpoch = initialStatus.db_epoch;
      writeSse("status", initialStatus);

      // 2) 若客户端游标大于当前库 latest_seq（说明网关 DB 被重建/重置），发送 gap 并从 0 开始重放新库事件
      let cursor = requestedAfter;
      let gapEmitted = false;
      if (requestedAfter > initialStatus.latest_seq) {
        gapEmitted = true;
        writeSse("gap", { after: requestedAfter, min_seq: initialStatus.min_seq, latest_seq: initialStatus.latest_seq });
        cursor = 0;
        lastSent = 0;
      }

      // 3) 分页异步补拉游标之后的增量事件，避免大积压阻塞事件循环
      while (!closed && !res.writableEnded && !res.destroyed) {
        const page = service.listEvents(cursor, MAX_EVENTS_LIMIT);
        if (page.truncated && !gapEmitted) {
          gapEmitted = true;
          writeSse("gap", { after: requestedAfter, min_seq: page.min_seq, latest_seq: page.latest_seq });
        }
        for (const ev of page.events) {
          if (closed) return;
          if (ev.seq <= lastSent) continue;
          lastSent = ev.seq;
          const ok = writeSse("event", ev, ev.seq);
          if (!ok && !closed) {
            const drained = await waitDrain(res, SSE_DRAIN_TIMEOUT_MS);
            if (!drained) {
              dropSlowClient();
              return;
            }
          }
        }
        // 以本页实际扫描到的最后一个 seq 续拉：整页事件都被排除规则过滤掉时也要继续往后翻
        if (!page.has_more || page.next_after <= cursor) break;
        cursor = page.next_after;
        await new Promise<void>((r) => setImmediate(r));
      }

      if (closed) return;
      catchingUp = false;
      for (const ev of pending) {
        if (closed) return;
        if (ev.seq <= lastSent) continue;
        lastSent = ev.seq;
        writeSse("event", ev, ev.seq);
      }
      pending.length = 0;
    } catch {
      dropSlowClient();
    }
  };

  const server = http.createServer(async (req, res) => {
    const reqCtrl = new AbortController();
    const onClose = () => {
      if (!res.writableEnded) reqCtrl.abort();
    };
    res.once("close", onClose);

    try {
      const method = req.method ?? "GET";
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(req.url ?? "/", "http://localhost");
      } catch {
        return sendError(res, new GatewayHttpError(400, "invalid_url", "请求路径格式非法", true));
      }
      const pathname = parsedUrl.pathname;

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
        return sendJson(res, 200, service.listEvents(after, limit));
      }

      if (method === "GET" && pathname === "/v1/stream") {
        const authErr = authorize(req, "read");
        if (authErr) return sendError(res, authErr);
        await handleStream(res, parsedUrl.searchParams.get("after"));
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
    // bind 前临时收紧 umask(0177) 确保 socket 初始权限严格 0600，再按需放宽到 socketMode（如 0660）
    const prevUmask = process.umask(0o177);
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(cfg.socketPath, () => {
          server.off("error", reject);
          resolve();
        });
      });
    } finally {
      process.umask(prevUmask);
    }
    try {
      fs.chmodSync(cfg.socketPath, cfg.socketMode);
    } catch (e) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try {
        if (fs.lstatSync(cfg.socketPath).isSocket()) fs.unlinkSync(cfg.socketPath);
      } catch {
        // ignore
      }
      throw e;
    }
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
      const h = cfg.listen.host.includes(":") ? `[${cfg.listen.host}]` : cfg.listen.host;
      boundUrl = `http://${h}:${cfg.listen.port}`;
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
