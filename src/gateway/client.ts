import http from "node:http";
import {
  GatewayHttpError,
  validateLoopbackGatewayUrl,
  type GatewayContextRequest,
  type GatewayContextResponse,
  type GatewayErrorBody,
  type GatewayEvent,
  type GatewayEventsResponse,
  type GatewayGapEvent,
  type GatewayHealth,
  type GatewayReplyRequest,
  type GatewayReplyResponse,
  type GatewayReplyResult,
  type GatewayStatus,
} from "./protocol.ts";

/**
 * 飞书个人 Web 独立网关客户端（纯传输层，零密钥/零 Cookie/零飞书协议依赖）。
 *
 * 支持：
 *   - Unix Domain Socket（推荐，与独立 OS 用户 / 属组权限隔离）
 *   - 回环 HTTP（127.0.0.1 / localhost / [::1]）
 *   - 严格区分 readToken（只读拉取/SSE/补读上下文）与 replyToken（受控回复）
 */

export interface FeishuGatewayClientOptions {
  socketPath?: string;
  baseUrl?: string;
  readToken?: string;
  replyToken?: string;
  timeoutMs?: number;
}

export interface StreamEventsOptions {
  after: number;
  signal: AbortSignal;
  onEvent: (ev: GatewayEvent) => Promise<void> | void;
  onStatus?: (st: GatewayStatus) => void;
  onGap?: (gap: GatewayGapEvent) => void;
  /** 心跳/数据空闲超时毫秒数（默认 45 秒，超时主动断开重连以检测半开连接） */
  idleTimeoutMs?: number;
}

const DEFAULT_READ_TIMEOUT_MS = 15_000;
const DEFAULT_REPLY_TIMEOUT_MS = 45_000;
const DEFAULT_SSE_IDLE_MS = 45_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export class FeishuGatewayClient {
  private readonly socketPath?: string;
  private readonly url?: URL;
  private readonly readToken: string;
  private readonly replyToken: string;
  private readonly defaultTimeoutMs: number;

  constructor(opts: FeishuGatewayClientOptions) {
    const sock = opts.socketPath?.trim() ?? "";
    const rawUrl = opts.baseUrl?.trim() ?? "";
    if (sock && rawUrl) {
      throw new Error("gateway_socket 与 gateway_url 只能二选一");
    }
    if (!sock && !rawUrl) {
      throw new Error("必须提供 gateway_socket 或 gateway_url 之一");
    }
    if (sock) {
      this.socketPath = sock;
    } else {
      this.url = validateLoopbackGatewayUrl(rawUrl);
    }
    this.readToken = opts.readToken?.trim() ?? "";
    this.replyToken = opts.replyToken?.trim() ?? "";
    this.defaultTimeoutMs = opts.timeoutMs ?? DEFAULT_READ_TIMEOUT_MS;
  }

  endpointLabel(): string {
    return this.socketPath ? `unix://${this.socketPath}` : (this.url?.origin ?? "");
  }

  private tokenFor(scope: "read" | "reply"): string {
    const token = scope === "read" ? this.readToken : this.replyToken;
    if (!token) {
      throw new GatewayHttpError(
        401,
        scope === "read" ? "missing_read_token" : "missing_reply_token",
        scope === "read" ? "缺少网关只读令牌（read_token）" : "缺少网关回复令牌（reply_token）",
        true,
      );
    }
    return token;
  }

  private buildRequestOptions(method: string, reqPath: string, headers: http.OutgoingHttpHeaders): http.RequestOptions {
    if (this.socketPath) {
      return {
        socketPath: this.socketPath,
        path: reqPath,
        method,
        headers: { host: "localhost", ...headers },
      };
    }
    const u = this.url!;
    return {
      protocol: u.protocol,
      hostname: u.hostname.replace(/^\[|\]$/g, ""),
      port: u.port || 80,
      path: reqPath,
      method,
      headers,
    };
  }

  private requestJson<T>(
    method: "GET" | "POST",
    reqPath: string,
    scope: "read" | "reply",
    body?: unknown,
    opts: { signal?: AbortSignal; timeoutMs?: number } = {},
  ): Promise<T> {
    const payload = body !== undefined ? Buffer.from(JSON.stringify(body), "utf8") : undefined;
    const timeoutMs = opts.timeoutMs ?? this.defaultTimeoutMs;

    return new Promise<T>((resolve, reject) => {
      if (opts.signal?.aborted) return reject(new Error("aborted"));
      let token: string;
      try {
        token = this.tokenFor(scope);
      } catch (err) {
        return reject(err);
      }
      const headers: http.OutgoingHttpHeaders = {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        ...(payload
          ? {
              "content-type": "application/json; charset=utf-8",
              "content-length": payload.length,
            }
          : {}),
      };
      const reqOpts = this.buildRequestOptions(method, reqPath, headers);
      let settled = false;
      const done = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
        fn();
      };

      const req = http.request(reqOpts, (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (c: Buffer) => {
          total += c.length;
          if (total > MAX_RESPONSE_BYTES) {
            req.destroy();
            done(() => reject(new GatewayHttpError(502, "response_too_large", "网关响应体超过上限", false)));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          const status = res.statusCode ?? 502;
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: unknown;
          let parseOk = false;
          if (text) {
            try {
              parsed = JSON.parse(text);
              parseOk = true;
            } catch {
              parseOk = false;
            }
          }
          if (status >= 200 && status < 300) {
            if (!parseOk) {
              done(() => reject(new GatewayHttpError(502, "invalid_response", "网关返回了空或非合法 JSON 响应", false)));
              return;
            }
            done(() => resolve(parsed as T));
            return;
          }
          const errBody = (parseOk ? parsed : undefined) as Partial<GatewayErrorBody> | undefined;
          const code = typeof errBody?.code === "string" ? errBody.code : `http_${status}`;
          const message = typeof errBody?.error === "string" ? errBody.error : text.slice(0, 300) || `HTTP ${status}`;
          const permanent = typeof errBody?.permanent === "boolean" ? errBody.permanent : status === 400 || status === 401 || status === 403 || status === 404 || status === 422;
          done(() => reject(new GatewayHttpError(status, code, message, permanent, errBody?.status)));
        });
        res.on("error", (err) => done(() => reject(err)));
      });

      const onAbort = () => {
        req.destroy();
        done(() => reject(new Error("aborted")));
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      const timer = setTimeout(() => {
        req.destroy();
        done(() => reject(new GatewayHttpError(504, "timeout", `请求网关超时（${timeoutMs}ms）：${method} ${reqPath}`, false)));
      }, timeoutMs);
      timer.unref?.();

      req.on("error", (err) => done(() => reject(err)));
      if (payload) req.write(payload);
      req.end();
    });
  }

  health(signal?: AbortSignal): Promise<GatewayHealth> {
    return this.requestJson<GatewayHealth>("GET", "/v1/health", "read", undefined, { signal });
  }

  status(opts: { verify?: boolean; signal?: AbortSignal; timeoutMs?: number } = {}): Promise<GatewayStatus> {
    const qs = opts.verify ? "?verify=1" : "";
    return this.requestJson<GatewayStatus>("GET", `/v1/status${qs}`, "read", undefined, {
      signal: opts.signal,
      timeoutMs: opts.timeoutMs ?? (opts.verify ? 30_000 : this.defaultTimeoutMs),
    });
  }

  listEvents(after = 0, limit = 200, signal?: AbortSignal): Promise<GatewayEventsResponse> {
    const a = Math.max(0, Math.floor(after));
    const l = Math.max(1, Math.min(500, Math.floor(limit)));
    return this.requestJson<GatewayEventsResponse>("GET", `/v1/events?after=${a}&limit=${l}`, "read", undefined, { signal });
  }

  readContext(req: GatewayContextRequest, signal?: AbortSignal): Promise<GatewayContextResponse> {
    return this.requestJson<GatewayContextResponse>("POST", "/v1/context", "read", req, { signal, timeoutMs: 25_000 });
  }

  async sendReply(req: GatewayReplyRequest, signal?: AbortSignal): Promise<GatewayReplyResult> {
    const res = await this.requestJson<GatewayReplyResponse>("POST", "/v1/replies", "reply", req, {
      signal,
      timeoutMs: DEFAULT_REPLY_TIMEOUT_MS,
    });
    return res.result;
  }

  /**
   * 订阅网关 SSE 事件流（从 `after` 游标之后开始补拉并持续实时推送）。
   * 严格按顺序逐条 `await onEvent(ev)`（背压暂停流读取），确保下游处理失败不会跳过后续游标。
   */
  streamEvents(opts: StreamEventsOptions): Promise<void> {
    const after = Math.max(0, Math.floor(opts.after));
    const idleMs = opts.idleTimeoutMs ?? DEFAULT_SSE_IDLE_MS;

    return new Promise<void>((resolve, reject) => {
      if (opts.signal.aborted) return resolve();
      let token: string;
      try {
        token = this.tokenFor("read");
      } catch (err) {
        return reject(err);
      }
      const reqOpts = this.buildRequestOptions("GET", `/v1/stream?after=${after}`, {
        authorization: `Bearer ${token}`,
        accept: "text/event-stream",
        "cache-control": "no-cache",
      });
      let settled = false;
      let idleTimer: NodeJS.Timeout | undefined;
      let activeRes: http.IncomingMessage | undefined;

      const finish = (err?: unknown) => {
        if (settled) return;
        settled = true;
        if (idleTimer) clearTimeout(idleTimer);
        opts.signal.removeEventListener("abort", onAbort);
        activeRes?.destroy();
        req.destroy();
        if (err && !opts.signal.aborted) reject(err);
        else resolve();
      };

      const clearIdle = () => {
        if (idleTimer) {
          clearTimeout(idleTimer);
          idleTimer = undefined;
        }
      };

      const resetIdle = () => {
        clearIdle();
        idleTimer = setTimeout(() => {
          finish(new GatewayHttpError(504, "stream_idle_timeout", `网关 SSE 连接超过 ${idleMs}ms 无心跳或数据`, false));
        }, idleMs);
        idleTimer.unref?.();
      };

      const onAbort = () => finish();
      opts.signal.addEventListener("abort", onAbort, { once: true });

      const req = http.request(reqOpts, (res) => {
        activeRes = res;
        const status = res.statusCode ?? 502;
        if (status !== 200) {
          const chunks: Buffer[] = [];
          let total = 0;
          res.on("data", (c: Buffer) => {
            total += c.length;
            if (total > MAX_RESPONSE_BYTES) {
              finish(new GatewayHttpError(502, "response_too_large", "网关错误响应体超过上限", false));
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let errBody: Partial<GatewayErrorBody> | undefined;
            try {
              errBody = text ? (JSON.parse(text) as Partial<GatewayErrorBody>) : undefined;
            } catch {
              errBody = undefined;
            }
            const code = typeof errBody?.code === "string" ? errBody.code : `http_${status}`;
            const message = typeof errBody?.error === "string" ? errBody.error : text.slice(0, 300) || `HTTP ${status}`;
            const permanent = typeof errBody?.permanent === "boolean" ? errBody.permanent : status === 401 || status === 403;
            finish(new GatewayHttpError(status, code, message, permanent, errBody?.status));
          });
          res.on("error", (err) => finish(err));
          return;
        }

        resetIdle();
        res.setEncoding("utf8");
        let buf = "";
        let eventName = "message";
        let dataLines: string[] = [];
        let ended = false;
        let pumping = false;
        const frames: Array<{ event: string; data: string }> = [];

        const pump = async () => {
          if (pumping) return;
          pumping = true;
          // 暂停读取期间同时暂停空闲检测，防止大批量补拉或慢 onEvent 消费被误判为半开连接超时
          clearIdle();
          res.pause();
          try {
            while (frames.length > 0 && !settled) {
              const f = frames.shift()!;
              if (!f.data) continue;
              const parsed = JSON.parse(f.data) as unknown;
              if (f.event === "event") {
                await opts.onEvent(parsed as GatewayEvent);
              } else if (f.event === "status") {
                opts.onStatus?.(parsed as GatewayStatus);
              } else if (f.event === "gap") {
                opts.onGap?.(parsed as GatewayGapEvent);
              }
            }
          } catch (err) {
            finish(err);
            return;
          } finally {
            pumping = false;
          }
          if (!settled) {
            if (ended) finish(new GatewayHttpError(503, "stream_closed", "网关 SSE 连接已关闭", false));
            else {
              resetIdle();
              res.resume();
            }
          }
        };

        res.on("data", (chunk: string) => {
          if (settled) return;
          resetIdle();
          buf += chunk;
          let nl = buf.indexOf("\n");
          while (nl !== -1) {
            const line = buf.slice(0, nl).replace(/\r$/, "");
            buf = buf.slice(nl + 1);
            if (line === "") {
              if (dataLines.length > 0) {
                frames.push({ event: eventName, data: dataLines.join("\n") });
              }
              eventName = "message";
              dataLines = [];
            } else if (line.startsWith(":")) {
              // heartbeat comment
            } else if (line.startsWith("event:")) {
              eventName = line.slice(6).trim();
            } else if (line.startsWith("data:")) {
              dataLines.push(line[5] === " " ? line.slice(6) : line.slice(5));
            }
            nl = buf.indexOf("\n");
          }
          if (frames.length > 0) void pump();
        });

        res.on("end", () => {
          ended = true;
          if (!pumping && frames.length === 0) {
            finish(new GatewayHttpError(503, "stream_closed", "网关 SSE 连接已关闭", false));
          }
        });
        res.on("error", (err) => finish(err));
      });

      resetIdle();
      req.on("error", (err) => finish(err));
      req.end();
    });
  }
}
