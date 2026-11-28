import WebSocket, { type RawData } from "ws";
import { WebHttpError } from "./http.ts";
import { MAX_WIRE_BYTES } from "./proto.ts";

/**
 * Pull-based binary WebSocket wrapper backed by the `ws` library.
 * Provides custom handshake headers (Origin, User-Agent), 401/403 credential error classification,
 * strict payload ceiling, bounded receive queue with native TCP backpressure (`pause`/`resume`),
 * automatic Ping/Pong handling with read-idle timer reset, and AbortSignal support.
 */

const DEFAULT_MAX_QUEUE_BYTES = 16 * 1024 * 1024; // 16 MiB aggregate cap
const DEFAULT_MAX_QUEUE_FRAMES = 2048;

export interface WebSocketFrame {
  kind: "binary" | "text";
  data: Buffer;
}

export interface DialWebSocketOptions {
  headers?: Record<string, string>;
  handshakeTimeoutMs?: number;
  maxFrameBytes?: number;
  maxQueueBytes?: number;
  maxQueueFrames?: number;
  signal?: AbortSignal;
}

interface Waiter {
  resolve: (frame: WebSocketFrame) => void;
  reject: (err: Error) => void;
  resetIdle: () => void;
}

function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return Buffer.from(data);
}

export class BinaryWebSocket {
  private readonly ws: WebSocket;
  private readonly maxQueueBytes: number;
  private readonly maxQueueFrames: number;
  private readonly queue: WebSocketFrame[] = [];
  private queuedBytes = 0;
  private paused = false;
  private readonly waiters: Waiter[] = [];
  private closedErr: Error | null = null;

  private constructor(ws: WebSocket, maxQueueBytes: number, maxQueueFrames: number) {
    this.ws = ws;
    this.maxQueueBytes = Math.max(maxQueueBytes, 1024);
    this.maxQueueFrames = Math.max(maxQueueFrames, 16);

    ws.on("ping", () => this.noteInboundActivity());
    ws.on("pong", () => this.noteInboundActivity());
    ws.on("message", (raw: RawData, isBinary: boolean) => {
      if (this.closedErr) return;
      this.noteInboundActivity();
      this.enqueue({ kind: isBinary ? "binary" : "text", data: rawDataToBuffer(raw) });
    });
    ws.on("error", (err) => this.fail(err));
    ws.on("close", (code) => {
      this.fail(new Error(`WebSocket 对端关闭 (code=${code})`));
    });
  }

  static dial(address: string, opts: DialWebSocketOptions = {}): Promise<BinaryWebSocket> {
    const handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 20_000;
    const maxFrameBytes = opts.maxFrameBytes ?? MAX_WIRE_BYTES;
    const maxQueueBytes = opts.maxQueueBytes ?? DEFAULT_MAX_QUEUE_BYTES;
    const maxQueueFrames = opts.maxQueueFrames ?? DEFAULT_MAX_QUEUE_FRAMES;

    return new Promise((resolve, reject) => {
      if (opts.signal?.aborted) {
        reject(new Error("WebSocket 握手已取消"));
        return;
      }

      let settled = false;
      const ws = new WebSocket(address, {
        headers: opts.headers,
        handshakeTimeout: handshakeTimeoutMs,
        maxPayload: maxFrameBytes,
        perMessageDeflate: false,
      });

      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        opts.signal?.removeEventListener("abort", onAbort);
        ws.off("open", onOpen);
        ws.off("unexpected-response", onUnexpected);
        ws.off("error", onError);
        ws.off("close", onEarlyClose);
        fn();
      };

      const safeTerminate = () => {
        ws.on("error", () => undefined);
        try {
          ws.terminate();
        } catch {
          // ignore terminate errors during handshake abort/rejection
        }
      };

      const onAbort = () => {
        finish(() => reject(new Error("WebSocket 握手已取消")));
        safeTerminate();
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      const onOpen = () => {
        finish(() => resolve(new BinaryWebSocket(ws, maxQueueBytes, maxQueueFrames)));
      };

      const onUnexpected = (_req: unknown, res: { statusCode?: number; resume: () => void }) => {
        res.resume();
        const status = res.statusCode ?? 0;
        if (status === 401 || status === 403) {
          finish(() => reject(new WebHttpError("credential_denied", `WebSocket 握手鉴权被拒绝 (HTTP ${status})`, status)));
        } else {
          finish(() => reject(new WebHttpError("http_error", `WebSocket 握手被拒绝 (HTTP ${status})`, status)));
        }
        safeTerminate();
      };

      const onError = (err: Error) => {
        finish(() => reject(err));
        safeTerminate();
      };

      const onEarlyClose = (code: number) => {
        finish(() => reject(new Error(`WebSocket 握手期间连接关闭 (code=${code})`)));
      };

      ws.on("open", onOpen);
      ws.on("unexpected-response", onUnexpected);
      ws.on("error", onError);
      ws.on("close", onEarlyClose);
    });
  }

  private noteInboundActivity(): void {
    for (const w of this.waiters) {
      w.resetIdle();
    }
  }

  private enqueue(frame: WebSocketFrame): void {
    const w = this.waiters.shift();
    if (w) {
      w.resolve(frame);
      return;
    }
    this.queuedBytes += frame.data.length;
    if (this.queuedBytes > this.maxQueueBytes) {
      this.fail(new Error(`WebSocket 接收队列超过内存上限 (${this.maxQueueBytes} bytes)`));
      this.close();
      return;
    }
    if (this.queue.length >= this.maxQueueFrames) {
      this.fail(new Error(`WebSocket 接收队列帧数超过上限 (${this.maxQueueFrames})`));
      this.close();
      return;
    }
    this.queue.push(frame);
    if (!this.paused && (this.queuedBytes >= Math.floor(this.maxQueueBytes / 2) || this.queue.length >= Math.floor(this.maxQueueFrames / 2))) {
      this.paused = true;
      this.ws.pause();
    }
  }

  private fail(err: Error): void {
    if (this.closedErr) return;
    this.closedErr = err;
    while (this.waiters.length) {
      this.waiters.shift()!.reject(err);
    }
  }

  writeBinary(data: Uint8Array, timeoutMs = 20_000, signal?: AbortSignal): Promise<void> {
    if (this.closedErr) return Promise.reject(this.closedErr);
    if (signal?.aborted) return Promise.reject(new Error("WebSocket 写入已取消"));
    if (this.ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error("WebSocket 连接未打开"));

    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        fn();
      };
      const onAbort = () => done(() => reject(new Error("WebSocket 写入已取消")));
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => {
        this.close();
        done(() => reject(new Error(`WebSocket 写入超时 (${timeoutMs}ms)`)));
      }, timeoutMs);
      this.ws.send(data, { binary: true }, (err) => {
        if (err) done(() => reject(err));
        else done(() => resolve());
      });
    });
  }

  read(timeoutMs: number, signal?: AbortSignal): Promise<WebSocketFrame> {
    if (this.queue.length > 0) {
      const frame = this.queue.shift()!;
      this.queuedBytes = Math.max(0, this.queuedBytes - frame.data.length);
      if (this.paused && this.queuedBytes <= Math.floor(this.maxQueueBytes / 4) && this.queue.length <= Math.floor(this.maxQueueFrames / 4)) {
        this.paused = false;
        this.ws.resume();
      }
      return Promise.resolve(frame);
    }
    if (this.closedErr) return Promise.reject(this.closedErr);
    if (signal?.aborted) return Promise.reject(new Error("WebSocket 读取已取消"));

    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const clearIdle = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
      };
      const remove = () => {
        const idx = this.waiters.indexOf(waiter);
        if (idx >= 0) this.waiters.splice(idx, 1);
      };
      const armIdle = () => {
        clearIdle();
        timer = setTimeout(() => {
          remove();
          this.close();
          waiter.reject(new Error(`WebSocket 读空闲超时 (${timeoutMs}ms)`));
        }, timeoutMs);
      };
      const waiter: Waiter = {
        resolve: (f) => {
          clearIdle();
          signal?.removeEventListener("abort", onAbort);
          resolve(f);
        },
        reject: (err) => {
          clearIdle();
          signal?.removeEventListener("abort", onAbort);
          reject(err);
        },
        resetIdle: () => {
          if (this.closedErr) return;
          armIdle();
        },
      };
      const onAbort = () => {
        remove();
        waiter.reject(new Error("WebSocket 读取已取消"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      armIdle();
      this.waiters.push(waiter);
    });
  }

  close(): void {
    this.fail(new Error("WebSocket 已主动关闭"));
    if (this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.close(1000);
      } catch {
        // ignore close frame errors
      }
    }
    try {
      this.ws.terminate();
    } catch {
      // ignore terminate errors
    }
  }
}
