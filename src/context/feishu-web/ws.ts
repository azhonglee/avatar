import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import type net from "node:net";
import { WebHttpError } from "./http.ts";
import { MAX_WIRE_BYTES } from "./proto.ts";

/**
 * Zero-dependency RFC 6455 WebSocket client built directly on Node's http/https upgrade API.
 * Supports custom handshake headers (Origin, User-Agent), strict max frame bounds,
 * bounded receive queue with TCP socket pause/resume backpressure, automatic Pong replies,
 * and fragmented binary/text frames.
 */

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const DEFAULT_MAX_QUEUE_BYTES = 16 * 1024 * 1024; // 16 MiB aggregate cap

const OP_CONT = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

export interface WebSocketFrame {
  kind: "binary" | "text";
  data: Buffer;
}

export interface DialWebSocketOptions {
  headers?: Record<string, string>;
  handshakeTimeoutMs?: number;
  maxFrameBytes?: number;
  maxQueueBytes?: number;
  signal?: AbortSignal;
}

interface Waiter {
  resolve: (frame: WebSocketFrame) => void;
  reject: (err: Error) => void;
}

function buildClientFrame(opcode: number, payload: Uint8Array): Buffer {
  const len = payload.byteLength;
  const mask = crypto.randomBytes(4);
  let headerLen = 2 + 4;
  if (len >= 126 && len < 65536) headerLen += 2;
  else if (len >= 65536) headerLen += 8;

  const out = Buffer.allocUnsafe(headerLen + len);
  out[0] = 0x80 | (opcode & 0x0f);
  let offset = 2;
  if (len < 126) {
    out[1] = 0x80 | len;
  } else if (len < 65536) {
    out[1] = 0x80 | 126;
    out.writeUInt16BE(len, 2);
    offset = 4;
  } else {
    out[1] = 0x80 | 127;
    out.writeBigUInt64BE(BigInt(len), 2);
    offset = 10;
  }
  mask.copy(out, offset);
  offset += 4;
  for (let i = 0; i < len; i++) {
    out[offset + i] = payload[i] ^ mask[i & 3];
  }
  return out;
}

export class BinaryWebSocket {
  private readonly socket: net.Socket;
  private readonly maxFrameBytes: number;
  private readonly maxQueueBytes: number;
  private buf: Buffer = Buffer.alloc(0);
  private fragOpcode: number | null = null;
  private fragChunks: Buffer[] = [];
  private fragBytes = 0;
  private readonly queue: WebSocketFrame[] = [];
  private queuedBytes = 0;
  private paused = false;
  private readonly waiters: Waiter[] = [];
  private closedErr: Error | null = null;

  constructor(socket: net.Socket, initialHead: Buffer, maxFrameBytes = MAX_WIRE_BYTES, maxQueueBytes = DEFAULT_MAX_QUEUE_BYTES) {
    this.socket = socket;
    this.maxFrameBytes = maxFrameBytes;
    this.maxQueueBytes = Math.max(maxQueueBytes, 1024);

    socket.on("data", (chunk: Buffer) => this.onData(chunk));
    socket.on("error", (err) => this.fail(err));
    socket.on("close", () => this.fail(new Error("WebSocket 连接已关闭")));
    socket.on("end", () => this.fail(new Error("WebSocket 对端已断开")));

    if (initialHead.length > 0) this.onData(initialHead);
  }

  static dial(address: string, opts: DialWebSocketOptions = {}): Promise<BinaryWebSocket> {
    const handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 20_000;
    const maxFrameBytes = opts.maxFrameBytes ?? MAX_WIRE_BYTES;
    const maxQueueBytes = opts.maxQueueBytes ?? DEFAULT_MAX_QUEUE_BYTES;
    const parsed = new URL(address);
    const isTls = parsed.protocol === "wss:" || parsed.protocol === "https:";
    const mod = isTls ? https : http;
    const httpUrl = new URL(address);
    httpUrl.protocol = isTls ? "https:" : "http:";

    const key = crypto.randomBytes(16).toString("base64");
    const expectedAccept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");

    return new Promise((resolve, reject) => {
      if (opts.signal?.aborted) {
        reject(new Error("WebSocket 握手已取消"));
        return;
      }
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
        fn();
      };

      const req = mod.request(httpUrl, {
        method: "GET",
        headers: {
          ...(opts.headers ?? {}),
          Connection: "Upgrade",
          Upgrade: "websocket",
          "Sec-WebSocket-Version": "13",
          "Sec-WebSocket-Key": key,
        },
      });

      const onAbort = () => {
        req.destroy();
        finish(() => reject(new Error("WebSocket 握手已取消")));
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      const timer = setTimeout(() => {
        req.destroy();
        finish(() => reject(new Error(`WebSocket 握手超时 (${handshakeTimeoutMs}ms)`)));
      }, handshakeTimeoutMs);

      req.on("upgrade", (res, socket, head) => {
        const accept = String(res.headers["sec-websocket-accept"] ?? "");
        if (res.statusCode !== 101 || accept !== expectedAccept) {
          socket.destroy();
          finish(() => reject(new WebHttpError("http_error", `WebSocket 握手校验失败 (status=${res.statusCode})`, res.statusCode)));
          return;
        }
        finish(() => resolve(new BinaryWebSocket(socket, head, maxFrameBytes, maxQueueBytes)));
      });

      req.on("response", (res) => {
        res.resume();
        const status = res.statusCode ?? 0;
        if (status === 401 || status === 403) {
          finish(() => reject(new WebHttpError("credential_denied", `WebSocket 握手鉴权被拒绝 (HTTP ${status})`, status)));
          return;
        }
        finish(() => reject(new WebHttpError("http_error", `WebSocket 握手被拒绝 (HTTP ${status})`, status)));
      });

      req.on("error", (err) => {
        finish(() => reject(err));
      });

      req.end();
    });
  }

  private onData(chunk: Buffer): void {
    if (this.closedErr) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;

    while (this.buf.length >= 2 && !this.closedErr) {
      const b0 = this.buf[0];
      const b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0;
      const rsv = b0 & 0x70;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;

      if (rsv !== 0) {
        this.protocolError("WebSocket 帧包含未协商的保留位");
        return;
      }

      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        const bigLen = this.buf.readBigUInt64BE(2);
        if (bigLen > BigInt(this.maxFrameBytes)) {
          this.protocolError("WebSocket 帧超过最大字节限制");
          return;
        }
        len = Number(bigLen);
        offset = 10;
      }

      if (len > this.maxFrameBytes) {
        this.protocolError("WebSocket 帧超过最大字节限制");
        return;
      }

      const maskLen = masked ? 4 : 0;
      if (this.buf.length < offset + maskLen + len) return;

      let payload = Buffer.from(this.buf.subarray(offset + maskLen, offset + maskLen + len));
      if (masked) {
        const mask = this.buf.subarray(offset, offset + 4);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      }
      this.buf = this.buf.subarray(offset + maskLen + len);

      this.handleFrame(fin, opcode, payload);
    }
  }

  private handleFrame(fin: boolean, opcode: number, payload: Buffer): void {
    if (opcode === OP_PING) {
      this.sendRaw(OP_PONG, payload);
      return;
    }
    if (opcode === OP_PONG) {
      return;
    }
    if (opcode === OP_CLOSE) {
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
      this.sendRaw(OP_CLOSE, payload.subarray(0, 2));
      this.socket.end();
      this.fail(new Error(`WebSocket 对端关闭 (code=${code})`));
      return;
    }

    if (opcode === OP_BINARY || opcode === OP_TEXT) {
      if (this.fragOpcode !== null) {
        this.protocolError("WebSocket 收到未完成分片的新数据帧");
        return;
      }
      if (fin) {
        this.enqueue({ kind: opcode === OP_BINARY ? "binary" : "text", data: payload });
      } else {
        this.fragOpcode = opcode;
        this.fragChunks = [payload];
        this.fragBytes = payload.length;
      }
      return;
    }

    if (opcode === OP_CONT) {
      if (this.fragOpcode === null) {
        this.protocolError("WebSocket 收到意外的续帧");
        return;
      }
      this.fragBytes += payload.length;
      if (this.fragBytes > this.maxFrameBytes) {
        this.protocolError("WebSocket 分片消息超过最大字节限制");
        return;
      }
      this.fragChunks.push(payload);
      if (fin) {
        const op = this.fragOpcode;
        const full = Buffer.concat(this.fragChunks, this.fragBytes);
        this.fragOpcode = null;
        this.fragChunks = [];
        this.fragBytes = 0;
        this.enqueue({ kind: op === OP_BINARY ? "binary" : "text", data: full });
      }
      return;
    }

    this.protocolError(`未知 WebSocket opcode: ${opcode}`);
  }

  private enqueue(frame: WebSocketFrame): void {
    const w = this.waiters.shift();
    if (w) {
      w.resolve(frame);
      return;
    }
    this.queuedBytes += frame.data.length;
    if (this.queuedBytes > this.maxQueueBytes) {
      this.protocolError(`WebSocket 接收队列超过内存上限 (${this.maxQueueBytes} bytes)`);
      return;
    }
    this.queue.push(frame);
    if (!this.paused && this.queuedBytes >= Math.floor(this.maxQueueBytes / 2)) {
      this.paused = true;
      this.socket.pause();
    }
  }

  private protocolError(message: string): void {
    this.fail(new Error(message));
    this.close();
  }

  private fail(err: Error): void {
    if (this.closedErr) return;
    this.closedErr = err;
    while (this.waiters.length) {
      this.waiters.shift()!.reject(err);
    }
  }

  private sendRaw(opcode: number, payload: Uint8Array): void {
    if (this.closedErr || this.socket.destroyed) return;
    try {
      this.socket.write(buildClientFrame(opcode, payload));
    } catch {
      // socket close/error listener handles cleanup
    }
  }

  writeBinary(data: Uint8Array, timeoutMs = 20_000, signal?: AbortSignal): Promise<void> {
    if (this.closedErr) return Promise.reject(this.closedErr);
    if (signal?.aborted) return Promise.reject(new Error("WebSocket 写入已取消"));
    const frame = buildClientFrame(OP_BINARY, data);
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
      this.socket.write(frame, (err) => {
        if (err) done(() => reject(err));
        else done(() => resolve());
      });
    });
  }

  read(timeoutMs: number, signal?: AbortSignal): Promise<WebSocketFrame> {
    if (this.queue.length > 0) {
      const frame = this.queue.shift()!;
      this.queuedBytes = Math.max(0, this.queuedBytes - frame.data.length);
      if (this.paused && this.queuedBytes <= Math.floor(this.maxQueueBytes / 4)) {
        this.paused = false;
        this.socket.resume();
      }
      return Promise.resolve(frame);
    }
    if (this.closedErr) return Promise.reject(this.closedErr);
    if (signal?.aborted) return Promise.reject(new Error("WebSocket 读取已取消"));
    return new Promise((resolve, reject) => {
      const waiter: Waiter = {
        resolve: (f) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          resolve(f);
        },
        reject: (err) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          reject(err);
        },
      };
      const remove = () => {
        const idx = this.waiters.indexOf(waiter);
        if (idx >= 0) this.waiters.splice(idx, 1);
      };
      const onAbort = () => {
        remove();
        waiter.reject(new Error("WebSocket 读取已取消"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => {
        remove();
        this.close();
        waiter.reject(new Error(`WebSocket 读空闲超时 (${timeoutMs}ms)`));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  close(): void {
    if (!this.socket.destroyed) {
      try {
        const closePayload = Buffer.alloc(2);
        closePayload.writeUInt16BE(1000, 0);
        this.socket.write(buildClientFrame(OP_CLOSE, closePayload));
      } catch {
        // ignore write errors during close
      }
      this.socket.destroy();
    }
    this.fail(new Error("WebSocket 已主动关闭"));
  }
}
