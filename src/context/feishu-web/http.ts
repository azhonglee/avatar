import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import { isAllowedFeishuHost, RecordingCookieJar } from "./cookies.ts";
import { MAX_WIRE_BYTES } from "./proto.ts";

/**
 * Bounded HTTPS/HTTP transport with manual redirect boundary enforcement and recording cookie jar.
 * Every hop (including 3xx redirects) validates host allowlist, records rotated Set-Cookie headers,
 * and strips sensitive auth-flow headers across host changes.
 */

export const WEB_USER_AGENT =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

export const DEFAULT_HTTP_TIMEOUT_MS = 20_000;
export const MAX_REDIRECTS = 30;

const CROSS_HOST_STRIP_HEADERS = new Set(["x-flow-key", "x-web-id", "x-proxy-unit", "x-csrf-token"]);

export interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  url: string;
  /** 本次请求（含重定向跳）是否收到过 Set-Cookie 响应头 */
  cookiesUpdated?: boolean;
}

export interface HttpRequestOptions {
  method: "GET" | "POST";
  url: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
  timeoutMs?: number;
  maxBytes?: number;
  signal?: AbortSignal;
  /** Default false in production (HTTPS only); tests can set true for local http:// mock servers. */
  allowInsecureHttp?: boolean;
  extraAllowedHosts?: Iterable<string>;
}

export class WebHttpError extends Error {
  readonly code: "credential_denied" | "http_error" | "transport" | "redirect_rejected" | "aborted";
  readonly status?: number;

  constructor(
    code: WebHttpError["code"],
    message: string,
    status?: number,
    cause?: unknown,
  ) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "WebHttpError";
    this.code = code;
    this.status = status;
  }
}

export function getHeader(headers: Record<string, string | string[] | undefined>, name: string): string {
  const v = headers[name.toLowerCase()];
  if (Array.isArray(v)) return v[0] ?? "";
  return v ?? "";
}

function validateTarget(target: URL, allowInsecureHttp: boolean, extraAllowed?: Iterable<string>): void {
  const protocolOk = target.protocol === "https:" || (allowInsecureHttp && target.protocol === "http:");
  if (!protocolOk || !isAllowedFeishuHost(target.hostname, extraAllowed)) {
    throw new WebHttpError("redirect_rejected", `拒绝访问非允许的目标地址：${target.origin}`);
  }
}

function singleRequest(
  target: URL,
  method: "GET" | "POST",
  headers: Record<string, string>,
  body: Buffer | undefined,
  timeoutMs: number,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new WebHttpError("aborted", "请求已取消"));
      return;
    }
    const mod = target.protocol === "https:" ? https : http;
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      fn();
    };

    const req = mod.request(
      target,
      {
        method,
        headers: {
          ...headers,
          ...(body ? { "Content-Length": String(body.length) } : {}),
        },
      },
      (res) => {
        const encoding = String(res.headers["content-encoding"] ?? "").toLowerCase();
        const emptyBody = res.statusCode === 204 || res.statusCode === 304 || res.headers["content-length"] === "0";
        let stream: NodeJS.ReadableStream = res;
        if (!emptyBody && encoding === "gzip") {
          const gz = zlib.createGunzip();
          res.pipe(gz);
          stream = gz;
        } else if (!emptyBody && encoding === "deflate") {
          const inf = zlib.createInflate();
          res.pipe(inf);
          stream = inf;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        stream.on("data", (chunk: Buffer | string) => {
          const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
          total += buf.length;
          if (total > maxBytes) {
            req.destroy();
            done(() => reject(new WebHttpError("http_error", `响应体超过上限 (${maxBytes} bytes)`)));
            return;
          }
          chunks.push(buf);
        });
        stream.on("error", (err) => {
          done(() => reject(new WebHttpError("transport", `读取响应失败：${err.message}`, undefined, err)));
        });
        stream.on("end", () => {
          done(() =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks, total),
              url: target.toString(),
            }),
          );
        });
      },
    );

    const onAbort = () => {
      req.destroy();
      done(() => reject(new WebHttpError("aborted", "请求已取消")));
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    const timer = setTimeout(() => {
      req.destroy();
      done(() => reject(new WebHttpError("transport", `请求超时 (${timeoutMs}ms)`)));
    }, timeoutMs);

    req.on("error", (err) => {
      done(() => reject(new WebHttpError("transport", `网络请求失败：${err.message}`, undefined, err)));
    });

    if (body && body.length > 0) req.write(body);
    req.end();
  });
}

/** Execute a bounded HTTP request following Feishu-only redirects while recording rotated cookies. */
export async function fetchWithJar(jar: RecordingCookieJar, opts: HttpRequestOptions): Promise<HttpResponse> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? MAX_WIRE_BYTES;
  const allowInsecureHttp = !!opts.allowInsecureHttp;

  let currentUrl = new URL(opts.url);
  let method: "GET" | "POST" = opts.method;
  let body = opts.body === undefined ? undefined : Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, "utf8");
  let headers: Record<string, string> = { ...(opts.headers ?? {}) };
  let cookiesUpdated = false;
  const hadCsrfHeader = Object.keys(headers).some((k) => k.toLowerCase() === "x-csrf-token");

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    validateTarget(currentUrl, allowInsecureHttp, opts.extraAllowedHosts);
    const reqHeaders: Record<string, string> = { ...headers };
    const cookie = jar.cookieHeader(currentUrl);
    if (cookie) reqHeaders["Cookie"] = cookie;
    else delete reqHeaders["Cookie"];

    const reqSnap = jar.snapshot();
    const res = await singleRequest(currentUrl, method, reqHeaders, body, timeoutMs, maxBytes, opts.signal);
    if (res.headers["set-cookie"]) {
      if (jar.setFromHeaders(currentUrl, res.headers["set-cookie"], Date.now(), reqSnap)) {
        cookiesUpdated = true;
      }
    }

    const isRedirect = res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308;
    const loc = getHeader(res.headers, "location");
    if (!isRedirect || !loc) return { ...res, cookiesUpdated };

    if (hop >= MAX_REDIRECTS) {
      throw new WebHttpError("redirect_rejected", "个人 Web 重定向次数超过上限");
    }
    const nextUrl = new URL(loc, currentUrl);
    validateTarget(nextUrl, allowInsecureHttp, opts.extraAllowedHosts);

    if (nextUrl.host !== currentUrl.host) {
      const cleaned: Record<string, string> = {};
      for (const [k, v] of Object.entries(headers)) {
        if (!CROSS_HOST_STRIP_HEADERS.has(k.toLowerCase())) cleaned[k] = v;
      }
      if (hadCsrfHeader) {
        const destCsrf = jar.cookieValue(nextUrl, "swp_csrf_token");
        if (destCsrf) cleaned["x-csrf-token"] = destCsrf;
      }
      headers = cleaned;
    }

    if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
      method = "GET";
      body = undefined;
      for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === "content-type" || k.toLowerCase() === "content-length") delete headers[k];
      }
    }
    currentUrl = nextUrl;
  }

  throw new WebHttpError("redirect_rejected", "个人 Web 重定向次数超过上限");
}
