import type { ApiError, CommandArgs, CommandName, CommandResult } from "./types.ts";

/** 请求失败：status 为 HTTP 状态码（网络错误为 0），code / message 来自后端的 ApiError。 */
export class ApiRequestError extends Error {
  status: number;
  code: ApiError["error"]["code"] | "network";
  body: unknown;
  constructor(status: number, code: ApiRequestError["code"], message: string, body?: unknown) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
  get unauthorized(): boolean {
    return this.status === 401;
  }
  /** 后端模块未启用（501） */
  get unavailable(): boolean {
    return this.status === 501;
  }
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

/** 任何请求返回 401 时通知（App 据此切到“需要登录”界面）。 */
export function onUnauthorized(fn: Listener): () => void {
  unauthorizedListeners.add(fn);
  return () => unauthorizedListeners.delete(fn);
}

const FALLBACK: Record<number, string> = {
  400: "请求参数有误",
  401: "需要登录",
  403: "没有权限",
  404: "没有找到",
  409: "当前状态不允许这个操作",
  413: "请求体过大",
  415: "请求格式不正确",
  500: "服务出错了",
  501: "该功能未启用",
  502: "控制台服务不可达",
  503: "服务暂不可用",
  504: "控制台服务响应超时",
};

function isApiError(v: unknown): v is ApiError {
  return !!v && typeof v === "object" && "error" in v && !!(v as ApiError).error && typeof (v as ApiError).error.message === "string";
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT";
  body?: unknown;
  signal?: AbortSignal;
  /** 这些状态码不抛错，直接返回 body（例如设置保存的 400 带字段错误） */
  accept?: number[];
}

export async function request<T>(path: string, o: RequestOptions = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: o.method ?? "GET",
      credentials: "same-origin",
      headers: o.body !== undefined ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
      signal: o.signal,
    });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw e;
    throw new ApiRequestError(0, "network", "无法连接控制台服务：请确认常驻进程在运行、端口转发正常");
  }
  const body = await parseBody(res);
  if (res.ok || o.accept?.includes(res.status)) return body as T;
  const code: ApiRequestError["code"] = isApiError(body)
    ? body.error.code
    : res.status === 401
      ? "unauthorized"
      : res.status === 501
        ? "unavailable"
        : "internal";
  const message = isApiError(body) ? body.error.message : (FALLBACK[res.status] ?? `请求失败（HTTP ${res.status}）`);
  const err = new ApiRequestError(res.status, code, message, body);
  if (res.status === 401) unauthorizedListeners.forEach((f) => f());
  throw err;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  command: <N extends CommandName>(name: N, args: CommandArgs[N]) =>
    request<CommandResult>(`/api/commands/${encodeURIComponent(name)}`, { method: "POST", body: { args } }),
  logout: () => request<{ ok: boolean }>("/logout", { method: "POST", body: {} }),
};

export function errorMessage(e: unknown): string {
  if (e instanceof ApiRequestError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}
