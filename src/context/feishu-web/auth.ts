import crypto from "node:crypto";
import { hasSessionCookie, RecordingCookieJar, type CookieRecord, type WebLogin } from "./cookies.ts";
import { fetchWithJar, getHeader, WEB_USER_AGENT, WebHttpError } from "./http.ts";

/**
 * Feishu personal Web QR login flow:
 *   1. Bootstrap web device ID (`window.passport_web_did`) from Messenger page
 *   2. Initialize QR challenge (`/accounts/qrlogin/init`)
 *   3. Poll scan/approval (`/accounts/qrlogin/polling`) every 2s up to 5m
 *   4. Verify live profile (`/accounts/web/user?app_id=12`) and Messenger metadata (`appKey`)
 */

export interface WebEndpoints {
  messengerUrl: string;
  qrInitUrl: string;
  qrPollUrl: string;
  qrRedirectUri: string;
  profileUrl: string;
  gatewayUrl: string;
  ticketUrl: string;
  websocketUrl: string;
  accountsOrigin: string;
  accountsReferer: string;
  messengerOrigin: string;
  allowInsecureHttp?: boolean;
  extraAllowedHosts?: string[];
}

export const DEFAULT_ENDPOINTS: WebEndpoints = {
  messengerUrl: "https://open-dev.feishu.cn/messenger/",
  qrInitUrl: "https://accounts.feishu.cn/accounts/qrlogin/init",
  qrPollUrl: "https://accounts.feishu.cn/accounts/qrlogin/polling",
  qrRedirectUri: "https://open-dev.feishu.cn/next/messenger",
  profileUrl: "https://internal-api-lark-api.feishu.cn/accounts/web/user?app_id=12",
  gatewayUrl: "https://internal-api-lark-api.feishu.cn/im/gateway/",
  ticketUrl: "https://login.feishu.cn/suite/passport/frontier_ticket/",
  websocketUrl: "wss://msg-frontier.feishu.cn/ws/v2",
  accountsOrigin: "https://accounts.feishu.cn",
  accountsReferer: "https://accounts.feishu.cn/accounts/page/login?app_id=1",
  messengerOrigin: "https://open-dev.feishu.cn",
};

export const QR_LOGIN_TIMEOUT_MS = 5 * 60_000;
export const QR_POLL_INTERVAL_MS = 2_000;

const AUTH_WEB_ID_RE = /window\.passport_web_did\s*=\s*["']([^"']+)["']/;
export const APP_KEY_RE = /appKey["']?\s*:\s*["']([^"']+)/;

export interface LoginChallenge {
  webId: string;
  proxyUnit: string;
  qrCode: string;
  flowKey: string;
  cookies: CookieRecord[];
  createdAtMs: number;
  expiresAtMs: number;
  approvedOwnerId?: string;
}

export type LoginPollStatus = "waiting" | "scanned" | "approved";

export interface NativeProfile {
  id: string;
  name: string;
  openId?: string;
}

const LOSSLESS_ID_KEYS = new Set(["id", "front_user_id"]);

/**
 * 解析 JSON 时无损保留 64 位原生账号 ID（如 7123456789012345678），避免 IEEE-754 double 舍入导致 owner 错配。
 * 优先使用 Node 22+ 原生 JSON.parse reviver 的 context.source；若运行环境不支持则拒绝非安全整数。
 */
export function parseJsonPreserveNativeIds<T>(text: string): T {
  const parseWithCtx = JSON.parse as (
    src: string,
    reviver: (key: string, value: unknown, context?: { source?: string }) => unknown,
  ) => unknown;
  return parseWithCtx(text, (key, value, ctx) => {
    if (LOSSLESS_ID_KEYS.has(key) && typeof value === "number" && ctx?.source && /^-?\d+$/.test(ctx.source)) {
      return ctx.source;
    }
    return value;
  }) as T;
}

export function normalizeNativeId(raw: unknown): string {
  if (typeof raw === "string") return raw.trim();
  if (typeof raw === "number") {
    if (!Number.isSafeInteger(raw)) {
      throw new WebHttpError("http_error", "飞书原生账号 ID 超出安全整数范围且未能无损解析");
    }
    return String(raw);
  }
  return "";
}

export function resolveEndpoints(overrides?: Partial<WebEndpoints>): WebEndpoints {
  return { ...DEFAULT_ENDPOINTS, ...(overrides ?? {}) };
}

export function authHeaders(
  endpoints: WebEndpoints,
  challenge: Pick<LoginChallenge, "flowKey" | "webId" | "proxyUnit">,
): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": WEB_USER_AGENT,
    "X-App-Id": "1",
    "X-Api-Version": "1.0.8",
    "X-Device-Info": "platform=websdk",
    "X-Terminal-Type": "2",
    Origin: endpoints.accountsOrigin,
    Referer: endpoints.accountsReferer,
  };
  if (challenge.flowKey) h["X-Flow-Key"] = challenge.flowKey;
  if (challenge.webId) h["X-Web-Id"] = challenge.webId;
  if (challenge.proxyUnit) h["X-Proxy-Unit"] = challenge.proxyUnit;
  return h;
}

export function authenticatedHeaders(
  jar: RecordingCookieJar,
  endpoints: WebEndpoints,
  targetUrl: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": WEB_USER_AGENT,
    "X-App-Id": "1",
    "X-Api-Version": "1.0.8",
    "X-Device-Info": "platform=websdk",
    "X-Terminal-Type": "2",
    Origin: endpoints.accountsOrigin,
    Referer: endpoints.accountsReferer,
    ...extra,
  };
  const csrf = jar.cookieValue(new URL(targetUrl), "swp_csrf_token");
  if (csrf) headers["x-csrf-token"] = csrf;
  return headers;
}

export async function readNativeProfile(
  jar: RecordingCookieJar,
  endpoints: WebEndpoints,
  opts: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<NativeProfile> {
  const res = await fetchWithJar(jar, {
    method: "GET",
    url: endpoints.profileUrl,
    headers: authenticatedHeaders(jar, endpoints, endpoints.profileUrl, { "X-App-Id": "12" }),
    timeoutMs: opts.timeoutMs,
    signal: opts.signal,
    allowInsecureHttp: endpoints.allowInsecureHttp,
    extraAllowedHosts: endpoints.extraAllowedHosts,
  });
  if (res.status === 401 || res.status === 403) {
    throw new WebHttpError("credential_denied", `个人 Web 会话鉴权被拒绝 (HTTP ${res.status})`, res.status);
  }
  if (res.status !== 200) {
    throw new WebHttpError("http_error", `查询个人 Web 资料失败 (HTTP ${res.status})`, res.status);
  }
  let parsed: { code?: number; data?: { user?: { id?: unknown; name?: string; open_id?: string; openId?: string } } };
  try {
    parsed = parseJsonPreserveNativeIds<typeof parsed>(res.body.toString("utf8"));
  } catch {
    // 200 with non-JSON body (interstitial / throttle) is transient, never a definitive sign-out
    throw new WebHttpError("http_error", "个人 Web 资料响应暂不可解析", res.status);
  }
  const id = normalizeNativeId(parsed?.data?.user?.id);
  if (typeof parsed?.code !== "number" || parsed.code !== 0 || !id) {
    throw new WebHttpError("http_error", "个人 Web 资料服务暂时不可用", res.status);
  }
  const rawOpenId = parsed.data?.user?.open_id ?? parsed.data?.user?.openId;
  const openId = typeof rawOpenId === "string" && rawOpenId.trim() ? rawOpenId.trim() : undefined;
  return { id, name: String(parsed.data?.user?.name ?? ""), ...(openId ? { openId } : {}) };
}

export async function loadWebMetadata(
  jar: RecordingCookieJar,
  endpoints: WebEndpoints,
  opts: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<{ deviceId: string; appKey: string }> {
  const messengerUrl = new URL(endpoints.messengerUrl);
  const accountsUrl = new URL(endpoints.accountsOrigin + "/");
  const deviceId = jar.cookieValue(messengerUrl, "passport_web_did") || jar.cookieValue(accountsUrl, "passport_web_did");
  const res = await fetchWithJar(jar, {
    method: "GET",
    url: endpoints.messengerUrl,
    headers: authenticatedHeaders(jar, endpoints, endpoints.messengerUrl),
    timeoutMs: opts.timeoutMs,
    signal: opts.signal,
    allowInsecureHttp: endpoints.allowInsecureHttp,
    extraAllowedHosts: endpoints.extraAllowedHosts,
  });
  if (res.status === 401 || res.status === 403) {
    throw new WebHttpError("credential_denied", `个人 Web 元数据鉴权被拒绝 (HTTP ${res.status})`, res.status);
  }
  if (res.status !== 200) {
    throw new WebHttpError("http_error", `获取个人 Web 元数据失败 (HTTP ${res.status})`, res.status);
  }
  const body = res.body.toString("utf8");
  const match = body.match(APP_KEY_RE);
  const resolvedDeviceId =
    deviceId || jar.cookieValue(messengerUrl, "passport_web_did") || jar.cookieValue(accountsUrl, "passport_web_did");
  if (!match?.[1] || !resolvedDeviceId) {
    throw new WebHttpError("http_error", "已登录的个人 Web 元数据暂不可用（缺少 appKey 或 passport_web_did）", res.status);
  }
  return { deviceId: resolvedDeviceId, appKey: match[1] };
}

/** Step 1 & 2: Bootstrap Web device ID and request a fresh QR login challenge. */
export async function beginLogin(opts: {
  endpoints?: Partial<WebEndpoints>;
  signal?: AbortSignal;
  timeoutMs?: number;
} = {}): Promise<LoginChallenge> {
  const ep = resolveEndpoints(opts.endpoints);
  const jar = new RecordingCookieJar(ep.extraAllowedHosts);

  // Step 1: Fetch messenger page for issuer-assigned passport_web_did
  const bootRes = await fetchWithJar(jar, {
    method: "GET",
    url: ep.messengerUrl,
    headers: { "User-Agent": WEB_USER_AGENT },
    signal: opts.signal,
    timeoutMs: opts.timeoutMs,
    allowInsecureHttp: ep.allowInsecureHttp,
    extraAllowedHosts: ep.extraAllowedHosts,
  });
  if (bootRes.status !== 200) {
    throw new WebHttpError("http_error", `初始化个人 Web 登录页失败 (HTTP ${bootRes.status})`, bootRes.status);
  }
  const webIdMatch = bootRes.body.toString("utf8").match(AUTH_WEB_ID_RE);
  const webId = webIdMatch?.[1] ?? "";
  if (!webId || webId.length > 256 || webId !== webId.trim() || /[\r\n\0]/.test(webId)) {
    throw new WebHttpError("http_error", "未能从飞书登录页获取到有效的 Web 设备标识");
  }
  const initialProxyUnit = getHeader(bootRes.headers, "x-proxy-unit");

  // Step 2: Init QR login challenge
  const initRes = await fetchWithJar(jar, {
    method: "POST",
    url: ep.qrInitUrl,
    headers: authHeaders(ep, { flowKey: "", webId, proxyUnit: initialProxyUnit }),
    body: JSON.stringify({ redirect_uri: ep.qrRedirectUri }),
    signal: opts.signal,
    timeoutMs: opts.timeoutMs,
    allowInsecureHttp: ep.allowInsecureHttp,
    extraAllowedHosts: ep.extraAllowedHosts,
  });
  if (initRes.status !== 200) {
    throw new WebHttpError("http_error", `申请扫码登录二维码失败 (HTTP ${initRes.status})`, initRes.status);
  }
  let parsed: { code?: number; data?: { step_info?: { token?: string } } };
  try {
    parsed = JSON.parse(initRes.body.toString("utf8")) as typeof parsed;
  } catch {
    throw new WebHttpError("http_error", "扫码登录初始化响应不可解析");
  }
  const token = parsed?.data?.step_info?.token ?? "";
  if (parsed?.code !== 0 || !token) {
    throw new WebHttpError("http_error", `未签发登录二维码 (code=${String(parsed?.code ?? "unknown")})`);
  }

  const now = Date.now();
  return {
    webId,
    proxyUnit: getHeader(initRes.headers, "x-proxy-unit") || initialProxyUnit,
    qrCode: JSON.stringify({ qrlogin: { token } }),
    flowKey: getHeader(initRes.headers, "x-flow-key").trim(),
    cookies: jar.records(now),
    createdAtMs: now,
    expiresAtMs: now + QR_LOGIN_TIMEOUT_MS,
  };
}

interface PollDecision {
  approved: boolean;
  scanned: boolean;
  ownerId: string;
  unreadable?: boolean;
}

export function decodeLoginPoll(body: Buffer): PollDecision {
  let parsed: {
    code?: number;
    data?: {
      step_info?: { status?: number; front_user_id?: unknown };
      next_step?: string;
    };
  };
  try {
    parsed = parseJsonPreserveNativeIds<typeof parsed>(body.toString("utf8"));
  } catch {
    return { approved: false, scanned: false, ownerId: "", unreadable: true };
  }
  if (typeof parsed?.code !== "number") {
    return { approved: false, scanned: false, ownerId: "", unreadable: true };
  }
  if (parsed.code !== 0) {
    throw new WebHttpError("http_error", `扫码状态轮询被拒绝 (code=${parsed.code})`);
  }
  const step = parsed.data?.step_info;
  const status = typeof step?.status === "number" ? step.status : undefined;
  const nextStep = parsed.data?.next_step ?? "";
  if (status !== undefined && (status < 0 || status >= 3)) {
    throw new WebHttpError("credential_denied", "二维码已过期或被取消");
  }
  if (nextStep === "enter_app" && (status === undefined || status === 0)) {
    const ownerId = normalizeNativeId(step?.front_user_id);
    if (ownerId) return { approved: true, scanned: true, ownerId };
  }
  if (nextStep && nextStep !== "qr_login_polling") {
    throw new WebHttpError("credential_denied", `需要额外的网页端人工验证步骤：${nextStep}`);
  }
  if (status === undefined) {
    throw new WebHttpError("http_error", "扫码轮询缺少状态字段");
  }
  return { approved: status === 0, scanned: status === 2, ownerId: normalizeNativeId(step?.front_user_id) };
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new WebHttpError("aborted", "扫码登录已取消"));
      return;
    }
    const onAbort = () => {
      clearTimeout(t);
      reject(new WebHttpError("aborted", "扫码登录已取消"));
    };
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Step 3 & 4: Poll until the human scans and approves the QR code, then verify owner & metadata. */
export async function pollLogin(
  initialChallenge: LoginChallenge,
  opts: {
    endpoints?: Partial<WebEndpoints>;
    pollIntervalMs?: number;
    signal?: AbortSignal;
    onProgress?: (status: LoginPollStatus, challenge: LoginChallenge) => void;
  } = {},
): Promise<WebLogin> {
  const ep = resolveEndpoints(opts.endpoints);
  const pollIntervalMs = opts.pollIntervalMs ?? QR_POLL_INTERVAL_MS;
  let challenge: LoginChallenge = { ...initialChallenge, cookies: [...initialChallenge.cookies] };

  if (!challenge.createdAtMs || !challenge.flowKey) {
    throw new WebHttpError("credential_denied", "无效的二维码登录会话");
  }

  const jar = RecordingCookieJar.fromRecords(challenge.cookies, ep.extraAllowedHosts);

  const finalize = async (): Promise<WebLogin> => {
    const profile = await readNativeProfile(jar, ep, { signal: opts.signal });
    if (challenge.approvedOwnerId && profile.id !== challenge.approvedOwnerId) {
      throw new WebHttpError("credential_denied", "已登录账号与扫码确认的账号不一致");
    }
    await loadWebMetadata(jar, ep, { signal: opts.signal });
    return {
      cookies: jar.records(),
      owner_id: profile.id,
      owner_name: profile.name,
      ...(profile.openId ? { owner_open_id: profile.openId } : {}),
      session_id: crypto.randomUUID(),
      cookie_version: 1,
      updated_at: new Date().toISOString(),
    };
  };

  if (hasSessionCookie(jar.records())) {
    return finalize();
  }

  let lastProgress: LoginPollStatus | "" = "";
  const emitProgress = (s: LoginPollStatus) => {
    if (s !== lastProgress) {
      lastProgress = s;
      opts.onProgress?.(s, challenge);
    }
  };

  while (true) {
    if (opts.signal?.aborted) {
      throw new WebHttpError("aborted", "扫码登录已取消");
    }
    if (Date.now() >= challenge.expiresAtMs) {
      throw new WebHttpError("credential_denied", "登录二维码已过期，请重新执行扫码");
    }

    const res = await fetchWithJar(jar, {
      method: "POST",
      url: ep.qrPollUrl,
      headers: authHeaders(ep, challenge),
      body: "{}",
      signal: opts.signal,
      allowInsecureHttp: ep.allowInsecureHttp,
      extraAllowedHosts: ep.extraAllowedHosts,
    });
    if (res.status !== 200) {
      throw new WebHttpError("http_error", `扫码轮询被拒绝 (HTTP ${res.status})`, res.status);
    }
    const decision = decodeLoginPoll(res.body);
    if (!decision.unreadable) {
      const nextFlow = getHeader(res.headers, "x-flow-key").trim();
      const nextProxy = getHeader(res.headers, "x-proxy-unit");
      challenge = {
        ...challenge,
        cookies: jar.records(),
        flowKey: nextFlow || challenge.flowKey,
        proxyUnit: nextProxy || challenge.proxyUnit,
        approvedOwnerId: decision.ownerId || challenge.approvedOwnerId,
      };
      if (decision.approved) {
        emitProgress("approved");
        return finalize();
      }
      emitProgress(decision.scanned ? "scanned" : "waiting");
    }

    const remaining = challenge.expiresAtMs - Date.now();
    if (remaining <= 0) {
      throw new WebHttpError("credential_denied", "登录二维码已过期，请重新执行扫码");
    }
    await sleep(Math.min(pollIntervalMs, remaining), opts.signal);
  }
}
