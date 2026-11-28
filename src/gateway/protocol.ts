/**
 * 飞书个人 Web 独立网关与客户端之间的最小 HTTP/SSE 契约。
 *
 * 边界约定：
 *   - 仅包含纯数据类型、校验工具与错误分类，零业务依赖；
 *   - 客户端（如 Avatar 主进程）只引入本文件与 client.ts，不接触 feishu-web 协议层、密钥或 Cookie。
 */

export type GatewayListenerState =
  | "idle"
  | "connecting"
  | "listening"
  | "reconnecting"
  | "reverifying"
  | "publication_blocked"
  | "needs_login"
  | "stopped";

export type GatewayCredentialStatus = "ok" | "missing" | "missing_key" | "plaintext_rejected" | "invalid";

export interface GatewayMention {
  id: string;
  name: string;
  start: number;
  end: number;
}

export interface GatewayResource {
  kind: "image" | "file" | "media" | "audio" | "sticker" | "other";
  key: string;
  name: string;
}

export interface GatewayAnchor {
  id: string;
  conversationId: string;
  rootId: string;
  parentId: string;
  threadId: string;
  position: number;
  createdAtMs: number;
}

export interface GatewayMessagePayload {
  id: string;
  conversationId: string;
  conversationKind: "dm" | "group" | "";
  chatName: string;
  /** 网关是否成功核验过该会话的名称（true 表示 readChat 成功或命中缓存，即使会话本身无名也可放心按 ID 放行；false 表示未能核验） */
  chatNameResolved?: boolean;
  actorId: string;
  senderType: number;
  text: string;
  rootId: string;
  parentId: string;
  threadId: string;
  position: number;
  createdAtMs: number;
  mentions: GatewayMention[];
  resources: GatewayResource[];
  ownerId: string;
  ownerName: string;
}

export type GatewayEvent =
  | {
      seq: number;
      kind: "message";
      message_id: string;
      chat_id: string;
      created_at: number;
      message: GatewayMessagePayload;
    }
  | {
      seq: number;
      kind: "delete";
      message_id: string;
      chat_id: string;
      created_at: number;
    };

export interface GatewayStatus {
  state: GatewayListenerState;
  logged_in: boolean;
  credential_status: GatewayCredentialStatus;
  owner_id: string;
  owner_name: string;
  since: number;
  last_message_at: number | null;
  last_error: string;
  allow_reply: boolean;
  min_seq: number;
  latest_seq: number;
  cached_events: number;
  /** 网关事件库实例标识（建库时随机生成）；变化说明网关库被重建，客户端须重置游标 */
  db_epoch?: string;
  verified?: boolean;
}

export interface GatewayHealth {
  ok: true;
  state: GatewayListenerState;
  logged_in: boolean;
  latest_seq: number;
  allow_reply: boolean;
}

export interface GatewayEventsResponse {
  events: GatewayEvent[];
  min_seq: number;
  latest_seq: number;
  has_more: boolean;
  truncated: boolean;
  /** 本页实际扫描到的最后一个 seq（含被过滤掉的事件），续拉时以它为游标，避免整页被过滤时卡住 */
  next_after: number;
}

export interface GatewayContextRequest {
  anchor: GatewayAnchor;
  limit?: number;
}

export interface GatewayContextResponse {
  owner_id: string;
  owner_name: string;
  chat_name: string;
  messages: GatewayMessagePayload[];
}

export interface GatewayReplyRequest {
  chat_id: string;
  message_id: string;
  root_id?: string;
  text: string;
  cid: string;
  /** 可选：调用方期望网关当前绑定的个人账号 ID，不匹配时原子拒绝（防跨账号误发） */
  expected_owner_id?: string;
  /** 只允许对已发出（created）的回复做回读核验，拒绝任何新发送（客户端已关闭 send_replies 时使用） */
  readback_only?: boolean;
  /** 客户端侧的排除规则（会话 ID 或子串关键字），网关在发送前用实时会话名一并核对 */
  client_deny?: string[];
  /** 客户端侧的精确会话名排除规则（如静音会话名、oc_ 反查群名），网关仅做精确/规范化私聊名匹配，不做子串误拦 */
  client_deny_exact?: string[];
}

export interface GatewayReplyResult {
  replyId: string;
  rootId: string;
  parentId: string;
  threadId: string;
  verified: boolean;
}

export interface GatewayReplyResponse {
  ok: true;
  result: GatewayReplyResult;
}

export interface GatewayErrorBody {
  ok: false;
  code: string;
  error: string;
  permanent?: boolean;
  status?: GatewayStatus;
}

export interface GatewayGapEvent {
  after: number;
  min_seq: number;
  latest_seq: number;
}

export class GatewayHttpError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly permanent: boolean;
  readonly gatewayStatus?: GatewayStatus;

  constructor(statusCode: number, code: string, message: string, permanent = false, gatewayStatus?: GatewayStatus) {
    super(message);
    this.name = "GatewayHttpError";
    this.statusCode = statusCode;
    this.code = code;
    this.permanent = permanent;
    this.gatewayStatus = gatewayStatus;
  }
}

export const GATEWAY_USER_SENDER_TYPE = 1;
export const MAX_REPLY_TEXT_BYTES = 16 * 1024;
export const MAX_CONTEXT_LIMIT = 30;
export const MAX_EVENTS_LIMIT = 500;
export const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const CID_RE = /^[A-Za-z0-9._:-]{8,128}$/;
export const MAX_CLIENT_DENY_RULES = 500;
export const MAX_CLIENT_DENY_RULE_LEN = 200;

export function isLoopbackHostname(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "127.0.0.1" || h === "localhost" || h === "::1";
}

/** 仅允许回环地址的明文 HTTP 网关地址，防止把个人飞书网关误暴露到局域网或触发 SSRF。 */
export function validateLoopbackGatewayUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`无效的网关地址：${raw}`);
  }
  if (u.protocol !== "http:") {
    throw new Error(`网关 HTTP 地址仅支持 http:// 回环地址，收到协议：${u.protocol}`);
  }
  if (!isLoopbackHostname(u.hostname)) {
    throw new Error(`出于安全边界限制，网关 TCP 地址仅允许回环地址（127.0.0.1 / localhost / [::1]），拒绝：${u.hostname}`);
  }
  if (u.username || u.password) {
    throw new Error("网关地址不允许内嵌用户名或密码，请使用独立的令牌环境变量");
  }
  if (u.pathname && u.pathname !== "/") {
    throw new Error(`网关地址不应包含路径后缀：${u.pathname}`);
  }
  if (u.search || u.hash) {
    throw new Error("网关地址不应包含查询参数或片段");
  }
  return u;
}

export function isValidOctalSocketMode(raw: string): boolean {
  if (!/^0?[0-7]{3}$/.test(raw.trim())) return false;
  const n = Number.parseInt(raw.trim(), 8);
  // 禁止对其他用户（other）开放任何权限，且至少允许属主读写
  return (n & 0o007) === 0 && (n & 0o600) === 0o600;
}

export function parseSocketMode(raw: string): number {
  if (!isValidOctalSocketMode(raw)) {
    throw new Error(`不安全的 socket_mode「${raw}」：仅允许如 0600 / 0660（禁止对 other 开放权限）`);
  }
  return Number.parseInt(raw.trim(), 8);
}
