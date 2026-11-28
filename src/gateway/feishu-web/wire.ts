import zlib from "node:zlib";
import { MAX_WIRE_BYTES, parseProto, ProtoFields, ProtoWriter, WIRE_BYTES, WIRE_VARINT } from "./proto.ts";

/**
 * Feishu personal Web gateway / Frontier wire codec.
 * Encodes & decodes frames, gateway packets, rich-text messages, cards, forwards, and replies.
 */

// Gateway / Frontier command identifiers
export const CMD_RESPONSE = 1;
export const CMD_HEARTBEAT = 4;
export const CMD_SEND_MESSAGE = 5;
export const CMD_PUSH_PACKET = 6;
export const CMD_READ_MESSAGE = 8;
export const CMD_HISTORY = 43;
export const CMD_CHAT_MODE = 64;

// Native chat kinds & modes
export const CHAT_KIND_P2P = 1;
export const CHAT_KIND_GROUP = 2;
export const CHAT_KIND_TOPIC = 3;

export const CHAT_MODE_TOPIC = 2;
export const CHAT_MODE_TOPIC_THREAD = 3;

export const CHAT_ID_FIELD = 1;
export const CHAT_KIND_FIELD = 2;
export const CHAT_NAME_FIELD = 4;
export const CHAT_MODE_FIELD = 39;

// Native message & sender types
export const USER_SENDER_TYPE = 1;

export const MSG_POST = 2;
export const MSG_TEXT = 4;
export const MSG_IMAGE = 5;
export const MSG_FILE = 6;
export const MSG_SHARE_CHAT = 9;
export const MSG_MERGE_FORWARD = 11;
export const MSG_CARD = 14;
export const MSG_SHARE_USER = 23;

const BASIC_CARD_TYPE = 2;

// Rich-text element tags
const TAG_TEXT = 1;
const TAG_IMAGE = 2;
const TAG_PARAGRAPH = 3;
const TAG_FIGURE = 4;
const TAG_MENTION = 5;
const TAG_LINK = 6;
const TAG_BOLD = 7;
const TAG_ITALIC = 8;
const TAG_UNDERLINE = 9;
const TAG_DOCUMENT = 22;
const TAG_H1 = 23;
const TAG_H2 = 24;
const TAG_H3 = 25;
const TAG_UL = 26;
const TAG_OL = 27;
const TAG_LI = 28;
const TAG_QUOTE = 29;
const TAG_CODE = 30;
const TAG_CODE_BLOCK = 31;

const MAX_RICH_ELEMENTS = 4096;
const MAX_RICH_DEPTH = 16;
const MAX_RICH_OUTPUT_CHARS = 64 * 1024;
const MAX_FORWARD_MESSAGES = 200;
const MAX_FORWARD_DEPTH = 8;
const NATIVE_RICH_VERSION = 2;

const STYLE_DEFS: [string, string][] = [
  ["fontWeight", "bold"],
  ["fontStyle", "italic"],
  ["fontSize", "14"],
  ["fontSize", "12"],
  ["color", "#646a73"],
  ["fontSize", "16"],
];

// Public Feishu Web SDK protocol constants
export const WEB_APP_ID = "161471";
export const WEB_SDK_VERSION = "7.72.8";
export const WEB_LARK_VERSION = "7.72.0";
export const ACCESS_KEY_SALT = "f8a69f1719916z";

export function isGroupChat(kind: number): boolean {
  return kind === CHAT_KIND_GROUP || kind === CHAT_KIND_TOPIC;
}

export function isTopicChatMode(mode: number): boolean {
  return mode === CHAT_MODE_TOPIC || mode === CHAT_MODE_TOPIC_THREAD;
}

/**
 * Whether PutMessageRequest must set is_reply_in_thread (field 12).
 * P2P chats and ordinary groups thread replies explicitly; topic-mode groups thread natively.
 */
export function replyInThread(kind: number, mode: number): boolean {
  return kind === CHAT_KIND_P2P || (isGroupChat(kind) && !isTopicChatMode(mode));
}

export interface WebMention {
  id: string;
  name: string;
  start: number;
  end: number;
}

export interface WebResource {
  kind: "image" | "file";
  key: string;
  name: string;
  mime: string;
  size: number;
}

export interface WebMessage {
  id: string;
  ownerId: string;
  actorId: string;
  conversationId: string;
  conversationKind: "dm" | "group" | "";
  rootId: string;
  parentId: string;
  threadId: string;
  cid: string;
  kind: number;
  senderType: number;
  messageType: string;
  createdAtMs: number;
  position: number;
  threadPosition: number;
  sendToChat: boolean;
  text: string;
  mentions: WebMention[];
  resources: WebResource[];
  sharedChat?: { id: string; name: string };
  unsupported: boolean;
  partial: boolean;
}

export interface RichSegment {
  text: string;
  mentionId?: string;
  url?: string;
  bold?: boolean;
  italic?: boolean;
}

export class GatewayError extends Error {
  readonly status?: number;
  readonly emptyPayload?: boolean;

  constructor(message: string, opts: { status?: number; emptyPayload?: boolean } = {}) {
    super(message);
    this.name = "GatewayError";
    this.status = opts.status;
    this.emptyPayload = opts.emptyPayload;
  }
}

/** Wrap one gateway command with its client request ID. */
export function encodePacket(command: number, payload: Uint8Array | undefined, cid: string): Buffer {
  const w = new ProtoWriter().uint(2, 1).uint(3, command);
  if (payload && payload.byteLength > 0) w.bytes(5, payload);
  if (cid) w.str(6, cid);
  return w.finish();
}

/** Wrap one packet in a Frontier WebSocket binary frame. */
export function encodeFrame(packet: Uint8Array, nowMs = Date.now()): Buffer {
  const header = new ProtoWriter().str(1, "x-request-time").str(2, String(nowMs)).finish();
  return new ProtoWriter()
    .uint(1, nowMs)
    .uint(2, nowMs)
    .uint(3, 1)
    .uint(4, 1)
    .bytes(5, header)
    .str(7, "pb")
    .bytes(8, packet)
    .finish();
}

/** Decode one Frontier WebSocket frame (supporting gzip or identity payload encoding). */
export function decodeFrame(data: Uint8Array): ProtoFields {
  const outer = parseProto(data, MAX_WIRE_BYTES);
  let payload = outer.bytes(8);
  const encoding = outer.str(6);
  if (encoding === "gzip") {
    payload = zlib.gunzipSync(payload, { maxOutputLength: MAX_WIRE_BYTES });
  } else if (encoding && encoding !== "identity") {
    throw new Error(`不支持的个人 Web 帧压缩编码：${encoding}`);
  }
  return parseProto(payload, MAX_WIRE_BYTES);
}

/** Encode a Frontier push ACK frame for a server packet ID (sid). */
export function encodeAckFrame(sid: string, nowMs = Date.now()): Buffer {
  const ack = new ProtoWriter()
    .str(1, sid)
    .uint(2, 1)
    .uint(3, CMD_RESPONSE)
    .bytes(5, Buffer.from([8, 0]))
    .finish();
  return encodeFrame(ack, nowMs);
}

/** Unwrap a gateway HTTP response packet and verify envelope shape, field wire types, and status === 0. */
export function unwrapGatewayPayload(
  data: Uint8Array,
  opts: { allowEmptyPayload?: boolean; expectedCommand?: number; expectedCid?: string } = {},
): Buffer {
  if (data.length === 0) {
    throw new GatewayError("个人 Web 网关返回空响应", { emptyPayload: true });
  }
  const packet = parseProto(data, MAX_WIRE_BYTES);
  const assertWireType = (field: number, expected: number, label: string): void => {
    for (const v of packet.allFields(field)) {
      if (v.type !== expected) {
        throw new GatewayError(`个人 Web 网关响应 ${label} 字段线型非法`);
      }
    }
  };
  assertWireType(1, WIRE_BYTES, "sid");
  assertWireType(2, WIRE_VARINT, "payloadType");
  assertWireType(3, WIRE_VARINT, "cmd");
  assertWireType(4, WIRE_VARINT, "status");
  assertWireType(5, WIRE_BYTES, "payload");
  assertWireType(6, WIRE_BYTES, "cid");

  const payloadTypeField = packet.lastField(2);
  if (payloadTypeField !== undefined && Number(payloadTypeField.uint ?? 0n) !== 1) {
    throw new GatewayError(`个人 Web 网关响应 payloadType 非法 (${Number(payloadTypeField.uint ?? 0n)})`);
  }

  const cmdField = packet.lastField(3);
  const gotCmd = cmdField !== undefined ? Number(cmdField.uint ?? 0n) : undefined;
  // 真实飞书网关 HTTP 响应信封的 field 3 (cmd) 固定为 CMD_RESPONSE (1)，而非回显请求命令号
  const matchesExpectedCmd = (cmd: number, expected: number): boolean => cmd === CMD_RESPONSE || cmd === expected;
  if (opts.expectedCommand !== undefined && gotCmd !== undefined && !matchesExpectedCmd(gotCmd, opts.expectedCommand)) {
    throw new GatewayError(
      `个人 Web 网关响应命令号不匹配 (got=${gotCmd}, want=${CMD_RESPONSE} 或 ${opts.expectedCommand})`,
    );
  }

  const cidField = packet.lastField(6);
  if (opts.expectedCid && cidField !== undefined) {
    const gotCid = cidField.bytes?.toString("utf8") ?? "";
    if (gotCid && gotCid !== opts.expectedCid) {
      throw new GatewayError("个人 Web 网关响应 cid 不匹配");
    }
  }

  const statusField = packet.lastField(4);
  const status = statusField ? Number(statusField.uint ?? 0n) : 0;
  if (status !== 0) {
    throw new GatewayError(`个人 Web 网关拒绝请求 (status=${status})`, { status });
  }

  const payloadField = packet.lastField(5);
  const payload = payloadField?.bytes ?? Buffer.alloc(0);
  if (payload.length === 0) {
    if (!opts.allowEmptyPayload) {
      throw new GatewayError("个人 Web 网关返回空载荷", { emptyPayload: true });
    }
    // 仅当响应明确包含合法的 Packet 响应信封头（payloadType=1 / 匹配的 cmd / 匹配的 cid），
    // 才把 0 字节载荷视作权威空结果；防止无关 protobuf 或畸形 HTTP 200 响应被误判为「消息已不存在」
    const hasValidPayloadType = payloadTypeField !== undefined && Number(payloadTypeField.uint ?? 0n) === 1;
    const hasValidCmd =
      gotCmd !== undefined &&
      (opts.expectedCommand === undefined ? gotCmd > 0 : matchesExpectedCmd(gotCmd, opts.expectedCommand));
    const hasMatchingCid =
      !!opts.expectedCid &&
      cidField !== undefined &&
      (cidField.bytes?.toString("utf8") ?? "") === opts.expectedCid;
    if (!hasValidPayloadType && !hasValidCmd && !hasMatchingCid) {
      throw new GatewayError("个人 Web 网关响应缺少有效信封头，拒绝视为空结果", { emptyPayload: true });
    }
  }
  return payload;
}

/** Encode rich-text segments into Feishu native RichText protobuf (schema v2). */
export function encodeRichText(segments: RichSegment[]): Buffer {
  const dict = new ProtoWriter();
  const rootIds: string[] = [];
  const mentionIds: string[] = [];
  const linkIds: string[] = [];
  let plain = "";
  let styled = false;

  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const id = `dt-${i}`;
    let tag = TAG_TEXT;
    const prop = new ProtoWriter();
    if (seg.mentionId) {
      tag = TAG_MENTION;
      prop.str(1, seg.mentionId).str(2, seg.text);
    } else if (seg.url) {
      tag = TAG_LINK;
      prop.str(1, seg.url).str(2, seg.text);
    } else {
      prop.str(1, seg.text);
    }

    const elem = new ProtoWriter().uint(1, tag);
    const styleIndices: number[] = [];
    if (seg.bold) {
      elem.bytes(2, new ProtoWriter().str(1, "fontWeight").str(2, "bold").finish()).str(5, "fontWeight");
      styleIndices.push(0);
    }
    if (seg.italic) {
      elem.bytes(2, new ProtoWriter().str(1, "fontStyle").str(2, "italic").finish()).str(5, "fontStyle");
      styleIndices.push(1);
    }
    elem.bytes(3, prop.finish());

    dict.bytes(1, new ProtoWriter().str(1, id).bytes(2, elem.finish()).finish());
    rootIds.push(id);
    if (tag === TAG_MENTION) mentionIds.push(id);
    if (tag === TAG_LINK) linkIds.push(id);

    if (styleIndices.length > 0) {
      styled = true;
      const idxWriter = new ProtoWriter();
      for (const idx of styleIndices) idxWriter.uint(1, idx);
      dict.bytes(2, new ProtoWriter().str(1, id).bytes(2, idxWriter.finish()).finish());
    }
    plain += seg.text;
  }

  if (styled) {
    for (const [k, v] of STYLE_DEFS) {
      dict.bytes(3, new ProtoWriter().str(1, k).str(2, v).finish());
    }
  }

  const out = new ProtoWriter();
  for (const id of rootIds) out.str(1, id);
  out.str(2, plain);
  out.bytes(3, dict.finish());
  for (const id of mentionIds) out.str(6, id);
  for (const id of linkIds) out.str(7, id);
  out.uint(13, NATIVE_RICH_VERSION);
  return out.finish();
}

/** Encode a PutMessageRequest text reply packet wrapped with command 5 and deterministic CID. */
export function encodeReplyPacket(
  chatId: string,
  rootId: string,
  cid: string,
  segments: RichSegment[],
  inThread: boolean,
  parentId = rootId,
): Buffer {
  const content = new ProtoWriter().bytes(14, encodeRichText(segments)).finish();
  const req = new ProtoWriter()
    .uint(1, MSG_TEXT)
    .bytes(2, content)
    .str(3, chatId);
  if (rootId) {
    req.str(4, rootId).str(5, parentId || rootId);
  }
  req.str(6, cid).uint(7, 1).uint(9, 1);
  if (inThread && rootId) req.uint(12, 1);
  return encodePacket(CMD_SEND_MESSAGE, req.finish(), cid);
}

/** Encode a command 43 history-window request for positions [next .. position - 1]. */
export function encodeHistoryWindowPayload(chatId: string, position: number, next: number): Buffer {
  if (
    !Number.isSafeInteger(position) ||
    !Number.isSafeInteger(next) ||
    position < 0 ||
    next < 0 ||
    position > 0x7fffffff ||
    next > position ||
    position - next > 100
  ) {
    throw new Error(`非法的历史消息窗口区间：[${next}, ${position})`);
  }
  const w = new ProtoWriter().str(1, chatId);
  for (let cur = position - 1; cur >= next; cur--) {
    w.uint(2, cur);
  }
  return w.finish();
}

function isTextBlockTag(tag: number): boolean {
  return (
    tag === TAG_PARAGRAPH ||
    tag === TAG_FIGURE ||
    tag === TAG_H1 ||
    tag === TAG_H2 ||
    tag === TAG_H3 ||
    tag === TAG_LI ||
    tag === TAG_QUOTE ||
    tag === TAG_CODE_BLOCK
  );
}

interface DecodedRich {
  text: string;
  mentions: WebMention[];
  resources: WebResource[];
  partial: boolean;
}

export function decodeRichText(data: Uint8Array): DecodedRich {
  const rich = parseProto(data, MAX_WIRE_BYTES);
  const dictFields = parseProto(rich.bytes(3), MAX_WIRE_BYTES);
  const elements = new Map<string, ProtoFields>();
  for (const entry of dictFields.allBytes(1)) {
    const pair = parseProto(entry, MAX_WIRE_BYTES);
    elements.set(pair.str(1), parseProto(pair.bytes(2), MAX_WIRE_BYTES));
    if (elements.size > MAX_RICH_ELEMENTS) {
      throw new Error("富文本元素数量超过上限");
    }
  }

  let text = "";
  const mentions: WebMention[] = [];
  const resources: WebResource[] = [];
  let partial = false;
  let budgetExhausted = false;
  let visited = 0;
  const active = new Set<string>();

  const safeSlice = (s: string, max: number): string => {
    if (max <= 0) return "";
    if (s.length <= max) return s;
    let end = max;
    const last = s.charCodeAt(end - 1);
    if (last >= 0xd800 && last <= 0xdbff) end--;
    return s.slice(0, end);
  };

  const readBoundedStr = (f: ProtoFields, field: number, maxChars: number): { value: string; clipped: boolean } => {
    const raw = f.bytes(field);
    if (!raw.length) return { value: "", clipped: false };
    if (maxChars <= 0) return { value: "", clipped: true };
    const byteCap = Math.min(raw.length, maxChars * 4);
    const slice = byteCap < raw.length ? raw.subarray(0, byteCap) : raw;
    const decoded = slice.toString("utf8");
    if (decoded.length > maxChars) {
      return { value: safeSlice(decoded, maxChars), clipped: true };
    }
    return { value: decoded, clipped: byteCap < raw.length };
  };

  const appendText = (chunk: string, alreadyClipped = false): number => {
    if (alreadyClipped) partial = true;
    if (!chunk) {
      if (alreadyClipped) budgetExhausted = true;
      return 0;
    }
    const remaining = MAX_RICH_OUTPUT_CHARS - text.length;
    if (remaining <= 0) {
      partial = true;
      budgetExhausted = true;
      return 0;
    }
    if (chunk.length > remaining) {
      const piece = safeSlice(chunk, remaining);
      text += piece;
      partial = true;
      budgetExhausted = true;
      return piece.length;
    }
    text += chunk;
    if (alreadyClipped) budgetExhausted = true;
    return chunk.length;
  };

  const walk = (id: string, depth: number): void => {
    if (budgetExhausted) {
      partial = true;
      return;
    }
    visited++;
    if (depth > MAX_RICH_DEPTH || visited > MAX_RICH_ELEMENTS || active.has(id)) {
      throw new Error("富文本结构深度或循环超过上限");
    }
    if (text.length >= MAX_RICH_OUTPUT_CHARS) {
      partial = true;
      budgetExhausted = true;
      return;
    }
    const elem = elements.get(id);
    if (!elem) {
      partial = true;
      return;
    }
    active.add(id);
    try {
      const tag = elem.uint(1);
      const prop = parseProto(elem.bytes(3), MAX_WIRE_BYTES);
      const rem = MAX_RICH_OUTPUT_CHARS - text.length;
      switch (tag) {
        case TAG_TEXT: {
          const piece = readBoundedStr(prop, 1, rem);
          appendText(piece.value, piece.clipped);
          break;
        }
        case TAG_MENTION: {
          const uid = readBoundedStr(prop, 1, 256).value;
          const displayField = readBoundedStr(prop, 2, rem);
          const display = displayField.value || (uid ? `@${uid}` : "");
          const start = text.length;
          const appended = appendText(display, displayField.clipped);
          if (appended > 0) {
            mentions.push({
              id: uid,
              name: display.slice(0, appended).replace(/^@/, ""),
              start,
              end: start + appended,
            });
          }
          break;
        }
        case TAG_LINK: {
          const labelField = readBoundedStr(prop, 2, rem);
          if (labelField.value || labelField.clipped) {
            appendText(labelField.value, labelField.clipped);
          } else {
            const urlField = readBoundedStr(prop, 1, rem);
            appendText(urlField.value, urlField.clipped);
          }
          break;
        }
        case TAG_IMAGE: {
          const key = prop.str(4) || prop.str(2);
          const name = prop.str(10);
          if (key) resources.push({ kind: "image", key, name, mime: "", size: 0 });
          appendText("[图片]");
          break;
        }
        case TAG_CODE:
        case TAG_CODE_BLOCK: {
          const children = elem.allBytes(4);
          if (children.length > 0) {
            walkChildren(elem, tag, depth);
          } else {
            const codeField = readBoundedStr(prop, 1, rem);
            if (!codeField.value && !codeField.clipped) {
              if (elem.bytes(3).length > 0) partial = true;
            } else {
              appendText(codeField.value, codeField.clipped);
              if (tag === TAG_CODE_BLOCK && !budgetExhausted) appendText("\n");
            }
          }
          break;
        }
        case TAG_PARAGRAPH:
        case TAG_FIGURE:
        case TAG_BOLD:
        case TAG_ITALIC:
        case TAG_UNDERLINE:
        case TAG_DOCUMENT:
        case TAG_H1:
        case TAG_H2:
        case TAG_H3:
        case TAG_UL:
        case TAG_OL:
        case TAG_LI:
        case TAG_QUOTE:
          walkChildren(elem, tag, depth);
          break;
        default:
          partial = true;
          break;
      }
    } finally {
      active.delete(id);
    }
  };

  const walkChildren = (elem: ProtoFields, tag: number, depth: number): void => {
    const children = elem.allBytes(4);
    if (tag === TAG_DOCUMENT && children.length === 0) {
      partial = true;
      return;
    }
    for (const child of children) {
      if (budgetExhausted) {
        partial = true;
        break;
      }
      walk(child.toString("utf8"), depth + 1);
    }
    if (budgetExhausted) return;
    const allNestedParagraphs =
      children.length > 0 &&
      children.every((c) => {
        const nested = elements.get(c.toString("utf8"));
        return nested !== undefined && nested.uint(1) === TAG_PARAGRAPH;
      });
    if (isTextBlockTag(tag) && !allNestedParagraphs) {
      appendText("\n");
    }
  };

  for (const rootId of rich.allBytes(1)) {
    if (budgetExhausted) {
      partial = true;
      break;
    }
    walk(rootId.toString("utf8"), 0);
  }
  if (!text) {
    const fallback = readBoundedStr(rich, 2, MAX_RICH_OUTPUT_CHARS);
    if (fallback.value || fallback.clipped) {
      appendText(fallback.value, fallback.clipped);
    }
  }
  return { text: text.replace(/\n+$/, ""), mentions, resources, partial };
}

function extractCardJsonText(raw: string): string {
  try {
    const parsed: unknown = JSON.parse(raw);
    const out: string[] = [];
    const visit = (v: unknown): void => {
      if (Array.isArray(v)) {
        for (const item of v) visit(item);
        return;
      }
      if (v && typeof v === "object") {
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          if (typeof val === "string" && ["text", "content", "title", "plain_text"].includes(k) && val.trim()) {
            out.push(val.trim());
          } else {
            visit(val);
          }
        }
      }
    };
    visit(parsed);
    return out.join(" / ");
  } catch {
    return raw.trim();
  }
}

function decodeResourceContent(content: ProtoFields, kind: number): WebResource | undefined {
  if (kind === MSG_FILE) {
    const key = content.str(1);
    if (!key) return undefined;
    return { kind: "file", key, name: content.str(2), mime: content.str(4), size: content.uint(3) };
  }
  if (kind === MSG_IMAGE) {
    const img = parseProto(content.bytes(2), MAX_WIRE_BYTES);
    let key = img.str(1);
    if (!key) {
      const legacy = parseProto(content.bytes(1), MAX_WIRE_BYTES);
      const origin = parseProto(legacy.bytes(2), MAX_WIRE_BYTES);
      key = origin.str(1);
    }
    if (!key) return undefined;
    return { kind: "image", key, name: "", mime: "", size: content.uint(4) };
  }
  return undefined;
}

function decodeForwardText(content: ProtoFields, depth: number, counter: { n: number }): { text: string; partial: boolean } {
  if (depth >= MAX_FORWARD_DEPTH || counter.n >= MAX_FORWARD_MESSAGES) {
    return { text: "[转发内容已截断]", partial: true };
  }
  const lines: string[] = [];
  let totalChars = 0;
  let partial = false;
  for (const raw of content.allBytes(1)) {
    counter.n++;
    if (counter.n > MAX_FORWARD_MESSAGES || totalChars >= MAX_RICH_OUTPUT_CHARS) {
      partial = true;
      break;
    }
    try {
      const child = decodeMessageInner(parseProto(raw, MAX_WIRE_BYTES), "", depth + 1, counter);
      const trimmed = child.text.trim();
      if (trimmed) {
        const rem = MAX_RICH_OUTPUT_CHARS - totalChars;
        if (trimmed.length > rem) {
          lines.push(trimmed.slice(0, rem));
          totalChars = MAX_RICH_OUTPUT_CHARS;
          partial = true;
          break;
        }
        lines.push(trimmed);
        totalChars += trimmed.length + 1;
      }
      if (child.partial) partial = true;
    } catch {
      partial = true;
    }
  }
  return { text: lines.length ? `[合并转发]\n${lines.join("\n")}` : "[合并转发]", partial };
}

function decodeMessageInner(
  fields: ProtoFields,
  ownerId: string,
  depth: number,
  counter: { n: number },
): WebMessage {
  const kind = fields.uint(2);
  const senderType = fields.uint(7);
  const chatKind = fields.uint(46);
  const conversationKind: WebMessage["conversationKind"] =
    chatKind === CHAT_KIND_P2P ? "dm" : isGroupChat(chatKind) ? "group" : "";

  const msg: WebMessage = {
    id: fields.str(1),
    ownerId,
    actorId: fields.str(3),
    conversationId: fields.str(10),
    conversationKind,
    rootId: fields.str(8),
    parentId: fields.str(9),
    threadId: fields.str(20),
    cid: fields.str(12),
    kind,
    senderType,
    messageType: `native_${kind}`,
    createdAtMs: fields.uint(4) * 1000,
    position: fields.int32(13),
    threadPosition: fields.int32(28),
    sendToChat: fields.uint(21) !== 0,
    text: "",
    mentions: [],
    resources: [],
    unsupported: conversationKind === "",
    partial: false,
  };

  const contentBytes = fields.bytes(5);
  const content = contentBytes.length ? parseProto(contentBytes, MAX_WIRE_BYTES) : new ProtoFields();

  switch (kind) {
    case MSG_TEXT:
    case MSG_POST: {
      msg.messageType = kind === MSG_POST ? "post" : "text";
      const richBytes = content.bytes(kind === MSG_POST ? 6 : 3);
      const title = kind === MSG_POST ? content.str(1) : "";
      if (richBytes.length > 0) {
        const decoded = decodeRichText(richBytes);
        const prefix = title ? `${title}\n` : "";
        msg.text = prefix + decoded.text;
        msg.mentions = prefix
          ? decoded.mentions.map((m) => ({ ...m, start: m.start + prefix.length, end: m.end + prefix.length }))
          : decoded.mentions;
        msg.resources = decoded.resources;
        msg.partial = decoded.partial;
      } else {
        const rawText = content.str(kind === MSG_POST ? 2 : 1);
        msg.text = title && rawText ? `${title}\n${rawText}` : title || rawText;
      }
      break;
    }
    case MSG_CARD: {
      msg.messageType = "interactive";
      const cardType = content.uint(1);
      const cardSource = content.uint(15);
      const richBytes = content.bytes(2);
      const cardJson = content.str(20);
      if (cardType === BASIC_CARD_TYPE && senderType === USER_SENDER_TYPE && (cardSource === 0 || cardSource === 3) && richBytes.length > 0) {
        const decoded = decodeRichText(richBytes);
        msg.text = decoded.text;
        msg.mentions = decoded.mentions;
        msg.resources = decoded.resources;
        msg.partial = decoded.partial;
      } else if (cardJson) {
        msg.text = extractCardJsonText(cardJson);
      } else if (richBytes.length > 0) {
        const decoded = decodeRichText(richBytes);
        const cardTitle = content.str(6);
        const prefix = cardTitle && decoded.text ? `${cardTitle}\n` : "";
        msg.text = prefix ? prefix + decoded.text : cardTitle || decoded.text;
        msg.mentions = prefix
          ? decoded.mentions.map((m) => ({ ...m, start: m.start + prefix.length, end: m.end + prefix.length }))
          : decoded.mentions;
        msg.partial = decoded.partial;
      } else {
        msg.unsupported = true;
      }
      break;
    }
    case MSG_IMAGE:
    case MSG_FILE: {
      msg.messageType = kind === MSG_IMAGE ? "image" : "file";
      const res = decodeResourceContent(content, kind);
      if (res) {
        msg.resources.push(res);
        msg.text = kind === MSG_IMAGE ? "[图片]" : `[文件: ${res.name || res.key}]`;
      } else {
        msg.unsupported = true;
      }
      break;
    }
    case MSG_MERGE_FORWARD: {
      msg.messageType = "merge_forward";
      const fwd = decodeForwardText(content, depth, counter);
      msg.text = fwd.text;
      msg.partial = fwd.partial;
      break;
    }
    case MSG_SHARE_CHAT: {
      msg.messageType = "share_chat";
      const chatEntity = parseProto(content.bytes(1), MAX_WIRE_BYTES);
      const id = content.str(4) || chatEntity.str(CHAT_ID_FIELD);
      const name = chatEntity.str(CHAT_NAME_FIELD);
      msg.sharedChat = { id, name };
      msg.text = name ? `[分享群聊: ${name}]` : id ? `[分享群聊: ${id}]` : "[分享群聊]";
      break;
    }
    case MSG_SHARE_USER: {
      msg.messageType = "share_user";
      const name = content.str(3) || content.str(1);
      msg.text = name ? `[分享名片: ${name}]` : "[分享名片]";
      break;
    }
    default:
      msg.unsupported = true;
      break;
  }

  return msg;
}

/** Decode a single native Feishu Web protobuf Message record. */
export function decodeMessage(data: Uint8Array, ownerId: string): WebMessage {
  return decodeMessageInner(parseProto(data, MAX_WIRE_BYTES), ownerId, 0, { n: 0 });
}

export interface ChatMeta {
  id: string;
  name: string;
  kind: number;
  mode: number;
}

export function decodeChatRecord(data: Uint8Array, fallbackId = ""): ChatMeta {
  const f = parseProto(data, MAX_WIRE_BYTES);
  return {
    id: f.str(CHAT_ID_FIELD) || fallbackId,
    name: f.str(CHAT_NAME_FIELD),
    kind: f.uint(CHAT_KIND_FIELD),
    mode: f.uint(CHAT_MODE_FIELD),
  };
}
