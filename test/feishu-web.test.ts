/**
 * 飞书个人 Web 协议（从零 TypeScript 重新实现）全链路测试：
 *   - Protobuf wire 编解码、Cookie Jar + 域名白名单 + 0600 原子存储、纯 TS QR 编码
 *   - Frontier 帧（含 gzip）/ 网关包 / 富文本（含 @mention 偏移）/ 卡片 / 合并转发 / 回复包
 *   - 本地 Mock HTTP/WS 服务：QR 扫码登录、长连接推送 + 背压 ACK、心跳、3 次 401 退避进入 needs_login、
 *     readContext（最近窗口 + 话题锚点）、sendVerifiedReply（发送前核验 + 独立回读确认）
 *   - Working Context 集成：秒级快通道（@我 / 私聊）、自动预起草绝不自动发送、跨通道指纹去重（pw:* ↔ im:*）、
 *     确认草稿经 pw.reply 投递与 pa doctor 体检
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type net from "node:net";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import {
  ACCESS_KEY_SALT,
  authenticatedHeaders,
  beginLogin,
  BinaryWebSocket,
  CHAT_KIND_GROUP,
  CHAT_KIND_P2P,
  CHAT_KIND_TOPIC,
  CHAT_MODE_TOPIC,
  CHAT_MODE_TOPIC_THREAD,
  CMD_CHAT_MODE,
  CMD_HEARTBEAT,
  CMD_HISTORY,
  CMD_PUSH_PACKET,
  CMD_READ_MESSAGE,
  CMD_SEND_MESSAGE,
  decodeFrame,
  decodeMessage,
  encodeFrame,
  encodePacket,
  encodeQrMatrix,
  encodeReplyPacket,
  encodeRichText,
  FeishuWebClient,
  fetchWithJar,
  isAllowedFeishuHost,
  MSG_CARD,
  MSG_MERGE_FORWARD,
  MSG_POST,
  MSG_SHARE_CHAT,
  MSG_TEXT,
  normalizeNativeId,
  parseJsonPreserveNativeIds,
  parseProto,
  pollLogin,
  ProtoWireError,
  ProtoWriter,
  RecordingCookieJar,
  renderQrSvg,
  renderQrTerminal,
  replyInThread,
  SessionNeedsLoginError,
  unwrapGatewayPayload,
  USER_SENDER_TYPE,
  WebHttpError,
  WebLoginStore,
  type ListenerState,
  type WebEndpoints,
  type WebMessage,
} from "../src/context/feishu-web/index.ts";
import { ContextService } from "../src/context/index.ts";
import { BOUND_OWNER_KV_KEY, PersonalWebBridge, pwSpokenGroupsKey, verifyWorkspaceOwnerBinding } from "../src/context/personal-web.ts";
import { obsRevision } from "../src/context/store.ts";
import { runDoctor } from "../src/doctor.ts";
import { SettingsService } from "../src/settings.ts";
import { runProcess } from "../src/util.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test/stubs");
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const tmpDirs: string[] = [];
const makeTmp = (prefix: string) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
};
after(() => {
  for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
});

// ───────── 测试辅助：构造原生飞书 Protobuf 消息与本地 WS 服务端帧 ─────────

function buildNativeMessage(opts: {
  id: string;
  chatId: string;
  actorId: string;
  chatKind?: number;
  kind?: number;
  senderType?: number;
  createdAtSec?: number;
  text?: string;
  richBytes?: Buffer;
  contentBytes?: Buffer;
  rootId?: string;
  parentId?: string;
  threadId?: string;
  cid?: string;
  position?: number;
  sendToChat?: boolean;
}): Buffer {
  const kind = opts.kind ?? MSG_TEXT;
  let content = opts.contentBytes;
  if (!content) {
    const cw = new ProtoWriter();
    if (kind === MSG_TEXT) {
      if (opts.richBytes) cw.bytes(3, opts.richBytes);
      else cw.str(1, opts.text ?? "");
    } else if (kind === MSG_POST) {
      cw.str(1, "帖子标题");
      if (opts.richBytes) cw.bytes(6, opts.richBytes);
      else cw.str(2, opts.text ?? "");
    }
    content = cw.finish();
  }
  const w = new ProtoWriter()
    .str(1, opts.id)
    .uint(2, kind)
    .str(3, opts.actorId)
    .uint(4, opts.createdAtSec ?? Math.floor(Date.now() / 1000))
    .bytes(5, content)
    .uint(7, opts.senderType ?? USER_SENDER_TYPE)
    .str(10, opts.chatId)
    .uint(46, opts.chatKind ?? CHAT_KIND_GROUP);
  if (opts.rootId) w.str(8, opts.rootId);
  if (opts.parentId) w.str(9, opts.parentId);
  if (opts.cid) w.str(12, opts.cid);
  if (opts.position !== undefined) w.uint(13, opts.position);
  if (opts.threadId) w.str(20, opts.threadId);
  if (opts.sendToChat) w.uint(21, 1);
  return w.finish();
}

function buildGatewayResponse(payload: Buffer, status = 0): Buffer {
  const w = new ProtoWriter().uint(2, 1).uint(4, status);
  if (payload.length > 0) w.bytes(5, payload);
  return w.finish();
}

function buildServerWsFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  let head: Buffer;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

function parseClientWsFrames(buf: Buffer): { frames: { opcode: number; payload: Buffer }[]; rest: Buffer } {
  const frames: { opcode: number; payload: Buffer }[] = [];
  let pos = 0;
  while (buf.length - pos >= 2) {
    const opcode = buf[pos] & 0x0f;
    const masked = (buf[pos + 1] & 0x80) !== 0;
    let len = buf[pos + 1] & 0x7f;
    let off = pos + 2;
    if (len === 126) {
      if (buf.length - pos < 4) break;
      len = buf.readUInt16BE(pos + 2);
      off = pos + 4;
    } else if (len === 127) {
      if (buf.length - pos < 10) break;
      len = Number(buf.readBigUInt64BE(pos + 2));
      off = pos + 10;
    }
    const maskLen = masked ? 4 : 0;
    if (buf.length < off + maskLen + len) break;
    const payload = Buffer.from(buf.subarray(off + maskLen, off + maskLen + len));
    if (masked) {
      const mask = buf.subarray(off, off + 4);
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    }
    frames.push({ opcode, payload });
    pos = off + maskLen + len;
  }
  return { frames, rest: buf.subarray(pos) };
}

function buildPushFrame(sid: string, messages: Buffer[], gzip = false): Buffer {
  const push = new ProtoWriter();
  for (let i = 0; i < messages.length; i++) {
    const pair = new ProtoWriter().str(1, `m_${i}`).bytes(2, messages[i]).finish();
    push.bytes(1, pair);
  }
  const packet = new ProtoWriter()
    .str(1, sid)
    .uint(2, 1)
    .uint(3, CMD_PUSH_PACKET)
    .bytes(5, push.finish())
    .finish();
  if (!gzip) return encodeFrame(packet);
  const compressed = zlib.gzipSync(packet);
  return new ProtoWriter()
    .uint(1, Date.now())
    .uint(2, Date.now())
    .uint(3, 1)
    .uint(4, 1)
    .str(6, "gzip")
    .str(7, "pb")
    .bytes(8, compressed)
    .finish();
}

// ───────── 1. Protobuf Wire Codec ─────────

test("Protobuf wire 编解码：varint / bytes / repeated / 64 位时间戳 / 非法载荷拒绝", () => {
  const ts = 1795708970596n;
  const raw = new ProtoWriter()
    .uint(1, ts)
    .str(2, "你好飞书")
    .bytes(3, Buffer.from([1, 2, 3]))
    .str(4, "first")
    .str(4, "second")
    .uint(5, 0xffffffffn) // int32 = -1
    .finish();

  const f = parseProto(raw);
  assert.equal(f.uint64(1), ts);
  assert.equal(f.str(2), "你好飞书");
  assert.deepEqual(f.bytes(3), Buffer.from([1, 2, 3]));
  assert.equal(f.str(4), "second", "last-scalar-wins");
  assert.deepEqual(
    f.allBytes(4).map((b) => b.toString("utf8")),
    ["first", "second"],
  );
  assert.equal(f.int32(5), -1);

  assert.throws(() => parseProto(raw, 4), ProtoWireError, "超字节上限拒绝");
  assert.throws(() => parseProto(Buffer.from([0x0b])), ProtoWireError, "不支持的 wire type 3 拒绝");
  assert.throws(() => parseProto(Buffer.from([0x12, 0x05, 0x41])), ProtoWireError, "截断 bytes 拒绝");
});

// ───────── 2. Cookie Jar & 0600 凭据存储 ─────────

test("Cookie Jar：域名白名单、RFC 6265 匹配、轮换与删除、0600 原子落盘", () => {
  assert.equal(isAllowedFeishuHost("feishu.cn"), true);
  assert.equal(isAllowedFeishuHost("open-dev.feishu.cn"), true);
  assert.equal(isAllowedFeishuHost("internal-api-lark-api.feishu.cn"), true);
  assert.equal(isAllowedFeishuHost("meego.larkoffice.com"), true);
  assert.equal(isAllowedFeishuHost("feishu.cn.evil.com"), false);
  assert.equal(isAllowedFeishuHost("evil.com"), false);

  const jar = new RecordingCookieJar();
  const base = new URL("https://accounts.feishu.cn/accounts/qrlogin/init");
  jar.setFromHeaders(base, [
    "swp_csrf_token=tok_1; Domain=.feishu.cn; Path=/; Max-Age=3600",
    "host_only_c=abc; Path=/accounts",
    "bad_c=evil; Domain=.evil.com; Path=/",
    "session=s1; Domain=.feishu.cn; Path=/",
  ]);
  assert.equal(jar.cookieValue(new URL("https://accounts.feishu.cn/"), "swp_csrf_token"), "tok_1");
  assert.equal(jar.cookieValue(new URL("https://open-dev.feishu.cn/messenger/"), "session"), "s1");
  assert.equal(jar.cookieValue(new URL("https://open-dev.feishu.cn/accounts/x"), "host_only_c"), "", "host_only 不跨子域");
  assert.equal(jar.cookieValue(new URL("https://accounts.feishu.cn/accounts/x"), "host_only_c"), "abc");
  assert.ok(!jar.records().some((c) => c.name === "bad_c"), "拒绝非允许域名 Cookie");

  // 轮换 + Max-Age=0 删除
  jar.setFromHeaders(base, ["session=s2; Domain=.feishu.cn; Path=/", "swp_csrf_token=; Domain=.feishu.cn; Path=/; Max-Age=0"]);
  assert.equal(jar.cookieValue(new URL("https://open-dev.feishu.cn/"), "session"), "s2");
  assert.equal(jar.cookieValue(new URL("https://accounts.feishu.cn/"), "swp_csrf_token"), "");

  // 0600 原子持久化
  const dir = makeTmp("pa-pw-store-");
  const store = new WebLoginStore(dir);
  store.save({ owner_id: "7001", owner_name: "张三", cookies: jar.records() });
  const stat = fs.statSync(store.file);
  assert.equal(stat.mode & 0o777, 0o600, "凭据文件权限必须为 0600");
  const loaded = store.load()!;
  assert.equal(loaded.owner_id, "7001");
  assert.equal(loaded.owner_name, "张三");
  assert.ok(loaded.cookies.some((c) => c.name === "session" && c.value === "s2"));
  store.clear();
  assert.equal(store.load(), undefined);
});

// ───────── 3. 纯 TypeScript QR 编码器 ─────────

test("QR 编码器：生成合规矩阵、终端半块字符与 SVG", () => {
  const payload = JSON.stringify({ qrlogin: { token: "tok_9f8e7d6c5b4a3210fedcba9876543210" } });
  const m = encodeQrMatrix(payload);
  assert.ok(m.size >= 29 && m.size <= 57);
  // 左上 / 右上 / 左下 7x7 定位符中心 3x3 必为暗块
  assert.equal(m.modules[3 * m.size + 3], 1);
  assert.equal(m.modules[3 * m.size + (m.size - 4)], 1);
  assert.equal(m.modules[(m.size - 4) * m.size + 3], 1);
  // 固定暗模块 (size - 8, 8)
  assert.equal(m.modules[(m.size - 8) * m.size + 8], 1);
  // 两份格式信息位镜像校验（确保左下角位序正确）
  for (let i = 0; i <= 5; i++) {
    assert.equal(m.modules[8 * m.size + i], m.modules[(m.size - 1 - i) * m.size + 8], `format bit ${14 - i}`);
  }
  const term = renderQrTerminal(payload);
  assert.ok(term.includes("█") && term.split("\n").length > 10);
  const svg = renderQrSvg(payload);
  assert.match(svg, /^<\?xml.*<svg.*<\/svg>\n$/s);
});

// ───────── 4. Wire Codec（消息、@mention 偏移、卡片、转发、回复、gzip 帧） ─────────

test("Wire Codec：文本 / 富文本 @mention / 帖子 / 卡片 / 合并转发 / gzip 帧 / 回复包", () => {
  // 1) 富文本编码与解码 + 精确 mention 偏移
  const rich = encodeRichText([
    { text: "hi " },
    { text: "@张三", mentionId: "7001" },
    { text: " 帮看下 ", bold: true },
    { text: "设计稿", url: "https://example.feishu.cn/docx/1" },
  ]);
  const msgBytes = buildNativeMessage({
    id: "9001",
    chatId: "8001",
    actorId: "7002",
    chatKind: CHAT_KIND_GROUP,
    kind: MSG_TEXT,
    richBytes: rich,
    position: 42,
  });
  const decoded = decodeMessage(msgBytes, "7001");
  assert.equal(decoded.id, "9001");
  assert.equal(decoded.conversationKind, "group");
  assert.equal(decoded.text, "hi @张三 帮看下 设计稿");
  assert.equal(decoded.mentions.length, 1);
  assert.equal(decoded.mentions[0].id, "7001");
  assert.equal(decoded.mentions[0].name, "张三");
  assert.equal(decoded.text.slice(decoded.mentions[0].start, decoded.mentions[0].end), "@张三");
  assert.equal(decoded.position, 42);

  // 2) 帖子 + 卡片 + 合并转发 + 分享群聊
  const postMsg = decodeMessage(
    buildNativeMessage({ id: "9002", chatId: "8001", actorId: "7002", kind: MSG_POST, text: "正文内容" }),
    "7001",
  );
  assert.equal(postMsg.messageType, "post");
  assert.equal(postMsg.text, "帖子标题\n正文内容");

  const cardContent = new ProtoWriter()
    .str(20, JSON.stringify({ header: { title: { content: "Meego 提醒" } }, elements: [{ text: "请处理节点" }] }))
    .finish();
  const cardMsg = decodeMessage(
    buildNativeMessage({ id: "9003", chatId: "8001", actorId: "bot_1", senderType: 2, kind: MSG_CARD, contentBytes: cardContent }),
    "7001",
  );
  assert.equal(cardMsg.messageType, "interactive");
  assert.match(cardMsg.text, /Meego 提醒.*请处理节点/);

  const fwdContent = new ProtoWriter().bytes(1, msgBytes).finish();
  const fwdMsg = decodeMessage(
    buildNativeMessage({ id: "9004", chatId: "8001", actorId: "7002", kind: MSG_MERGE_FORWARD, contentBytes: fwdContent }),
    "7001",
  );
  assert.match(fwdMsg.text, /\[合并转发\].*@张三/s);

  const shareEntity = new ProtoWriter().str(1, "8888").str(4, "发布协同群").finish();
  const shareContent = new ProtoWriter().bytes(1, shareEntity).str(4, "8888").finish();
  const shareMsg = decodeMessage(
    buildNativeMessage({ id: "9005", chatId: "8001", actorId: "7002", kind: MSG_SHARE_CHAT, contentBytes: shareContent }),
    "7001",
  );
  assert.equal(shareMsg.text, "[分享群聊: 发布协同群]");

  // 3) replyInThread 规则
  assert.equal(replyInThread(CHAT_KIND_P2P, 0), true);
  assert.equal(replyInThread(CHAT_KIND_GROUP, 0), true);
  assert.equal(replyInThread(CHAT_KIND_GROUP, CHAT_MODE_TOPIC), false);
  assert.equal(replyInThread(CHAT_KIND_TOPIC, CHAT_MODE_TOPIC_THREAD), false);

  // 4) gzip 帧解包 + 回复包验证
  const gzFrame = buildPushFrame("sid_gz_1", [msgBytes], true);
  const pkt = decodeFrame(gzFrame);
  assert.equal(pkt.str(1), "sid_gz_1");
  assert.equal(pkt.uint(3), CMD_PUSH_PACKET);

  const replyPkt = parseProto(encodeReplyPacket("8001", "9001", "cid_fixed_1", [{ text: "收到，下午处理" }], true));
  assert.equal(replyPkt.uint(3), CMD_SEND_MESSAGE);
  assert.equal(replyPkt.str(6), "cid_fixed_1");
  const req = parseProto(replyPkt.bytes(5));
  assert.equal(req.str(3), "8001");
  assert.equal(req.str(4), "9001");
  assert.equal(req.uint(12), 1, "inThread=true 应设置 field 12");
});

// ───────── 5. 本地 Mock 服务器：QR 登录、长连接推送 + 背压 ACK、心跳、3 次 401、readContext、sendVerifiedReply ─────────

interface MockWebServer {
  endpoints: WebEndpoints;
  pushMessage: (sid: string, msgs: Buffer[], gzip?: boolean) => void;
  pushChunkedFrame: (sid: string, msgs: Buffer[], chunkSize: number) => Promise<void>;
  pushRawBytes: (raw: Buffer) => void;
  closeSockets: () => void;
  close: () => Promise<void>;
  acks: string[];
  heartbeats: number;
  chatModeCalls: string[];
  sentReplies: { chatId: string; rootId: string; parentId: string; cid: string; text: string; inThread: boolean }[];
  wsHeaders: http.IncomingHttpHeaders[];
  wsQueries: URLSearchParams[];
  setProfileStatus: (status: number) => void;
  setProfileStatuses: (seq: number[]) => void;
  setProfileUser: (id: string, name: string) => void;
  setMessengerStatus: (status: number) => void;
  setTicketStatus: (status: number) => void;
  setWsUpgradeStatus: (status: number) => void;
  setChatModeFail: (fail: boolean) => void;
  setOnChatMode: (fn: (() => void) | undefined) => void;
  setOnHistory: (fn: (() => void) | undefined) => void;
  setChatName: (chatId: string, name: string) => void;
  setChatMode: (chatId: string, mode: number) => void;
  setSendStatus: (status: number) => void;
  setSendEmptyPayload: (on: boolean) => void;
  setGatewayRotateCookie: (val: string) => void;
  setRedirectEvil: (on: boolean) => void;
  setTamperReadback: (on: boolean) => void;
  setFailReadbackCount: (n: number) => void;
  addMessage: (id: string, data: Buffer) => void;
  setHistory: (chatId: string, byPos: Record<number, Buffer>) => void;
}

async function startMockFeishuWebServer(): Promise<MockWebServer> {
  let pollCount = 0;
  let profileStatus = 200;
  let profileStatusSeq: number[] = [];
  let profileUser = { id: "7001", name: "张三" };
  let messengerStatus = 200;
  let ticketStatus = 200;
  let wsUpgradeStatus = 101;
  let chatModeFail = false;
  let onChatMode: (() => void) | undefined;
  let onHistory: (() => void) | undefined;
  const customChatNames = new Map<string, string>();
  const customChatModes = new Map<string, number>();
  const chatModeCalls: string[] = [];
  let sendStatus = 200;
  let sendEmptyPayload = false;
  let gatewayRotateCookie = "";
  let redirectEvil = false;
  let tamperReadback = false;
  let failReadbackCount = 0;
  const acks: string[] = [];
  let heartbeats = 0;
  const sentReplies: MockWebServer["sentReplies"] = [];
  const wsHeaders: http.IncomingHttpHeaders[] = [];
  const wsQueries: URLSearchParams[] = [];
  const messages = new Map<string, Buffer>();
  const historyByChat = new Map<string, Record<number, Buffer>>();
  const activeSockets = new Set<net.Socket>();
  let nextReplySeq = 1;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    const body = Buffer.concat(chunks);

    if (url.pathname === "/messenger/") {
      if (redirectEvil) {
        res.writeHead(302, { Location: "https://evil.example.com/steal" });
        res.end();
        return;
      }
      if (messengerStatus !== 200) {
        res.writeHead(messengerStatus);
        res.end("service unavailable");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/html",
        "X-Proxy-Unit": "pu-1",
        "Set-Cookie": "passport_web_did=did_test_123; Path=/",
      });
      res.end(`<script>window.passport_web_did = "did_test_123"; var cfg = { appKey: "appkey_xyz" };</script>`);
      return;
    }

    if (url.pathname === "/accounts/qrlogin/init") {
      assert.equal(req.headers["x-web-id"], "did_test_123");
      res.writeHead(200, {
        "Content-Type": "application/json",
        "X-Flow-Key": "flow_1",
        "X-Proxy-Unit": "pu-2",
        "Set-Cookie": "swp_csrf_token=csrf_abc; Path=/",
      });
      res.end(JSON.stringify({ code: 0, data: { step_info: { token: "qr_tok_999" } } }));
      return;
    }

    if (url.pathname === "/accounts/qrlogin/polling") {
      pollCount++;
      if (pollCount === 1) {
        // 模拟限流页 / 非 JSON 响应：客户端应忽略不覆盖状态并重试
        res.writeHead(200, { "Content-Type": "text/html", "X-Flow-Key": "corrupted_should_ignore" });
        res.end("<html>busy</html>");
        return;
      }
      if (pollCount === 2) {
        assert.equal(req.headers["x-flow-key"], "flow_1");
        res.writeHead(200, { "Content-Type": "application/json", "X-Flow-Key": "flow_2" });
        res.end(JSON.stringify({ code: 0, data: { step_info: { status: 2 }, next_step: "qr_login_polling" } }));
        return;
      }
      assert.equal(req.headers["x-flow-key"], "flow_2");
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "session=sess_live_1; Path=/; Max-Age=86400",
      });
      res.end(JSON.stringify({ code: 0, data: { step_info: { status: 0, front_user_id: "7001" }, next_step: "enter_app" } }));
      return;
    }

    if (url.pathname === "/accounts/web/user") {
      const effectiveStatus = profileStatusSeq.length > 0 ? profileStatusSeq.shift()! : profileStatus;
      if (effectiveStatus !== 200) {
        res.writeHead(effectiveStatus, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: effectiveStatus }));
        return;
      }
      assert.equal(req.headers["x-app-id"], "12");
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "session=sess_rotated_2; Path=/; Max-Age=86400",
      });
      res.end(JSON.stringify({ code: 0, data: { user: profileUser } }));
      return;
    }

    if (url.pathname === "/suite/passport/frontier_ticket/") {
      if (ticketStatus !== 200) {
        res.writeHead(ticketStatus, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: ticketStatus }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ code: 0, ticket: "ticket_live_42" }));
      return;
    }

    if (url.pathname === "/im/gateway/") {
      const pkt = parseProto(body);
      const cmd = pkt.uint(3);
      const payload = parseProto(pkt.bytes(5));
      const gwHeaders: Record<string, string> = { "Content-Type": "application/x-protobuf" };
      if (gatewayRotateCookie) gwHeaders["Set-Cookie"] = `session=${gatewayRotateCookie}; Path=/; Max-Age=86400`;
      if (cmd === CMD_READ_MESSAGE) {
        const id = payload.str(1);
        if (failReadbackCount > 0 && id.startsWith("reply_")) {
          failReadbackCount--;
          res.writeHead(503);
          res.end();
          return;
        }
        const found = messages.get(id);
        const resp = new ProtoWriter();
        if (found) resp.bytes(1, new ProtoWriter().str(1, id).bytes(2, found).finish());
        res.writeHead(200, gwHeaders);
        res.end(buildGatewayResponse(resp.finish()));
        return;
      }
      if (cmd === CMD_CHAT_MODE) {
        onChatMode?.();
        const chatId = payload.str(1);
        chatModeCalls.push(chatId);
        if (chatModeFail) {
          res.writeHead(500);
          res.end();
          return;
        }
        const chatName =
          customChatNames.get(chatId) ??
          (chatId.startsWith("dm_") ? "" : chatId === "8002" ? "未列入的群" : chatId === "8003" ? "绝密群" : "Ark 发布协同群");
        const chatRec = new ProtoWriter()
          .str(1, chatId)
          .uint(2, chatId.startsWith("dm_") ? CHAT_KIND_P2P : CHAT_KIND_GROUP)
          .str(4, chatName)
          .uint(39, customChatModes.get(chatId) ?? 0)
          .finish();
        const resp = new ProtoWriter().bytes(1, new ProtoWriter().str(1, chatId).bytes(2, chatRec).finish()).finish();
        res.writeHead(200, gwHeaders);
        res.end(buildGatewayResponse(resp));
        return;
      }
      if (cmd === CMD_HISTORY) {
        onHistory?.();
        const chatId = payload.str(1);
        const byPos = historyByChat.get(chatId) ?? {};
        const resp = new ProtoWriter();
        for (const p of payload.allUints(2)) {
          const m = byPos[Number(p)];
          if (m) resp.bytes(1, new ProtoWriter().str(1, String(p)).bytes(2, m).finish());
        }
        res.writeHead(200, gwHeaders);
        res.end(buildGatewayResponse(resp.finish()));
        return;
      }
      if (cmd === CMD_SEND_MESSAGE) {
        if (sendStatus !== 200) {
          res.writeHead(sendStatus);
          res.end();
          return;
        }
        if (sendEmptyPayload) {
          res.writeHead(200, gwHeaders);
          res.end(buildGatewayResponse(Buffer.alloc(0), 0));
          return;
        }
        const content = parseProto(payload.bytes(2));
        const rich = parseProto(content.bytes(14));
        const text = rich.str(2);
        const chatId = payload.str(3);
        const rootId = payload.str(4);
        const parentId = payload.str(5) || rootId;
        const cid = payload.str(6);
        const inThread = payload.uint(12) === 1;
        sentReplies.push({ chatId, rootId, parentId, cid, text, inThread });

        const replyId = `reply_${nextReplySeq++}`;
        const created = buildNativeMessage({
          id: replyId,
          chatId,
          actorId: profileUser.id,
          chatKind: chatId.startsWith("dm_") ? CHAT_KIND_P2P : CHAT_KIND_GROUP,
          kind: MSG_TEXT,
          text: tamperReadback ? "被篡改的正文" : text,
          rootId,
          parentId,
          threadId: inThread ? `th_${rootId}` : "",
          cid,
        });
        messages.set(replyId, created);
        const resp = new ProtoWriter().bytes(1, created).finish();
        res.writeHead(200, gwHeaders);
        res.end(buildGatewayResponse(resp));
        return;
      }
      res.writeHead(400);
      res.end();
      return;
    }

    res.writeHead(404);
    res.end();
  });

  server.on("upgrade", (req, socket: net.Socket, head) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    wsHeaders.push(req.headers);
    wsQueries.push(url.searchParams);
    if (wsUpgradeStatus !== 101) {
      socket.write(`HTTP/1.1 ${wsUpgradeStatus} Denied\r\nContent-Length: 0\r\n\r\n`);
      socket.end();
      return;
    }
    const key = String(req.headers["sec-websocket-key"] ?? "");
    const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    activeSockets.add(socket);
    let rx: Buffer = head.length ? Buffer.from(head) : Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      rx = Buffer.concat([rx, chunk]);
      const parsed = parseClientWsFrames(rx);
      rx = parsed.rest;
      for (const f of parsed.frames) {
        if (f.opcode === 0x8) {
          socket.end();
          continue;
        }
        if (f.opcode !== 0x2) continue;
        try {
          const pkt = decodeFrame(f.payload);
          if (pkt.uint(3) === CMD_HEARTBEAT) heartbeats++;
          else if (pkt.str(1) && pkt.uint(2) === 1 && pkt.uint(3) === 1) acks.push(pkt.str(1));
        } catch {
          // ignore
        }
      }
    });
    socket.on("close", () => activeSockets.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  return {
    endpoints: {
      messengerUrl: `${base}/messenger/`,
      qrInitUrl: `${base}/accounts/qrlogin/init`,
      qrPollUrl: `${base}/accounts/qrlogin/polling`,
      qrRedirectUri: `${base}/next/messenger`,
      profileUrl: `${base}/accounts/web/user?app_id=12`,
      gatewayUrl: `${base}/im/gateway/`,
      ticketUrl: `${base}/suite/passport/frontier_ticket/`,
      websocketUrl: `ws://127.0.0.1:${addr.port}/ws/v2`,
      accountsOrigin: base,
      accountsReferer: `${base}/accounts/page/login?app_id=1`,
      messengerOrigin: base,
      allowInsecureHttp: true,
      extraAllowedHosts: ["127.0.0.1"],
    },
    pushMessage: (sid, msgs, gzip = false) => {
      const frame = buildServerWsFrame(0x2, buildPushFrame(sid, msgs, gzip));
      for (const s of activeSockets) s.write(frame);
    },
    pushChunkedFrame: async (sid, msgs, chunkSize) => {
      const frame = buildServerWsFrame(0x2, buildPushFrame(sid, msgs, false));
      for (let off = 0; off < frame.length; off += chunkSize) {
        const slice = frame.subarray(off, Math.min(frame.length, off + chunkSize));
        for (const s of activeSockets) s.write(slice);
        await new Promise((r) => setTimeout(r, 1));
      }
    },
    pushRawBytes: (raw) => {
      for (const s of activeSockets) s.write(raw);
    },
    closeSockets: () => {
      for (const s of activeSockets) s.destroy();
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of activeSockets) s.destroy();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
    acks,
    get heartbeats() {
      return heartbeats;
    },
    chatModeCalls,
    sentReplies,
    wsHeaders,
    wsQueries,
    setProfileStatus: (s) => {
      profileStatus = s;
    },
    setProfileStatuses: (seq) => {
      profileStatusSeq = [...seq];
    },
    setProfileUser: (id, name) => {
      profileUser = { id, name };
    },
    setMessengerStatus: (s) => {
      messengerStatus = s;
    },
    setTicketStatus: (s) => {
      ticketStatus = s;
    },
    setWsUpgradeStatus: (s) => {
      wsUpgradeStatus = s;
    },
    setChatModeFail: (f) => {
      chatModeFail = f;
    },
    setOnChatMode: (fn) => {
      onChatMode = fn;
    },
    setOnHistory: (fn) => {
      onHistory = fn;
    },
    setChatName: (chatId, name) => {
      customChatNames.set(chatId, name);
    },
    setChatMode: (chatId, mode) => {
      customChatModes.set(chatId, mode);
    },
    setSendStatus: (s) => {
      sendStatus = s;
    },
    setSendEmptyPayload: (on) => {
      sendEmptyPayload = on;
    },
    setGatewayRotateCookie: (v) => {
      gatewayRotateCookie = v;
    },
    setRedirectEvil: (on) => {
      redirectEvil = on;
    },
    setTamperReadback: (on) => {
      tamperReadback = on;
    },
    setFailReadbackCount: (n) => {
      failReadbackCount = n;
    },
    addMessage: (id, data) => messages.set(id, data),
    setHistory: (chatId, byPos) => historyByChat.set(chatId, byPos),
  };
}

test("QR 登录全流程：bootstrap → init → 容忍限流页 → scanned → approved → 账号校验 → 拒绝非法重定向", async () => {
  const mock = await startMockFeishuWebServer();
  try {
    // 非法跨站重定向应被拒绝
    mock.setRedirectEvil(true);
    await assert.rejects(beginLogin({ endpoints: mock.endpoints }), (e: unknown) => e instanceof WebHttpError && e.code === "redirect_rejected");
    mock.setRedirectEvil(false);

    const challenge = await beginLogin({ endpoints: mock.endpoints });
    assert.equal(challenge.webId, "did_test_123");
    assert.equal(challenge.flowKey, "flow_1");
    assert.equal(challenge.qrCode, JSON.stringify({ qrlogin: { token: "qr_tok_999" } }));

    const progress: string[] = [];
    const login = await pollLogin(challenge, {
      endpoints: mock.endpoints,
      pollIntervalMs: 10,
      onProgress: (s) => progress.push(s),
    });
    assert.deepEqual(progress, ["scanned", "approved"]);
    assert.equal(login.owner_id, "7001");
    assert.equal(login.owner_name, "张三");
    assert.ok(login.cookies.some((c) => c.name === "session" && c.value === "sess_rotated_2"), "应记录轮换后的最新 session cookie");
  } finally {
    await mock.close();
  }
});

test("客户端全链路：连接签名、gzip 推送 + 背压 ACK、心跳、readContext、sendVerifiedReply、3 次 401 进入 needs_login", async () => {
  const mock = await startMockFeishuWebServer();
  try {
    const rotatedLogins: string[] = [];
    const client = await FeishuWebClient.connect(
      {
        owner_id: "7001",
        owner_name: "张三",
        cookies: [
          { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
          { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
        ],
      },
      {
        endpoints: mock.endpoints,
        onSessionConfirmed: (l) => {
          const s = l.cookies.find((c) => c.name === "session")?.value ?? "";
          if (s) rotatedLogins.push(s);
        },
        heartbeatIntervalMs: 40,
        socketIdleTimeoutMs: 5_000,
        reconnectBaseMs: 20,
        reconnectCeilingMs: 40,
        sessionDenialThreshold: 3,
        sessionDenialRetryMs: 15,
      },
    );
    assert.ok(rotatedLogins.includes("sess_rotated_2"), "连接核验后持久化轮换的 Cookie");

    // 1) readChat + readContext（最近窗口 + 话题锚点）
    const chat = await client.readChat("8001");
    assert.equal(chat.name, "Ark 发布协同群");
    assert.equal(chat.kind, CHAT_KIND_GROUP);

    const nowSec = Math.floor(Date.now() / 1000);
    const m1 = buildNativeMessage({ id: "m_1", chatId: "8001", actorId: "7002", text: "第一条背景", position: 10, createdAtSec: nowSec - 60 });
    const m2 = buildNativeMessage({ id: "m_2", chatId: "8001", actorId: "7001", text: "第二条背景", position: 11, createdAtSec: nowSec - 30 });
    mock.setHistory("8001", { 10: m1, 11: m2 });
    const hist = await client.readContext({
      id: "m_3",
      conversationId: "8001",
      rootId: "",
      parentId: "",
      threadId: "",
      position: 12,
      createdAtMs: nowSec * 1000,
    });
    assert.deepEqual(
      hist.map((m) => m.id),
      ["m_1", "m_2"],
    );

    // 话题锚点
    mock.addMessage("m_root", buildNativeMessage({ id: "m_root", chatId: "8001", actorId: "7002", text: "根话题", position: 1, createdAtSec: nowSec - 120 }));
    const topicHist = await client.readContext({
      id: "m_child",
      conversationId: "8001",
      rootId: "m_root",
      parentId: "m_root",
      threadId: "th_1",
      position: 2,
      createdAtMs: nowSec * 1000,
    });
    assert.deepEqual(
      topicHist.map((m) => m.id),
      ["m_root"],
    );

    // 2) sendVerifiedReply（正常回读通过 + 篡改回读失败）
    mock.addMessage("orig_1", buildNativeMessage({ id: "orig_1", chatId: "8001", actorId: "7002", text: "@张三 请确认", position: 20 }));
    const rep = await client.sendVerifiedReply({
      chatId: "8001",
      messageId: "orig_1",
      text: "收到，下午发你方案。",
      cid: "cid_verify_ok_01",
    });
    assert.equal(rep.verified, true);
    assert.equal(rep.rootId, "orig_1");
    assert.equal(mock.sentReplies.at(-1)!.inThread, true);

    mock.setTamperReadback(true);
    await assert.rejects(
      client.sendVerifiedReply({ chatId: "8001", messageId: "orig_1", text: "会被篡改", cid: "cid_verify_bad_02" }),
      /回读校验未通过/,
    );
    mock.setTamperReadback(false);

    // 3) Frontier WSS 长连接：签名、心跳、gzip 推送 + 严格背压 ACK
    const ctrl = new AbortController();
    const states: ListenerState[] = [];
    const received: WebMessage[] = [];
    let failNext = true;

    const listenDone = client.listen({
      signal: ctrl.signal,
      onState: (s) => states.push(s),
      onMessage: async (m) => {
        if (failNext) {
          failNext = false;
          throw new Error("simulated sqlite lock");
        }
        received.push(m);
      },
    });

    // 等进入 listening
    await waitUntil(() => states.includes("listening"));
    // 验证握手头与 access_key 签名
    const expectedKey = crypto.createHash("md5").update(`2appkey_xyzdid_test_123${ACCESS_KEY_SALT}`).digest("hex");
    assert.equal(mock.wsQueries[0].get("access_key"), expectedKey);
    assert.equal(mock.wsQueries[0].get("ticket"), "ticket_live_42");
    assert.equal(mock.wsHeaders[0].origin, mock.endpoints.messengerOrigin);

    // 推送 1：onMessage 抛错 → 绝不能 ACK，状态切到 publication_blocked
    const pushMsg1 = buildNativeMessage({
      id: "push_1",
      chatId: "8001",
      actorId: "7002",
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 背压测试" }]),
      position: 50,
    });
    mock.pushMessage("sid_fail_1", [pushMsg1], true);
    await waitUntil(() => states.includes("publication_blocked"));
    await new Promise((r) => setTimeout(r, 40));
    assert.ok(!mock.acks.includes("sid_fail_1"), "落库失败绝不发送 ACK");

    // 推送 2：onMessage 成功 → 必须 ACK 且恢复 listening
    const pushMsg2 = buildNativeMessage({
      id: "push_2",
      chatId: "8001",
      actorId: "7002",
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 正常推送" }]),
      position: 51,
    });
    mock.pushMessage("sid_ok_2", [pushMsg2], true);
    await waitUntil(() => mock.acks.includes("sid_ok_2"));
    assert.equal(received.length, 1);
    assert.equal(received[0].id, "push_2");
    assert.equal(received[0].mentions[0].id, "7001");
    assert.equal(states.at(-1), "listening");

    // 验证心跳帧已发出
    await waitUntil(() => mock.heartbeats >= 1);
    ctrl.abort();
    await listenDone;

    // 4) 3 次连续 401 → 两次 reverifying → 第 3 次 needs_login 退出
    mock.setProfileStatus(401);
    const denialStates: ListenerState[] = [];
    const ctrl2 = new AbortController();
    await assert.rejects(
      client.listen({
        signal: ctrl2.signal,
        onState: (s) => denialStates.push(s),
        onMessage: () => undefined,
      }),
      (e: unknown) => e instanceof WebHttpError && e.code === "credential_denied",
    );
    assert.equal(denialStates.filter((s) => s === "reverifying").length, 2);
    assert.equal(denialStates.at(-1), "needs_login");
  } finally {
    await mock.close();
  }
});

// ───────── 6. Working Context 集成：快通道、跨通道去重、确认后 pw.reply、pa doctor ─────────

test("Working Context 集成：个人 Web @我 秒级快通道 + 预起草不自动发 + 跨通道指纹去重 + 确认经 pw.reply 投递 + doctor", async () => {
  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-pw-ctx-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevCtxDir = process.env.CTX_DIR;
  process.env.CTX_DIR = ctxDir;

  const cfgFile = path.join(dir, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
      harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner" },
      cards: { enabled: true },
      engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 2 },
      context: {
        harness: "cx",
        groups_deny: ["9999"],
        personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
      },
    }),
  );

  let app: ReturnType<typeof createApp> | undefined;
  try {
    app = createApp(loadConfig(cfgFile));
    // 1) 未登录时 doctor 报 warn
    const doc1 = await runDoctor(app);
    const pwCheck1 = doc1.checks.find((c) => c.id === "personal_web")!;
    assert.equal(pwCheck1.status, "warn");
    assert.match(pwCheck1.detail, /尚未扫码登录/);

    // 写入登录凭据
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    loginStore.save({
      owner_id: "7001",
      owner_name: "张三",
      cookies: [
        { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
        { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
      ],
    });
    const doc2 = await runDoctor(app);
    assert.equal(doc2.checks.find((c) => c.id === "personal_web")!.status, "ok");

    // 2) 建立带 mock endpoints 的 live client 并模拟 @我 推送进入快通道
    const svc = new ContextService(app);
    // 用带 mock endpoints 的 bridge 覆盖 effectHooks 以便测试 pw.reply
    const client = await FeishuWebClient.connect(loginStore.load()!, { endpoints: mock.endpoints });
    app.effectHooks.pwReply = async (args) => {
      await client.sendVerifiedReply({
        chatId: args.chat_id,
        messageId: args.message_id,
        rootId: args.root_id,
        text: args.text,
        cid: args.cid,
      });
    };

    const nowSec = Math.floor(Date.now() / 1000);
    const rawMsg = buildNativeMessage({
      id: "pw_msg_100",
      chatId: "8001",
      actorId: "7002",
      chatKind: CHAT_KIND_GROUP,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 线上接口 500 帮忙立刻看下" }]),
      createdAtSec: nowSec,
      position: 88,
    });
    mock.addMessage("pw_msg_100", rawMsg);

    fs.writeFileSync(
      path.join(ctxDir, "understand.json"),
      JSON.stringify({
        projects: [{ name: "Ark 网关", stage: "线上运行" }],
        items: [
          {
            title: "排查线上接口 500 告警",
            kind: "ask_me",
            project: "Ark 网关",
            priority: "high",
            counterpart: "7002",
            next_step: "查看网关错误日志并回复排查进展",
            confidence: 0.95,
            evidence: [{ obs_id: "pw:pw_msg_100", quote: "线上接口 500 帮忙立刻看下" }],
          },
        ],
      }),
    );
    fs.writeFileSync(path.join(ctxDir, "draft.txt"), "收到，我正在看网关日志，10 分钟内同步结论。");

    const decoded = decodeMessage(rawMsg, "7001");
    await svc.personalWeb.handleMessage(decoded, client);

    // 不跑 pullAll 周期，直接 drain 快通道作业 + 预起草作业 + 提醒卡片
    await app.engine.drain(["context", "effect"]);

    const it = app.ext.context!.items({ status: "open" }).find((i) => i.title === "排查线上接口 500 告警")!;
    assert.ok(it, "快通道立即生成事项");
    assert.equal(mock.sentReplies.length, 0, "即使开启 pre_draft 也绝不自动回复");

    const drafts = app.ext.context!.drafts("proposed");
    assert.equal(drafts.length, 1, "自动生成一份待确认回复草稿");
    assert.match(drafts[0].target_label, /个人 Web/);

    // 验证提醒卡片已发出
    const nudgeFx = app.ledger.list({ kinds: ["effect"], ref: `card:ctx-item:${it.id}`, limit: 10 });
    assert.ok(nudgeFx.length >= 1, "快通道高优先级事项立刻发提醒卡片");

    // 3) 用户显式确认草稿（尚未补齐开放平台 ID）→ 经 pw.reply 投递（带回读校验）→ 状态变为 sent
    //    先模拟回读连续失败 2 次（耗尽 effect_attempts=2 让草稿进入 failed），验证用户重新批准同一草稿时
    //    复用相同 CID、不重发第二条，只补做独立回读并变为 sent！
    mock.setFailReadbackCount(2);
    const bridgeWithMock = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    app.effectHooks.pwReply = async (args) => {
      await bridgeWithMock.sendVerifiedReply(args);
    };
    await app.commands.exec("context.draft_approve", { id: drafts[0].id }, { source: "web", actor: "owner" });
    await app.engine.drain(["effect"]);
    await new Promise((r) => setTimeout(r, 40));
    await app.engine.drain(["effect"]);
    assert.equal(mock.sentReplies.length, 1, "首次发出后即使引擎重试也绝不重发第二条");
    assert.equal(app.ext.context!.drafts("failed").find((d) => d.id === drafts[0].id)?.status, "failed");

    // 再次确认同一草稿（新 effect ID）：必须复用同一个 CID，只跑独立回读，绝不再发第二条！
    await app.commands.exec("context.draft_approve", { id: drafts[0].id }, { source: "web", actor: "owner" });
    await app.engine.drain(["effect"]);
    assert.equal(mock.sentReplies.length, 1, "重新批准同一草稿也绝不发送第二条重复消息");
    assert.equal(mock.sentReplies[0].chatId, "8001");
    assert.equal(mock.sentReplies[0].rootId, "pw_msg_100");
    assert.equal(mock.sentReplies[0].parentId, "pw_msg_100");
    assert.equal(mock.sentReplies[0].text, "收到，我正在看网关日志，10 分钟内同步结论。");
    assert.equal(app.ext.context!.drafts("sent").find((d) => d.id === drafts[0].id)?.status, "sent");

    // 4) 严格按原生主键索引存储（pw:* 与 im:* 独立，不做跨通道启发式合并），且同 ID 编辑原地更新
    const added = svc.store.addObs([
      {
        id: "im:om_open_100",
        source: "im",
        kind: "at_me",
        conv: "oc_open_8001",
        conv_name: "Ark 发布协同群",
        actor_id: "ou_li",
        actor_name: "李四",
        is_me: false,
        time: nowSec * 1000 + 2_000,
        text: "@张三 线上接口 500 帮忙立刻看下",
        url: "https://applink.feishu.cn/client/chat/open?openChatId=oc_open_8001",
        meta: { message_id: "om_open_100", chat_type: "group" },
      },
    ]);
    assert.equal(added, 1, "开放平台与个人 Web 观测保持各自原生主键独立");
    assert.equal(svc.store.obs("pw:pw_msg_100")?.conv, "pw_chat:8001");
    assert.equal(svc.store.obs("im:om_open_100")?.conv, "oc_open_8001");

    // 同一 ID 投递编辑更新：原地更新正文并重新标为待处理，不产生重复行
    const edited = svc.store.addObs([
      {
        id: "pw:pw_msg_100",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:8001",
        conv_name: "Ark 发布协同群",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: nowSec * 1000,
        text: "@张三 线上接口 500 已定位到网关超时，帮忙确认下回滚",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "pw_msg_100", native_chat_id: "8001", chat_type: "group" },
      },
    ]);
    assert.equal(edited, 1);
    assert.match(svc.store.obs("pw:pw_msg_100")!.text, /已定位到网关超时/);
    assert.equal(svc.store.obsPending("pw:pw_msg_100"), true);
    // 5) 过滤边界：本人回显 / 禁用群 / 非白名单机器人不触发快通道；对方私聊触发快通道
    const fastBefore = app.ledger.list({ kinds: ["context"], ref: "fast", limit: 50 }).length;
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_self_1", chatId: "8001", actorId: "7001", text: "我自己发的" }), "7001"),
      client,
    );
    await svc.personalWeb.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "pw_deny_1",
          chatId: "9999",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 禁用群" }]),
        }),
        "7001",
      ),
      client,
    );
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_bot_drop", chatId: "8001", actorId: "bot_ci", senderType: 2, text: "Jenkins build ok" }), "7001"),
      client,
    );
    assert.equal(svc.store.obs("pw:pw_deny_1"), undefined, "禁用群消息不入库");
    assert.equal(svc.store.obs("pw:pw_bot_drop"), undefined, "非白名单机器人噪音丢弃");
    assert.equal(app.ledger.list({ kinds: ["context"], ref: "fast", limit: 50 }).length, fastBefore, "回显与噪音不触发快通道");

    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_dm_1", chatId: "dm_7003", actorId: "7003", chatKind: CHAT_KIND_P2P, text: "在吗，帮看下权限" }), "7001"),
      client,
    );
    assert.equal(app.ledger.list({ kinds: ["context"], ref: "fast", limit: 50 }).length, fastBefore + 1, "对方私聊立即触发快通道");
  } finally {
    app?.store.db.close();
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 7. Codex Review 专项回归测试 ─────────

test("协议加固回归：64 位无损账号 ID、跨主机剥离 x-csrf-token、WS 401 分类、队列上限、话题子回复 parentId、网关 Cookie 轮换与保活 401", async () => {
  // 1) 64 位原生 ID 无损解析，拒绝不安全浮点
  const parsed = parseJsonPreserveNativeIds<{ data: { user: { id: string }; step_info: { front_user_id: string } } }>(
    `{"data":{"user":{"id":7123456789012345678},"step_info":{"front_user_id":7987654321098765432}}}`,
  );
  assert.equal(parsed.data.user.id, "7123456789012345678");
  assert.equal(parsed.data.step_info.front_user_id, "7987654321098765432");
  assert.throws(() => normalizeNativeId(7123456789012345678), /安全整数/);

  // 2) 跨主机重定向必须剥离 x-csrf-token
  let destCsrf: string | undefined;
  const destSrv = http.createServer((req, res) => {
    destCsrf = req.headers["x-csrf-token"] as string | undefined;
    res.writeHead(200);
    res.end("ok");
  });
  await new Promise<void>((r) => destSrv.listen(0, "127.0.0.1", () => r()));
  const destPort = (destSrv.address() as { port: number }).port;
  const srcSrv = http.createServer((_req, res) => {
    res.writeHead(302, { Location: `http://localhost:${destPort}/target` });
    res.end();
  });
  await new Promise<void>((r) => srcSrv.listen(0, "127.0.0.1", () => r()));
  const srcPort = (srcSrv.address() as { port: number }).port;
  try {
    const jar = new RecordingCookieJar(["127.0.0.1", "localhost"]);
    jar.setFromHeaders(new URL(`http://127.0.0.1:${srcPort}/`), "swp_csrf_token=secret_1; Path=/");
    const r = await fetchWithJar(jar, {
      method: "GET",
      url: `http://127.0.0.1:${srcPort}/start`,
      headers: { "x-csrf-token": "secret_1" },
      allowInsecureHttp: true,
      extraAllowedHosts: ["127.0.0.1", "localhost"],
    });
    assert.equal(r.status, 200);
    assert.equal(destCsrf, undefined, "跨主机重定向后不能把原主机 x-csrf-token 带过去");
  } finally {
    srcSrv.closeAllConnections();
    destSrv.closeAllConnections();
    await Promise.all([new Promise<void>((r) => srcSrv.close(() => r())), new Promise<void>((r) => destSrv.close(() => r()))]);
  }

  // 3) Mock 服务回归：WS 401 分类、队列内存上限、话题内子回复 parentId != rootId、网关 Cookie 轮换、保活 401 退出
  const mock = await startMockFeishuWebServer();
  try {
    const rotated: string[] = [];
    const client = await FeishuWebClient.connect(
      {
        owner_id: "7001",
        owner_name: "张三",
        session_id: "sess_gen_1",
        cookies: [
          { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
          { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
        ],
      },
      {
        endpoints: mock.endpoints,
        onSessionConfirmed: (l) => {
          const s = l.cookies.find((c) => c.name === "session")?.value;
          if (s) rotated.push(s);
        },
        heartbeatIntervalMs: 500,
        keepaliveIntervalMs: 35,
        socketIdleTimeoutMs: 5_000,
        reconnectBaseMs: 15,
        reconnectCeilingMs: 30,
        sessionDenialThreshold: 3,
        sessionDenialRetryMs: 15,
        maxQueueBytes: 2048,
      },
    );

    // 网关返回 Set-Cookie 应立即触发持久化回调
    mock.setGatewayRotateCookie("sess_gw_rotated_3");
    await client.readChat("8001", { force: true });
    assert.ok(rotated.includes("sess_gw_rotated_3"), "网关成功调用轮换的 Cookie 立即持久化");
    mock.setGatewayRotateCookie("");

    // 话题内回复子消息：rootId 与 parentId 必须分别保留并独立回读校验
    mock.addMessage(
      "sub_reply_2",
      buildNativeMessage({
        id: "sub_reply_2",
        chatId: "8001",
        actorId: "7002",
        text: "话题里的追问",
        rootId: "root_topic_1",
        parentId: "root_topic_1",
        threadId: "th_root_topic_1",
      }),
    );
    const threadRep = await client.sendVerifiedReply({
      chatId: "8001",
      messageId: "sub_reply_2",
      rootId: "root_topic_1",
      text: "针对这条追问的回复",
      cid: "cid_thread_parent_01",
    });
    assert.equal(threadRep.rootId, "root_topic_1");
    assert.equal(threadRep.parentId, "sub_reply_2");
    assert.equal(mock.sentReplies.at(-1)!.rootId, "root_topic_1");
    assert.equal(mock.sentReplies.at(-1)!.parentId, "sub_reply_2");

    // WS 握手返回 401 必须归类为 credential_denied 而不是普通网络错误
    mock.setWsUpgradeStatus(401);
    await assert.rejects(
      BinaryWebSocket.dial(mock.endpoints.websocketUrl),
      (e: unknown) => e instanceof WebHttpError && e.code === "credential_denied" && e.status === 401,
    );
    mock.setWsUpgradeStatus(101);

    // 接收队列超限时主动断开保护内存，并保留真实错误原因
    const ws = await BinaryWebSocket.dial(mock.endpoints.websocketUrl, { maxQueueBytes: 1024 });
    const bigPayload = buildNativeMessage({ id: "big_1", chatId: "8001", actorId: "7002", text: "A".repeat(400) });
    for (let i = 0; i < 6; i++) mock.pushMessage(`sid_q_${i}`, [bigPayload], false);
    await new Promise((r) => setTimeout(r, 40));
    await assert.rejects(
      (async () => {
        for (let i = 0; i < 10; i++) await ws.read(200);
      })(),
      /接收队列超过内存上限/,
    );
    ws.close();

    // 保活期间返回 401 必须中断长连接并进入 3 次核验 → SessionNeedsLoginError
    const kaStates: ListenerState[] = [];
    const ctrl = new AbortController();
    const listenPromise = client.listen({
      signal: ctrl.signal,
      onState: (s) => {
        kaStates.push(s);
        if (s === "listening") mock.setProfileStatus(401);
      },
      onMessage: () => undefined,
    });
    await assert.rejects(listenPromise, SessionNeedsLoginError);
    assert.equal(kaStates.at(-1), "needs_login");
  } finally {
    await mock.close();
  }
});

test("存储、范围、并发、草稿解耦、登出/绑定、热加载与离线状态回归", async () => {
  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-pw-reg-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevCtxDir = process.env.CTX_DIR;
  process.env.CTX_DIR = ctxDir;

  const cfgFile = path.join(dir, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    [
      `data_dir: ${JSON.stringify(path.join(dir, "data"))}`,
      "bins:",
      `  lark: ${JSON.stringify(path.join(STUBS, "ctx-lark"))}`,
      `  acpx: ${JSON.stringify(path.join(STUBS, "acpx"))}`,
      `  bytedcli: ${JSON.stringify(path.join(STUBS, "ctx-bytedcli"))}`,
      "harnesses:",
      "  claude: { agent: claude }",
      `  cx: { type: codex-exec, cmd: ${JSON.stringify(path.join(STUBS, "ctx-codex"))} }`,
      "roles: { brain: claude }",
      "owner: { open_id: ou_owner }",
      "engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50 }",
      "context:",
      "  harness: cx",
      "  groups: allowlist",
      "  groups_allow: []",
      "  groups_deny: [oc_secret_8003]",
      "  personal_web:",
      "    enabled: true",
      "    fast_lane: true",
      "    debounce_ms: 0",
      "    pre_draft: true",
      "    send_replies: false",
    ].join("\n") + "\n",
  );

  let app: ReturnType<typeof createApp> | undefined;
  try {
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    const now = Date.now();

    // 1) [P1-1] 不同群两条相同的「收到」绝不能跨群误合并或误绑定 open_message_id
    svc.store.addObs([
      {
        id: "pw:short_a",
        source: "im",
        kind: "group",
        conv: "pw_chat:101",
        conv_name: "A 群",
        actor_id: "7010",
        actor_name: "甲",
        is_me: false,
        time: now,
        text: "收到",
        url: "",
        meta: { transport: "personal_web", native_message_id: "short_a", native_chat_id: "101", chat_type: "group" },
      },
      {
        id: "im:om_short_b",
        source: "im",
        kind: "group",
        conv: "oc_group_b",
        conv_name: "B 群",
        actor_id: "ou_yi",
        actor_name: "乙",
        is_me: false,
        time: now + 1000,
        text: "收到",
        url: "https://applink.feishu.cn/client/chat/open?openChatId=oc_group_b",
        meta: { message_id: "om_short_b", chat_type: "group" },
      },
    ]);
    assert.ok(svc.store.obs("pw:short_a") && svc.store.obs("im:om_short_b"));
    assert.equal(svc.store.obs("pw:short_a")!.meta.open_message_id, undefined, "不同群短文本绝不误绑定");

    // 2) [P2-3] 背景观测在首次真实投递时必须提升为 processed = 0
    svc.store.addBackgroundObs([
      {
        id: "pw:bg_dm_1",
        source: "im",
        kind: "p2p",
        conv: "pw_chat:dm_9",
        conv_name: "私聊：王五",
        actor_id: "7099",
        actor_name: "王五",
        is_me: false,
        time: now - 60_000,
        text: "刚才忘了说，今天上线前要加索引",
        url: "",
        meta: { transport: "personal_web", chat_type: "p2p" },
      },
    ]);
    assert.equal(svc.store.pendingConvs(50).some((c) => c.conv === "pw_chat:dm_9"), false);
    const promoted = svc.store.addObs([
      {
        id: "pw:bg_dm_1",
        source: "im",
        kind: "p2p",
        conv: "pw_chat:dm_9",
        conv_name: "私聊：王五",
        actor_id: "7099",
        actor_name: "王五",
        is_me: false,
        time: now - 60_000,
        text: "刚才忘了说，今天上线前要加索引",
        url: "",
        meta: { transport: "personal_web", chat_type: "p2p" },
      },
    ]);
    assert.equal(promoted, 1, "首次真实投递必须将 background_only 提升为待处理");
    assert.equal(svc.store.pendingConvs(50).some((c) => c.conv === "pw_chat:dm_9"), true);

    // 3) [P2-1] 积压 80 条时，convWindowAround 必须包含触发消息，同时更早积压仍留待常规周期
    const backlog = Array.from({ length: 80 }, (_, i) => ({
      id: `pw:bk_${i}`,
      source: "im" as const,
      kind: "group",
      conv: "pw_chat:backlog_1",
      conv_name: "高流量群",
      actor_id: "7010",
      actor_name: "某人",
      is_me: false,
      time: now - 100_000 + i * 1000,
      text: `普通消息 ${i}`,
      url: "",
      meta: {},
    }));
    backlog.push({
      id: "pw:bk_urgent",
      source: "im",
      kind: "at_me",
      conv: "pw_chat:backlog_1",
      conv_name: "高流量群",
      actor_id: "7010",
      actor_name: "某人",
      is_me: false,
      time: now,
      text: "@张三 紧急回滚",
      url: "",
      meta: {},
    });
    svc.store.addObs(backlog);
    const fastWin = svc.store.convWindowAround("pw_chat:backlog_1", "pw:bk_urgent", 20, 5);
    assert.ok(fastWin.some((o) => o.id === "pw:bk_urgent"), "快通道窗口必须包含触发消息");
    assert.ok(!fastWin.some((o) => o.id === "pw:bk_0"), "过早无关积压留给常规周期");

    // 4) [R2 P1-1] oc_secret_8003 无任何本地历史时，经 lark-cli `im chats get` 独立解析并阻断对应个人 Web 推送；readChat 失败时 fail-closed
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner",
        user_name: "张三",
        chat_meta: {
          oc_secret_8003: { name: "绝密群", chat_mode: "group" },
        },
      }),
    );
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const savedLogin = loginStore.save({
      owner_id: "7001",
      owner_name: "张三",
      cookies: [
        { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
        { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
      ],
    });
    const client = await FeishuWebClient.connect(savedLogin, { endpoints: mock.endpoints });

    // [P1-2] groups=allowlist 且 allowlist=[]：非 @我 群消息不入库；sources.im=false 全部不入库
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_unlisted_1", chatId: "8002", actorId: "7002", text: "未列入群的普通闲聊" }), "7001"),
      client,
    );
    assert.equal(svc.store.obs("pw:pw_unlisted_1"), undefined, "allowlist 外的非 @我 群消息绝不入库");

    // [R2 P1-1] oc_secret_8003 在 groups_deny 里且零本地历史：独立解析群名「绝密群」后阻断个人 Web 推送
    await svc.personalWeb.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "pw_secret_1",
          chatId: "8003",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 绝密内容" }]),
        }),
        "7001",
      ),
      client,
    );
    assert.equal(svc.store.obs("pw:pw_secret_1"), undefined, "零本地历史的 oc_ 禁用群同样阻断个人 Web 推送");

    // readChat 失败且存在排除规则时 fail-closed（抛错暂缓 ACK，不落库）
    mock.setChatModeFail(true);
    await assert.rejects(
      svc.personalWeb.handleMessage(
        decodeMessage(
          buildNativeMessage({
            id: "pw_unknown_chat_1",
            chatId: "8099",
            actorId: "7002",
            richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 未知群名" }]),
          }),
          "7001",
        ),
        client,
      ),
      /暂缓入库/,
    );
    assert.equal(svc.store.obs("pw:pw_unknown_chat_1"), undefined);
    mock.setChatModeFail(false);

    // [P1-2] sources.im = false 时连私聊也不入库
    app.cfg.context.sources.im = false;
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_im_off", chatId: "dm_99", actorId: "7003", chatKind: CHAT_KIND_P2P, text: "关闭 im 来源" }), "7001"),
      client,
    );
    assert.equal(svc.store.obs("pw:pw_im_off"), undefined);
    app.cfg.context.sources.im = true;

    // [R2 P1-4] allowlist=[] 时，对未列入群 hydrateContext 绝不拉取普通背景；加入 allowlist 后补读并仅保留人类消息
    const nowSec = Math.floor(now / 1000);
    mock.setHistory("8001", {
      1: buildNativeMessage({ id: "h_bot_drop", chatId: "8001", actorId: "bot_x", senderType: 2, text: "Jenkins spam", position: 1, createdAtSec: nowSec - 60 }),
      2: buildNativeMessage({ id: "h_human_ok", chatId: "8001", actorId: "7002", senderType: 1, text: "人类上下文", position: 2, createdAtSec: nowSec - 30 }),
    });
    const bridgeForHydrate = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (bridgeForHydrate as unknown as { client?: FeishuWebClient }).client = client;
    const skippedOutOfScope = await bridgeForHydrate.hydrateContext(
      { id: "h_anchor", conversationId: "8001", rootId: "", parentId: "", threadId: "", position: 3, createdAtMs: nowSec * 1000 },
      "pw_chat:8001",
      "Ark 发布协同群",
    );
    assert.equal(skippedOutOfScope, 0, "allowlist 未列入的群在快通道下绝不补读普通背景");
    assert.equal(svc.store.obs("pw:h_human_ok"), undefined);

    app.cfg.context.groups_allow = ["8001"];
    await bridgeForHydrate.hydrateContext(
      { id: "h_anchor", conversationId: "8001", rootId: "", parentId: "", threadId: "", position: 3, createdAtMs: nowSec * 1000 },
      "pw_chat:8001",
      "Ark 发布协同群",
    );
    assert.equal(svc.store.obs("pw:h_bot_drop"), undefined, "补读历史同样忽略机器人消息（交由 lark-cli bot_allow 统一处理）");
    assert.ok(svc.store.obs("pw:h_human_ok"), "列入范围的群人类历史背景正常写入");
    app.cfg.context.groups_allow = [];

    // [P2-6 & R2 P1-6] pre_draft=true 且 send_replies=false 时仍允许起草；确认时绝不降级成群顶层 im.send，必须明确提示开启 send_replies
    svc.store.addObs([
      {
        id: "pw:pre_draft_1",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:8001",
        conv_name: "Ark 发布协同群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@张三 麻烦确认下今天下午的发布窗口",
        url: "",
        meta: {
          transport: "personal_web",
          native_owner_id: "7001",
          native_message_id: "pre_draft_1",
          native_chat_id: "8001",
          native_root_id: "pre_draft_1",
          chat_type: "group",
        },
      },
    ]);
    const { item: askItem } = svc.store.upsertItem({ title: "确认下午发布窗口", kind: "ask_me", priority: "high", source: "im", confidence: 0.95 });
    svc.store.addEvidence("item", askItem.id, "pw:pre_draft_1", "麻烦确认下今天下午的发布窗口", now);
    assert.equal(svc.draftable(askItem), true, "send_replies=false 时仍允许起草");
    fs.writeFileSync(path.join(ctxDir, "draft.txt"), "下午 4 点可以发布。");
    const preDraft = await svc.drafter.forItem(askItem.id, "reply");
    assert.equal(preDraft.status, "proposed");
    assert.equal(preDraft.target.native_owner_id, "7001");
    await assert.rejects(
      app.commands.exec("context.draft_approve", { id: preDraft.id }, { source: "web", actor: "owner" }),
      /context\.personal_web\.send_replies/,
    );
    app.cfg.context.personal_web.send_replies = true;
    const fxPw = svc.drafter.effectFor(preDraft, "下午 4 点可以发布。");
    assert.equal(fxPw.op, "pw.reply");
    assert.equal((fxPw.args as { owner_id: string }).owner_id, "7001");
    app.cfg.context.personal_web.send_replies = false;

    // [P2-2 & R3 P2-9] 同会话并发占用保护（SQLite 跨进程租约）：fastCycle 遇到已被占用的会话返回 busy: true
    assert.equal(svc.store.claimConv("pw_chat:8001", "context:other-job", app.ledger.owner), true);
    const busyRes = await svc.fastCycle("context:fast:test-busy", { conv: "pw_chat:8001", conv_name: "Ark 发布协同群", trigger_obs_id: "pw:pre_draft_1" });
    assert.equal(busyRes.busy, true);
    svc.store.releaseConv("pw_chat:8001", "context:other-job");

    // [P2-17] 防抖定时器里 onFastTrigger 抛错绝不能产生未捕获异常崩溃进程
    const throwingBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => {
        throw new Error("SQLITE_BUSY");
      },
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
    });
    app.cfg.context.personal_web.debounce_ms = 10;
    await throwingBridge.handleMessage(
      decodeMessage(buildNativeMessage({ id: "pw_timer_err", chatId: "dm_88", actorId: "7088", chatKind: CHAT_KIND_P2P, text: "触发防抖异常测试" }), "7001"),
      client,
    );
    await new Promise((r) => setTimeout(r, 40));
    throwingBridge.stop();

    // [P1-5] 账号绑定校验：禁止误扫他人账号或切换账号覆盖
    app.store.set(BOUND_OWNER_KV_KEY, "7001");
    app.store.set("ctx.owner_name", "张三");
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "9999", owner_name: "张三", cookies: [] }),
      /已绑定个人 Web 账号 7001/,
    );
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "别人账号", cookies: [] }),
      /与当前工作区主人「张三」.*不一致/,
    );

    // [P1-4] + [P2-8] 运行中登出：删除凭据文件后常驻监听迅速断开且绝不回写旧凭据；ticket 持续 401 时停止重试不再循环
    const liveBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 30,
      clientOptions: { endpoints: mock.endpoints, heartbeatIntervalMs: 500, sessionDenialRetryMs: 15 },
    });
    const handle = liveBridge.start();
    await waitUntil(() => liveBridge.status().state === "listening");
    loginStore.clear();
    await waitUntil(() => liveBridge.status().state === "needs_login");
    await new Promise((r) => setTimeout(r, 60));
    assert.equal(loginStore.exists(), false, "登出后旧常驻会话绝不能把凭据写回磁盘");
    handle.stop();

    // [P3-1] 离线状态区分：无活跃 daemon.heartbeat 时即使 KV 里存着 listening，status() 也返回 stopped 且保留 last_message_at
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({ state: "listening", owner_id: "7001", owner_name: "张三", since: now, last_message_at: now - 1000, last_error: "" }),
    );
    loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: savedLogin.cookies });
    app.store.set("daemon.heartbeat", `host:1|${now - 120_000}`);
    const offlineSt = svc.personalWeb.status(now);
    assert.equal(offlineSt.state, "stopped", "守护进程心跳超时后不应误报实时在线");
    assert.equal(offlineSt.last_message_at, now - 1000, "保留最近消息时间用于诊断");

    // [P2-12] 三层嵌套冷字段 context.personal_web.enabled 不被热加载覆盖，同层热字段 fast_lane 立即生效
    const settingsSvc = new SettingsService(app);
    const putRes = await settingsSvc.put({ context: { personal_web: { enabled: false, fast_lane: false } } });
    assert.equal(putRes.ok, true);
    assert.equal(putRes.restart_required, true);
    assert.equal(app.cfg.context.personal_web.enabled, true, "冷字段在重启前保持原值，状态不与实际运行中的长连接脱节");
    assert.equal(app.cfg.context.personal_web.fast_lane, false, "热字段立即生效");
  } finally {
    app?.store.db.close();
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 8. Codex Review 第二轮专项回归测试 ─────────

test("Codex 第二轮回归：PK 索引查询、同名群静音隔离、话题锚点补读、编辑防吞、账号绑定与发包前复核、明确拒绝可重试、非连续 401、分片 WS、关闭模块登出", async () => {
  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-pw-r2-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevCtxDir = process.env.CTX_DIR;
  process.env.CTX_DIR = ctxDir;

  const cfgFile = path.join(dir, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
      harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner" },
      cards: { enabled: false },
      engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 2 },
      context: {
        harness: "cx",
        groups: "spoken",
        max_groups: 1,
        groups_deny: [],
        personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
      },
    }),
  );

  let app: ReturnType<typeof createApp> | undefined;
  try {
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);

    // 1) [R2 P1-11] ctx_obs 主键查询必须走索引（禁止 SCAN）
    const plan = svc.store.db.prepare("EXPLAIN QUERY PLAN SELECT * FROM ctx_obs WHERE id = ?").all("im:any") as { detail: string }[];
    assert.ok(
      plan.some((r) => /SEARCH ctx_obs USING INDEX/i.test(r.detail)),
      `ctx_obs 主键查询必须走索引，实际：${JSON.stringify(plan)}`,
    );

    // 2) [R2 P2-12] 同名群按真实会话 ID 隔离静音：静音 oc_same_1 绝不影响同名 oc_same_2
    svc.store.addObs([
      {
        id: "im:same_1",
        source: "im",
        kind: "group",
        conv: "oc_same_1",
        conv_name: "核心研发群",
        actor_id: "ou_a",
        actor_name: "A",
        is_me: false,
        time: now - 2000,
        text: "群1消息",
        url: "",
        meta: { chat_type: "group" },
      },
      {
        id: "im:same_2",
        source: "im",
        kind: "group",
        conv: "oc_same_2",
        conv_name: "核心研发群",
        actor_id: "ou_b",
        actor_name: "B",
        is_me: false,
        time: now - 1000,
        text: "群2消息",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    svc.store.muteConv("oc_same_1", "核心研发群", true);
    const pend = svc.store.pendingConvs(20);
    assert.equal(pend.some((c) => c.conv === "oc_same_1"), false);
    assert.equal(pend.some((c) => c.conv === "oc_same_2"), true, "静音一个群不能波及同名另一群");
    svc.store.muteConv("oc_same_1", "", false);

    // 3) [R2 P2-4 & P2-6] markProcessed 按版本保护并发编辑；convWindowAround 对已处理触发器返回空窗口
    svc.store.addObs([
      {
        id: "pw:edit_race_1",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9001",
        conv_name: "测试群",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "旧版本文",
        url: "",
        meta: { transport: "personal_web" },
      },
    ]);
    // 模拟模型推理期间到达消息编辑
    svc.store.addObs([
      {
        id: "pw:edit_race_1",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9001",
        conv_name: "测试群",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "新版本文（已修改需求）",
        url: "",
        meta: { transport: "personal_web" },
      },
    ]);
    // 旧批次按旧正文 markProcessed 绝不能把新版标成已处理
    svc.store.markProcessed([{ id: "pw:edit_race_1", text: "旧版本文" }]);
    assert.equal(svc.store.obsPending("pw:edit_race_1"), true, "并发编辑后的新版必须保留待处理");
    // 按新版 markProcessed 后才标为已处理，且 convWindowAround 返回空数组（不回退扫积压）
    svc.store.markProcessed([{ id: "pw:edit_race_1", text: "新版本文（已修改需求）" }]);
    assert.equal(svc.store.obsPending("pw:edit_race_1"), false);
    assert.deepEqual(svc.store.convWindowAround("pw_chat:9001", "pw:edit_race_1"), [], "已处理触发器返回空窗口");

    // 4) [R2 P2-2 & P2-10] 个人 Web 发言群隔离到 ctx.pw_spoken_groups（不污染 ctx.spoken_groups），并遵守 max_groups=1
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const login1 = loginStore.save({
      owner_id: "7001",
      owner_name: "张三",
      cookies: [
        { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
        { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
      ],
    });
    app.store.set(BOUND_OWNER_KV_KEY, "7001");
    const client = await FeishuWebClient.connect(login1, { endpoints: mock.endpoints });

    mock.setChatName("9101", "群A");
    mock.setChatName("9102", "群B");
    // 我先在 9101 发言，再在 9102 发言（max_groups=1 只保留最新的 9102）
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "me_a", chatId: "9101", actorId: "7001", text: "我在A发言", createdAtSec: nowSec - 20 }), "7001"),
      client,
    );
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "me_b", chatId: "9102", actorId: "7001", text: "我在B发言", createdAtSec: nowSec - 10 }), "7001"),
      client,
    );
    assert.equal(app.store.get("ctx.spoken_groups"), undefined, "绝不能把 pw_chat:* 写入 lark-cli 使用的 ctx.spoken_groups");
    const pwSpoken = JSON.parse(app.store.get(pwSpokenGroupsKey("7001")) ?? "{}") as Record<string, unknown>;
    assert.ok(pwSpoken["pw_chat:9101"] && pwSpoken["pw_chat:9102"]);

    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "ord_a", chatId: "9101", actorId: "7002", text: "A群普通消息应被 max_groups=1 过滤", createdAtSec: nowSec }), "7001"),
      client,
    );
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "ord_b", chatId: "9102", actorId: "7002", text: "B群普通消息应入库", createdAtSec: nowSec }), "7001"),
      client,
    );
    assert.equal(svc.store.obs("pw:ord_a"), undefined, "超出 max_groups 的旧发言群普通消息不入库");
    assert.ok(svc.store.obs("pw:ord_b"), "排名在 max_groups 内的群普通消息正常入库");

    // 5) [R2 P2-13] 活跃会话（已有 >= 5 条近期消息）收到话题回复 @我 时，仍补读缺失的 root/parent 锚点并在 convWindowAround 呈现
    for (let i = 0; i < 6; i++) {
      svc.store.addObs([
        {
          id: `pw:recent_b_${i}`,
          source: "im",
          kind: "group",
          conv: "pw_chat:9102",
          conv_name: "群B",
          actor_id: "7002",
          actor_name: "7002",
          is_me: false,
          time: now - 5000 + i * 100,
          text: `近期无关讨论 ${i}`,
          url: "",
          meta: { transport: "personal_web" },
        },
      ]);
      svc.store.markProcessed([`pw:recent_b_${i}`]);
    }
    mock.addMessage(
      "old_root_99",
      buildNativeMessage({ id: "old_root_99", chatId: "9102", actorId: "7003", text: "三天前的根需求背景", createdAtSec: nowSec - 3600, position: 1 }),
    );
    svc.store.addObs([
      {
        id: "pw:thread_at_me",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9102",
        conv_name: "群B",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "@张三 这个需求你来拍板",
        url: "",
        meta: {
          transport: "personal_web",
          native_owner_id: "7001",
          native_message_id: "thread_at_me",
          native_chat_id: "9102",
          native_root_id: "old_root_99",
          native_parent_id: "old_root_99",
          chat_type: "group",
        },
      },
    ]);
    const hydrateBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (hydrateBridge as unknown as { client?: FeishuWebClient }).client = client;
    const fetchedAnchors = await hydrateBridge.hydrateContext(
      { id: "thread_at_me", conversationId: "9102", rootId: "old_root_99", parentId: "old_root_99", threadId: "th_99", position: 50, createdAtMs: now },
      "pw_chat:9102",
      "群B",
    );
    assert.equal(fetchedAnchors, 1, "即使会话已有 >=5 条近期消息，仍必须补读缺失的话题根锚点");
    const winWithAnchor = svc.store.convWindowAround("pw_chat:9102", "pw:thread_at_me", 10, 2);
    assert.ok(winWithAnchor.some((o) => o.id === "pw:old_root_99"), "convWindowAround 必须显式包含话题根锚点");

    // 6) [R2 P2-14] pre_draft 跳过静音项目和静音上级项目的子项目
    const mutedParent = svc.store.upsertProject({ name: "已静音大项目", muted: true });
    const childUnderMuted = svc.store.upsertProject({ name: "子专项", parent_id: mutedParent.id });
    svc.store.addObs([
      {
        id: "pw:muted_proj_msg",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9102",
        conv_name: "群B",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now + 500,
        text: "@张三 静音项目里的紧急请求",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "muted_proj_msg", native_chat_id: "9102", native_root_id: "muted_proj_msg", chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "understand.json"),
      JSON.stringify({
        items: [
          {
            title: "静音子项目的紧急事项",
            kind: "ask_me",
            project: childUnderMuted.name,
            priority: "high",
            confidence: 0.95,
            evidence: [{ obs_id: "pw:muted_proj_msg", quote: "静音项目里的紧急请求" }],
          },
        ],
      }),
    );
    const fastMutedRes = await svc.fastCycle("context:fast:muted-proj", {
      conv: "pw_chat:9102",
      conv_name: "群B",
      trigger_obs_id: "pw:muted_proj_msg",
    });
    assert.equal(fastMutedRes.pre_drafted, 0, "静音上级项目的子项目绝不自动预起草");

    // 7) [R2 P1-7, P1-8, P2-8] 账号绑定校验、发包前二次复核、401 明确拒绝可重试、500 不明失败禁重发
    mock.addMessage("send_target_1", buildNativeMessage({ id: "send_target_1", chatId: "9102", actorId: "7002", text: "请回复", position: 60 }));
    const sendBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });

    // 7a) [R2 P1-8] 在 readChat 期间用户登出/关闭 send_replies，onBeforeSend 必须在发包前拦截（sentReplies=0 且不卡 sending）
    mock.setOnChatMode(() => {
      app!.cfg.context.personal_web.send_replies = false;
    });
    await assert.rejects(
      sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "发包前被关闭", cid: "cid_preflight_1" }),
      /未开启个人 Web 回复/,
    );
    assert.equal(mock.sentReplies.length, 0, "发包前关闭 send_replies 绝不能发出请求");
    mock.setOnChatMode(undefined);
    app.cfg.context.personal_web.send_replies = true;

    // 7b) [R2 P2-8] 明确 401 拒绝记为 rejected，恢复 200 后允许以相同 CID 重试成功
    mock.setSendStatus(401);
    await assert.rejects(
      sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "401 后重试", cid: "cid_401_retry" }),
      /鉴权失败/,
    );
    mock.setSendStatus(200);
    const retried = await sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "401 后重试", cid: "cid_401_retry" });
    assert.equal(retried.verified, true, "明确 401 未创建消息后允许同内容重试成功");

    // 7c) [R2 P2-8] 模糊 500 故障留在 sending，拒绝盲目重发
    mock.setSendStatus(500);
    await assert.rejects(
      sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "500 模糊失败", cid: "cid_500_guard" }),
      /HTTP 500/,
    );
    mock.setSendStatus(200);
    await assert.rejects(
      sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "500 模糊失败", cid: "cid_500_guard" }),
      /上次个人 Web 发送结果不明确/,
    );

    // 7d) [R2 P1-7] 换号后（force-switch-account 到 7002），已绑定给 7001 的回复绝不能用 7002 发出
    loginStore.save({ owner_id: "7002", owner_name: "李四", cookies: login1.cookies });
    app.store.set(BOUND_OWNER_KV_KEY, "7002");
    mock.setProfileUser("7002", "李四");
    await assert.rejects(
      sendBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9102", message_id: "send_target_1", text: "跨账号测试", cid: "cid_cross_acct" }),
      /与当前登录账号 \(7002\) 不一致/,
    );
    mock.setProfileUser("7001", "张三");
    loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: login1.cookies });
    app.store.set(BOUND_OWNER_KV_KEY, "7001");

    // 8) [R2 P1-10] 首次绑定主人核验：lark-cli openId 与 owner.open_id 不一致直接拒绝；无独立核验依据时拒绝（除非 allowUnverifiedOwner）
    app.store.db.prepare("DELETE FROM kv WHERE k IN (?, 'ctx.owner_name')").run(BOUND_OWNER_KV_KEY);
    loginStore.clear();
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_someone_else", user_name: "张三" }));
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "张三", cookies: [] }),
      /与 config\.yaml 配置的主人 \(ou_owner\) 不一致/,
    );
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ auth_fail: true }));
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "张三", cookies: [] }),
      /allow-unverified-owner/,
    );
    await verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "张三", cookies: [] }, { allowUnverifiedOwner: true });

    // 9) [R2 P2-9] 非连续 401（401 → 503 → 401 → 503 → 401 → 200）重置连续鉴权拒绝计数，绝不误入 needs_login
    const clientRetry = await FeishuWebClient.connect(
      { owner_id: "7001", owner_name: "张三", cookies: login1.cookies },
      {
        endpoints: mock.endpoints,
        heartbeatIntervalMs: 500,
        reconnectBaseMs: 10,
        reconnectCeilingMs: 20,
        sessionDenialThreshold: 3,
        sessionDenialRetryMs: 10,
      },
    );
    mock.setProfileStatuses([401, 503, 401, 503, 401, 200]);
    const retryStates: ListenerState[] = [];
    const retryCtrl = new AbortController();
    const retryPromise = clientRetry.listen({
      signal: retryCtrl.signal,
      onState: (s) => {
        retryStates.push(s);
        if (s === "listening") {
          retryCtrl.abort();
        }
      },
      onMessage: () => undefined,
    });
    // listen 首次 connect 前如果 socket 连接成功就先断开以走 profile 核验：直接用 WS 401 触发首连失败走重试循环
    await retryPromise;
    assert.ok(!retryStates.includes("needs_login"), "非连续 401 不应进入 needs_login");
    assert.equal(retryStates.filter((s) => s === "reverifying").length, 3, "应经历 3 次非连续 401 复核且全部被中间 503 重置");
    assert.ok(retryStates.includes("listening"), "第 6 次恢复 200 后正常进入 listening");

    // 10) [R2 P2-17] 分片大 WS 帧重组（ChunkReader）
    const wsBig = await BinaryWebSocket.dial(mock.endpoints.websocketUrl);
    const largeText = "分片大消息".repeat(3000);
    const largeMsg = buildNativeMessage({ id: "big_chunk_1", chatId: "9102", actorId: "7002", text: largeText });
    const sendTask = mock.pushChunkedFrame("sid_chunk_1", [largeMsg], 512);
    const frame = await wsBig.read(5_000);
    await sendTask;
    const pkt = decodeFrame(frame.data);
    assert.equal(pkt.str(1), "sid_chunk_1");
    wsBig.close();

    // 11) [R2 P1-1] oc_ 排除规则在 lark-cli 无法解析时 fail-closed（不落库）
    app.cfg.context.groups_deny = ["oc_unresolvable_999"];
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ chat_meta_fail: true }));
    const ocFailBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    await assert.rejects(
      ocFailBridge.handleMessage(
        decodeMessage(
          buildNativeMessage({
            id: "pw_fail_closed_oc",
            chatId: "9102",
            actorId: "7002",
            richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 不可解析排除测试" }]),
          }),
          "7001",
        ),
        client,
      ),
      /fail-closed/,
    );
    assert.equal(svc.store.obs("pw:pw_fail_closed_oc"), undefined);

    // 12) [R2 P2-15] context.enabled = false 时 pa context web-logout 仍可正常清除磁盘凭据
    const disabledCfg = path.join(dir, "config-disabled.yaml");
    const disabledData = path.join(dir, "data-disabled");
    fs.writeFileSync(
      disabledCfg,
      JSON.stringify({
        data_dir: disabledData,
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { claude: { agent: "claude" } },
        roles: { brain: "claude" },
        owner: { open_id: "ou_owner" },
        context: { enabled: false },
      }),
    );
    const disStore = new WebLoginStore(disabledData);
    disStore.save({ owner_id: "7001", owner_name: "张三", cookies: login1.cookies });
    assert.equal(disStore.exists(), true);
    const cliRes = await runProcess(
      process.execPath,
      ["--experimental-strip-types", path.join(ROOT, "src/cli.ts"), "context", "web-logout"],
      { timeoutMs: 20_000, env: { ...process.env, PA_CONFIG: disabledCfg } },
    );
    assert.equal(cliRes.code, 0, `context.enabled=false 时 web-logout 必须成功：${cliRes.stderr}`);
    assert.equal(disStore.exists(), false, "web-logout 必须删除磁盘凭据文件");
  } finally {
    app?.store.db.close();
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 9. Codex Review 第三轮专项回归测试 ─────────

test("Codex 第三轮回归：空载荷发送保护、稳定 ID 首次绑定、静音改名 fail-closed、跨通道原生排除、快通道二次校验、补读换号隔离、强制刷新群模式、Cookie 版本合并、CSRF 域名作用域、@mention 编辑、近邻背景窗口、帧数上限与状态清理", async () => {
  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-pw-r3-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevCtxDir = process.env.CTX_DIR;
  process.env.CTX_DIR = ctxDir;

  const cfgFile = path.join(dir, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
      harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner" },
      cards: { enabled: false },
      engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 2 },
      context: {
        harness: "cx",
        groups: "allowlist",
        max_groups: 1,
        groups_allow: ["pw_chat:9501", "pw_chat:9502", "oc_allow_1"],
        groups_deny: [],
        personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: false, send_replies: true },
      },
    }),
  );

  let app: ReturnType<typeof createApp> | undefined;
  try {
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);

    const baseCookies = [
      { name: "session", value: "sess_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
    ];
    const login1 = loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    app.store.set(BOUND_OWNER_KV_KEY, "7001");

    // 1) [R3 P2-3] CSRF header 必须按实际请求 URL 主机/路径作用域选取
    const scopedJar = new RecordingCookieJar(["accounts.example.test", "gateway.example.test"]);
    scopedJar.setFromHeaders(new URL("https://accounts.example.test/accounts/qrlogin/init"), "swp_csrf_token=acct_only_tok; Path=/");
    scopedJar.setFromHeaders(new URL("https://gateway.example.test/im/gateway/"), "swp_csrf_token=gw_tok; Path=/im");
    const epScoped: WebEndpoints = {
      ...mock.endpoints,
      accountsOrigin: "https://accounts.example.test",
      gatewayUrl: "https://gateway.example.test/im/gateway/",
    };
    const gwHeaders = authenticatedHeaders(scopedJar, epScoped, "https://gateway.example.test/im/gateway/");
    const otherHostHeaders = authenticatedHeaders(scopedJar, epScoped, "https://login.feishu.cn/suite/passport/frontier_ticket/");
    assert.equal(gwHeaders["x-csrf-token"], "gw_tok", "网关请求必须发送匹配网关主机的 CSRF token");
    assert.equal(otherHostHeaders["x-csrf-token"], undefined, "不相关主机绝不能泄露 accounts host-only CSRF token");

    // 2) [R3 P2-1] 同会话多进程 Cookie 版本合并：旧快照绝不回滚已轮换的新 session Cookie
    const savedV1 = loginStore.load()!;
    const mergedV2 = loginStore.saveIfSessionMatches(
      { ...savedV1, cookies: [...baseCookies.filter((c) => c.name !== "session"), { name: "session", value: "sess_v2", domain: "127.0.0.1", path: "/" }] },
      { upserts: [{ name: "session", value: "sess_v2", domain: "127.0.0.1", path: "/" }], deletes: [] },
    );
    assert.ok(mergedV2 && mergedV2.cookie_version === 2);
    // 另一个持 v1 快照的并发进程（如 web-status --verify）带着空 delta 或无关 Cookie 回写，绝不能把 sess_v2 回滚成 sess_v1
    const mergedV3 = loginStore.saveIfSessionMatches(savedV1, {
      upserts: [{ name: "extra_flag", value: "1", domain: "127.0.0.1", path: "/" }],
      deletes: [],
    });
    assert.ok(mergedV3 && mergedV3.cookie_version === 3);
    assert.equal(mergedV3.cookies.find((c) => c.name === "session")?.value, "sess_v2", "不得回滚其他进程已轮换的 session");
    assert.equal(mergedV3.cookies.find((c) => c.name === "extra_flag")?.value, "1", "增量新 Cookie 正确合并");

    // 3) [R3 P2-2] connect 阶段 readNativeProfile 轮换 Cookie 后若 loadWebMetadata 503，新 Cookie 仍已落盘
    mock.setMessengerStatus(503);
    const rotatedOnFail: string[] = [];
    await assert.rejects(
      FeishuWebClient.connect(loginStore.load()!, {
        endpoints: mock.endpoints,
        onSessionConfirmed: (u, d) => {
          const s = u.cookies.find((c) => c.name === "session")?.value;
          if (s) rotatedOnFail.push(s);
          return loginStore.saveIfSessionMatches(u, d);
        },
      }),
      /获取个人 Web 元数据失败/,
    );
    assert.ok(rotatedOnFail.includes("sess_rotated_2"), "元数据 503 前已持久化 profile 轮换出的新 session");
    assert.equal(loginStore.load()!.cookies.find((c) => c.name === "session")?.value, "sess_rotated_2");
    mock.setMessengerStatus(200);

    // 4) [R3 P1-1 & P2-10 & P1-7] 空载荷发送留在 sending；已 verified 无需登录/开关即可幂等返回；发包前强制刷新群模式
    const client = await FeishuWebClient.connect(loginStore.load()!, { endpoints: mock.endpoints });
    mock.addMessage("r3_msg_1", buildNativeMessage({ id: "r3_msg_1", chatId: "9501", actorId: "7002", text: "请回复", position: 10 }));

    // 4a) [R3 P1-7] 先缓存群 9501 为话题模式（mode=2），再切回普通群（mode=0），sendVerifiedReply 必须 force 刷新并带上 inThread=true
    mock.setChatMode("9501", CHAT_MODE_TOPIC);
    const cachedMeta = await client.readChat("9501");
    assert.equal(cachedMeta.mode, CHAT_MODE_TOPIC);
    mock.setChatMode("9501", 0);
    const sendBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (sendBridge as unknown as { client?: FeishuWebClient }).client = client;
    const verifiedRes = await sendBridge.sendVerifiedReply({
      owner_id: "7001",
      chat_id: "9501",
      message_id: "r3_msg_1",
      text: "普通群强制线程回复",
      cid: "cid_r3_mode_refresh",
    });
    assert.equal(verifiedRes.verified, true);
    assert.equal(mock.sentReplies.at(-1)!.inThread, true, "发包前必须 force 刷新群模式，不能沿用过期的话题模式缓存");

    // 4b) [R3 P2-10] 已 verified 后即使已登出且关闭 send_replies，重试仍直接返回已确认结果而不标失败
    app.cfg.context.personal_web.send_replies = false;
    loginStore.clear();
    const idempotentVerified = await sendBridge.sendVerifiedReply({
      owner_id: "7001",
      chat_id: "9501",
      message_id: "r3_msg_1",
      text: "普通群强制线程回复",
      cid: "cid_r3_mode_refresh",
    });
    assert.equal(idempotentVerified.verified, true);
    assert.equal(idempotentVerified.replyId, verifiedRes.replyId);
    app.cfg.context.personal_web.send_replies = true;
    loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });

    // 4c) [R3 P1-1] 网关返回 status=0 空载荷（emptyPayload=true）必须停留在 sending，绝不能记为 rejected 导致重复发送
    mock.setSendEmptyPayload(true);
    await assert.rejects(
      sendBridge.sendVerifiedReply({
        owner_id: "7001",
        chat_id: "9501",
        message_id: "r3_msg_1",
        text: "空载荷测试",
        cid: "cid_r3_empty_payload",
      }),
      /空载荷/,
    );
    mock.setSendEmptyPayload(false);
    await assert.rejects(
      sendBridge.sendVerifiedReply({
        owner_id: "7001",
        chat_id: "9501",
        message_id: "r3_msg_1",
        text: "空载荷测试",
        cid: "cid_r3_empty_payload",
      }),
      /上次个人 Web 发送结果不明确/,
    );

    // 5) [R3 P1-2] 首次绑定不能仅凭显示名称相同通过：需稳定 open_id 匹配或显式 --allow-unverified-owner
    app.store.db.prepare("DELETE FROM kv WHERE k IN (?, 'ctx.owner_name')").run(BOUND_OWNER_KV_KEY);
    loginStore.clear();
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner", user_name: "张三" }));
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7777", owner_name: "张三", cookies: [] }),
      /allow-unverified-owner/,
    );
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7777", owner_name: "张三", owner_open_id: "ou_impostor", cookies: [] }, { allowUnverifiedOwner: true }),
      /open_id \(ou_impostor\) 与 config\.yaml 配置的主人 \(ou_owner\) 不一致/,
    );
    await verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "张三", owner_open_id: "ou_owner", cookies: [] });
    loginStore.save({ owner_id: "7001", owner_name: "张三", owner_open_id: "ou_owner", cookies: baseCookies });
    app.store.set(BOUND_OWNER_KV_KEY, "7001");

    // 6) [R3 P2-4 & P2-7] allowlist 按传输分区并遵守 max_groups=1；范围外普通群绝不调用 readChat
    const liveClient = await FeishuWebClient.connect(loginStore.load()!, { endpoints: mock.endpoints });
    mock.chatModeCalls.length = 0;
    // 9502 是 allowlist 里第二个原生群，max_groups=1 截断后不在范围；且不能触发任何 readChat RPC
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "r3_out_cap", chatId: "9502", actorId: "7002", text: "超出 max_groups 的 allowlist 群" }), "7001"),
      liveClient,
    );
    assert.equal(svc.store.obs("pw:r3_out_cap"), undefined, "allowlist 超出 max_groups 的第二个原生群不入库");
    assert.equal(mock.chatModeCalls.length, 0, "范围外普通群必须在调用 readChat 前即被过滤");

    // 7) [R3 P1-3] 已静音 oc_* 群在 im chats get 失败时：旧标签不匹配（改名场景）必须 fail-closed
    svc.store.muteConv("oc_muted_renamed", "旧群名", true);
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ chat_meta_fail: true }));
    mock.setChatName("9501", "改名后的新群名");
    await assert.rejects(
      svc.personalWeb.handleMessage(
        decodeMessage(
          buildNativeMessage({
            id: "r3_renamed_muted",
            chatId: "9501",
            actorId: "7002",
            richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 改名逃逸测试" }]),
          }),
          "7001",
        ),
        liveClient,
      ),
      /fail-closed/,
    );
    assert.equal(svc.store.obs("pw:r3_renamed_muted"), undefined);
    svc.store.muteConv("oc_muted_renamed", "", false);

    // 8) [R3 P1-4] 原生 pw_chat 静音同步生效到 lark-cli 兜底轮询（pullIm）与 allowlist 分区
    svc.store.muteConv("pw_chat:9503", "秘密研发群", true);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner",
        user_name: "张三",
        chats: {
          oc_allow_1: [
            {
              message_id: "om_allow_ok",
              chat_id: "oc_allow_1",
              chat_name: "开放平台白名单群",
              chat_type: "group",
              create_time: String(nowSec),
              sender: { id: "ou_colleague", name: "同事", sender_type: "user" },
              content: "白名单群正常消息",
            },
          ],
        },
        at_me: [
          {
            message_id: "om_secret_poll",
            chat_id: "oc_secret_9503",
            chat_name: "秘密研发群",
            chat_type: "group",
            create_time: String(nowSec),
            sender: { id: "ou_colleague", name: "同事", sender_type: "user" },
            content: "@张三 不应被轮询读入",
          },
        ],
      }),
    );
    await svc.connectors.pullIm();
    assert.ok(svc.store.obs("im:om_allow_ok"), "pw_chat:* 白名单不占用开放平台 max_groups=1 配额");
    assert.equal(svc.store.obs("im:om_secret_poll"), undefined, "静音 pw_chat 同样拦截兜底轮询中的同名开放平台群");
    svc.store.muteConv("pw_chat:9503", "", false);

    // 9) [R3 P1-5 & P2-8] 入库后新增排除规则阻断快通道与常规周期；关闭 fast_lane 后跳过已入队快通道
    mock.setChatName("9501", "正常群A");
    svc.store.addObs([
      {
        id: "pw:r3_queued_deny",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9501",
        conv_name: "正常群A",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "@张三 入库后被加黑名单",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "group" },
      },
    ]);
    app.cfg.context.groups_deny = ["正常群A"];
    const deniedFast = await svc.fastCycle("context:fast:r3-deny", {
      conv: "pw_chat:9501",
      conv_name: "正常群A",
      trigger_obs_id: "pw:r3_queued_deny",
    });
    assert.equal(deniedFast.fresh, 0, "入库后新增 groups_deny 必须阻断快通道运行模型");
    app.cfg.context.groups_deny = [];

    app.cfg.context.personal_web.fast_lane = false;
    const disabledFast = await svc.fastCycle("context:fast:r3-off", {
      conv: "pw_chat:9501",
      conv_name: "正常群A",
      trigger_obs_id: "pw:r3_queued_deny",
    });
    assert.equal(disabledFast.fresh, 0, "关闭 fast_lane 后必须跳过已入队快通道作业");
    app.cfg.context.personal_web.fast_lane = true;

    // 10) [R3 P2-5 & P2-6] 普通文本改真实 @mention 触发重新待处理；convWindowAround 包含触发前近邻背景而非只看最老积压 t0
    const mentionObsBase = {
      id: "pw:r3_mention_edit",
      source: "im" as const,
      kind: "group",
      conv: "pw_chat:9501",
      conv_name: "正常群A",
      actor_id: "7002",
      actor_name: "7002",
      is_me: false,
      time: now,
      text: "@张三 看下方案",
      url: "",
      meta: { transport: "personal_web", at_me: false, mentions: [] as unknown[] },
    };
    svc.store.addObs([mentionObsBase]);
    svc.store.markProcessed([{ id: mentionObsBase.id, rev: obsRevision(mentionObsBase) }]);
    assert.equal(svc.store.obsPending(mentionObsBase.id), false);
    const mentionObsEdited = {
      ...mentionObsBase,
      kind: "at_me",
      meta: { transport: "personal_web", at_me: true, mentions: [{ id: "7001", name: "张三", start: 0, end: 3 }] },
    };
    const editMentionCount = svc.store.addObs([mentionObsEdited]);
    assert.equal(editMentionCount, 1, "文本不变但新增真实 @mention 必须视为编辑并重新待处理");
    assert.equal(svc.store.obsPending(mentionObsBase.id), true);
    // 旧 rev markProcessed 不得吞掉新 @mention 版本
    svc.store.markProcessed([{ id: mentionObsBase.id, rev: obsRevision(mentionObsBase) }]);
    assert.equal(svc.store.obsPending(mentionObsBase.id), true);

    // 近邻背景窗口测试（09:00 待处理 + 09:59 已补读背景 + 10:00 触发）
    svc.store.addObs([
      {
        id: "pw:win_0900",
        source: "im",
        kind: "group",
        conv: "pw_chat:win_near",
        conv_name: "近邻群",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now - 3_600_000,
        text: "09:00 较早待处理",
        url: "",
        meta: {},
      },
      {
        id: "pw:win_1000",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:win_near",
        conv_name: "近邻群",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "@张三 10:00 触发消息",
        url: "",
        meta: {},
      },
    ]);
    svc.store.addBackgroundObs([
      {
        id: "pw:win_0959",
        source: "im",
        kind: "group",
        conv: "pw_chat:win_near",
        conv_name: "近邻群",
        actor_id: "7003",
        actor_name: "7003",
        is_me: false,
        time: now - 60_000,
        text: "09:59 刚补读的近邻背景",
        url: "",
        meta: {},
      },
    ]);
    const nearWin = svc.store.convWindowAround("pw_chat:win_near", "pw:win_1000", 10, 5);
    assert.deepEqual(
      nearWin.map((o) => o.id),
      ["pw:win_0900", "pw:win_0959", "pw:win_1000"],
      "紧贴触发消息之前的刚补读背景必须按时间顺序进入提示词窗口",
    );

    // 11) [R3 P1-6 & P2-11] hydrateContext 跨 await 遇到换号必须丢弃结果；发言群按账号隔离
    mock.setHistory("9501", {
      1: buildNativeMessage({ id: "r3_h_race", chatId: "9501", actorId: "7002", text: "并发换号历史", position: 1, createdAtSec: nowSec - 30 }),
    });
    const raceBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (raceBridge as unknown as { client?: FeishuWebClient }).client = liveClient;
    mock.setOnHistory(() => {
      // 在 readContext 飞行途中模拟用户切换到另一个账号
      loginStore.save({ owner_id: "7002", owner_name: "李四", cookies: baseCookies });
      app!.store.set(BOUND_OWNER_KV_KEY, "7002");
    });
    const raceAdded = await raceBridge.hydrateContext(
      { id: "r3_anchor_race", conversationId: "9501", rootId: "", parentId: "", threadId: "", position: 2, createdAtMs: now },
      "pw_chat:9501",
      "正常群A",
    );
    mock.setOnHistory(undefined);
    assert.equal(raceAdded, 0, "补读途中换号必须丢弃结果，绝不以新账号标记旧历史");
    assert.equal(svc.store.obs("pw:r3_h_race"), undefined);

    // 发言群按账号隔离（7001 发言不授予 7002 采集权限）
    app.cfg.context.groups = "spoken";
    app.store.set(pwSpokenGroupsKey("7001"), JSON.stringify({ "pw_chat:9599": { name: "共享群", at: now } }));
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "r3_other_spoken", chatId: "9599", actorId: "7003", text: "旧账号发过言但新账号未发过言" }), "7002"),
      liveClient,
    );
    assert.equal(svc.store.obs("pw:r3_other_spoken"), undefined, "旧账号的发言群绝不能授权给新账号");

    // 12) [R3 P2-12 & P3-1] 绑定键更新立即唤醒休眠监听；新会话保存后清除陈旧 needs_login 状态
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({ state: "needs_login", owner_id: "7001", owner_name: "张三", session_id: "old_expired_sess", since: now - 1000, last_message_at: null, last_error: "已过期" }),
    );
    loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    const freshStatus = svc.personalWeb.status(now);
    assert.equal(freshStatus.state, "stopped", "保存新会话后不应继续显示旧会话的 needs_login");
    assert.equal(freshStatus.last_error, "");

    // 模拟先落盘 7001 凭据但 BOUND_OWNER_KV_KEY 仍指向旧账号 9999，随后更新 BOUND_OWNER_KV_KEY 必须唤醒监听上线
    app.store.set(BOUND_OWNER_KV_KEY, "9999");
    const wakeBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 25,
      clientOptions: { endpoints: mock.endpoints, heartbeatIntervalMs: 500 },
    });
    const wakeHandle = wakeBridge.start();
    await waitUntil(() => wakeBridge.status().state === "needs_login");
    app.store.set(BOUND_OWNER_KV_KEY, "7001");
    await waitUntil(() => wakeBridge.status().state === "listening");
    wakeHandle.stop();

    // 13) [R3 P2-13] WebSocket 零长度帧数量上限与空分片数量上限保护
    const wsZero = await BinaryWebSocket.dial(mock.endpoints.websocketUrl, { maxQueueFrames: 16 });
    const emptyBinFrame = buildServerWsFrame(0x2, Buffer.alloc(0));
    for (let i = 0; i < 20; i++) mock.pushRawBytes(emptyBinFrame);
    await new Promise((r) => setTimeout(r, 30));
    await assert.rejects(
      (async () => {
        for (let i = 0; i < 20; i++) await wsZero.read(200);
      })(),
      /接收队列帧数超过上限/,
    );
    wsZero.close();

    const wsFrag = await BinaryWebSocket.dial(mock.endpoints.websocketUrl, { maxFragFrames: 4 });
    // 首帧 FIN=0 opcode=2 len=0，后续发送 5 个空续帧 FIN=0 opcode=0 len=0
    mock.pushRawBytes(Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    await assert.rejects(wsFrag.read(500), /分片数量超过上限/);
    wsFrag.close();
  } finally {
    app?.store.db.close();
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

async function waitUntil(pred: () => boolean, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 15));
  }
  throw new Error("waitUntil timeout");
}
