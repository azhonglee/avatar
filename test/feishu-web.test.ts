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
import { BOUND_OWNER_KV_KEY, PersonalWebBridge, verifyWorkspaceOwnerBinding } from "../src/context/personal-web.ts";
import { runDoctor } from "../src/doctor.ts";
import { SettingsService } from "../src/settings.ts";

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
  closeSockets: () => void;
  close: () => Promise<void>;
  acks: string[];
  heartbeats: number;
  sentReplies: { chatId: string; rootId: string; parentId: string; cid: string; text: string; inThread: boolean }[];
  wsHeaders: http.IncomingHttpHeaders[];
  wsQueries: URLSearchParams[];
  setProfileStatus: (status: number) => void;
  setTicketStatus: (status: number) => void;
  setWsUpgradeStatus: (status: number) => void;
  setChatModeFail: (fail: boolean) => void;
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
  let ticketStatus = 200;
  let wsUpgradeStatus = 101;
  let chatModeFail = false;
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
      if (profileStatus !== 200) {
        res.writeHead(profileStatus, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: 401 }));
        return;
      }
      assert.equal(req.headers["x-app-id"], "12");
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "session=sess_rotated_2; Path=/; Max-Age=86400",
      });
      res.end(JSON.stringify({ code: 0, data: { user: { id: "7001", name: "张三" } } }));
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
        if (chatModeFail) {
          res.writeHead(500);
          res.end();
          return;
        }
        const chatId = payload.str(1);
        const chatName =
          chatId.startsWith("dm_") ? "" : chatId === "8002" ? "未列入的群" : chatId === "8003" ? "绝密群" : "Ark 发布协同群";
        const chatRec = new ProtoWriter()
          .str(1, chatId)
          .uint(2, chatId.startsWith("dm_") ? CHAT_KIND_P2P : CHAT_KIND_GROUP)
          .str(4, chatName)
          .uint(39, 0)
          .finish();
        const resp = new ProtoWriter().bytes(1, new ProtoWriter().str(1, chatId).bytes(2, chatRec).finish()).finish();
        res.writeHead(200, gwHeaders);
        res.end(buildGatewayResponse(resp));
        return;
      }
      if (cmd === CMD_HISTORY) {
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
          actorId: "7001",
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
    sentReplies,
    wsHeaders,
    wsQueries,
    setProfileStatus: (s) => {
      profileStatus = s;
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

    // 4) 跨通道 1 对 1 指纹去重与 alt_id 编辑更新
    const beforePending = svc.store.pendingCount();
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
    assert.equal(added, 0, "同群同内容 ±15s 内不重复插入");
    assert.equal(svc.store.pendingCount(), beforePending, "不重复触发理解");
    const enriched = svc.store.obs("pw:pw_msg_100")!;
    assert.equal(svc.store.obs("im:om_open_100")?.id, "pw:pw_msg_100", "通过 alt_id 定位到规范观测");
    assert.equal(enriched.meta.open_message_id, "om_open_100");
    assert.equal(enriched.meta.open_chat_id, "oc_open_8001");
    assert.equal(enriched.actor_name, "李四");
    assert.match(enriched.url, /oc_open_8001/);

    // 经开放平台 ID 投递编辑更新：应原地更新规范行并重新标为待处理，而非新增重复行
    const edited = svc.store.addObs([
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
        text: "@张三 线上接口 500 已定位到网关超时，帮忙确认下回滚",
        url: "https://applink.feishu.cn/client/chat/open?openChatId=oc_open_8001",
        meta: { message_id: "om_open_100", chat_type: "group" },
      },
    ]);
    assert.equal(edited, 1);
    assert.match(svc.store.obs("pw:pw_msg_100")!.text, /已定位到网关超时/);
    assert.equal(
      (svc.store.db.prepare("SELECT COUNT(*) AS n FROM ctx_obs WHERE id = 'im:om_open_100'").get() as { n: number }).n,
      0,
      "不创建重复行",
    );
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

    // 4) [P2-5] 会话别名共享轮询历史与 Web 推送；[P1-3] oc_ 禁用群阻断对应 pw_chat 且 readChat 失败时 fail-closed
    svc.store.addObs([
      {
        id: "im:om_sec_old",
        source: "im",
        kind: "group",
        conv: "oc_secret_8003",
        conv_name: "绝密群",
        actor_id: "ou_a",
        actor_name: "A",
        is_me: false,
        time: now - 5000,
        text: "历史消息",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
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

    // [P1-3] oc_secret_8003 在 groups_deny 里，通过群名「绝密群」反查到 oc_secret_8003 后必须拒绝入库
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
    assert.equal(svc.store.obs("pw:pw_secret_1"), undefined, "oc_ 禁用群同样阻断个人 Web 推送");

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

    // [P2-14] hydrateContext 过滤非白名单机器人
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
    // 挂上 live client 测试 hydrateContext
    (bridgeForHydrate as unknown as { client?: FeishuWebClient }).client = client;
    await bridgeForHydrate.hydrateContext(
      { id: "h_anchor", conversationId: "8001", rootId: "", parentId: "", threadId: "", position: 3, createdAtMs: nowSec * 1000 },
      "pw_chat:8001",
      "Ark 发布协同群",
    );
    assert.equal(svc.store.obs("pw:h_bot_drop"), undefined, "补读历史同样过滤非白名单机器人");
    assert.ok(svc.store.obs("pw:h_human_ok"), "人类历史背景正常写入");

    // [P2-6] pre_draft=true 且 send_replies=false 时仍应生成待确认草稿；未补齐 om_ 前确认给清晰错误，补齐后可走 im.reply
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
        meta: { transport: "personal_web", native_message_id: "pre_draft_1", native_chat_id: "8001", native_root_id: "pre_draft_1", chat_type: "group" },
      },
    ]);
    const { item: askItem } = svc.store.upsertItem({ title: "确认下午发布窗口", kind: "ask_me", priority: "high", source: "im", confidence: 0.95 });
    svc.store.addEvidence("item", askItem.id, "pw:pre_draft_1", "麻烦确认下今天下午的发布窗口", now);
    assert.equal(svc.draftable(askItem), true, "send_replies=false 时仍允许起草");
    fs.writeFileSync(path.join(ctxDir, "draft.txt"), "下午 4 点可以发布。");
    const preDraft = await svc.drafter.forItem(askItem.id, "reply");
    assert.equal(preDraft.status, "proposed");
    await assert.rejects(
      app.commands.exec("context.draft_approve", { id: preDraft.id }, { source: "web", actor: "owner" }),
      /context\.personal_web\.send_replies/,
    );
    // lark-cli 补齐开放平台 ID 后，无需重新起草，确认直接走 im.reply
    svc.store.addObs([
      {
        id: "im:om_window_1",
        source: "im",
        kind: "at_me",
        conv: "oc_window_8001",
        conv_name: "Ark 发布协同群",
        actor_id: "ou_ww",
        actor_name: "王五",
        is_me: false,
        time: now + 1000,
        text: "@张三 麻烦确认下今天下午的发布窗口",
        url: "https://applink.feishu.cn/client/chat/open?openChatId=oc_window_8001",
        meta: { message_id: "om_window_1", chat_type: "group" },
      },
    ]);
    const fxAfterEnrich = svc.drafter.effectFor(preDraft, "下午 4 点可以发布。");
    assert.equal(fxAfterEnrich.op, "im.reply");
    assert.equal((fxAfterEnrich.args as { message_id: string }).message_id, "om_window_1");

    // [P2-2] 同会话并发占用保护：fastCycle 遇到已在处理的会话返回 busy: true
    (svc as unknown as { activeConvs: Set<string> }).activeConvs.add(svc.store.canonicalConv("pw_chat:8001"));
    const busyRes = await svc.fastCycle("context:fast:test-busy", { conv: "pw_chat:8001", conv_name: "Ark 发布协同群", trigger_obs_id: "pw:pre_draft_1" });
    assert.equal(busyRes.busy, true);
    (svc as unknown as { activeConvs: Set<string> }).activeConvs.delete(svc.store.canonicalConv("pw_chat:8001"));

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

async function waitUntil(pred: () => boolean, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 15));
  }
  throw new Error("waitUntil timeout");
}
