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
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type net from "node:net";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import * as Q from "../src/api/queries.ts";
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
import { selectEffectiveOpenGroups } from "../src/context/connectors.ts";
import { ContextService } from "../src/context/index.ts";
import {
  BOUND_OWNER_KV_KEY,
  BOUND_WORKSPACE_OWNER_KV_KEY,
  commitWorkspaceLogin,
  computePwReplyCid,
  hasWorkspaceOwnerMismatch,
  PENDING_CRED_COMMIT_KV_KEY,
  PersonalWebBridge,
  pwSpokenGroupsKey,
  saveWorkspaceBinding,
  verifyWorkspaceOwnerBinding,
} from "../src/context/personal-web.ts";
import { obsRevision, type Obs } from "../src/context/store.ts";
import { tryGit } from "../src/delivery/git.ts";
import { runDoctor } from "../src/doctor.ts";
import { extractSafeCodexProviderArgs, extractSafeCodexProviderConfig, mergeHarnessEnv, prepareHarnessEnv, wrapCredentialIsolatedCommand } from "../src/harness.ts";
import { SettingsService } from "../src/settings.ts";
import { parseToml } from "../src/toml.ts";
import { runProcess } from "../src/util.ts";
import { Dispatcher } from "../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test/stubs");
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// [R5 P1-1] 在构造任何 WebLoginStore 或派生 CLI 子进程前，彻底剥离宿主环境中的真实凭据路径与密钥，避免测试覆盖或删除真实登录态
delete process.env.PA_FEISHU_WEB_CRED_FILE;
delete process.env.CREDENTIALS_DIRECTORY;
const TEST_WEB_KEY = `pa-test-feishu-web-key-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;

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
  setChatKind: (chatId: string, kind: number) => void;
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
  const customChatKinds = new Map<string, number>();
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
          .uint(2, customChatKinds.get(chatId) ?? (chatId.startsWith("dm_") ? CHAT_KIND_P2P : CHAT_KIND_GROUP))
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
    setChatKind: (chatId, kind) => {
      customChatKinds.set(chatId, kind);
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
        groups_deny: ["pw_chat:9999"],
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

    // 写入登录凭据并完成工作区显式绑定
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    loginStore.save({
      owner_id: "7001",
      owner_name: "张三",
      cookies: [
        { name: "session", value: "sess_live_1", domain: "127.0.0.1", path: "/" },
        { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
      ],
    });
    saveWorkspaceBinding(app.store, "7001", app.cfg.owner.open_id);
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
    saveWorkspaceBinding(app.store, "7001", app.cfg.owner.open_id);
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
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
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
    saveWorkspaceBinding(app.store, "7001", app.cfg.owner.open_id);
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
    saveWorkspaceBinding(app.store, "7001", app.cfg.owner.open_id);

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

    // 2) [R3 P2-1 & R4 P2-5] 同会话多进程 Cookie 3-way 版本合并：非冲突键正确合并，同键冲突（陈旧响应重提旧 session）绝不回滚
    const savedV1 = loginStore.load()!;
    const sessKey = "127.0.0.1\0/\0session";
    const extraKey = "127.0.0.1\0/\0extra_flag";
    const mergedV2 = loginStore.saveIfSessionMatches(
      { ...savedV1, cookies: [...baseCookies.filter((c) => c.name !== "session"), { name: "session", value: "sess_v2", domain: "127.0.0.1", path: "/" }] },
      { upserts: [{ name: "session", value: "sess_v2", domain: "127.0.0.1", path: "/" }], deletes: [], baseValues: { [sessKey]: "sess_v1" } },
    );
    assert.ok(mergedV2 && mergedV2.cookie_version === 2);
    // 另一个持 v1 快照的并发进程：同键 session 试图写回旧值 sess_v1（冲突→丢弃），非冲突键 extra_flag 正常合并
    const mergedV3 = loginStore.saveIfSessionMatches(savedV1, {
      upserts: [
        { name: "session", value: "sess_stale_v1", domain: "127.0.0.1", path: "/" },
        { name: "extra_flag", value: "1", domain: "127.0.0.1", path: "/" },
      ],
      deletes: [],
      baseValues: { [sessKey]: "sess_v1", [extraKey]: null },
    });
    assert.ok(mergedV3 && mergedV3.cookie_version === 3);
    assert.equal(mergedV3.cookies.find((c) => c.name === "session")?.value, "sess_v2", "同键冲突绝不回滚其他进程已轮换的新 session");
    assert.equal(mergedV3.cookies.find((c) => c.name === "extra_flag")?.value, "1", "非冲突键增量正确合并");

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

    // 5) [R3 P1-2 & R4 P2-2] 首次绑定不能仅凭显示名称相同通过（且不同应用的 open_id 不做跨应用等价或误拒）；需显式 --allow-unverified-owner，重登同一已绑定账号免重复确认
    app.store.db.prepare("DELETE FROM kv WHERE k IN (?, ?, 'ctx.owner_name')").run(BOUND_OWNER_KV_KEY, BOUND_WORKSPACE_OWNER_KV_KEY);
    loginStore.clear();
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner", user_name: "张三" }));
    await assert.rejects(
      verifyWorkspaceOwnerBinding(app, { owner_id: "7777", owner_name: "张三", cookies: [] }),
      /allow-unverified-owner/,
    );
    // 不同应用（app_id=12）的 open_id 与工作区 lark-cli 应用的 open_id 不同属一个应用空间：传 --allow-unverified-owner 时不应误拒本人
    await verifyWorkspaceOwnerBinding(
      app,
      { owner_id: "7001", owner_name: "张三", owner_open_id: "ou_app12_different", cookies: [] },
      { allowUnverifiedOwner: true },
    );
    loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    saveWorkspaceBinding(app.store, "7001", "ou_owner");
    // 同一已绑定原生账号且同一工作区主人重登：无需再传 --allow-unverified-owner
    await verifyWorkspaceOwnerBinding(app, { owner_id: "7001", owner_name: "张三", cookies: [] });

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

    // 8) [R3 P1-4 & R4 P1-4 & R4 P1-9] 原生 pw_chat 静音同步生效到 lark-cli 兜底轮询（在线实时解析）；无在线客户端时 inconclusive 暂缓且保留游标
    svc.store.muteConv("pw_chat:9503", "秘密研发群", true);
    mock.setChatName("9503", "秘密研发群");
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
    // 8a) 无在线客户端（如独立 pa context run）：无法核实静音群是否已改名，必须 inconclusive 暂缓且不推进 cursor.im
    app.store.db.prepare("DELETE FROM kv WHERE k = 'ctx.cursor.im'").run();
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_allow_ok"), undefined, "无在线 Web 客户端无法核实原生静音群名时暂缓群入库");
    assert.equal(app.store.get("ctx.cursor.im"), undefined, "排除状态 inconclusive 时绝不推进 cursor.im 导致后续漏采");

    // 8b) 在线 Web 客户端就绪后：实时解析 9503 群名，放行白名单群并精确拦截静音群
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = liveClient;
    await svc.connectors.pullIm();
    assert.ok(svc.store.obs("im:om_allow_ok"), "pw_chat:* 白名单不占用开放平台 max_groups=1 配额");
    assert.equal(svc.store.obs("im:om_secret_poll"), undefined, "静音 pw_chat 同样拦截兜底轮询中的同名开放平台群");
    assert.ok(app.store.get("ctx.cursor.im"), "确认解析后正常推进 cursor.im");
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = undefined;
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

// ───────── 10. Codex Review 第四轮专项回归测试 ─────────

test("Codex 第四轮回归：凭据加密与 harness 隔离、工作区主人绑定、脏库换号拦截、负向排除复核、推送中止保护、自动预起草复核、分页不饿死、数字关键词、已建待回读、多话题锚点与 RFC6455 校验", async () => {
  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-pw-r4-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevCtxDir = process.env.CTX_DIR;
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.CTX_DIR = ctxDir;

  const cfgFile = path.join(dir, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
      harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner_a" },
      cards: { enabled: false },
      engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 2 },
      context: {
        harness: "cx",
        groups: "allowlist",
        max_groups: 5,
        groups_allow: ["pw_chat:9601"],
        groups_deny: ["2024"],
        personal_web: { enabled: true, fast_lane: true, debounce_ms: 20, pre_draft: true, send_replies: true },
      },
    }),
  );

  let app: ReturnType<typeof createApp> | undefined;
  try {
    // 1) [R4 P1-1] AES-256-GCM 静态加密存储：开启 PA_FEISHU_WEB_KEY 后磁盘不含明文 session
    process.env.PA_FEISHU_WEB_KEY = "super-secret-master-key-for-test";
    const encDir = makeTmp("pa-pw-enc-");
    const encStore = new WebLoginStore(encDir);
    const baseCookies = [
      { name: "session", value: "sess_super_secret_raw", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
    ];
    encStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    const rawDisk = fs.readFileSync(encStore.file, "utf8");
    assert.ok(!rawDisk.includes("sess_super_secret_raw"), "加密模式下磁盘绝不能出现明文 session");
    assert.equal(encStore.load()?.cookies.find((c) => c.name === "session")?.value, "sess_super_secret_raw");
    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;

    // 2) [R4 P2-6 & R5 P2-12] 跨进程 SQLite BEGIN IMMEDIATE 原子文件锁：可重入/保存后正常释放且 0600 权限
    const lockDir = makeTmp("pa-pw-lock-");
    const lockStore = new WebLoginStore(lockDir, "feishu-web.json", 300);
    lockStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    assert.equal(lockStore.load()?.owner_id, "7001");
    assert.equal(fs.statSync(lockStore.lockFile).mode & 0o777, 0o600, "凭据锁文件权限必须为 0600");

    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const savedLogin = loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    saveWorkspaceBinding(app.store, "7001", "ou_owner_a");

    // 3) [R4 P1-2] config.yaml 的 owner.open_id 变更后，启动校验必须拒绝旧主人的 Web 凭据进入 needs_login
    app.cfg.owner.open_id = "ou_owner_b";
    const mismatchBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 25,
      clientOptions: { endpoints: mock.endpoints },
    });
    const mHandle = mismatchBridge.start();
    await waitUntil(() => mismatchBridge.status().state === "needs_login");
    assert.match(mismatchBridge.status().last_error, /已绑定的工作区主人 \(ou_owner_a\) 不一致/);
    mHandle.stop();
    app.cfg.owner.open_id = "ou_owner_a";

    // 4) [R4 P1-3] 脏数据目录拒绝原地换号，且存储窗口按当前绑定账号隔离旧账号 pw:* 观测
    svc.store.addObs([
      {
        id: "pw:old_owner_msg",
        source: "im",
        kind: "mine",
        conv: "pw_chat:shared_1",
        conv_name: "共享群",
        actor_id: "7001",
        actor_name: "张三",
        is_me: true,
        time: now - 5000,
        text: "前主人的发言",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "group" },
      },
      {
        id: "pw:new_owner_msg",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:shared_1",
        conv_name: "共享群",
        actor_id: "7003",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@李四 新主人的消息",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7002", chat_type: "group" },
      },
    ]);
    await assert.rejects(
      verifyWorkspaceOwnerBinding(
        app,
        { owner_id: "7002", owner_name: "李四", cookies: [] },
        { forceSwitch: true, allowNameMismatch: true, allowUnverifiedOwner: true },
      ),
      /拒绝原地换号/,
    );
    const scopedWin = svc.store.convWindowAround("pw_chat:shared_1", "pw:new_owner_msg", 20, 5, "7002");
    assert.deepEqual(
      scopedWin.map((o) => o.id),
      ["pw:new_owner_msg"],
      "按绑定账号隔离后绝不能把前主人的【我】消息带入新主人窗口",
    );

    // 5) [R4 P2-4] 纯数字 groups_deny ("2024") 保持原有群名关键词语义，不误阻断普通群轮询
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        at_me: [
          {
            message_id: "om_2024_deny",
            chat_id: "oc_2024",
            chat_name: "2024 规划复盘群",
            chat_type: "group",
            create_time: String(nowSec),
            sender: { id: "ou_x", name: "X", sender_type: "user" },
            content: "@张三 2024 关键词群应被拦截",
          },
          {
            message_id: "om_normal_ok",
            chat_id: "oc_norm",
            chat_name: "正常研发群",
            chat_type: "group",
            create_time: String(nowSec),
            sender: { id: "ou_x", name: "X", sender_type: "user" },
            content: "@张三 正常群不应受 2024 规则影响",
          },
        ],
      }),
    );
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_2024_deny"), undefined, "数字关键词仍按群名子串拦截");
    assert.ok(svc.store.obs("im:om_normal_ok"), "纯数字 groups_deny 绝不误当成不可解析原生 ID 导致全群停采");
    app.cfg.context.groups_deny = [];

    // 6) [R4 P1-5 & P2-1] 负向排除强制复核防改名逃逸；群名以 "私聊" 开头但 chat_type="group" 仍按群聊校验
    const client = await FeishuWebClient.connect(savedLogin, { endpoints: mock.endpoints });
    app.cfg.context.groups_deny = ["oc_rename_target"];
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三", chat_meta: { oc_rename_target: { name: "旧秘密群", chat_mode: "group" } } }),
    );
    mock.setChatName("9601", "普通群A");
    // 先缓存 oc_rename_target = "旧秘密群"
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "r4_warm_1", chatId: "9601", actorId: "7002", text: "预热缓存" }), "7001"),
      client,
    );
    // 随后 oc_rename_target 改名为 "私聊吐槽群"（注意群名以 "私聊" 开头！），且 9602 也是这个新群名
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三", chat_meta: { oc_rename_target: { name: "私聊吐槽群", chat_mode: "group" } } }),
    );
    mock.setChatName("9602", "私聊吐槽群");
    await svc.personalWeb.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "r4_renamed_escape",
          chatId: "9602",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 改名后不应逃逸" }]),
        }),
        "7001",
      ),
      client,
    );
    assert.equal(svc.store.obs("pw:r4_renamed_escape"), undefined, "负向不匹配强制刷新 oc_* 缓存后成功拦下改名后的禁用群");
    app.cfg.context.groups_deny = [];

    // 7) [R4 P1-6] 推送处理期间会话被中止（AbortSignal）绝不落库
    const abortCtrl = new AbortController();
    app.cfg.context.groups_allow = ["pw_chat:9601", "pw_chat:9603"];
    mock.setOnChatMode(() => abortCtrl.abort());
    await assert.rejects(
      svc.personalWeb.handleMessage(
        decodeMessage(buildNativeMessage({ id: "r4_aborted_push", chatId: "9603", actorId: "7002", text: "中止期间到达" }), "7001"),
        client,
        abortCtrl.signal,
      ),
      /中止|aborted/i,
    );
    mock.setOnChatMode(undefined);
    app.cfg.context.groups_allow = ["pw_chat:9601"];
    assert.equal(svc.store.obs("pw:r4_aborted_push"), undefined, "会话中止后绝不落库");

    // 8) [R4 P2-9] 范围外群的 @我 消息被编辑移除 @我 后，撤回旧待处理观测
    mock.setChatName("9699", "未列入群");
    await svc.personalWeb.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "r4_withdrawn_at",
          chatId: "9699",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 请处理" }]),
        }),
        "7001",
      ),
      client,
    );
    assert.equal(svc.store.obsPending("pw:r4_withdrawn_at"), true);
    // 发送者编辑移除了 @张三（服务端权威消息同步更新为不含 @张三）
    const editedWithdrawn = buildNativeMessage({ id: "r4_withdrawn_at", chatId: "9699", actorId: "7002", text: "没事了发错人" });
    mock.addMessage("r4_withdrawn_at", editedWithdrawn);
    await svc.personalWeb.handleMessage(decodeMessage(editedWithdrawn, "7001"), client);
    assert.equal(svc.store.obsPending("pw:r4_withdrawn_at"), false, "编辑移除 @我 后必须撤回旧待处理状态");
    assert.equal(svc.store.obs("pw:r4_withdrawn_at")?.meta.withdrawn, true);

    // 9) [R4 P2-10] 防抖合并同群两个不同话题的 @我 时保留全部锚点，并同时补读两个话题根消息
    const triggeredList: { anchors: { rootId: string }[] }[] = [];
    const multiBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: (t) => triggeredList.push(t),
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (multiBridge as unknown as { client?: FeishuWebClient }).client = client;
    mock.addMessage("root_th_a", buildNativeMessage({ id: "root_th_a", chatId: "9601", actorId: "7003", text: "话题A根消息", createdAtSec: nowSec - 600, position: 1 }));
    mock.addMessage("root_th_b", buildNativeMessage({ id: "root_th_b", chatId: "9601", actorId: "7004", text: "话题B根消息", createdAtSec: nowSec - 500, position: 2 }));
    await multiBridge.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "th_at_a",
          chatId: "9601",
          actorId: "7002",
          rootId: "root_th_a",
          parentId: "root_th_a",
          threadId: "th_a",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 看话题A" }]),
        }),
        "7001",
      ),
      client,
    );
    await multiBridge.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "th_at_b",
          chatId: "9601",
          actorId: "7002",
          rootId: "root_th_b",
          parentId: "root_th_b",
          threadId: "th_b",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 看话题B" }]),
        }),
        "7001",
      ),
      client,
    );
    await waitUntil(() => triggeredList.length === 1);
    assert.equal(triggeredList[0].anchors.length, 2, "防抖期内两个不同话题的锚点必须全部保留");
    await multiBridge.hydrateContext(triggeredList[0].anchors as never, "pw_chat:9601", "普通群A");
    const dualWin = svc.store.convWindowAround("pw_chat:9601", "pw:th_at_b", 20, 5, "7001");
    assert.ok(dualWin.some((o) => o.id === "pw:root_th_a"), "保留话题A根锚点");
    assert.ok(dualWin.some((o) => o.id === "pw:root_th_b"), "保留话题B根锚点");
    multiBridge.stop();

    // 10) [R4 P1-7] 自动预起草（auto: true）在排队期间关闭 pre_draft 后执行时必须跳过，绝不调模型
    const { item: autoDraftItem } = svc.store.upsertItem({ title: "排队后关闭预起草测试", kind: "ask_me", priority: "high", source: "im", confidence: 0.95 });
    svc.store.addEvidence("item", autoDraftItem.id, "pw:th_at_b", "看话题B", now);
    svc.enqueue("draft:auto-skip-1", { task: "draft", item_id: autoDraftItem.id, kind: "reply", auto: true });
    app.cfg.context.personal_web.pre_draft = false;
    await app.engine.drain(["context"]);
    assert.equal(app.ledger.get("context:draft:auto-skip-1")?.state, "skipped", "关闭 pre_draft 后自动预起草必须跳过");
    assert.equal(svc.store.drafts({}).some((d) => d.item_id === autoDraftItem.id), false);

    // 11) [R4 P1-8] 25 个被排除的 IM 会话排在前面时，cycle 必须翻页继续处理第 26 个会议纪要（不饿死）
    svc.store.db.prepare("UPDATE ctx_obs SET processed = 1").run();
    for (let i = 0; i < 25; i++) {
      svc.store.addObs([
        {
          id: `im:starve_${i}`,
          source: "im",
          kind: "group",
          conv: `oc_starve_${i}`,
          conv_name: `已禁用群_${i}`,
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now - 100_000 + i * 100,
          text: `被排除消息 ${i}`,
          url: "",
          meta: { chat_type: "group" },
        },
      ]);
    }
    svc.store.addObs([
      {
        id: "minutes:m_not_starved",
        source: "minutes",
        kind: "minutes",
        conv: "minutes:m_not_starved",
        conv_name: "会议：季度评审",
        actor_id: "",
        actor_name: "智能纪要",
        is_me: false,
        time: now,
        text: "会议纪要：确定 Q4 路线图",
        url: "",
        meta: {},
      },
    ]);
    app.cfg.context.groups_deny = ["已禁用群_"];
    app.cfg.context.sources = { meego: false, tasks: false, im: true, minutes: true, calendar: false, docs: false };
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三" }));
    fs.writeFileSync(path.join(ctxDir, "understand.json"), JSON.stringify({ projects: [], items: [] }));
    const cycRep = await svc.cycle("context:cycle:r4-page");
    assert.equal(cycRep.convs, 1, "翻页跳过 25 个被排除 IM 会话后必须处理会议纪要");
    assert.equal(svc.store.obsPending("minutes:m_not_starved"), false);
    app.cfg.context.groups_deny = [];

    // 12) [R4 P2-11 & P2-3] 已 created 待回读在关闭 send_replies 后仍可完成回读；跨进程修改 config.yaml 关闭 send_replies 阻止新发送
    mock.addMessage("r4_reply_orig", buildNativeMessage({ id: "r4_reply_orig", chatId: "9601", actorId: "7002", text: "待回复", position: 90 }));
    const replyBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    (replyBridge as unknown as { client?: FeishuWebClient }).client = client;
    mock.setFailReadbackCount(1);
    await assert.rejects(
      replyBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9601", message_id: "r4_reply_orig", text: "已创建待回读", cid: "cid_r4_readback_off" }),
      /HTTP 503/,
    );
    // 关闭 send_replies 后重试：应走只读回读完成确认而不报错
    app.cfg.context.personal_web.send_replies = false;
    const rbRes = await replyBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9601", message_id: "r4_reply_orig", text: "已创建待回读", cid: "cid_r4_readback_off" });
    assert.equal(rbRes.verified, true, "已创建的消息在关闭 send_replies 后仍应完成只读回读核验");

    // 跨进程修改磁盘 config.yaml 关闭 send_replies（本进程内存仍为 true）：新发送必须被拦截
    app.cfg.context.personal_web.send_replies = true;
    const diskCfg = JSON.parse(fs.readFileSync(cfgFile, "utf8")) as { context: { personal_web: { send_replies: boolean } } };
    diskCfg.context.personal_web.send_replies = false;
    await new Promise((r) => setTimeout(r, 15));
    fs.writeFileSync(cfgFile, JSON.stringify(diskCfg));
    await assert.rejects(
      replyBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9601", message_id: "r4_reply_orig", text: "跨进程关闭后新发", cid: "cid_r4_disk_off" }),
      /配置文件已关闭 context\.personal_web\.send_replies/,
    );

    // 13) [R4 P2-14] RFC 6455 校验：拒绝带掩码的服务端帧、分片控制帧和超 125 字节的 Ping 控制帧
    const wsMask = await BinaryWebSocket.dial(mock.endpoints.websocketUrl);
    mock.pushRawBytes(Buffer.from([0x82, 0x80, 0x01, 0x02, 0x03, 0x04])); // masked=1 from server
    await assert.rejects(wsMask.read(500), /掩码位/);
    wsMask.close();

    const wsBigPing = await BinaryWebSocket.dial(mock.endpoints.websocketUrl);
    mock.pushRawBytes(Buffer.from([0x89, 126, 0x00, 130])); // Ping with 130-byte payload (> 125)
    await assert.rejects(wsBigPing.read(500), /RFC 6455/);
    wsBigPing.close();

    // 14) [R4 P3-1] doctor 对 publication_blocked 返回 warn 并展示原因
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({ state: "publication_blocked", owner_id: "7001", owner_name: "张三", session_id: savedLogin.session_id, since: now, last_message_at: now, last_error: "SQLITE_FULL" }),
    );
    app.store.set("daemon.heartbeat", `host:1|${now}`);
    const docBlocked = await runDoctor(app);
    const pwDoc = docBlocked.checks.find((c) => c.id === "personal_web")!;
    assert.equal(pwDoc.status, "warn", "publication_blocked 必须在 doctor 中标为 warn");
    assert.match(pwDoc.detail, /SQLITE_FULL/);
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    app?.store.db.close();
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 13. Codex 第五轮回归：强制加密防降级、无静默绑定、换主人全链路阻断、MCP 隔离、关键词/轮询改名复核、独立游标、撤回隔离、权威编辑排序、有界防抖、原子锁、varint 溢出 ─────────

test("Codex 第五轮回归：加密防降级、显式绑定、主人变更全阻断、MCP/凭据隔离、改名复核、独立游标、撤回隔离、权威回读防回滚、有界防抖、回读恢复、原子锁与 varint 溢出", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const mock = await startMockFeishuWebServer();
  const root = makeTmp("pa-pw-r5-");
  const dataDir = path.join(root, "data");
  const ctxDir = path.join(root, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  process.env.CTX_DIR = ctxDir;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;

  const baseCookies = [
    { name: "session", value: "sess_r5_v1", domain: "127.0.0.1", path: "/" },
    { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
  ];

  let app: ReturnType<typeof createApp> | undefined;
  let freshApp: ReturnType<typeof createApp> | undefined;
  try {
    // 1) [R5 P3-1] 拒绝溢出的 10 字节 protobuf varint（第 10 字节 > 1 不得回绕），合法 uint64 最大值正常解析
    const maxU64 = new ProtoWriter().uint(1, 0xffff_ffff_ffff_ffffn).finish();
    assert.equal(parseProto(maxU64).uint64(1), 0xffff_ffff_ffff_ffffn);
    const overflow10Byte = Buffer.from([0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
    assert.throws(() => parseProto(overflow10Byte), ProtoWireError, "第 10 字节为 0x02 超过 64 位必须拒绝而非回绕");

    // 2) [R5 P1-4] 禁止明文落盘；缺少密钥时拒绝写入且拒绝降级覆盖既有加密文件；拒绝加载明文文件
    const encDir = makeTmp("pa-pw-r5-enc-");
    const encStore = new WebLoginStore(encDir);
    delete process.env.PA_FEISHU_WEB_KEY;
    delete process.env.CREDENTIALS_DIRECTORY;
    assert.throws(
      () => encStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies }),
      /静态加密密钥/,
      "无密钥时绝不以明文落盘",
    );
    assert.equal(fs.existsSync(encStore.file), false);

    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
    encStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    const encryptedSnapshot = fs.readFileSync(encStore.file, "utf8");
    assert.ok(!encryptedSnapshot.includes("sess_r5_v1"));

    // 剥离密钥后再次 save 必须拒绝降级覆盖，且原密文保持完好
    delete process.env.PA_FEISHU_WEB_KEY;
    assert.equal(encStore.inspect().status, "missing_key");
    assert.equal(encStore.load(), undefined);
    assert.throws(
      () => encStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies }),
      /拒绝降级覆盖/,
    );
    assert.equal(fs.readFileSync(encStore.file, "utf8"), encryptedSnapshot, "既有加密文件绝不能被降级破坏");

    // 伪造明文文件必须被 inspect/load 拒绝
    const plainDir = makeTmp("pa-pw-r5-plain-");
    const plainStore = new WebLoginStore(plainDir);
    fs.writeFileSync(plainStore.file, JSON.stringify({ owner_id: "7001", owner_name: "张三", cookies: baseCookies }), { mode: 0o600 });
    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
    assert.equal(plainStore.inspect().status, "plaintext_rejected");
    assert.equal(plainStore.load(), undefined);

    // 3) [R5 P2-14] prepareHarnessEnv 仅隔离 feishu-web-key，保留无关 systemd 凭据
    const credDirOnlyOther = makeTmp("pa-creds-other-");
    fs.writeFileSync(path.join(credDirOnlyOther, "openai-api-key"), "sk-other", { mode: 0o400 });
    const envOnlyOther = prepareHarnessEnv({ PATH: "/usr/bin", CREDENTIALS_DIRECTORY: credDirOnlyOther, PA_FEISHU_WEB_KEY: "secret" });
    try {
      assert.equal(envOnlyOther.env.PA_FEISHU_WEB_KEY, undefined);
      assert.equal(envOnlyOther.env.CREDENTIALS_DIRECTORY, credDirOnlyOther, "无 feishu-web-key 时原样保留 CREDENTIALS_DIRECTORY");
    } finally {
      envOnlyOther.cleanup();
    }

    const credDirMixed = makeTmp("pa-creds-mixed-");
    fs.writeFileSync(path.join(credDirMixed, "feishu-web-key"), "web-secret", { mode: 0o400 });
    fs.writeFileSync(path.join(credDirMixed, "provider-token"), "tok-keep", { mode: 0o400 });
    // 有可用内核 tmpfs 时投影无关凭据到 tmpfs；无可用 tmpfs 时按安全策略剥离 CREDENTIALS_DIRECTORY（绝不落盘到磁盘 /tmp）
    const knownTmpfs = [process.env.XDG_RUNTIME_DIR?.trim(), "/dev/shm"].find((d) => {
      if (!d) return false;
      try {
        if (fs.statfsSync(d).type !== 0x01021994) return false;
        fs.accessSync(d, fs.constants.W_OK | fs.constants.X_OK);
        return true;
      } catch {
        return false;
      }
    });
    if (knownTmpfs) {
      const envMixed = prepareHarnessEnv(
        { PATH: "/usr/bin", XDG_RUNTIME_DIR: knownTmpfs, CREDENTIALS_DIRECTORY: credDirMixed },
        { tmpfsCandidates: [knownTmpfs] },
      );
      const filteredDir = envMixed.env.CREDENTIALS_DIRECTORY!;
      try {
        assert.ok(filteredDir && filteredDir !== credDirMixed, "混合目录必须切到隔离 tmpfs 凭据目录");
        assert.equal(fs.existsSync(path.join(filteredDir, "feishu-web-key")), false, "feishu-web-key 绝不暴露给子进程");
        assert.equal(fs.readFileSync(path.join(filteredDir, "provider-token"), "utf8"), "tok-keep", "无关 systemd 凭据必须保留可读");
      } finally {
        envMixed.cleanup();
      }
      assert.equal(fs.existsSync(filteredDir), false, "子进程结束后临时凭据目录必须清理");
    }
    // 明确验证无可用 tmpfs 时的 fail-closed 回退：传空候选集避免受宿主机 os.tmpdir() 本身是否为 tmpfs 影响，彻底移除 CREDENTIALS_DIRECTORY
    const envNoTmpfs = prepareHarnessEnv(
      { PATH: "/usr/bin", CREDENTIALS_DIRECTORY: credDirMixed },
      { tmpfsCandidates: [] },
    );
    try {
      assert.equal(envNoTmpfs.env.CREDENTIALS_DIRECTORY, undefined, "无可用内核 tmpfs 时必须移除 CREDENTIALS_DIRECTORY 而绝不复制到磁盘");
    } finally {
      envNoTmpfs.cleanup();
    }

    const credDirOnlyWeb = makeTmp("pa-creds-webonly-");
    fs.writeFileSync(path.join(credDirOnlyWeb, "feishu-web-key"), "web-secret", { mode: 0o400 });
    const envOnlyWeb = prepareHarnessEnv({ PATH: "/usr/bin", CREDENTIALS_DIRECTORY: credDirOnlyWeb });
    try {
      assert.equal(envOnlyWeb.env.CREDENTIALS_DIRECTORY, undefined, "仅含 feishu-web-key 时彻底移除 CREDENTIALS_DIRECTORY");
    } finally {
      envOnlyWeb.cleanup();
    }

    // 4) [R5 P2-12 & P2-13] 跨进程 SQLite BEGIN IMMEDIATE 原子锁：活进程互斥、SIGKILL 立即原子释放、不可读锁快速失败
    const lockTestDir = makeTmp("pa-pw-r5-lock-");
    const shortLockStore = new WebLoginStore(lockTestDir, "feishu-web.json", 150);
    shortLockStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    const holder = spawn(
      process.execPath,
      [
        "-e",
        `const { DatabaseSync } = require("node:sqlite");
         const db = new DatabaseSync(${JSON.stringify(shortLockStore.lockFile)});
         db.exec("PRAGMA busy_timeout = 5000");
         db.exec("BEGIN IMMEDIATE");
         process.stdout.write("HELD\\n");
         setTimeout(() => {}, 60000);`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("holder timeout")), 5_000);
      holder.stdout.on("data", (d: Buffer) => {
        if (d.toString().includes("HELD")) {
          clearTimeout(t);
          resolve();
        }
      });
    });
    assert.throws(
      () => shortLockStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies }),
      /database is locked/,
      "存活进程持锁时竞争者必须在有界超时内失败而非破坏锁",
    );
    holder.kill("SIGKILL");
    await new Promise<void>((resolve) => holder.once("close", () => resolve()));
    // SIGKILL 后内核原子释放锁，立刻可重新落盘（零陈旧锁清理竞态）
    shortLockStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });

    // 不可打开锁路径（目录占位，即使在 root 容器中也必失败）必须快速报错，绝不无限自旋挂死
    const unreadableDir = makeTmp("pa-pw-r5-unreadable-");
    const unreadableStore = new WebLoginStore(unreadableDir, "feishu-web.json", 150);
    fs.mkdirSync(unreadableStore.lockFile, { recursive: true });
    const tFail0 = Date.now();
    try {
      assert.throws(() => unreadableStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies }));
      assert.ok(Date.now() - tFail0 < 2_000, "不可打开锁路径必须受限于截止时间或立即失败");
    } finally {
      fs.rmSync(unreadableStore.lockFile, { recursive: true, force: true });
    }

    // 5) [R5 P2-11] Cookie 轮换对比请求发出时刻快照：在途期间 syncFromDisk 轮换的新 Cookie 绝不被迟到响应覆盖
    const rotJar = RecordingCookieJar.fromRecords(baseCookies, ["127.0.0.1"]);
    const reqSnap = rotJar.snapshot();
    // 模拟请求在途期间另一进程通过 syncFromDisk 把 session 从 sess_r5_v1 轮换为 sess_r5_v2
    rotJar.syncFromRecords([
      { name: "session", value: "sess_r5_v2", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_test_123", domain: "127.0.0.1", path: "/" },
    ]);
    // 迟到的旧响应携带着陈旧的 session=sess_r5_stale 与无关的新 cookie other=ok
    const applied = rotJar.setFromHeaders(
      new URL("http://127.0.0.1/im/gateway/"),
      ["session=sess_r5_stale; Domain=127.0.0.1; Path=/", "other_cookie=ok; Domain=127.0.0.1; Path=/"],
      Date.now(),
      reqSnap,
    );
    assert.equal(applied, true);
    assert.equal(rotJar.cookieValue(new URL("http://127.0.0.1/"), "session"), "sess_r5_v2", "迟到响应绝不能覆盖在途期间已同步的新 session");
    assert.equal(rotJar.cookieValue(new URL("http://127.0.0.1/"), "other_cookie"), "ok", "无冲突的无关 Cookie 仍可正常应用");

    // 6) [R5 P1-2] 干净数据目录指向已有 PA_FEISHU_WEB_CRED_FILE 时，常驻监听绝不静默绑定，必须拒绝进入 needs_login
    const sharedCredFile = path.join(makeTmp("pa-pw-shared-"), "shared-cred.json");
    process.env.PA_FEISHU_WEB_CRED_FILE = sharedCredFile;
    new WebLoginStore(makeTmp("pa-pw-unused-")).save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    const freshDir = makeTmp("pa-pw-fresh-ws-");
    const freshCfgFile = path.join(freshDir, "config.yaml");
    fs.writeFileSync(
      freshCfgFile,
      JSON.stringify({
        owner: { open_id: "ou_victim_owner" },
        data_dir: path.join(freshDir, "data"),
        bins: { lark: path.join(STUBS, "ctx-lark"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
        roles: { brain: "cx" },
        server: { enabled: false },
        cards: { enabled: false },
        kb: { enabled: false },
        context: {
          harness: "cx",
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0 },
        },
      }),
    );
    freshApp = createApp(loadConfig(freshCfgFile));
    const freshSvc = new ContextService(freshApp);
    const freshLoginAlerts: string[] = [];
    const unboundBridge = new PersonalWebBridge(freshApp, freshSvc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: (r) => freshLoginAlerts.push(r),
      clientOptions: { endpoints: mock.endpoints },
      credentialWatchIntervalMs: 30,
    });
    const unboundHandle = unboundBridge.start();
    try {
      await waitUntil(() => freshLoginAlerts.length > 0, 2_000);
      assert.match(freshLoginAlerts[0], /尚未完成个人 Web 账号显式绑定/);
      assert.equal(freshApp.store.get(BOUND_OWNER_KV_KEY), undefined, "常驻监听绝不能静默写入 BOUND_OWNER_KV_KEY");
      assert.equal(freshApp.store.get(BOUND_WORKSPACE_OWNER_KV_KEY), undefined, "常驻监听绝不能静默写入 BOUND_WORKSPACE_OWNER_KV_KEY");
    } finally {
      unboundHandle.stop();
    }
    delete process.env.PA_FEISHU_WEB_CRED_FILE;

    // ───────── 建立主测试应用（含 codex-exec 与 lark stub）─────────
    const cfgFile = path.join(root, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        owner: { open_id: "ou_owner_a" },
        data_dir: dataDir,
        bins: { lark: path.join(STUBS, "ctx-lark"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
        roles: { brain: "cx" },
        server: { enabled: false },
        cards: { enabled: false },
        kb: { enabled: false },
        context: {
          harness: "cx",
          groups: "allowlist",
          max_groups: 5,
          groups_allow: ["pw_chat:9701"],
          groups_deny: [],
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const savedLogin = loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    saveWorkspaceBinding(app.store, "7001", "ou_owner_a");
    const client = await FeishuWebClient.connect(savedLogin, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;

    // 7) [R5 P1-5] codex-exec tools="none" 传入 --ignore-user-config / --ignore-rules / 禁用 MCP 与内置工具
    const callsLog = path.join(ctxDir, "calls.log");
    fs.writeFileSync(callsLog, "");
    fs.writeFileSync(path.join(ctxDir, "understand.json"), JSON.stringify({ projects: [], items: [] }));
    svc.store.addObs([
      {
        id: "pw:mcp_check_1",
        source: "im",
        kind: "p2p",
        conv: "pw_chat:dm_mcp",
        conv_name: "私聊：7002",
        actor_id: "7002",
        actor_name: "7002",
        is_me: false,
        time: now,
        text: "测试无工具无 MCP 隔离参数",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
      },
    ]);
    await svc.fastCycle("context:fast:mcp-check", { conv: "pw_chat:dm_mcp", conv_name: "私聊：7002", trigger_obs_id: "pw:mcp_check_1" });
    const codexCalls = fs
      .readFileSync(callsLog, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { role: string; argv: string[] })
      .filter((c) => c.role === "codex");
    assert.ok(codexCalls.length >= 1);
    const lastCodexArgv = codexCalls[codexCalls.length - 1].argv;
    assert.ok(lastCodexArgv.includes("--ignore-user-config"), "tools=none 必须禁用 ~/.codex/config.toml 防止加载用户 MCP Server");
    assert.ok(lastCodexArgv.includes("--ignore-rules"), "tools=none 必须禁用 execpolicy rules");
    assert.ok(lastCodexArgv.includes("code_mode") && lastCodexArgv.includes("plugins") && lastCodexArgv.includes("shell_tool"));

    // 8) [R5 P1-3] 工作区 owner.open_id 从 A 变更为 B 后，A 的待处理私聊观测必须被常规 cycle 与快通道彻底阻断
    svc.store.addObs([
      {
        id: "pw:owner_a_dm_secret",
        source: "im",
        kind: "p2p",
        conv: "pw_chat:dm_owner_a",
        conv_name: "私聊：7009",
        actor_id: "7009",
        actor_name: "7009",
        is_me: false,
        time: now,
        text: "A 的机密私聊，绝不能发给 B",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
      },
    ]);
    app.cfg.owner.open_id = "ou_owner_b";
    assert.equal(svc.personalWeb.activeBoundNativeOwner(), null, "主人变更后 activeBoundNativeOwner 必须返回 null");
    assert.equal(
      svc.store.pendingConvs(20, ["im"], { activeNativeOwner: svc.personalWeb.activeBoundNativeOwner() }).length,
      0,
      "activeNativeOwner=null 必须过滤掉全部 pw:* 观测而非解除过滤",
    );
    assert.equal(await svc.personalWeb.checkConvAllowedForUnderstand("pw_chat:dm_owner_a", "私聊：7009"), "excluded");
    const blockedFastOwnerChange = await svc.fastCycle("context:fast:owner-changed", {
      conv: "pw_chat:dm_owner_a",
      conv_name: "私聊：7009",
      trigger_obs_id: "pw:owner_a_dm_secret",
    });
    assert.equal(blockedFastOwnerChange.fresh, 0, "主人变更后排队的快通道作业不得理解旧主人的私聊");
    assert.equal(svc.store.obsPending("pw:owner_a_dm_secret"), true);
    app.cfg.owner.open_id = "ou_owner_a";
    svc.store.markProcessed(["pw:owner_a_dm_secret"]);

    // 9) [R5 P1-9] groups: allowlist 模式下，本人在未列白名单群发出的普通消息也不得作为 mine 入库
    mock.setChatName("9799", "未列白名单群");
    await svc.personalWeb.handleMessage(
      decodeMessage(buildNativeMessage({ id: "my_unlisted_msg", chatId: "9799", actorId: "7001", text: "我在未列群发的消息" }), "7001"),
      client,
    );
    assert.equal(svc.store.obs("pw:my_unlisted_msg"), undefined, "allowlist 模式下未列群的本人发言绝不入库");

    // 10) [R5 P1-7] groups_deny 关键词（无 oc_* 规则）：命中前刷新缓存群名，防止改名群借 TTL 逃逸；离线周期不得凭旧标签负向放行
    mock.setChatName("9701", "普通项目群");
    await client.readChat("9701"); // 填入 10 分钟缓存为 "普通项目群"
    mock.setChatName("9701", "机密财务群"); // 群改名以命中关键词 "机密"
    app.cfg.context.groups_deny = ["机密"];
    await svc.personalWeb.handleMessage(
      decodeMessage(
        buildNativeMessage({
          id: "pw_kw_renamed",
          chatId: "9701",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 改名后命中关键词" }]),
        }),
        "7001",
      ),
      client,
    );
    assert.equal(svc.store.obs("pw:pw_kw_renamed"), undefined, "存在 groups_deny 关键词时必须刷新群名拦截已改名群");
    // 离线周期（无在线 client）不得凭陈旧库标签对 groups_deny 关键词做负向放行
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = undefined;
    assert.equal(await svc.personalWeb.checkConvAllowedForUnderstand("pw_chat:9701", "普通项目群"), "uncertain");
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
    app.cfg.context.groups_deny = [];
    mock.setChatName("9701", "正常研发群");

    // 11) [R5 P1-6, P1-8, P2-5] 轮询：
    //     - 原生私聊静音使 dmsInconclusive=true 时：
    //       * --chat-type p2p 缺省 chat_type 行被保留为 p2p 并阻断（cursor.im.p2p 挂起）；
    //       * --is-at-me 中缺失 chat_type 的未知类型行按 inconclusive 阻断（不误当允许群）；
    //       * 正常群 @我 与发言人流独立推进 cursor.im.mine / cursor.im.groups / cursor.chat.*；
    //     - 轮询群行缺失 chat_name 时，实时查 im chats get 校验是否改名为原生静音群名，查失败则 inconclusive 不推进 cursor.chat.*
    svc.store.muteConv("pw_chat:9801", "旧静音群名", true);
    mock.setChatName("9801", "新保密群");
    // 在 spoken_groups 放入一个旧名 "旧正常群" 的 oc_renamed（其实已改名为 "新保密群"）与一个查元数据失败的 oc_fail_meta
    app.cfg.context.groups = "spoken";
    app.store.set(
      "ctx.spoken_groups",
      JSON.stringify({
        oc_renamed: { name: "旧正常群", at: now },
        oc_fail_meta: { name: "旧普通群", at: now },
        oc_clean: { name: "干净群", at: now },
      }),
    );
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_renamed: { name: "新保密群", chat_mode: "group" },
          oc_clean: { name: "干净群", chat_mode: "group" },
        },
        chats: {
          oc_renamed: [{ message_id: "om_renamed_1", chat_id: "oc_renamed", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "改名静音群消息" }],
          oc_fail_meta: [{ message_id: "om_failmeta_1", chat_id: "oc_fail_meta", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "元数据失败群消息" }],
          oc_clean: [{ message_id: "om_clean_1", chat_id: "oc_clean", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "正常群消息" }],
        },
      }),
    );
    app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_renamed_1"), undefined, "缺失 chat_name 的轮询群行经 im chats get 查出已改名命中静音群，必须拦截");
    assert.equal(svc.store.obs("im:om_failmeta_1"), undefined, "im chats get 失败时绝不能凭 spoken_groups 旧名放行");
    const failMetaPinned = Number(app.store.get("ctx.cursor.chat.oc_fail_meta") ?? "0");
    assert.ok(failMetaPinned > 0 && failMetaPinned < now, "首拉被阻塞的群必须钉住初始起始游标（不得推进到 now，也不得留空被 cursor.im.groups 跳过）");
    assert.ok(svc.store.obs("im:om_clean_1"), "实时查出未命中的正常群正常入库");
    assert.ok(app.store.get("ctx.cursor.chat.oc_clean"), "正常群独立推进 cursor.chat.oc_clean");
    svc.store.muteConv("pw_chat:9801", "", false);

    // 原生私聊静音（dmsInconclusive=true）：未知 chat_type 的 @我 拦截，p2p 挂起，而 mine/groups 游标独立推进
    svc.store.muteConv("pw_chat:dm_muted_1", "私聊：7088", true);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        at_me: [
          { message_id: "om_unknown_ct", chat_id: "oc_mystery", chat_name: "", chat_type: "", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "@张三 缺类型消息" },
        ],
        p2p: [
          { message_id: "om_p2p_no_ct", chat_id: "oc_dm_x", chat_name: "", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "缺 chat_type 的私聊" },
        ],
        mine: [
          { message_id: "om_mine_grp", chat_id: "oc_clean", chat_name: "干净群", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_owner_a", name: "张三", sender_type: "user" }, content: "我发的群消息" },
        ],
      }),
    );
    app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_unknown_ct"), undefined, "dmsInconclusive 下缺 chat_type 的行不得误按允许群放行");
    assert.equal(svc.store.obs("im:om_p2p_no_ct"), undefined, "p2p 查询行必须受 dmsInconclusive 阻断");
    const p2pPinned = Number(app.store.get("ctx.cursor.im.p2p") ?? "0");
    assert.ok(p2pPinned > 0 && p2pPinned < now, "私聊流受阻时在无既有游标下应钉住原始起始游标，不得推进到 now");
    const atMePinned = Number(app.store.get("ctx.cursor.im.at_me") ?? "0");
    assert.ok(atMePinned > 0 && atMePinned < now, "含未知类型 inconclusive 行的 at_me 流在无既有游标下应钉住原始起始游标，不得推进到 now");
    assert.ok(app.store.get("ctx.cursor.im.mine"), "不受影响的 mine 流游标必须独立推进");
    assert.ok(app.store.get("ctx.cursor.im.groups"), "不受影响的 groups 流标必须独立推进");
    svc.store.muteConv("pw_chat:dm_muted_1", "", false);
    app.cfg.context.groups = "allowlist";

    // 12) [R5 P2-3 & P2-4] 撤回的 @我 不得进入后续 convWindow/convWindowAround/convObs；再次收到合格 @我 时恢复；
    //     旧推送重放经权威 readMessage(id) 核对后绝不回滚较新编辑
    const origAtBuf = buildNativeMessage({
      id: "r5_edit_1",
      chatId: "9799",
      actorId: "7002",
      createdAtSec: nowSec - 10,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 原版请求" }]),
    });
    mock.addMessage("r5_edit_1", origAtBuf);
    await svc.personalWeb.handleMessage(decodeMessage(origAtBuf, "7001"), client);
    assert.equal(svc.store.obsPending("pw:r5_edit_1"), true);

    // 撤回 @我（服务端更新为无 @）
    const removedAtBuf = buildNativeMessage({ id: "r5_edit_1", chatId: "9799", actorId: "7002", createdAtSec: nowSec - 10, text: "已撤回无关" });
    mock.addMessage("r5_edit_1", removedAtBuf);
    await svc.personalWeb.handleMessage(decodeMessage(removedAtBuf, "7001"), client);
    assert.equal(svc.store.obs("pw:r5_edit_1")?.meta.withdrawn, true);

    // 同群新 @我 到达时，已撤回的 pw:r5_edit_1 绝不能作为背景进入窗口或草稿窗口
    const nextAtBuf = buildNativeMessage({
      id: "r5_next_at",
      chatId: "9799",
      actorId: "7002",
      createdAtSec: nowSec,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 新问题" }]),
    });
    await svc.personalWeb.handleMessage(decodeMessage(nextAtBuf, "7001"), client);
    assert.ok(!svc.store.convWindowAround("pw_chat:9799", "pw:r5_next_at").some((o) => o.id === "pw:r5_edit_1"), "已撤回观测绝不进入 convWindowAround");
    assert.ok(!svc.store.convWindow("pw_chat:9799").some((o) => o.id === "pw:r5_edit_1"), "已撤回观测绝不进入 convWindow");
    assert.ok(!svc.store.convObs("pw_chat:9799", now - 3600_000).some((o) => o.id === "pw:r5_edit_1"), "已撤回观测绝不进入 convObs");

    // 再次编辑恢复完全相同的原版 @我 文本 -> 必须显式重新激活为待处理
    mock.addMessage("r5_edit_1", origAtBuf);
    await svc.personalWeb.handleMessage(decodeMessage(origAtBuf, "7001"), client);
    assert.equal(svc.store.obsPending("pw:r5_edit_1"), true, "恢复原版 @我 必须重新激活为待处理");
    assert.equal(svc.store.obs("pw:r5_edit_1")?.meta.withdrawn, undefined);

    // 较新编辑到达并处理完后，重放旧版推送包 -> 权威 readMessage 仍返回新版，绝不回滚文本或重新标为待处理
    const newerEditBuf = buildNativeMessage({
      id: "r5_edit_1",
      chatId: "9799",
      actorId: "7002",
      createdAtSec: nowSec - 10,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 最新已确认版本" }]),
    });
    mock.addMessage("r5_edit_1", newerEditBuf);
    await svc.personalWeb.handleMessage(decodeMessage(newerEditBuf, "7001"), client);
    assert.match(svc.store.obs("pw:r5_edit_1")!.text, /最新已确认版本/);
    svc.store.markProcessed(["pw:r5_edit_1"]);
    assert.equal(svc.store.obsPending("pw:r5_edit_1"), false);
    // 重放陈旧的 origAtBuf
    await svc.personalWeb.handleMessage(decodeMessage(origAtBuf, "7001"), client);
    assert.match(svc.store.obs("pw:r5_edit_1")!.text, /最新已确认版本/, "旧推送重放绝不能回滚较新编辑");
    assert.equal(svc.store.obsPending("pw:r5_edit_1"), false, "旧推送重放绝不能把已处理新版重新标为待处理");

    // 13) [R5 P2-2] Understander.apply 在事务提交前校验观测修订与撤回状态，避免推理期间编辑/撤回的旧结果建事项或触发提醒
    const infObs: Obs = {
      id: "pw:inf_race_1",
      source: "im",
      kind: "at_me",
      conv: "pw_chat:9701",
      conv_name: "正常研发群",
      actor_id: "7002",
      actor_name: "王五",
      is_me: false,
      time: now,
      text: "@张三 今天必须上线",
      url: "",
      meta: { transport: "personal_web", native_owner_id: "7001", at_me: true, mentions: [{ id: "7001", name: "张三", start: 0, end: 3 }] },
    };
    svc.store.addObs([infObs]);
    const snapObs = svc.store.obs("pw:inf_race_1")!;
    // 模拟模型推理期间发送者撤回了该观测
    svc.store.retirePendingObs("pw:inf_race_1");
    const staleApply = svc.understander.apply(
      {
        projects: [{ ref: "", name: "过期项目", aliases: [], refs: [], description: "", my_role: "", stage: "", health: "ok", parent: "", status: "active" }],
        items: [
          {
            ref: "",
            title: "过期紧急上线",
            kind: "ask_me",
            project: "过期项目",
            status: "open",
            priority: "high",
            due: null,
            counterpart: "王五",
            next_step: "回复",
            confidence: 0.95,
            close_reason: "",
            evidence: [{ obs_id: "pw:inf_race_1", quote: "今天必须上线" }],
          },
        ],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      },
      [snapObs],
      ["pw:inf_race_1"],
    );
    assert.equal(staleApply.created.length, 0, "推理期间已撤回的观测绝不能创建事项或触发提醒");
    assert.equal(svc.store.items({ status: ["open"] }).some((i) => i.title === "过期紧急上线"), false);

    // 14) [R5 P2-1] readContext / handleMessage 落库前二次复核采集策略：在途期间关闭 sources.im 或静音群时拒绝持久化背景
    mock.setHistory("9701", {
      1: buildNativeMessage({ id: "h_race_bg", chatId: "9701", actorId: "7002", senderType: 1, text: "在途历史", position: 1, createdAtSec: nowSec - 30 }),
    });
    const origReadContext = client.readContext.bind(client);
    client.readContext = async (a, o) => {
      const res = await origReadContext(a, o);
      // 模拟 readContext 返回瞬间用户静音了该会话
      svc.store.muteConv("pw_chat:9701", "正常研发群", true);
      return res;
    };
    const hydratedAfterMute = await svc.personalWeb.hydrateContext(
      { id: "h_race_anchor", conversationId: "9701", rootId: "", parentId: "", threadId: "", position: 2, createdAtMs: now },
      "pw_chat:9701",
      "正常研发群",
    );
    assert.equal(hydratedAfterMute, 0, "readContext 在途期间被静音时绝不持久化拉回的历史");
    assert.equal(svc.store.obs("pw:h_race_bg"), undefined);
    client.readContext = origReadContext;
    svc.store.muteConv("pw_chat:9701", "", false);

    // 15) [R5 P2-7] 高频触发下的有界防抖：超过 maxDebounceAnchors 立即冲刷，不会无限重置防抖计时器
    const boundedTriggers: { anchors: { id: string }[] }[] = [];
    app.cfg.context.personal_web.debounce_ms = 5_000;
    const boundedBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: (t) => boundedTriggers.push(t),
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      maxDebounceAnchors: 3,
      maxDebounceWaitMs: 60,
    });
    (boundedBridge as unknown as { client?: FeishuWebClient }).client = client;
    for (let i = 1; i <= 3; i++) {
      await boundedBridge.handleMessage(
        decodeMessage(buildNativeMessage({ id: `burst_${i}`, chatId: "dm_burst", actorId: "7050", chatKind: CHAT_KIND_P2P, text: `高频私聊 ${i}`, createdAtSec: nowSec + i }), "7001"),
        client,
      );
    }
    assert.equal(boundedTriggers.length, 1, "达到 maxDebounceAnchors=3 时必须立刻冲刷而非等待 5s 防抖");
    assert.equal(boundedTriggers[0].anchors.length, 3);
    boundedBridge.stop();
    app.cfg.context.personal_web.debounce_ms = 0;

    // 16) [R5 P2-8 & P2-9] send_replies=false 时允许已 created 精确草稿经 effectFor 回读恢复，但拒绝修改正文的新发送；配置文件缺失时新发送 fail-closed
    const { item: recItem } = svc.store.upsertItem({ title: "待回读恢复事项", kind: "ask_me", priority: "high", source: "im", confidence: 0.95 });
    const recDraft = svc.store.addDraft({
      item_id: recItem.id,
      project_id: "",
      kind: "reply",
      target: {
        transport: "personal_web",
        native_owner_id: "7001",
        native_chat_id: "9701",
        native_message_id: "orig_rec_1",
        native_root_id: "orig_rec_1",
      },
      target_label: "回复对方",
      content: "精确已发包文本",
    });
    const { cid: recCid, textHash: recHash } = computePwReplyCid({
      draft_id: recDraft.id,
      owner_id: "7001",
      chat_id: "9701",
      message_id: "orig_rec_1",
      text: "精确已发包文本",
    });
    app.store.set(
      `pw.delivery.${recCid}`,
      JSON.stringify({
        cid: recCid,
        owner_id: "7001",
        chat_id: "9701",
        message_id: "orig_rec_1",
        root_id: "orig_rec_1",
        parent_id: "orig_rec_1",
        text_hash: recHash,
        threaded: true,
        state: "created",
        reply_id: "reply_rec_999",
        updated_at: now,
      }),
    );
    app.cfg.context.personal_web.send_replies = false;
    const recFx = svc.drafter.effectFor(recDraft, "精确已发包文本");
    assert.equal(recFx.op, "pw.reply", "已 created 的精确草稿在 send_replies=false 下必须允许回读恢复");
    assert.throws(
      () => svc.drafter.effectFor(recDraft, "改成了新文本"),
      /send_replies/,
      "修改正文属于新发送，send_replies=false 时必须继续拦截",
    );

    // 配置文件消失时，新发送必须 fail-closed（已 created 回读不受影响）
    app.cfg.context.personal_web.send_replies = true;
    const deletedCfgFile = path.join(root, "vanished-config.yaml");
    fs.writeFileSync(deletedCfgFile, fs.readFileSync(cfgFile, "utf8"));
    const vanishedApp = createApp(loadConfig(deletedCfgFile));
    saveWorkspaceBinding(vanishedApp.store, "7001", "ou_owner_a");
    const vanishedSvc = new ContextService(vanishedApp);
    fs.rmSync(deletedCfgFile);
    try {
      await assert.rejects(
        vanishedSvc.personalWeb.sendVerifiedReply({
          owner_id: "7001",
          chat_id: "9701",
          message_id: "orig_rec_1",
          text: "新发送消息",
          cid: "new_send_missing_cfg_123456789012",
        }),
        /不存在或无法读取/,
        "配置文件消失时新发送必须 fail-closed 中止",
      );
    } finally {
      vanishedApp.store.db.close();
    }

    // 17) [R5 P2-10] 排队中的自动预起草在执行前复用完整资格判据：降级 priority / needs_review / 关闭 fast_lane 均跳过，不调模型
    fs.writeFileSync(callsLog, "");
    const { item: autoItem } = svc.store.upsertItem({
      title: "将降级的自动预起草事项",
      kind: "ask_me",
      priority: "high",
      source: "im",
      confidence: 0.95,
    });
    svc.store.addObs([
      {
        id: "pw:auto_predraft_obs",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9701",
        conv_name: "正常研发群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@张三 麻烦看下",
        url: "",
        meta: {
          transport: "personal_web",
          native_owner_id: "7001",
          native_message_id: "auto_predraft_obs",
          native_chat_id: "9701",
          native_root_id: "auto_predraft_obs",
          chat_type: "group",
        },
      },
    ]);
    svc.store.addEvidence("item", autoItem.id, "pw:auto_predraft_obs", "麻烦看下", now);
    // 事项已被降级为 medium 优先级后才执行排队的 auto 预起草作业 -> 必须 skipped 且零模型调用
    svc.store.upsertItem({ ...autoItem, priority: "medium" });
    svc.enqueue("draft:r5-downgraded", { task: "draft", item_id: autoItem.id, kind: "reply", auto: true });
    await app.engine.drain(["context"]);
    assert.equal(app.ledger.get("context:draft:r5-downgraded")?.state, "skipped", "降级后的事项必须跳过自动预起草");

    // 恢复 high 但关闭 fast_lane -> 同样跳过
    svc.store.upsertItem({ ...autoItem, priority: "high" });
    app.cfg.context.personal_web.fast_lane = false;
    svc.enqueue("draft:r5-fastlane-off", { task: "draft", item_id: autoItem.id, kind: "reply", auto: true });
    await app.engine.drain(["context"]);
    assert.equal(app.ledger.get("context:draft:r5-fastlane-off")?.state, "skipped", "关闭 fast_lane 后必须跳过自动预起草");
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "跳过的自动预起草绝不能调用模型");
    app.cfg.context.personal_web.fast_lane = true;
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    freshApp?.store.db.close();
    app?.store.db.close();
    await mock.close();
  }
});

test("Codex 第六轮回归：派生上下文主人隔离、Codex 供应商保留、验证/git 凭据剥离、无归属观测隔离、策略变更重验、首拉钉游标、搜索合元数据、并发提交/锁/投递、轮换合并与上报、同域跳转 CSRF、tmpfs 凭据、CLI 读健康与预检", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const prevXdg = process.env.XDG_RUNTIME_DIR;
  process.env.PA_FEISHU_WEB_KEY = "r6-test-secret-key-32-bytes-ok!!";
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  let redirectSrv: http.Server | undefined;
  let preflightSrv: http.Server | undefined;
  try {
    // 1) [R6 P1-2] extractSafeCodexProviderArgs：保留自定义供应商、默认 openai 覆盖、extraArgs 联合配置与安全标量，剔除 MCP/hooks/plugins，缺失/复杂配置 fail-closed
    const codexHome = makeTmp("pa-r6-codex-home-");
    fs.writeFileSync(
      path.join(codexHome, "config.toml"),
      [
        'model = "gpt-5-internal"',
        'model_provider = "corp"',
        'model_reasoning_effort = "medium"',
        'service_tier = "flex"',
        "",
        "[model_providers.corp]",
        'name = "Corp Gateway"',
        'base_url = "https://gateway.corp.internal/v1"',
        'env_key = "CORP_API_KEY"',
        'wire_api = "responses"',
        "",
        "[model_providers.corp.http_headers]",
        '"X-Secret-Token" = "top-secret-header"',
        "",
        "[model_providers.corp.env_http_headers]",
        '"X-Tenant" = "CORP_TENANT"',
        "",
        "[mcp_servers.evil]",
        'command = "/bin/sh"',
        'args = ["-c", "echo pwned"]',
        "",
        "[plugins.bad]",
        "enabled = true",
      ].join("\n"),
    );
    const extractedCfg = extractSafeCodexProviderConfig({ CODEX_HOME: codexHome }, [], false);
    const extracted = extractedCfg.args;
    const parseProviderMap = (args: string[]) => {
      const mpArg = args.find((a) => a.startsWith("model_providers="));
      assert.ok(mpArg, `应以 TOML 内联表形式透传 model_providers：${JSON.stringify(args)}`);
      const doc = parseToml(mpArg!);
      return doc.model_providers as Record<string, Record<string, unknown>>;
    };
    assert.ok(extracted.includes('model="gpt-5-internal"'), "必须保留 config.toml 的 model");
    assert.ok(extracted.includes('model_provider="corp"'), "必须保留自定义 model_provider");
    const corpProv = parseProviderMap(extracted).corp as Record<string, unknown>;
    assert.equal(corpProv.base_url, "https://gateway.corp.internal/v1", "必须保留自定义供应商 base_url");
    assert.equal(corpProv.env_key, "CORP_API_KEY", "必须保留 env_key");
    assert.ok(!extracted.some((a) => a.includes("top-secret-header")), "静态 http_headers 明文绝不能进入 argv");
    const corpEnvHdrs = corpProv.env_http_headers as Record<string, string>;
    assert.ok(corpEnvHdrs?.["X-Secret-Token"], "静态 http_headers 必须自动转为 env_http_headers 环境变量引用");
    assert.equal(extractedCfg.extraEnv[corpEnvHdrs["X-Secret-Token"]], "top-secret-header", "静态 http_headers 值必须仅通过子进程环境变量传递");
    assert.equal(corpEnvHdrs["X-Tenant"], "CORP_TENANT", "必须保留 env_http_headers");
    assert.ok(!extracted.some((a) => a.includes("mcp_servers") || a.includes("plugins") || a.includes("evil")), "绝不能带入 mcp_servers 或 plugins");

    // 显式传 hasExplicitModel=true 时不得再覆盖 model
    const extractedWithExplicitModel = extractSafeCodexProviderArgs({ CODEX_HOME: codexHome }, [], true);
    assert.ok(!extractedWithExplicitModel.some((a) => a.startsWith("model=")), "显式配置了 model 时不重复注入 model");

    // 默认 openai 供应商覆盖 [model_providers.openai] 也必须保留
    const openaiProxyHome = makeTmp("pa-r6-codex-openai-");
    fs.writeFileSync(
      path.join(openaiProxyHome, "config.toml"),
      ['openai_base_url = "https://oai-proxy.corp/v1"', "[model_providers.openai]", 'base_url = "https://oai-proxy.corp/v1"'].join("\n"),
    );
    const extractedOai = extractSafeCodexProviderArgs({ CODEX_HOME: openaiProxyHome }, [], false);
    assert.ok(extractedOai.includes('openai_base_url="https://oai-proxy.corp/v1"'));
    assert.equal(parseProviderMap(extractedOai).openai.base_url, "https://oai-proxy.corp/v1");

    // extraArgs 仅指定 -c model_provider="corp" 时仍需提取 config.toml 中的 [model_providers.corp]
    const extractedFromExtra = extractSafeCodexProviderArgs({ CODEX_HOME: codexHome }, ["-c", 'model_provider="corp"'], false);
    assert.equal(parseProviderMap(extractedFromExtra).corp.base_url, "https://gateway.corp.internal/v1");
    assert.ok(!extractedFromExtra.includes('model_provider="corp"'), "extraArgs 已指定 model_provider 时不重复输出");

    // fail-closed：--profile、缺失的自定义供应商、非法 TOML 均直接抛错；合法内联表应完整解析
    assert.throws(() => extractSafeCodexProviderArgs({ CODEX_HOME: codexHome }, ["--profile", "work"], false), /--profile/);
    const missingProvHome = makeTmp("pa-r6-codex-missing-");
    fs.writeFileSync(path.join(missingProvHome, "config.toml"), 'model_provider = "ghost"\n');
    assert.throws(() => extractSafeCodexProviderArgs({ CODEX_HOME: missingProvHome }, [], false), /ghost/);
    const inlineProvHome = makeTmp("pa-r6-codex-inline-");
    fs.writeFileSync(path.join(inlineProvHome, "config.toml"), 'model_provider = "corp"\nmodel_providers = { corp = { base_url = "https://x" } }\n');
    assert.equal(parseProviderMap(extractSafeCodexProviderArgs({ CODEX_HOME: inlineProvHome }, [], false)).corp.base_url, "https://x");
    const brokenTomlHome = makeTmp("pa-r6-codex-broken-");
    fs.writeFileSync(path.join(brokenTomlHome, "config.toml"), 'model_provider = "corp"\n[model_providers.corp\nbase_url = "https://x"\n');
    assert.throws(() => extractSafeCodexProviderArgs({ CODEX_HOME: brokenTomlHome }, [], false), /无法安全解析|TOML/);

    // 2) [R6 P2-11 & P2-21] prepareHarnessEnv 仅用内核 tmpfs 投影混合凭据；mergeHarnessEnv 禁止覆写还原被过滤的凭据
    const mixedCredDir = makeTmp("pa-r6-mixed-creds-");
    fs.writeFileSync(path.join(mixedCredDir, "feishu-web-key"), "web-secret-value", { mode: 0o400 });
    fs.writeFileSync(path.join(mixedCredDir, "other-api-key"), "other-secret-value", { mode: 0o400 });
    const symlinkCredDir = path.join(makeTmp("pa-r6-sym-"), "cred-link");
    fs.symlinkSync(mixedCredDir, symlinkCredDir);
    const prepMixed = prepareHarnessEnv({
      PATH: process.env.PATH,
      XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
      PA_FEISHU_WEB_KEY: "should-be-stripped",
      PA_FEISHU_WEB_CRED_FILE: "/tmp/should-be-stripped",
      CREDENTIALS_DIRECTORY: mixedCredDir,
    });
    try {
      assert.equal(prepMixed.env.PA_FEISHU_WEB_KEY, undefined);
      assert.equal(prepMixed.env.PA_FEISHU_WEB_CRED_FILE, undefined);
      if (prepMixed.env.CREDENTIALS_DIRECTORY) {
        assert.notEqual(prepMixed.env.CREDENTIALS_DIRECTORY, mixedCredDir);
        assert.ok(!prepMixed.env.CREDENTIALS_DIRECTORY.startsWith(os.tmpdir() + path.sep), "混合凭据绝不能复制到磁盘 TMPDIR");
        const st = fs.statfsSync(prepMixed.env.CREDENTIALS_DIRECTORY);
        assert.equal(st.type, 0x01021994, "混合凭据过滤目录必须位于内核级易失 tmpfs");
        assert.equal(fs.existsSync(path.join(prepMixed.env.CREDENTIALS_DIRECTORY, "feishu-web-key")), false);
        assert.equal(fs.readFileSync(path.join(prepMixed.env.CREDENTIALS_DIRECTORY, "other-api-key"), "utf8"), "other-secret-value");
      }
      // mergeHarnessEnv：${PA_FEISHU_WEB_KEY} 从过滤后的 base 展开为空，且禁止通过路径、变量或软链还原原始 CREDENTIALS_DIRECTORY
      const merged = mergeHarnessEnv(
        prepMixed.env,
        {
          PA_FEISHU_WEB_KEY: "re-injected",
          LEAKED_KEY: "${PA_FEISHU_WEB_KEY}",
          CREDENTIALS_DIRECTORY: mixedCredDir,
          SAFE_VAR: "hello-${NONEXISTENT}",
        },
        mixedCredDir,
      );
      assert.equal(merged.PA_FEISHU_WEB_KEY, undefined);
      assert.equal(merged.LEAKED_KEY, "");
      assert.notEqual(merged.CREDENTIALS_DIRECTORY, mixedCredDir);
      assert.equal(merged.SAFE_VAR, "hello-");

      const mergedSym = mergeHarnessEnv(prepMixed.env, { CREDENTIALS_DIRECTORY: symlinkCredDir }, mixedCredDir);
      assert.notEqual(mergedSym.CREDENTIALS_DIRECTORY, symlinkCredDir, "指向含 feishu-web-key 目录的软链同样必须被阻断");
    } finally {
      prepMixed.cleanup();
    }
    if (prepMixed.env.CREDENTIALS_DIRECTORY) {
      assert.equal(fs.existsSync(prepMixed.env.CREDENTIALS_DIRECTORY), false, "cleanup 必须删除 tmpfs 临时目录");
    }

    // 3) [R6 P1-3] Dispatcher.runVerifyCommand 与 delivery/git.ts 剥离 PA_FEISHU_WEB_KEY 与含 feishu-web-key 的 CREDENTIALS_DIRECTORY
    const gitRepo = makeTmp("pa-r6-git-");
    await runProcess("git", ["init", "-q", gitRepo]);
    process.env.CREDENTIALS_DIRECTORY = mixedCredDir;
    const gitEnvOut = await tryGit(gitRepo, ["-c", "alias.envdump=!env", "envdump"]);
    assert.equal(gitEnvOut.code, 0);
    assert.ok(!gitEnvOut.stdout.includes("PA_FEISHU_WEB_KEY="), "git 子进程不得继承 PA_FEISHU_WEB_KEY");
    assert.ok(!gitEnvOut.stdout.includes(`CREDENTIALS_DIRECTORY=${mixedCredDir}`), "git 子进程不得继承原始混合 CREDENTIALS_DIRECTORY");
    delete process.env.CREDENTIALS_DIRECTORY;

    // 4) [R6 P2-18] syncFromRecords(preservePendingDelta=true) 保留未冲突的待落盘 Cookie 轮换
    const mergeJar = RecordingCookieJar.fromRecords(
      [
        { name: "session", value: "sess_v1", domain: "127.0.0.1", path: "/" },
        { name: "other", value: "other_v1", domain: "127.0.0.1", path: "/" },
      ],
      ["127.0.0.1"],
    );
    mergeJar.setFromHeaders(new URL("http://127.0.0.1/"), ["session=sess_rotated_local; Domain=127.0.0.1; Path=/"]);
    assert.equal(mergeJar.peekDelta().upserts.length > 0, true);
    // 另一进程在磁盘上只改了 other=other_v2，session 仍是 sess_v1
    mergeJar.syncFromRecords(
      [
        { name: "session", value: "sess_v1", domain: "127.0.0.1", path: "/" },
        { name: "other", value: "other_v2", domain: "127.0.0.1", path: "/" },
      ],
      Date.now(),
      { preservePendingDelta: true },
    );
    assert.equal(mergeJar.cookieValue(new URL("http://127.0.0.1/"), "session"), "sess_rotated_local", "无冲突的本地 Cookie 轮换绝不能被磁盘刷新抹掉");
    assert.equal(mergeJar.cookieValue(new URL("http://127.0.0.1/"), "other"), "other_v2", "磁盘上的无关更新必须同步生效");
    assert.equal(mergeJar.peekDelta().upserts.length > 0, true, "未落盘的本地轮换仍须保持待提交状态");

    // 5) [R6 P2-20] 同域 307 跳转轮换 swp_csrf_token 时必须刷新下一跳的 x-csrf-token 请求头
    const seenCsrf: string[] = [];
    redirectSrv = http.createServer((req, res) => {
      seenCsrf.push(String(req.headers["x-csrf-token"] ?? ""));
      if (req.url === "/step1") {
        res.writeHead(307, {
          Location: "/step2",
          "Set-Cookie": ["swp_csrf_token=csrf_hop2; Path=/"],
        });
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((r) => redirectSrv!.listen(0, "127.0.0.1", () => r()));
    const rPort = (redirectSrv.address() as net.AddressInfo).port;
    const redirJar = RecordingCookieJar.fromRecords([{ name: "swp_csrf_token", value: "csrf_hop1", domain: "127.0.0.1", path: "/" }], ["127.0.0.1"]);
    const redirRes = await fetchWithJar(redirJar, {
      url: `http://127.0.0.1:${rPort}/step1`,
      method: "POST",
      headers: { "x-csrf-token": "csrf_hop1" },
      body: "ping",
      allowInsecureHttp: true,
      extraAllowedHosts: ["127.0.0.1"],
    });
    assert.equal(redirRes.status, 200);
    assert.deepEqual(seenCsrf, ["csrf_hop1", "csrf_hop2"], "同域 307 轮换 swp_csrf_token 后第二跳必须携带刷新后的 x-csrf-token");

    // 6) [R6 P2-19] notifySessionConfirmed 在持久化失败时不得吞错，且错误信息不得包含 Cookie 明文
    const baseCookies = [
      { name: "session", value: "sess_secret_r6_do_not_leak", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r6_123", domain: "127.0.0.1", path: "/" },
    ];
    let shouldFailPersist = false;
    const failPersistClient = await FeishuWebClient.connect(
      { owner_id: "7001", owner_name: "张三", cookies: baseCookies },
      {
        endpoints: mock.endpoints,
        onSessionConfirmed: () => {
          if (shouldFailPersist) throw new Error("disk full with sess_secret_r6_do_not_leak");
        },
      },
    );
    shouldFailPersist = true;
    // 手动在 jar 中制造一笔待落盘轮换并调用 verifyOwner 触发 notifySessionConfirmed
    (failPersistClient as unknown as { jar: RecordingCookieJar }).jar.setFromHeaders(
      new URL(mock.endpoints.messengerUrl),
      ["session=sess_secret_r6_rotated; Domain=127.0.0.1; Path=/"],
    );
    await assert.rejects(
      () => failPersistClient.verifyOwner(),
      (err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        assert.match(msg, /持久化.*失败/);
        assert.ok(!msg.includes("sess_secret_r6_do_not_leak") && !msg.includes("sess_secret_r6_rotated"), "持久化报错绝不能泄露 Cookie 明文");
        return true;
      },
    );
    assert.equal(
      (failPersistClient as unknown as { jar: RecordingCookieJar }).jar.peekDelta().upserts.length > 0,
      true,
      "持久化失败时必须保留待提交 delta 以便重试",
    );

    // 7) 构造完整 Working Context + Dispatcher 应用，覆盖所有上下文与并发边界
    const dir = makeTmp("pa-r6-ctx-");
    const ctxDir = makeTmp("pa-r6-lark-");
    process.env.CTX_DIR = ctxDir;
    const callsLog = path.join(dir, "harness-calls.log");
    const harnessScript = path.join(dir, "fake-r6-harness.mjs");
    fs.writeFileSync(
      harnessScript,
      `#!/usr/bin/env node
import fs from "node:fs";
const prompt = fs.readFileSync(0, "utf8");
fs.appendFileSync(${JSON.stringify(callsLog)}, JSON.stringify({ at: Date.now(), len: prompt.length }) + "\\n");
const modeFile = ${JSON.stringify(path.join(dir, "harness-mode.json"))};
const mode = fs.existsSync(modeFile) ? JSON.parse(fs.readFileSync(modeFile, "utf8")) : {};
if (mode.onRunHookFile) fs.writeFileSync(mode.onRunHookFile, "ran");
if (mode.resumeFile) {
  const deadline = Date.now() + 3000;
  while (!fs.existsSync(mode.resumeFile) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 15));
  }
}
if (mode.delayMs) await new Promise((r) => setTimeout(r, mode.delayMs));
if (mode.output !== undefined) {
  process.stdout.write(JSON.stringify(mode.output));
} else {
  process.stdout.write(JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], conflicts: [] }));
}
`,
      { mode: 0o755 },
    );

    // 创建一个支持动态钩子（模拟轮询中途变更静音）的 lark 包装脚本
    const larkWrap = path.join(dir, "fake-lark-wrap.mjs");
    const larkHookSignal = path.join(dir, "lark-midpoll-hook.flag");
    const larkResumeSignal = path.join(dir, "lark-midpoll-resume.flag");
    fs.writeFileSync(
      larkWrap,
      `#!/usr/bin/env node
import fs from "node:fs";
import { spawnSync } from "node:child_process";
const args = process.argv.slice(2);
if (fs.existsSync(${JSON.stringify(larkHookSignal)}) && args.includes("+messages-search")) {
  fs.writeFileSync(${JSON.stringify(larkHookSignal)}, "hit");
  const deadline = Date.now() + 3000;
  while (!fs.existsSync(${JSON.stringify(larkResumeSignal)}) && Date.now() < deadline) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15);
  }
}
const r = spawnSync(${JSON.stringify(path.join(STUBS, "ctx-lark"))}, args, { stdio: "inherit", env: process.env });
process.exit(r.status ?? 1);
`,
      { mode: 0o755 },
    );

    const cfgPath = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      `owner:
  open_id: ou_owner_a
  name: 张三
  timezone: Asia/Shanghai
bins:
  lark: ${larkWrap}
  bytedcli: ${path.join(STUBS, "ctx-bytedcli")}
harnesses:
  codex:
    type: codex-exec
    cmd: ${harnessScript}
    model: gpt-5
roles:
  brain: codex
server:
  enabled: false
cards:
  enabled: false
kb:
  enabled: false
dispatch:
  repos:
    demo:
      path: ${gitRepo}
      verify: "env"
context:
  enabled: true
  understand: true
  harness: codex
  groups: allowlist
  groups_allow: []
  groups_deny: ["保密"]
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: false
    send_replies: false
    debounce_ms: 50
data_dir: ${dir}
`,
    );
    app = createApp(loadConfig(cfgPath));
    // 注册 context 扩展与命令（用于测试 app.ext.context 与 effectHandler）
    const { registerContext } = await import("../src/context/index.ts");
    const regSvc = registerContext(app)!;
    const svc = regSvc;
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);

    // 先验证 Dispatcher.runVerifyCommand 剥离 PA_FEISHU_WEB_KEY 与 CREDENTIALS_DIRECTORY
    process.env.CREDENTIALS_DIRECTORY = mixedCredDir;
    fs.mkdirSync(path.join(dir, "runs", "g_r6_ver"), { recursive: true });
    const dispatcher = new Dispatcher(app.cfg, app.ledger, app.store, app.board);
    app.ledger.enqueue({
      id: "dispatch:r6-verify",
      kind: "dispatch",
      ref: "r6-verify",
      state: "verifying",
      payload: {
        guid: "g_r6_ver",
        summary: "verify env isolation",
        description: "",
        harness: "codex",
        repo: "demo",
        cwd: gitRepo,
        branch: "pa/r6",
        base: "",
        verify: "env",
        round: 1,
      },
    });
    const verifyWork = app.ledger.get("dispatch:r6-verify")!;
    const checkRes = await (
      dispatcher as unknown as {
        runVerifyCommand(it: typeof verifyWork, ctx: { attempt: number; signal: AbortSignal }): Promise<{ status: string; detail: string }>;
      }
    ).runVerifyCommand(verifyWork, { attempt: 1, signal: new AbortController().signal });
    delete process.env.CREDENTIALS_DIRECTORY;
    assert.equal(checkRes.status, "pass", checkRes.detail);
    const verifyLog = fs.readFileSync(path.join(dir, "runs", "g_r6_ver", "verify-1-1.log"), "utf8");
    assert.ok(!verifyLog.includes("PA_FEISHU_WEB_KEY="), "verify 命令日志绝不能包含 PA_FEISHU_WEB_KEY");
    assert.ok(!verifyLog.includes(`CREDENTIALS_DIRECTORY=${mixedCredDir}`), "verify 命令不得继承原始混合 CREDENTIALS_DIRECTORY");

    // 8) [R6 P2-13] commitWorkspaceLogin 原子加锁重验：首次登录成功后，并发第二个账号不得静默覆写；含无归属/旧账号观测时即使 forceSwitch 也拒绝
    const loginA = { owner_id: "7001", owner_name: "张三", cookies: baseCookies };
    const loginB = { owner_id: "7002", owner_name: "李四", cookies: baseCookies };
    assert.throws(() => commitWorkspaceLogin(app!, loginA), /--allow-unverified-owner/, "首次提交绑定必须要求 allowUnverifiedOwner");
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });
    assert.equal(app.store.get(BOUND_OWNER_KV_KEY), "7001");
    assert.equal(app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY), "ou_owner_a");
    assert.throws(
      () => commitWorkspaceLogin(app!, loginB, { allowUnverifiedOwner: true }),
      /已被其他个人 Web 账号/,
      "未传 forceSwitch 时绝不能覆写已提交的绑定",
    );

    // 9) [R6 P1-4] 无归属 pw:* 观测（缺少 native_owner_id）：必须被查询隔离，阻断换号与草稿目标选择
    svc.store.addObs([
      {
        id: "pw:ownerless_1",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9600",
        conv_name: "无归属测试群",
        actor_id: "7009",
        actor_name: "某同事",
        is_me: false,
        time: now - 5_000,
        text: "@张三 旧版无归属消息",
        url: "",
        meta: { transport: "personal_web", native_message_id: "ownerless_1", native_chat_id: "9600", chat_type: "group" },
      },
    ]);
    assert.equal(svc.store.hasOtherNativeOwnerObs("7001"), true, "无归属 pw:* 观测必须被视作非本账号脏数据");
    assert.equal(svc.store.hasOtherNativeOwnerObs("7002"), true, "无归属 pw:* 观测必须阻断换号");
    assert.throws(
      () => commitWorkspaceLogin(app!, loginB, { forceSwitch: true, allowUnverifiedOwner: true }),
      /历史观测|无归属/,
      "存在无归属 pw:* 观测时即使 forceSwitch 也拒绝提交换号",
    );
    assert.ok(!svc.store.convWindow("pw_chat:9600", 60, 12, "7001").some((o) => o.id === "pw:ownerless_1"), "无归属 pw:* 观测必须被隔离，不得进入 convWindow");
    assert.equal(svc.store.pendingConvs(20, ["im"], { activeNativeOwner: "7001" }).some((c) => c.conv === "pw_chat:9600"), false, "无归属 pw:* 观测不得进入 pendingConvs");
    const { item: ownerlessItem } = svc.store.upsertItem({ title: "无归属事项", kind: "ask_me", priority: "high", source: "im" });
    svc.store.addEvidence("item", ownerlessItem.id, "pw:ownerless_1", "无归属引用", now - 5_000);
    assert.throws(() => svc.drafter.target(ownerlessItem, "reply"), /找不到.*飞书会话|归属账号/, "草稿 target 绝不能回退当前绑定去采用无归属 pw:* 观测");
    // 清理无归属测试行，继续后续测试
    app.store.db.prepare("DELETE FROM ctx_evidence WHERE obs_id = 'pw:ownerless_1'").run();
    app.store.db.prepare("DELETE FROM ctx_obs WHERE id = 'pw:ownerless_1'").run();
    app.store.db.prepare("DELETE FROM ctx_item WHERE id = ?").run(ownerlessItem.id);

    // 10) [R6 P2-16] 已撤回证据不得被选作回复目标（store.lastEvidenceObs 与 Drafter.target 均跳过 withdrawn）
    svc.store.addObs([
      {
        id: "pw:ev_surviving",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9601",
        conv_name: "证据群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 20_000,
        text: "@张三 有效请求",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "ev_surviving", native_chat_id: "9601", chat_type: "group" },
      },
      {
        id: "pw:ev_withdrawn",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9601",
        conv_name: "证据群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 10_000,
        text: "已编辑撤回",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "ev_withdrawn", native_chat_id: "9601", chat_type: "group", withdrawn: true },
      },
    ]);
    const { item: evItem } = svc.store.upsertItem({ title: "证据测试事项", kind: "ask_me", priority: "high", source: "im" });
    svc.store.addEvidence("item", evItem.id, "pw:ev_surviving", "有效", now - 20_000);
    svc.store.addEvidence("item", evItem.id, "pw:ev_withdrawn", "撤回", now - 10_000);
    assert.equal(svc.store.lastEvidenceObs("item", evItem.id)?.id, "pw:ev_surviving", "lastEvidenceObs 必须跳过已撤回证据");
    assert.equal(svc.drafter.target(evItem, "reply").target.native_message_id, "ev_surviving", "Drafter.target 必须选中幸存的有效证据");
    // 若全部证据都被撤回，Drafter.target 必须拒绝起草
    svc.store.retirePendingObs("pw:ev_surviving");
    assert.throws(() => svc.drafter.target(evItem, "reply"), /找不到.*飞书会话|没有找到/, "无幸存有效证据时必须拒绝起草回复");
    app.store.db.prepare("DELETE FROM ctx_evidence WHERE entity_id = ?").run(evItem.id);
    app.store.db.prepare("DELETE FROM ctx_item WHERE id = ?").run(evItem.id);

    // 11) [R6 P2-17] 会话认领租约续期与释放绑定 worker token + proc_owner，旧 worker 绝不能续期或删除继任者认领
    assert.equal(svc.store.claimConv("pw_chat:9602", "work:1:procA:tok1", "procA", 1_000, 10_000), true);
    // 过期后 procB 接管（即使工作 ID 前缀相同，token / procOwner 不同）
    assert.equal(svc.store.claimConv("pw_chat:9602", "work:1:procB:tok2", "procB", 60_000, 12_000), true);
    assert.equal(svc.store.renewConv("pw_chat:9602", "work:1:procA:tok1", "procA", 60_000, 13_000), false, "过期旧 worker 不得续期继任者的认领");
    svc.store.releaseConv("pw_chat:9602", "work:1:procA:tok1", "procA");
    // 继任者的认领仍必须有效，第三者无法抢占
    assert.equal(svc.store.claimConv("pw_chat:9602", "work:2:procC:tok3", "procC", 60_000, 14_000), false, "过期旧 worker 的 release 不得删除继任者认领");
    svc.store.releaseConv("pw_chat:9602", "work:1:procB:tok2", "procB");
    assert.equal(svc.store.claimConv("pw_chat:9602", "work:2:procC:tok3", "procC", 60_000, 14_500), true);
    svc.store.releaseConv("pw_chat:9602", "work:2:procC:tok3", "procC");

    // 12) [R6 P2-14] Understander.apply 部分失效批次：模型事项同时引用有效请求 A 与已撤回跟进 B 时，拒绝该事项但保留 A 为 pending 以便重试
    svc.store.addObs([
      {
        id: "pw:partial_a",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9603",
        conv_name: "研发群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 5_000,
        text: "@张三 帮看线上超时",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "partial_a", native_chat_id: "9603", chat_type: "group" },
      },
      {
        id: "pw:partial_b",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9603",
        conv_name: "研发群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 3_000,
        text: "@张三 顺便看下日志",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "partial_b", native_chat_id: "9603", chat_type: "group" },
      },
    ]);
    const obsA = svc.store.obs("pw:partial_a")!;
    const obsB = svc.store.obs("pw:partial_b")!;
    // 推理期间 B 被撤回
    svc.store.retirePendingObs("pw:partial_b");
    const applyRes = svc.understander.apply(
      {
        projects: [],
        items: [
          {
            ref: "",
            title: "排查线上超时",
            kind: "ask_me",
            project: "",
            status: "open",
            priority: "high",
            due: null,
            counterpart: "王五",
            next_step: "查日志",
            confidence: 0.9,
            close_reason: "",
            evidence: [
              { obs_id: "pw:partial_a", quote: "帮看线上超时" },
              { obs_id: "pw:partial_b", quote: "顺便看下日志" },
            ],
          },
        ],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      },
      [obsA, obsB],
      ["pw:partial_a", "pw:partial_b"],
    );
    assert.equal(applyRes.created.length, 0, "引用了已撤回证据 B 的事项必须被拒绝");
    assert.equal(svc.store.obsPending("pw:partial_a"), true, "有效请求 A 绝不能被静默消费，必须保留 pending 以便重试");
    assert.equal(svc.store.obsPending("pw:partial_b"), false);
    svc.store.markProcessed(["pw:partial_a"]);

    // 13) [R6 P1-5 & P1-6] checkConvAllowedForUnderstand 刷新已知 oc_* 群名 + 未知 chat_mode 保持 unknown（对群与私聊双双 fail-closed）
    const client = await FeishuWebClient.connect(loginA, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
    mock.setChatName("9604", "新静音群名");
    svc.store.muteConv("pw_chat:9604", "新静音群名", true);
    svc.store.addObs([
      {
        id: "im:om_r6_renamed",
        source: "im",
        kind: "group",
        conv: "oc_r6_renamed",
        conv_name: "旧正常群名",
        actor_id: "ou_x",
        actor_name: "X",
        is_me: false,
        time: now,
        text: "改名前采集的消息",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_r6_renamed: { name: "新静音群名", chat_mode: "group" },
          oc_r6_unknown_mode: { name: "某带名字的未知类型会话", chat_mode: "custom_mystery_mode" },
        },
      }),
    );
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("oc_r6_renamed", "旧正常群名"),
      "excluded",
      "已入库的 oc_* 群改名命中静音群后，理解前实时复核必须拦截",
    );
    // 元数据查不到时返回 uncertain（不得放行给模型）
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三", chat_meta: {} }));
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("oc_r6_renamed", "旧正常群名"),
      "uncertain",
      "已入库 oc_* 群在有名称规则时实时查询失败必须返回 uncertain",
    );
    svc.store.muteConv("pw_chat:9604", "", false);

    // 未知 chat_mode 的 muted oc_* 会话：即使有非空 name 也必须保持 unknown，对传入 DM 与群双双阻断！
    svc.store.muteConv("oc_r6_unknown_mode", "某带名字的未知类型会话", true);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: { oc_r6_unknown_mode: { name: "某带名字的未知类型会话", chat_mode: "custom_mystery_mode" } },
      }),
    );
    const dmBuf = buildNativeMessage({ id: "r6_dm_blocked", chatId: "9605", actorId: "7002", createdAtSec: nowSec, text: "私聊内容" });
    mock.addMessage("r6_dm_blocked", dmBuf);
    mock.setChatMode("9605", CHAT_KIND_P2P);
    await svc.personalWeb.handleMessage(decodeMessage(dmBuf, "7001"), client);
    assert.equal(svc.store.obs("pw:r6_dm_blocked"), undefined, "含非空 name 但未知 chat_mode 的静音 oc_* 必须保持 unknown，进而阻断私聊入库");
    svc.store.muteConv("oc_r6_unknown_mode", "", false);
    svc.store.markProcessed(["im:om_r6_renamed"]);

    // 14) [R6 P1-9 & P2-10] pullIm：首拉阻塞钉住起始游标恢复后不漏消息 + 同 ID 合并搜索与群列表元数据 + 仅搜索命中群补查元数据
    app.cfg.context.groups = "spoken";
    const tEarly = now - 10 * 60_000; // 10 分钟前（远超 1 分钟重叠窗口）
    const tEarlySec = Math.floor(tEarly / 1000);
    app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r6_block: { name: "暂失联群", at: now }, oc_r6_merge: { name: "合并测试群", at: now } }));
    // 先把初始 groups 游标设在 tEarly - 120s
    const startGroupsCur = tEarly - 120_000;
    app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
    app.store.set("ctx.cursor.im.groups", String(startGroupsCur));
    app.store.set("ctx.cursor.im.at_me", String(startGroupsCur));
    app.store.set("ctx.cursor.im.p2p", String(startGroupsCur));
    app.store.set("ctx.cursor.im.mine", String(startGroupsCur));
    // 第一次拉取：oc_r6_block 查不到 chat_meta（阻塞），而 oc_r6_merge 在 at_me 缺 chat_name 但群列表有 chat_name，oc_r6_searchonly 仅在 at_me 且通过 im chats get 补查成功
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_r6_merge: { name: "合并测试群", chat_mode: "group" },
          oc_r6_searchonly: { name: "搜索补查群", chat_mode: "group" },
        },
        at_me: [
          { message_id: "om_r6_merged", chat_id: "oc_r6_merge", chat_name: "", chat_type: "", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "@张三 合并消息" },
          { message_id: "om_r6_searchonly", chat_id: "oc_r6_searchonly", chat_name: "", chat_type: "", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "@张三 仅搜索消息" },
        ],
        chats: {
          oc_r6_block: [{ message_id: "om_r6_early", chat_id: "oc_r6_block", create_time: String(tEarlySec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "早期消息不得漏掉" }],
          oc_r6_merge: [{ message_id: "om_r6_merged", chat_id: "oc_r6_merge", chat_name: "合并测试群", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "@张三 合并消息" }],
        },
      }),
    );
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_r6_early"), undefined, "首拉查元数据失败时先拦截");
    assert.equal(app.store.get("ctx.cursor.chat.oc_r6_block"), String(startGroupsCur), "首拉失败必须把原始起始游标钉入 cursor.chat.oc_r6_block");
    assert.ok(Number(app.store.get("ctx.cursor.im.groups")) > tEarly, "共享 cursor.im.groups 已推进到最新");
    assert.ok(svc.store.obs("im:om_r6_merged"), "同 ID 合并搜索与群列表元数据后，带名命中必须正常入库");
    assert.equal(svc.store.obs("im:om_r6_merged")?.kind, "at_me", "合并时应保留更高优先级的 at_me kind");
    assert.ok(svc.store.obs("im:om_r6_searchonly"), "仅搜索命中的缺名群经 im chats get 补查后应正常入库");

    // 第二次拉取：oc_r6_block 元数据恢复 -> 必须从钉住的 startGroupsCur 拉回 10 分钟前的早期消息，不漏！
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_r6_block: { name: "暂失联群", chat_mode: "group" },
          oc_r6_merge: { name: "合并测试群", chat_mode: "group" },
          oc_r6_searchonly: { name: "搜索补查群", chat_mode: "group" },
        },
        chats: {
          oc_r6_block: [{ message_id: "om_r6_early", chat_id: "oc_r6_block", create_time: String(tEarlySec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "早期消息不得漏掉" }],
        },
      }),
    );
    await svc.connectors.pullIm();
    assert.ok(svc.store.obs("im:om_r6_early"), "元数据恢复后必须按钉住的起始游标补拉到超过 1 分钟窗口的历史消息");

    // 15) [R6 P1-7] pullIm 提交前复检：轮询网络调用中途新增 pw_chat:* 静音，提交点必须拦截并重分类
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: { oc_r6_midmute: { name: "中途被静音的群", chat_mode: "group" } },
        at_me: [
          { message_id: "om_r6_midmute", chat_id: "oc_r6_midmute", chat_name: "中途被静音的群", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "@张三 中途静音测试" },
        ],
      }),
    );
    fs.rmSync(larkResumeSignal, { force: true });
    fs.writeFileSync(larkHookSignal, "armed");
    const pullPromise = svc.connectors.pullIm();
    await waitUntil(() => fs.readFileSync(larkHookSignal, "utf8") === "hit");
    // 在拉取进行中静音同名的原生会话
    mock.setChatName("9606", "中途被静音的群");
    svc.store.muteConv("pw_chat:9606", "中途被静音的群", true);
    fs.writeFileSync(larkResumeSignal, "go");
    await pullPromise;
    fs.rmSync(larkHookSignal, { force: true });
    fs.rmSync(larkResumeSignal, { force: true });
    assert.equal(svc.store.obs("im:om_r6_midmute"), undefined, "轮询途中新增原生静音，提交点复检必须拦截该群消息");
    svc.store.muteConv("pw_chat:9606", "", false);
    app.cfg.context.groups = "allowlist";

    // 16) [R6 P1-8] 理解批次途中静音策略变化：validateBeforeApply 必须在 apply 前令结果失效，不创建事项或提醒
    app.store.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE processed = 0").run();
    svc.store.addObs([
      {
        id: "im:om_r6_inbatch",
        source: "im",
        kind: "at_me",
        conv: "oc_r6_inbatch",
        conv_name: "推理中途静音群",
        actor_id: "ou_x",
        actor_name: "X",
        is_me: false,
        time: now,
        text: "@张三 帮我看一下接口",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: { oc_r6_inbatch: { name: "推理中途静音群", chat_mode: "group" } },
      }),
    );
    const inBatchHook = path.join(dir, "inbatch-ran.flag");
    const inBatchResume = path.join(dir, "inbatch-resume.flag");
    fs.rmSync(inBatchHook, { force: true });
    fs.rmSync(inBatchResume, { force: true });
    fs.writeFileSync(
      path.join(dir, "harness-mode.json"),
      JSON.stringify({
        onRunHookFile: inBatchHook,
        resumeFile: inBatchResume,
        output: {
          projects: [],
          items: [{ title: "中途静音不应入库的事项", kind: "ask_me", priority: "high", confidence: 0.95, evidence: [{ obs_id: "im:om_r6_inbatch", quote: "帮我看一下接口" }] }],
          knowledge: [],
          updates: [],
          conflicts: [],
        },
      }),
    );
    const cyclePromise = svc.cycle("work:r6-inbatch");
    await waitUntil(() => fs.existsSync(inBatchHook));
    // 模型正在推理时静音同名原生群
    mock.setChatName("9607", "推理中途静音群");
    svc.store.muteConv("pw_chat:9607", "推理中途静音群", true);
    fs.writeFileSync(inBatchResume, "go");
    await cyclePromise;
    assert.ok(!svc.store.items({}).some((i) => i.title === "中途静音不应入库的事项"), "推理期间静音策略变化后，结果必须失效不得创建事项");
    svc.store.muteConv("pw_chat:9607", "", false);
    fs.rmSync(path.join(dir, "harness-mode.json"), { force: true });

    // 17) [R6 P2-15] fastCycle 防抖多锚点：最后一条被撤回时必须挑选幸存的早期 @我；群消息编辑去掉 @我 时不得触发推理
    app.store.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE processed = 0").run();
    fs.writeFileSync(callsLog, "");
    const m1Buf = buildNativeMessage({
      id: "r6_deb_1",
      chatId: "9608",
      actorId: "7002",
      createdAtSec: nowSec - 5,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 早期幸存请求" }]),
    });
    const m2Buf = buildNativeMessage({
      id: "r6_deb_2",
      chatId: "9608",
      actorId: "7002",
      createdAtSec: nowSec - 2,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 稍后会被撤回" }]),
    });
    mock.addMessage("r6_deb_1", m1Buf);
    mock.addMessage("r6_deb_2", m2Buf);
    await svc.personalWeb.handleMessage(decodeMessage(m1Buf, "7001"), client);
    await svc.personalWeb.handleMessage(decodeMessage(m2Buf, "7001"), client);
    // 撤回最后一条 m2
    svc.store.retirePendingObs("pw:r6_deb_2");
    fs.writeFileSync(
      path.join(dir, "harness-mode.json"),
      JSON.stringify({
        output: {
          projects: [],
          items: [{ title: "防抖幸存事项", kind: "ask_me", priority: "high", confidence: 0.95, evidence: [{ obs_id: "pw:r6_deb_1", quote: "早期幸存请求" }] }],
          knowledge: [],
          updates: [],
          conflicts: [],
        },
      }),
    );
    await svc.fastCycle("work:r6-deb1", {
      conv: "pw_chat:9608",
      conv_name: "防抖群",
      trigger_obs_id: "pw:r6_deb_2",
      anchors: [
        { id: "r6_deb_1", conversationId: "9608", rootId: "", parentId: "", threadId: "", position: 1, createdAtMs: now - 5_000 },
        { id: "r6_deb_2", conversationId: "9608", rootId: "", parentId: "", threadId: "", position: 2, createdAtMs: now - 2_000 },
      ],
    });
    assert.ok(svc.store.items({}).some((i) => i.title === "防抖幸存事项"), "最后一条锚点被撤回时，fastCycle 必须选中幸存的早期有效 @我");

    // 群内白名单群里某条消息被编辑去掉 @我（仍留在库里且 pending=true 但 kind="group"）-> fastCycle 不得再触发快通道推理
    app.cfg.context.groups_allow = ["防抖白名单群"];
    fs.writeFileSync(callsLog, "");
    svc.store.addObs([
      {
        id: "pw:r6_demoted_mention",
        source: "im",
        kind: "group",
        conv: "pw_chat:9609",
        conv_name: "防抖白名单群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "原本@张三现在改成了普通群消息",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r6_demoted_mention", native_chat_id: "9609", chat_type: "group", is_mention_me: false },
      },
    ]);
    await svc.fastCycle("work:r6-demoted", {
      conv: "pw_chat:9609",
      conv_name: "防抖白名单群",
      trigger_obs_id: "pw:r6_demoted_mention",
      anchors: [{ id: "r6_demoted_mention", conversationId: "9609", rootId: "", parentId: "", threadId: "", position: 1, createdAtMs: now }],
    });
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "已编辑去掉 @我 的群消息不得触发 fastCycle 模型推理");
    app.cfg.context.groups_allow = [];
    fs.rmSync(path.join(dir, "harness-mode.json"), { force: true });

    // 18) [R6 P2-12] sendVerifiedReply 发送前原子认领 CAS：sending 拦截竞争者，verified 幂等返回不重发，created 仅回读确认不重发，在途抢占也不重发
    const replyTargetBuf = buildNativeMessage({
      id: "r6_reply_target",
      chatId: "9610",
      actorId: "7002",
      createdAtSec: nowSec - 10,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 请回复" }]),
    });
    mock.addMessage("r6_reply_target", replyTargetBuf);
    const replyTextHash = crypto.createHash("sha256").update("收到").digest("hex");
    const sendsBefore = mock.sentReplies.length;
    // (a) 已处于 sending 状态 -> 竞争者立即拒绝，不发包
    app.store.set(
      "pw.delivery.cid_r6_sending",
      JSON.stringify({ cid: "cid_r6_sending", state: "sending", owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", root_id: "", parent_id: "r6_reply_target", text_hash: replyTextHash, updated_at: now }),
    );
    await assert.rejects(
      () => svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", text: "收到", cid: "cid_r6_sending" }),
      /不明确|正在发送|避免重复/,
    );
    assert.equal(mock.sentReplies.length, sendsBefore, "sending 状态的竞争者绝不能再发回复");
    // (b) 已处于 verified 状态 -> 幂等返回，绝不覆写也不重发
    app.store.set(
      "pw.delivery.cid_r6_verified",
      JSON.stringify({ cid: "cid_r6_verified", state: "verified", owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", root_id: "r6_reply_target", parent_id: "r6_reply_target", reply_id: "sent_v1", text_hash: replyTextHash, updated_at: now }),
    );
    const verRes = await svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", text: "收到", cid: "cid_r6_verified" });
    assert.equal(verRes.replyId, "sent_v1");
    assert.equal(mock.sentReplies.length, sendsBefore, "verified 状态下必须幂等返回且绝不重发");
    // (c) 已处于 created 状态 -> 仅独立回读确认，升级为 verified 且不重发
    const createdSentBuf = buildNativeMessage({ id: "sent_c1", chatId: "9610", actorId: "7001", createdAtSec: nowSec, text: "收到", cid: "cid_r6_created", parentId: "r6_reply_target", rootId: "r6_reply_target" });
    mock.addMessage("sent_c1", createdSentBuf);
    app.store.set(
      "pw.delivery.cid_r6_created",
      JSON.stringify({ cid: "cid_r6_created", state: "created", owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", root_id: "r6_reply_target", parent_id: "r6_reply_target", reply_id: "sent_c1", text_hash: replyTextHash, updated_at: now }),
    );
    const createdRes = await svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", text: "收到", cid: "cid_r6_created" });
    assert.equal(createdRes.replyId, "sent_c1");
    assert.equal(mock.sentReplies.length, sendsBefore, "created 状态只做回读确认，绝不重发");
    assert.equal(JSON.parse(app.store.get("pw.delivery.cid_r6_created")!).state, "verified");
    // (d) 在途抢占模拟：入口初检无记录，但在 readChatMode 异步检查期间另一进程写下 verified -> onBeforeSend 原子 CAS 必须中止发包并幂等返回
    app.cfg.context.personal_web.send_replies = true;
    const origCfgYaml = fs.readFileSync(cfgPath, "utf8");
    fs.writeFileSync(cfgPath, origCfgYaml.replace("send_replies: false", "send_replies: true"));
    let injectedRace = false;
    mock.setOnChatMode(() => {
      if (!injectedRace) {
        injectedRace = true;
        app!.store.set(
          "pw.delivery.cid_r6_race",
          JSON.stringify({ cid: "cid_r6_race", state: "verified", owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", root_id: "r6_reply_target", parent_id: "r6_reply_target", reply_id: "sent_race_winner", text_hash: replyTextHash, updated_at: Date.now() }),
        );
      }
    });
    const raceRes = await svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9610", message_id: "r6_reply_target", text: "收到", cid: "cid_r6_race" });
    mock.setOnChatMode(undefined);
    fs.writeFileSync(cfgPath, origCfgYaml);
    app.cfg.context.personal_web.send_replies = false;
    assert.equal(raceRes.replyId, "sent_race_winner", "在途被竞争者抢先 verified 时，CAS 必须停止发包并幂等返回胜者记录");
    assert.equal(mock.sentReplies.length, sendsBefore, "在途被抢占后绝不能发出重复回复包");

    // 19) [R6 P2-22] 常驻进程监听健康与 CLI 本地缺密钥解耦：缺 PA_FEISHU_WEB_KEY 时保留新鲜 listening 状态
    app.store.set("daemon.heartbeat", `${process.pid}|${now}`);
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({
        state: "listening",
        owner_id: "7001",
        owner_name: "张三",
        last_message_at: now,
        last_error: "",
      }),
    );
    const savedKey = process.env.PA_FEISHU_WEB_KEY;
    delete process.env.PA_FEISHU_WEB_KEY;
    try {
      const cliStatus = svc.personalWeb.status();
      assert.equal(cliStatus.state, "listening", "本地 shell 缺解密密钥但常驻心跳新鲜时，必须保留 listening 状态而非改写成 needs_login");
      assert.equal(cliStatus.logged_in, true);
      const docRep = await runDoctor(app);
      const pwCheck = docRep.checks.find((c) => c.id === "personal_web");
      assert.equal(pwCheck?.status, "ok", "doctor 看到常驻监听新鲜时应报告正常（含本地无法解密提示），而非报错 needs_login");
    } finally {
      app.store.db.prepare("DELETE FROM kv WHERE k = 'daemon.heartbeat'").run();
      process.env.PA_FEISHU_WEB_KEY = savedKey;
    }

    // 20) [R6 P1-1] 工作区主人变更（owner.open_id A -> B）时，彻底阻断所有派生上下文视图、早晚报、命令与上下文 effect 投递
    app.cfg.owner.open_id = "ou_owner_b";
    assert.equal(hasWorkspaceOwnerMismatch(app.store, app.cfg.owner.open_id), true);
    assert.throws(() => app!.ext.context!.today(), /owner\.open_id|不一致/, "主人变更后 today() 必须阻断，防止 B 看到 A 的旧事项");
    assert.throws(() => app!.ext.context!.items({}), /owner\.open_id|不一致/);
    assert.throws(() => app!.ext.context!.drafts(), /owner\.open_id|不一致/);
    assert.throws(() => app!.ext.context!.sendDigest("morning"), /owner\.open_id|不一致/);
    await assert.rejects(() => app!.commands.exec("context.weekly_report", {}, { source: "cli", actor: "owner" }), /owner\.open_id|不一致/);
    // status() 保持可读，以便控制台/体检诊断主人不一致
    assert.ok(app.ext.context!.status());
    // renderMorning / sendItem / sendDigest 不得入队任何发往新主人 B 的效果
    const ledgerCountBefore = app.ledger.list({ kinds: ["effect"], limit: 200 }).length;
    regSvc.renderMorning("2026-11-26");
    regSvc.sendDigest("morning");
    assert.equal(app.ledger.list({ kinds: ["effect"], limit: 200 }).length, ledgerCountBefore, "主人变更后 renderMorning/sendDigest 不得产生任何新 effect");
    // 已排队的旧上下文 effect（如 card:ctx-morning / context:digest）在 effectHandler 投递前也必须被拦截！
    const { effectHandler, notify } = await import("../src/effects.ts");
    const effHandler = effectHandler(app.cfg, app.ledger, app.board, app.lark, app.store);
    app.ledger.enqueue({
      id: "eff:r6-leaked-digest",
      kind: "effect",
      ref: "context:digest",
      state: "pending",
      payload: notify("主人 A 的私密晨报", "brief"),
    });
    const leakedEff = app.ledger.get<ReturnType<typeof notify>>("eff:r6-leaked-digest")!;
    await assert.rejects(
      () => effHandler.run(leakedEff, { attempt: 1, signal: new AbortController().signal }),
      /跨账号泄漏|不一致/,
      "主人变更后 effectHandler 必须拦截已排队的旧上下文通知",
    );
    app.cfg.owner.open_id = "ou_owner_a";

    // 21) [R6 P3-23] CLI web-login 预检：未绑定工作区未传 --allow-unverified-owner 时，必须在请求二维码前就拒绝（0 次 HTTP QR 请求）
    let qrRequests = 0;
    preflightSrv = http.createServer((_req, res) => {
      qrRequests++;
      res.writeHead(500);
      res.end("should not be called");
    });
    await new Promise<void>((r) => preflightSrv!.listen(0, "127.0.0.1", () => r()));
    const pfPort = (preflightSrv.address() as net.AddressInfo).port;
    const pfDir = makeTmp("pa-r6-preflight-");
    const pfCfg = path.join(pfDir, "config.yaml");
    fs.writeFileSync(
      pfCfg,
      `owner:
  open_id: ou_owner_pf
  name: 张三
bins:
  lark: ${path.join(STUBS, "ctx-lark")}
harnesses:
  codex:
    type: codex-exec
    cmd: ${harnessScript}
roles:
  brain: codex
server:
  enabled: false
cards:
  enabled: false
kb:
  enabled: false
context:
  enabled: true
  personal_web:
    enabled: true
data_dir: ${pfDir}
`,
    );
    const cliRes = await runProcess(
      process.execPath,
      ["--experimental-strip-types", "--disable-warning=ExperimentalWarning", path.join(ROOT, "src/cli.ts"), "context", "web-login"],
      {
        cwd: ROOT,
        env: {
          ...process.env,
          PA_CONFIG: pfCfg,
          PA_FEISHU_WEB_KEY: "r6-test-secret-key-32-bytes-ok!!",
          HTTP_PROXY: `http://127.0.0.1:${pfPort}`,
          HTTPS_PROXY: `http://127.0.0.1:${pfPort}`,
        },
        timeoutMs: 15_000,
      },
    );
    assert.notEqual(cliRes.code, 0, "未绑定工作区且未传 --allow-unverified-owner 时 web-login 必须失败");
    assert.match(cliRes.stderr + cliRes.stdout, /--allow-unverified-owner/, "必须明确提示需要追加 --allow-unverified-owner");
    assert.equal(qrRequests, 0, "预检失败必须在请求二维码接口之前中止，绝不让用户白扫码");
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    if (prevXdg === undefined) delete process.env.XDG_RUNTIME_DIR;
    else process.env.XDG_RUNTIME_DIR = prevXdg;
    app?.store.db.close();
    if (redirectSrv) await new Promise<void>((r) => redirectSrv!.close(() => r()));
    if (preflightSrv) await new Promise<void>((r) => preflightSrv!.close(() => r()));
    await mock.close();
  }
});

test("Codex 第七轮回归：TOML 解析与内联头隔离、extraArgs 白名单、env.HOME、诊断主人隔离、开关/策略/白名单重验、未知类型、终检、无归属结果丢弃、群名前缀、未扫游标、回复先落回执、租约写校验、撤回草稿拒绝、两阶段凭据恢复与编辑复原快通道", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  process.env.PA_FEISHU_WEB_KEY = "r7-test-secret-key-32-bytes-ok!!";
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  try {
    // 1) [R7 P1-1, P1-3, P1-4, P1-5] 完整 TOML 解析、env.HOME、内联/子表 http_headers 走环境变量、extraArgs 白名单
    const fakeHome = makeTmp("pa-r7-home-");
    const fakeCodexDir = path.join(fakeHome, ".codex");
    fs.mkdirSync(fakeCodexDir, { recursive: true });
    // 多行字符串内嵌伪造 [section] 表头，随后才是顶层 model_provider；且供应商使用内联 http_headers 与 experimental_bearer_token
    fs.writeFileSync(
      path.join(fakeCodexDir, "config.toml"),
      [
        'developer_instructions = """',
        "注意以下示例不是真实表头：",
        "[mcp_servers.fake_inside_string]",
        'command = "nope"',
        '"""',
        'model = "gpt-5-private"',
        'model_provider = "private_gw"',
        "",
        "[model_providers.private_gw]",
        'name = "Private GW"',
        'base_url = "https://gw.private.internal/v1"',
        'http_headers = { Authorization = "Bearer inline-super-secret", "X-Region" = "cn" }',
        'query_params = { "api-version" = "2025-04-01" }',
      ].join("\n"),
    );
    const parsedDoc = parseToml(fs.readFileSync(path.join(fakeCodexDir, "config.toml"), "utf8"));
    assert.equal(parsedDoc.model_provider, "private_gw", "多行字符串内的 [xxx] 绝不能把后续顶层 model_provider 误归错表");

    // 不设 CODEX_HOME，仅设 env.HOME -> 必须解析 env.HOME/.codex/config.toml 而非 os.homedir()
    const homeCfg = extractSafeCodexProviderConfig({ HOME: fakeHome }, [], false);
    assert.ok(homeCfg.args.includes('model_provider="private_gw"'), "必须按子进程 env.HOME 解析 config.toml");
    const homeMpArg = homeCfg.args.find((a) => a.startsWith("model_providers="));
    assert.ok(homeMpArg, "应以 TOML 内联表形式输出 model_providers");
    const homePrivGw = (parseToml(homeMpArg!).model_providers as Record<string, Record<string, unknown>>).private_gw;
    assert.equal(homePrivGw.base_url, "https://gw.private.internal/v1");
    assert.equal((homePrivGw.query_params as Record<string, string>)["api-version"], "2025-04-01");
    assert.ok(
      !homeCfg.args.some((a) => a.includes("inline-super-secret")),
      "内联 http_headers 中的明文密钥绝不能进入 Codex argv",
    );
    const authVarName = (homePrivGw.env_http_headers as Record<string, string>)?.Authorization;
    assert.ok(authVarName, "内联 http_headers 必须自动转为 env_http_headers 环境变量引用");
    assert.equal(homeCfg.extraEnv[authVarName], "Bearer inline-super-secret");

    // extraArgs 白名单：拒绝 MCP、--enable、--sandbox、--full-auto、含密钥 query_params；净化 extraArgs 里的内联 http_headers
    assert.throws(
      () => extractSafeCodexProviderConfig({ HOME: fakeHome }, ["-c", 'mcp_servers.evil.command="/bin/sh"'], false),
      /禁止|不安全/,
    );
    assert.throws(() => extractSafeCodexProviderConfig({ HOME: fakeHome }, ["--enable", "shell_tool"], false), /拒绝|不支持/);
    assert.throws(() => extractSafeCodexProviderConfig({ HOME: fakeHome }, ["--full-auto"], false), /拒绝|不支持/);
    assert.throws(
      () => extractSafeCodexProviderConfig({ HOME: fakeHome }, ["-c", 'model_providers.private_gw.query_params.api_key="sk-leak"'], false),
      /疑似密钥/,
    );
    const extraHdrCfg = extractSafeCodexProviderConfig(
      { HOME: fakeHome },
      ["-c", 'model_providers.private_gw.http_headers={ "X-Api-Key" = "extra-hdr-secret" }', "--disable", "view_image"],
      false,
    );
    assert.ok(!extraHdrCfg.sanitizedExtraArgs.some((a) => a.includes("extra-hdr-secret")), "extraArgs 内联 http_headers 明文绝不能留存 argv");
    assert.ok(Object.values(extraHdrCfg.extraEnv).includes("extra-hdr-secret"));
    assert.ok(extraHdrCfg.sanitizedExtraArgs.includes("--disable"));

    // 2) 构建完整 Working Context 实例
    const dir = makeTmp("pa-r7-ctx-");
    const ctxDir = makeTmp("pa-r7-lark-");
    process.env.CTX_DIR = ctxDir;
    const callsLog = path.join(dir, "calls.log");
    const harnessScript = path.join(dir, "fake-r7-harness.mjs");
    fs.writeFileSync(
      harnessScript,
      `#!/usr/bin/env node
import fs from "node:fs";
const prompt = fs.readFileSync(0, "utf8");
fs.appendFileSync(${JSON.stringify(callsLog)}, JSON.stringify({ at: Date.now(), prompt, argv: process.argv.slice(2), envKeys: Object.keys(process.env).filter((k) => k.startsWith("__PA_CODEX_HDR_")) }) + "\\n");
const modeFile = ${JSON.stringify(path.join(dir, "harness-mode.json"))};
const mode = fs.existsSync(modeFile) ? JSON.parse(fs.readFileSync(modeFile, "utf8")) : {};
if (mode.output !== undefined) {
  process.stdout.write(JSON.stringify(mode.output));
} else {
  process.stdout.write(JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], people: [], conflicts: [] }));
}
`,
      { mode: 0o755 },
    );

    const cfgPath = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      `owner:
  open_id: ou_owner_a
  name: 张三
  timezone: Asia/Shanghai
bins:
  lark: ${path.join(STUBS, "ctx-lark")}
  bytedcli: ${path.join(STUBS, "ctx-bytedcli")}
harnesses:
  codex:
    type: codex-exec
    cmd: ${harnessScript}
    env:
      HOME: ${fakeHome}
roles:
  brain: codex
server:
  enabled: false
cards:
  enabled: false
kb:
  enabled: false
context:
  enabled: true
  understand: true
  harness: codex
  groups: allowlist
  groups_allow: ["pw_chat:9501"]
  groups_deny: []
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: false
    send_replies: true
    debounce_ms: 0
data_dir: ${dir}
`,
    );
    app = createApp(loadConfig(cfgPath));
    const { registerContext } = await import("../src/context/index.ts");
    const svc = registerContext(app)!;
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const baseCookies = [
      { name: "session", value: "sess_r7_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r7_1", domain: "127.0.0.1", path: "/" },
    ];
    const loginA = { owner_id: "7001", owner_name: "张三", cookies: baseCookies };
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });
    const client = await FeishuWebClient.connect(loginA, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;

    // 3) [R7 P2-17] 两阶段暂存凭据提交：SQLite COMMIT 失败时不覆盖旧凭据且清理 .staged；COMMIT 后崩溃未 rename 时启动自动协调补全
    const loginStore = new WebLoginStore(dir);
    const beforeCredRaw = fs.readFileSync(loginStore.file, "utf8");
    // 模拟 SQLite 写入阶段抛错：使用已中止 signal 或故意把 kv 设为临时只读触发表约束失败 -> 使用临时触发器让 COMMIT 阶段/写阶段失败
    app.store.db.exec(`CREATE TRIGGER fail_r7_kv BEFORE INSERT ON kv WHEN NEW.k = '${PENDING_CRED_COMMIT_KV_KEY}' BEGIN SELECT RAISE(ABORT, 'simulated sqlite failure'); END;`);
    try {
      assert.throws(
        () => commitWorkspaceLogin(app!, { owner_id: "7001", owner_name: "新名字", cookies: [{ name: "session", value: "sess_should_rollback", domain: "127.0.0.1", path: "/" }] }, { allowUnverifiedOwner: true }),
        /simulated sqlite failure/,
      );
    } finally {
      app.store.db.exec("DROP TRIGGER IF EXISTS fail_r7_kv");
    }
    assert.equal(fs.readFileSync(loginStore.file, "utf8"), beforeCredRaw, "SQLite 失败回滚时，现网凭据文件绝不能被新凭据覆盖");
    assert.equal(fs.existsSync(loginStore.stagedFile), false, "SQLite 失败回滚时必须清理 .staged 暂存文件");

    // 模拟崩溃发生在 SQLite COMMIT 之后、renameSync(.staged -> file) 之前
    loginStore.stageWithLock((stage) => {
      const s = stage({ owner_id: "7001", owner_name: "已提交待恢复", cookies: [{ name: "session", value: "sess_r7_recovered", domain: "127.0.0.1", path: "/" }] });
      app!.store.set(PENDING_CRED_COMMIT_KV_KEY, JSON.stringify({ owner_id: "7001", session_id: s.payload.session_id }));
      // 故意不调用 s.commitFile()，模拟进程此时崩溃
    });
    assert.equal(fs.existsSync(loginStore.stagedFile), true);
    assert.equal(loginStore.load()?.owner_name, "张三", "协调前旧文件尚未切换");
    // 触发 reconcilePendingCommit（例如下次 status() / 重启）
    svc.personalWeb.status();
    assert.equal(fs.existsSync(loginStore.stagedFile), false, "崩溃恢复后必须完成 rename 并清除 .staged");
    assert.equal(app.store.get(PENDING_CRED_COMMIT_KV_KEY), "", "崩溃恢复后必须清除 pending_cred_commit 标记");
    assert.equal(loginStore.load()?.owner_name, "已提交待恢复", "崩溃恢复必须把已提交的新凭据原子就位");
    // 恢复正常登录态以便后续测试
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });

    // 4) [R7 P1-8] resolveNativeExclusionsForPolling：未知原生会话类型即使有非空名也必须让群与私聊双路 inconclusive
    mock.setChatName("9502", "某个名字非空的未知类型会话");
    mock.setChatKind("9502", 99); // 未识别的 kind
    svc.store.muteConv("pw_chat:9502", "", true);
    const exclUnknownKind = await svc.personalWeb.resolveNativeExclusionsForPolling();
    assert.equal(exclUnknownKind.groupsInconclusive, true, "未知原生会话类型必须标记 groupsInconclusive");
    assert.equal(exclUnknownKind.dmsInconclusive, true, "未知原生会话类型绝不能仅因有名称就跳过私聊保护，必须标记 dmsInconclusive");
    svc.store.muteConv("pw_chat:9502", "", false);

    // 5) [R7 P2-12] classifyRecordedChatType 不得凭群名“私聊xxx”前缀误判为 DM：无 chat_type 的“私聊讨论群”仍须查元信息并受静音阻断
    mock.setChatName("9503", "私聊讨论群");
    mock.setChatKind("9503", CHAT_KIND_GROUP);
    svc.store.muteConv("pw_chat:9503", "私聊讨论群", true);
    svc.store.addObs([
      {
        id: "im:om_r7_fake_dm_name",
        source: "im",
        kind: "at_me",
        conv: "oc_r7_fake_dm_name",
        conv_name: "私聊讨论群",
        actor_id: "ou_x",
        actor_name: "X",
        is_me: false,
        time: now,
        text: "@张三 名字叫私聊的其实是群",
        url: "",
        meta: {}, // 刻意缺少 chat_type
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: { oc_r7_fake_dm_name: { name: "私聊讨论群", chat_mode: "group" } },
      }),
    );
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("oc_r7_fake_dm_name", "私聊讨论群"),
      "excluded",
      "名称以“私聊”开头但无权威 chat_type 的群绝不能被误判为 DM 跳过元数据刷新，必须命中原生群静音被拦截",
    );
    svc.store.muteConv("pw_chat:9503", "", false);
    svc.store.markProcessed(["im:om_r7_fake_dm_name"]);

    // 6) [R7 P1-9] 群移出 groups_allow 后，已入库的普通群消息与普通背景不得进入模型提示词，仅保留真实 @我 例外
    svc.store.addObs([
      {
        id: "pw:r7_allow_ord",
        source: "im",
        kind: "group",
        conv: "pw_chat:9501",
        conv_name: "曾允许群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 5_000,
        text: "普通群内闲聊消息",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r7_allow_ord", native_chat_id: "9501", chat_type: "group" },
      },
    ]);
    // 把 pw_chat:9501 移出 groups_allow -> 普通群消息绝不能送模型
    app.cfg.context.groups_allow = [];
    fs.writeFileSync(callsLog, "");
    await svc.cycle("work:r7-allow-removed");
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "群移出 groups_allow 后，已排队的普通群消息不得送往模型");
    assert.equal(svc.store.obsPending("pw:r7_allow_ord"), true, "未处理的普通群消息也不得被静默 skipConv 吞掉");

    // 同一已移出白名单的群里收到真实 @我：仅允许该 @我 进入提示词，普通群消息仍不得混入背景！
    svc.store.addObs([
      {
        id: "pw:r7_allow_atme",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9501",
        conv_name: "曾允许群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 1_000,
        text: "@张三 帮忙审批",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r7_allow_atme", native_chat_id: "9501", chat_type: "group", at_me: true },
      },
    ]);
    fs.writeFileSync(callsLog, "");
    await svc.cycle("work:r7-allow-atme");
    const allowAtCalls = fs.readFileSync(callsLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { prompt: string });
    assert.equal(allowAtCalls.length, 1, "已移出白名单的群仍应放行真实 @我");
    assert.ok(allowAtCalls[0].prompt.includes("帮忙审批"), "真实 @我 应进入提示词");
    assert.ok(!allowAtCalls[0].prompt.includes("普通群内闲聊消息"), "已移出白名单的群的普通群消息绝不能作为背景进入提示词");
    // 顺带验证运行日志不含任何明文供应商密钥（[R7 P1-1] 端到端验证）
    const runFiles = fs.readdirSync(path.join(dir, "runs")).filter((f) => f.startsWith("context-"));
    assert.ok(runFiles.length > 0);
    const latestRunLog = fs.readFileSync(path.join(dir, "runs", runFiles[runFiles.length - 1]), "utf8");
    assert.ok(!latestRunLog.includes("inline-super-secret"), "持久化运行日志绝不能包含内联 http_headers 明文密钥");
    svc.store.markProcessed(["pw:r7_allow_ord"]);

    // 7) [R7 P1-6] fastCycle 在 hydrateContext 结束后必须重检 context.understand 开关：补读期间关闭 understand 不得再调模型
    app.cfg.context.groups_allow = ["pw_chat:9504"];
    mock.setChatName("9504", "补读开关群");
    mock.setChatKind("9504", CHAT_KIND_GROUP);
    const hydrateAtBuf = buildNativeMessage({
      id: "r7_hyd_1",
      chatId: "9504",
      actorId: "7002",
      createdAtSec: nowSec,
      position: 5,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 看下" }]),
    });
    mock.addMessage("r7_hyd_1", hydrateAtBuf);
    await svc.personalWeb.handleMessage(decodeMessage(hydrateAtBuf, "7001"), client);
    fs.writeFileSync(callsLog, "");
    mock.setOnHistory(() => {
      app!.cfg.context.understand = false;
    });
    try {
      await svc.fastCycle("work:r7-fast-switch", {
        conv: "pw_chat:9504",
        conv_name: "补读开关群",
        trigger_obs_id: "pw:r7_hyd_1",
        anchors: [{ id: "r7_hyd_1", conversationId: "9504", rootId: "", parentId: "", threadId: "", position: 5, createdAtMs: now }],
      });
    } finally {
      mock.setOnHistory(undefined);
      app.cfg.context.understand = true;
    }
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "hydrateContext 期间关闭 context.understand 后绝不能启动模型推理");
    app.cfg.context.groups_allow = [];
    svc.store.markProcessed(["pw:r7_hyd_1"]);

    // 8) [R7 P1-7] cycle 候选筛选绑定策略快照：在筛选第二个候选期间新增静音第一个候选对应的原生群，必须重启筛选且不送模型
    app.store.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE processed = 0").run();
    app.cfg.context.groups = "spoken";
    app.store.set(
      "ctx.spoken_groups",
      JSON.stringify({
        oc_r7_sel1: { name: "候选群一", at: now },
        oc_r7_sel2: { name: "候选群二", at: now },
      }),
    );
    svc.store.addObs([
      {
        id: "im:om_r7_sel1",
        source: "im",
        kind: "group",
        conv: "oc_r7_sel1",
        conv_name: "候选群一",
        actor_id: "ou_x",
        actor_name: "X",
        is_me: false,
        time: now - 10_000,
        text: "候选群一敏感消息",
        url: "",
        meta: { chat_type: "group" },
      },
      {
        id: "im:om_r7_sel2",
        source: "im",
        kind: "group",
        conv: "oc_r7_sel2",
        conv_name: "候选群二",
        actor_id: "ou_x",
        actor_name: "X",
        is_me: false,
        time: now - 5_000,
        text: "候选群二普通消息",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_r7_sel1: { name: "候选群一", chat_mode: "group" },
          oc_r7_sel2: { name: "候选群二", chat_mode: "group" },
        },
      }),
    );
    // 拦截 checkConvAllowedForUnderstand 在校验第二个候选 oc_r7_sel2 时把候选群一静音
    const origCheckConv = svc.personalWeb.checkConvAllowedForUnderstand.bind(svc.personalWeb);
    let injectedSelMute = false;
    svc.personalWeb.checkConvAllowedForUnderstand = async (conv, convName, snap) => {
      const r = await origCheckConv(conv, convName, snap);
      if (conv === "oc_r7_sel2" && !injectedSelMute) {
        injectedSelMute = true;
        mock.setChatName("9505", "候选群一");
        mock.setChatKind("9505", CHAT_KIND_GROUP);
        svc.store.muteConv("pw_chat:9505", "候选群一", true);
      }
      return r;
    };
    fs.writeFileSync(callsLog, "");
    try {
      await svc.cycle("work:r7-sel-snap");
    } finally {
      svc.personalWeb.checkConvAllowedForUnderstand = origCheckConv;
      svc.store.muteConv("pw_chat:9505", "", false);
      app.cfg.context.groups = "allowlist";
    }
    const selCalls = fs.readFileSync(callsLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { prompt: string });
    assert.ok(selCalls.every((c) => !c.prompt.includes("候选群一敏感消息")), "筛选中途被静音的候选群一绝不能带着旧快照进入模型提示词");
    assert.ok(selCalls.some((c) => c.prompt.includes("候选群二普通消息")), "重启筛选后未静音的候选群二应正常被理解");
    svc.store.markProcessed(["im:om_r7_sel1", "im:om_r7_sel2"]);

    // 9) [R7 P1-10] handleMessage 第二次排除 await 期间被关闭 sources.im 或静音时，最终同步终检必须阻断入库
    svc.store.muteConv("oc_r7_trigger_recheck", "旧无关静音群", true);
    const origEval = (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion.bind(svc.personalWeb);
    let evalCount = 0;
    (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion = async (...args: unknown[]) => {
      evalCount++;
      const r = await origEval(...args);
      if (evalCount === 1) {
        // 第一次排除查询返回 false 之后，触发 ocExclKey 变化以进入第二次 await
        svc.store.muteConv("oc_r7_trigger_recheck_2", "另一无关静音群", true);
      } else if (evalCount === 2) {
        // 第二次 await 期间，主人静音了本原生 DM！
        svc.store.muteConv("pw_chat:9506", "私聊", true);
      }
      return r;
    };
    const lateMuteDmBuf = buildNativeMessage({ id: "r7_late_mute_dm", chatId: "9506", actorId: "7002", createdAtSec: nowSec, text: "二检期间静音的私聊" });
    mock.addMessage("r7_late_mute_dm", lateMuteDmBuf);
    mock.setChatKind("9506", CHAT_KIND_P2P);
    try {
      await svc.personalWeb.handleMessage(decodeMessage(lateMuteDmBuf, "7001"), client);
    } finally {
      (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion = origEval;
      svc.store.muteConv("oc_r7_trigger_recheck", "", false);
      svc.store.muteConv("oc_r7_trigger_recheck_2", "", false);
      svc.store.muteConv("pw_chat:9506", "", false);
    }
    assert.equal(svc.store.obs("pw:r7_late_mute_dm"), undefined, "第二次异步排除查询期间被静音后，同步终检必须阻止写入");

    // 10) [R7 P1-11 & P2-15] 部分失效批次丢弃无归属 projects/people 且保留有效观测待重跑；失去租约时写事务必须整体拒绝
    svc.store.addObs([
      {
        id: "pw:r7_batch_keep",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9507",
        conv_name: "正常群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 4_000,
        text: "@张三 正常请求",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r7_batch_keep", native_chat_id: "9507", chat_type: "group", at_me: true },
      },
      {
        id: "pw:r7_batch_stale",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9508",
        conv_name: "将静音群",
        actor_id: "7003",
        actor_name: "机密人",
        is_me: false,
        time: now - 3_000,
        text: "@张三 机密项目绝密代号",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r7_batch_stale", native_chat_id: "9508", chat_type: "group", at_me: true },
      },
    ]);
    const keepObs = svc.store.obs("pw:r7_batch_keep")!;
    const staleObs = svc.store.obs("pw:r7_batch_stale")!;
    // 模拟 pw_chat:9508 在推理期间被静音
    svc.store.muteConv("pw_chat:9508", "将静音群", true);
    const staleBatchRes = svc.understander.apply(
      {
        projects: [{ ref: "", name: "绝密泄露项目", parent: "", aliases: [], refs: [], description: "来自被静音群", my_role: "", stage: "", health: "green", status: "active" }],
        items: [{ ref: "", title: "正常请求事项", kind: "ask_me", project: "", status: "open", priority: "high", due: null, counterpart: "王五", next_step: "", confidence: 0.95, close_reason: "", evidence: [{ obs_id: "pw:r7_batch_keep", quote: "正常请求" }] }],
        knowledge: [],
        updates: [],
        people: [{ name: "绝密联系人", open_id: "", relation: "外部", projects: [] }],
        conflicts: [],
      },
      [keepObs, staleObs],
      ["pw:r7_batch_keep", "pw:r7_batch_stale"],
      new Set(["pw_chat:9508"]),
    );
    assert.equal(staleBatchRes.projects, 0, "部分失效批次不得写入无 evidence 归属的 projects");
    assert.equal(staleBatchRes.people, 0, "部分失效批次不得写入无 evidence 归属的 people");
    assert.equal(svc.store.findProject("绝密泄露项目"), undefined);
    assert.ok(!svc.store.people().some((p) => p.name === "绝密联系人"));
    assert.equal(svc.store.obsPending("pw:r7_batch_keep"), true, "有效观测必须保持 pending 以便用干净批次重跑");
    svc.store.muteConv("pw_chat:9508", "", false);

    // [R7 P2-15] 失去租约后 apply 写事务必须整体丢弃，绝不覆写继任者结果
    assert.equal(svc.store.claimConv("pw_chat:9507", "tok_old", "procOld", 60_000, now), true);
    svc.store.releaseConv("pw_chat:9507", "tok_old", "procOld");
    assert.equal(svc.store.claimConv("pw_chat:9507", "tok_new", "procNew", 60_000, now + 10), true);
    const lostLeaseRes = svc.understander.apply(
      {
        projects: [{ ref: "", name: "陈旧租约项目", parent: "", aliases: [], refs: [], description: "", my_role: "", stage: "", health: "green", status: "active" }],
        items: [{ ref: "", title: "陈旧租约事项", kind: "ask_me", project: "", status: "open", priority: "high", due: null, counterpart: "王五", next_step: "", confidence: 0.95, close_reason: "", evidence: [{ obs_id: "pw:r7_batch_keep", quote: "正常请求" }] }],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      },
      [keepObs],
      ["pw:r7_batch_keep"],
      undefined,
      { convs: ["pw_chat:9507"], holder: "tok_old", procOwner: "procOld" },
    );
    assert.equal(lostLeaseRes.created.length, 0, "失去会话租约的旧执行者绝不能写入事项");
    assert.equal(svc.store.findProject("陈旧租约项目"), undefined);
    assert.equal(svc.store.obsPending("pw:r7_batch_keep"), true);
    svc.store.releaseConv("pw_chat:9507", "tok_new", "procNew");
    svc.store.markProcessed(["pw:r7_batch_keep", "pw:r7_batch_stale"]);

    // 11) [R7 P2-13 + R8 P1-5] pullIm：若排除规则在群排行前阻断了群拉取、随后在提交前清除，绝不能在未扫描的情况下推进 cursor.im.groups——
    //     必须重启完整拉取该群并落库消息（或在不稳定时放弃且不推进游标）
    app.cfg.context.groups = "spoken";
    app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r7_unscanned: { name: "未扫描群", at: now } }));
    app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
    const origNativeExcl = svc.connectors.nativeExclusions;
    let neCalls = 0;
    svc.connectors.nativeExclusions = async () => {
      neCalls++;
      if (neCalls === 1) {
        // 首次进入 pullIm 时 groupsInconclusive=true（导致 ranked=[] 未拉任何群），同时制造一次策略变更以触发提交前刷新
        return { confirmedGroupNames: new Set<string>(), groupsInconclusive: true, dmsInconclusive: false };
      }
      return { confirmedGroupNames: new Set<string>(), groupsInconclusive: false, dmsInconclusive: false };
    };
    const origSig = (svc.connectors as unknown as { pollingPolicySignature: () => string }).pollingPolicySignature.bind(svc.connectors);
    let sigCalls = 0;
    (svc.connectors as unknown as { pollingPolicySignature: () => string }).pollingPolicySignature = () => {
      sigCalls++;
      return sigCalls === 1 ? "sig_before" : "sig_after";
    };
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chats: {
          oc_r7_unscanned: [
            { message_id: "om_r7_unscanned_1", chat_id: "oc_r7_unscanned", chat_name: "未扫描群", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "重启后必须扫到的群消息" },
          ],
        },
      }),
    );
    try {
      await svc.connectors.pullIm();
    } finally {
      svc.connectors.nativeExclusions = origNativeExcl;
      (svc.connectors as unknown as { pollingPolicySignature: () => string }).pollingPolicySignature = origSig;
      app.cfg.context.groups = "allowlist";
    }
    assert.ok(svc.store.obs("im:om_r7_unscanned_1"), "提交前排除阻断解除后必须重启并实际扫描该群，绝不能漏采就推进 cursor.im.groups");
    assert.ok(app.store.get("ctx.cursor.chat.oc_r7_unscanned"), "重启实际扫描完成后才推进该群游标");

    // 12) [R7 P2-14] sendVerifiedReply：发包响应同时返回新消息 ID 与 Cookie 轮换，但 Cookie 落盘失败时必须先记 created，重跑只做回读不重发
    const r7TargetBuf = buildNativeMessage({
      id: "r7_reply_orig",
      chatId: "9510",
      actorId: "7002",
      createdAtSec: nowSec - 10,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 请确认" }]),
    });
    mock.addMessage("r7_reply_orig", r7TargetBuf);
    mock.setChatKind("9510", CHAT_KIND_GROUP);
    const sendsBeforeRot = mock.sentReplies.length;
    // 用带失败保存回调的独立客户端替换桥接客户端，在 readChat 完成后（恰好在 CMD_SEND_MESSAGE 响应）触发 Cookie 轮换与落盘报错
    let blockCookieSave = false;
    const diskLoginNow = svc.personalWeb.loginStore.load()!;
    const rotFailClient = await FeishuWebClient.connect(diskLoginNow, {
      endpoints: mock.endpoints,
      onSessionConfirmed: (updated, delta) => {
        if (blockCookieSave) throw new Error("transient lock timeout");
        return svc.personalWeb.loginStore.saveIfSessionMatches(updated, delta);
      },
    });
    mock.setOnChatMode(() => {
      mock.setGatewayRotateCookie("session=sess_r7_rot_on_send; Path=/");
      blockCookieSave = true;
    });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = rotFailClient;
    try {
      await assert.rejects(
        () => svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9510", message_id: "r7_reply_orig", text: "好的收到", cid: "cid_r7_rot_send" }),
        /持久化.*失败/,
      );
    } finally {
      mock.setOnChatMode(undefined);
      mock.setGatewayRotateCookie("");
    }
    assert.equal(mock.sentReplies.length, sendsBeforeRot + 1, "第一次发包已送达服务端");
    const savedRecAfterCookieFail = JSON.parse(app.store.get("pw.delivery.cid_r7_rot_send") ?? "null") as { state?: string; reply_id?: string } | null;
    assert.equal(savedRecAfterCookieFail?.state, "created", "即使 Cookie 落盘报错，也必须先持久化 created 与 reply_id 而非滞留 sending");
    assert.ok(savedRecAfterCookieFail?.reply_id, "必须已保存服务端返回的 reply_id");
    // 解除锁故障后重试：只走独立回读确认，绝不重发第二条消息
    blockCookieSave = false;
    const recoveredReply = await svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9510", message_id: "r7_reply_orig", text: "好的收到", cid: "cid_r7_rot_send" });
    assert.equal(recoveredReply.replyId, savedRecAfterCookieFail?.reply_id);
    assert.equal(mock.sentReplies.length, sendsBeforeRot + 1, "重试必须仅回读确认，绝不重复发包");
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;

    // 13) [R7 P2-16] Drafter.effectFor 拒绝向已撤回（withdrawn）观测发起新发送，但保留对已 created 回复的只读回读恢复
    svc.store.addObs([
      {
        id: "pw:r7_draft_target",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9511",
        conv_name: "范围外群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@张三 原始提问",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r7_draft_target", native_chat_id: "9511", native_root_id: "r7_draft_target", chat_type: "group", at_me: true },
      },
    ]);
    const { item: drfItem } = svc.store.upsertItem({ title: "待撤回草稿事项", kind: "ask_me", priority: "high", source: "im" });
    svc.store.addEvidence("item", drfItem.id, "pw:r7_draft_target", "原始提问", now);
    const proposedDraft = svc.store.addDraft({
      item_id: drfItem.id,
      project_id: "",
      kind: "reply",
      target: {
        transport: "personal_web",
        obs_id: "pw:r7_draft_target",
        native_owner_id: "7001",
        native_chat_id: "9511",
        native_message_id: "r7_draft_target",
        native_root_id: "r7_draft_target",
      },
      target_label: "回复王五",
      content: "马上处理",
    });
    // 原消息被编辑移除 @我 -> withdrawn=true
    svc.store.retirePendingObs("pw:r7_draft_target");
    assert.throws(
      () => svc.drafter.effectFor(proposedDraft, "马上处理"),
      /撤回|移出/,
      "尚未发出的草稿在目标观测被撤回后必须拒绝发送",
    );
    // 但若此前已经创建过 reply（state=created），仍允许回读恢复
    const { cid: recovCid, textHash: recovHash } = computePwReplyCid({
      draft_id: proposedDraft.id,
      owner_id: "7001",
      chat_id: "9511",
      message_id: "r7_draft_target",
      text: "马上处理",
    });
    app.store.set(
      `pw.delivery.${recovCid}`,
      JSON.stringify({ cid: recovCid, state: "created", owner_id: "7001", chat_id: "9511", message_id: "r7_draft_target", root_id: "r7_draft_target", parent_id: "r7_draft_target", reply_id: "sent_r7_recov", text_hash: recovHash, updated_at: now }),
    );
    assert.equal(svc.drafter.effectFor(proposedDraft, "马上处理").op, "pw.reply", "已创建的回复即使原观测后续被撤回仍须允许只读回读恢复");

    // 14) [R7 P2-18] 范围外 @我 经「已处理 → 编辑去掉 @我 → 恢复原文本 @我」后，edit_gen 递增并调度全新的 fast 作业；重复推送原样去重
    const revertMsgOrig = buildNativeMessage({
      id: "r7_revert_1",
      chatId: "9512",
      actorId: "7002",
      createdAtSec: nowSec,
      richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 原封不动的请求" }]),
    });
    const revertMsgNoAt = buildNativeMessage({
      id: "r7_revert_1",
      chatId: "9512",
      actorId: "7002",
      createdAtSec: nowSec,
      text: "暂时去掉了提及",
    });
    mock.addMessage("r7_revert_1", revertMsgOrig);
    mock.setChatKind("9512", CHAT_KIND_GROUP);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgOrig, "7001"), client);
    const fastWorks1 = app.ledger.list({ kinds: ["context"], limit: 50 }).filter((w) => w.id.includes("pw:r7_revert_1"));
    assert.equal(fastWorks1.length, 1);
    const firstFastId = fastWorks1[0].id;
    // 把第一次 fast 作业标为终态，再重复投递完全相同的推送 -> edit_gen 不变，不产生新作业
    app.ledger.db.prepare("UPDATE work SET state = 'done', terminal = 1 WHERE id = ?").run(firstFastId);
    svc.store.markProcessed(["pw:r7_revert_1"]);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgOrig, "7001"), client);
    assert.equal(
      app.ledger.list({ kinds: ["context"], limit: 50 }).filter((w) => w.id.includes("pw:r7_revert_1")).length,
      1,
      "重复推送未变更消息绝不产生重复 fast 作业",
    );
    // 编辑移除 @我 -> withdrawn + edit_gen 递增
    mock.addMessage("r7_revert_1", revertMsgNoAt);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgNoAt, "7001"), client);
    // 再编辑恢复回一字不差的原 @我 文本 -> edit_gen 再度递增，必须生成全新 fastWorkId 入队！
    mock.addMessage("r7_revert_1", revertMsgOrig);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgOrig, "7001"), client);
    const fastWorksAfterRevert = app.ledger.list({ kinds: ["context"], limit: 50 }).filter((w) => w.id.includes("pw:r7_revert_1"));
    assert.equal(fastWorksAfterRevert.length, 2, "撤回后再恢复完全相同的 @我 文本必须生成新的 fast 作业立即触发快通道");
    assert.notEqual(fastWorksAfterRevert.find((w) => w.id !== firstFastId)?.id, firstFastId);

    // 15) [R7 P1-2] 诊断读取主人隔离：owner.open_id 变更后，Q.stepLog 拒绝读取上下文步骤日志、views.status 脱敏 ctx.last_error、Q.health 脱敏上下文 effect
    const ctxStepLog = path.join(dir, "runs", "context-r7-secret.log");
    fs.writeFileSync(ctxStepLog, "## prompt\n主人 A 的私密飞书聊天记录\n");
    const stepId = app.ledger.startStep({ work_id: "context:cycle:r7-diag", name: "understand", harness: "codex", log: ctxStepLog });
    app.ledger.endStep(stepId, "ok", "done");
    app.store.set("ctx.last_error", "模型输出片段：主人 A 的机密议题");
    app.ledger.enqueue({
      id: "fx:r7-health-secret",
      kind: "effect",
      ref: "ctx-draft:drf_secret",
      state: "pending",
      payload: { op: "pw.reply", args: { owner_id: "7001", chat_id: "9511", message_id: "m1", text: "秘密回复", draft_id: "drf_secret" } },
    });
    app.ledger.db.prepare("UPDATE work SET state = 'dead', terminal = 1, error = ? WHERE id = ?").run("发往机密群失败：原消息内容", "fx:r7-health-secret");

    app.cfg.owner.open_id = "ou_owner_b";
    assert.throws(() => Q.stepLog(app!, stepId, 0), /owner\.open_id|不一致/, "主人变更后 Q.stepLog 必须阻断读取旧主人的上下文步骤日志");
    const safeStatus = app.ext.context!.status();
    assert.ok(!safeStatus.last_error.includes("机密议题"), "主人变更后 status() 绝不能返回包含模型输出的原始 ctx.last_error");
    assert.equal(safeStatus.personal_web?.owner_name, "", "主人变更后 status() 不得暴露旧主人昵称");
    assert.equal(safeStatus.totals.open_items, 0, "主人变更后 status() 统计必须归零脱敏");
    const safeHealth = Q.health(app);
    const ctxHealthRow = safeHealth.failed.find((x) => x.id === "fx:r7-health-secret");
    assert.ok(ctxHealthRow, "健康页可保留脱敏后的故障占位");
    assert.ok(!ctxHealthRow!.error.includes("机密群") && !ctxHealthRow!.summary.includes("秘密回复"), "主人变更后 health() 必须脱敏上下文 effect 的摘要与错误");
    app.cfg.owner.open_id = "ou_owner_a";
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    app?.store.db.close();
    await mock.close();
  }
});

test("Codex 第八轮回归：挂载命名空间密钥隔离、草稿范围过滤、精确输入复核、发包前撤回复检、选群变更重启轮询、URL/重复键/凭据存储/点号供应商/错误脱敏、审计与派单主人隔离、@我预筛、共享选群榜单、路径绑定恢复、同会话轮换唤醒、快通道取消与元数据失效", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  try {
    // 1) [R8 P1-1] 挂载命名空间隔离 feishu-web-key：即使子进程按原 CREDENTIALS_DIRECTORY 绝对路径读取也读不到密钥，同时无关凭据仍可读；无隔离后端时 fail-closed
    const isoCredDir = makeTmp("pa-r8-iso-creds-");
    const isoKeyFile = path.join(isoCredDir, "feishu-web-key");
    const isoOtherFile = path.join(isoCredDir, "other-service-token");
    fs.writeFileSync(isoKeyFile, "SUPER_SECRET_FEISHU_KEY_R8", { mode: 0o400 });
    fs.writeFileSync(isoOtherFile, "KEEP_OTHER_TOKEN_R8", { mode: 0o400 });
    assert.throws(
      () => wrapCredentialIsolatedCommand("sh", ["-c", "true"], { CREDENTIALS_DIRECTORY: isoCredDir }, { forceBackend: { kind: "none" } }),
      /bwrap|unshare|拒绝执行/,
      "无挂载命名空间后端时必须 fail-closed 拒绝启动子进程",
    );
    const wrappedRead = wrapCredentialIsolatedCommand(
      "sh",
      ["-c", `cat "$1" 2>/dev/null || true; printf "|"; cat "$2" 2>/dev/null || true`, "_", isoKeyFile, isoOtherFile],
      { CREDENTIALS_DIRECTORY: isoCredDir },
    );
    assert.equal(wrappedRead.isolated, true, "存在 feishu-web-key 时必须启用挂载命名空间遮罩");
    const isoRes = await runProcess(wrappedRead.cmd, wrappedRead.args, { timeoutMs: 15_000 });
    assert.equal(isoRes.code, 0, isoRes.stderr);
    const [maskedKeyOut, otherOut] = isoRes.stdout.split("|");
    assert.equal(maskedKeyOut, "", "子进程即使按绝对路径直接 cat CREDENTIALS_DIRECTORY/feishu-web-key 也绝不能读出密钥");
    assert.equal(otherOut, "KEEP_OTHER_TOKEN_R8", "同目录内无关凭据应保持可读");

    // tryGit 在 CREDENTIALS_DIRECTORY 存在 feishu-web-key 时同样自动隔离，且禁用仓库 hooks / external diff 同时保留正常内部 diff
    const testRepo = makeTmp("pa-r8-git-");
    process.env.CREDENTIALS_DIRECTORY = isoCredDir;
    try {
      assert.equal((await tryGit(testRepo, ["init", "-q"])).code, 0);
      fs.writeFileSync(path.join(testRepo, "a.txt"), "line1\n");
      assert.equal((await tryGit(testRepo, ["add", "a.txt"])).code, 0);
      assert.equal((await tryGit(testRepo, ["commit", "-qm", "init"])).code, 0);
      fs.writeFileSync(path.join(testRepo, "a.txt"), "line1\nline2\n");
      const diffRes = await tryGit(testRepo, ["diff", "--no-color"]);
      assert.equal(diffRes.code, 0, diffRes.stderr);
      assert.match(diffRes.stdout, /\+line2/, "禁用 diff.external 后内部 diff 必须正常输出");
    } finally {
      delete process.env.CREDENTIALS_DIRECTORY;
    }

    // 2) [R8 P1-6, P1-7, P2-12, P2-13, P2-14] TOML 重复键拒绝、错误不含原始值、URL 含凭据拒绝、保留 cli_auth_credentials_store、点号供应商内联表编码
    assert.throws(
      () => parseToml('model_provider = "corp"\nmodel_provider = "openai"\n'),
      /重复定义/,
      "重复顶层键必须按 TOML 1.0 规范显式拒绝",
    );
    assert.throws(
      () => parseToml('[model_providers.corp]\nbase_url = "https://a"\n[model_providers.corp]\nbase_url = "https://b"\n'),
      /重复定义/,
      "重复表头必须显式拒绝",
    );
    assert.throws(
      () => parseToml('x = { a = "1", a = "2" }\n'),
      /重复定义/,
      "内联表重复键必须显式拒绝",
    );
    try {
      parseToml("api_token = sk_live_unquoted_secret_r8\n");
      assert.fail("未加引号的非法标量必须报错");
    } catch (err) {
      const msg = (err as Error).message;
      assert.match(msg, /第 1 行/, "解析错误应指出行列位置");
      assert.ok(!msg.includes("sk_live_unquoted_secret_r8"), `TOML 解析错误绝不能回显原始敏感值：${msg}`);
    }

    const r8CodexHome = makeTmp("pa-r8-codex-");
    fs.writeFileSync(
      path.join(r8CodexHome, "config.toml"),
      [
        'cli_auth_credentials_store = "keyring"',
        'model = "gpt-5-dotted"',
        'model_provider = "corp.test"',
        "",
        '[model_providers."corp.test"]',
        'name = "Corp Dotted"',
        'base_url = "https://gw.corp.internal/v1"',
        'wire_api = "responses"',
        'http_headers = { Authorization = "Bearer dotted-secret-r8" }',
      ].join("\n"),
    );
    const dottedCfg = extractSafeCodexProviderConfig({ CODEX_HOME: r8CodexHome }, [], false);
    assert.ok(dottedCfg.args.includes('cli_auth_credentials_store="keyring"'), "必须保留合法的 cli_auth_credentials_store");
    assert.ok(dottedCfg.args.includes('model_provider="corp.test"'));
    const mpInlineArg = dottedCfg.args.find((a) => a.startsWith("model_providers="));
    assert.ok(mpInlineArg && mpInlineArg.includes('"corp.test"'), `点号供应商名必须编码在 TOML 内联表中：${mpInlineArg}`);
    const parsedMp = (parseToml(mpInlineArg!).model_providers as Record<string, Record<string, unknown>>)["corp.test"];
    assert.equal(parsedMp.base_url, "https://gw.corp.internal/v1");
    const dottedAuthVar = (parsedMp.env_http_headers as Record<string, string>).Authorization;
    assert.equal(dottedCfg.extraEnv[dottedAuthVar], "Bearer dotted-secret-r8");
    assert.ok(!dottedCfg.args.some((a) => a.includes("dotted-secret-r8")), "密钥值绝不能进入 argv");

    // URL 含 userinfo / 密钥 query_param 拒绝；非法 -c 值错误不回显原始值；非法 cli_auth_credentials_store 拒绝
    const badUrlHome = makeTmp("pa-r8-badurl-");
    fs.writeFileSync(
      path.join(badUrlHome, "config.toml"),
      'model_provider = "gw"\n[model_providers.gw]\nbase_url = "https://user:topsecret@gw.corp/v1"\n',
    );
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: badUrlHome }, [], false), /凭据|用户信息/);
    fs.writeFileSync(
      path.join(badUrlHome, "config.toml"),
      'model_provider = "gw"\n[model_providers.gw]\nbase_url = "https://gw.corp/v1?api_key=sk-url-leak"\n',
    );
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: badUrlHome }, [], false), /查询参数|凭据/);
    fs.writeFileSync(path.join(badUrlHome, "config.toml"), 'openai_base_url = "https://tok@oai.corp/v1"\n');
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: badUrlHome }, [], false), /凭据|用户信息/);
    fs.writeFileSync(path.join(badUrlHome, "config.toml"), 'cli_auth_credentials_store = "bogus"\n');
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: badUrlHome }, [], false), /cli_auth_credentials_store/);
    try {
      extractSafeCodexProviderConfig({ CODEX_HOME: r8CodexHome }, ["-c", "model_providers.corp.http_headers={ broken = sk_cli_secret_r8"], false);
      assert.fail("非法 -c 表达式必须报错");
    } catch (err) {
      const msg = (err as Error).message;
      assert.ok(!msg.includes("sk_cli_secret_r8"), `无效 -c 错误绝不能回显原始敏感值：${msg}`);
    }

    // 3) [R8 P2-18] 元数据加载期间被登出/替换会话：FeishuWebClient.connect 必须拒绝返回过期客户端
    let confirmSeq = 0;
    await assert.rejects(
      () =>
        FeishuWebClient.connect(
          {
            owner_id: "7001",
            owner_name: "张三",
            session_id: "sess_r8_meta_race",
            cookie_version: 1,
            cookies: [{ name: "session", value: "valid_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
            updated_at: new Date().toISOString(),
          },
          {
            endpoints: mock.endpoints,
            onSessionConfirmed: (updated) => {
              confirmSeq++;
              // 第一次（verifyOwner）通过，第二次（loadWebMetadata 之后）模拟已被登出/换会话返回 null
              return confirmSeq === 1 ? updated : null;
            },
          },
        ),
      /登出|更新/,
      "loadWebMetadata 期间会话被登出或替换时 connect 必须抛错而不是返回过期客户端",
    );

    // 4) [R8 P2-15] 凭据崩溃恢复严格绑定文件路径与 session_id：默认路径 CLI 绝不清除自定义路径常驻进程的 pending 标记
    const recDir = makeTmp("pa-r8-recover-");
    const customCredPath = path.join(recDir, "daemon-custom-cred.json");
    const recAppCfgFile = path.join(recDir, "config.yaml");
    const ctxDir = makeTmp("pa-r8-lark-");
    process.env.CTX_DIR = ctxDir;
    const callsLog = path.join(recDir, "calls.log");
    const harnessScript = path.join(recDir, "fake-r8-harness.mjs");
    const gateFlagFile = path.join(recDir, "r8-gate.flag");
    const enteredFlagFile = path.join(recDir, "r8-entered.flag");
    const responseJsonFile = path.join(recDir, "r8-response.json");
    fs.writeFileSync(responseJsonFile, JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], people: [], conflicts: [] }));
    fs.writeFileSync(
      harnessScript,
      `#!/usr/bin/env node
import fs from "node:fs";
const prompt = fs.readFileSync(0, "utf8");
fs.appendFileSync(${JSON.stringify(callsLog)}, JSON.stringify({ prompt }) + "\\n");
if (fs.existsSync(${JSON.stringify(gateFlagFile)})) {
  fs.writeFileSync(${JSON.stringify(enteredFlagFile)}, "1");
  const deadline = Date.now() + 8000;
  while (fs.existsSync(${JSON.stringify(gateFlagFile)}) && Date.now() < deadline) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
}
if (prompt.includes("草稿") || prompt.includes("答复或进展")) {
  process.stdout.write("收到，我这边马上处理。\\n");
} else {
  process.stdout.write(fs.readFileSync(${JSON.stringify(responseJsonFile)}, "utf8") + "\\n");
}
`,
      { mode: 0o755 },
    );
    fs.writeFileSync(
      recAppCfgFile,
      `
data_dir: ${recDir}
bins:
  lark: ${path.join(STUBS, "ctx-lark")}
  bytedcli: ${path.join(STUBS, "ctx-bytedcli")}
owner:
  open_id: ou_owner_a
harnesses:
  mock_ctx:
    type: codex-exec
    cmd: ${harnessScript}
roles:
  brain: mock_ctx
context:
  enabled: true
  harness: mock_ctx
  groups: allowlist
  max_groups: 5
  groups_allow: ["pw_chat:9801", "oc_r8_mix"]
  groups_deny: []
  sources:
    meego: false
    tasks: false
    im: true
    minutes: false
    calendar: false
    docs: false
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: false
    send_replies: true
    debounce_ms: 0
`,
    );
    app = createApp(loadConfig(recAppCfgFile));
    const svc = new ContextService(app);
    const daemonCredStore = new WebLoginStore(recDir, customCredPath);
    const defaultCredStore = new WebLoginStore(recDir);
    daemonCredStore.stageWithLock((stage) => {
      const staged = stage({
        owner_id: "7001",
        owner_name: "张三",
        session_id: "sess_r8_custom",
        cookie_version: 1,
        cookies: [{ name: "session", value: "custom_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
        updated_at: new Date().toISOString(),
      });
      // 模拟 SQLite 已提交但 rename 之前崩溃
      app!.store.set(
        PENDING_CRED_COMMIT_KV_KEY,
        JSON.stringify({
          file: daemonCredStore.file,
          staged_file: daemonCredStore.stagedFile,
          owner_id: staged.payload.owner_id,
          session_id: staged.payload.session_id,
          at: Date.now(),
        }),
      );
    });
    assert.equal(fs.existsSync(daemonCredStore.stagedFile), true);
    // 默认路径 CLI 进程运行恢复：绝不能清除属于自定义路径的 pending 标记，也不能删除他人 staged 文件
    defaultCredStore.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
    assert.ok(app.store.get(PENDING_CRED_COMMIT_KV_KEY), "不同路径的 CLI 绝不能误清自定义路径的 pending 标记");
    assert.equal(fs.existsSync(daemonCredStore.stagedFile), true, "不同路径的 CLI 绝不能删除他人 staged 文件");
    // 常驻进程按自定义路径启动恢复：必须补全 rename 并清除标记
    daemonCredStore.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
    assert.equal(app.store.get(PENDING_CRED_COMMIT_KV_KEY), "", "目标路径恢复完成后清除 pending 标记");
    assert.equal(daemonCredStore.load()?.session_id, "sess_r8_custom", "已批准登录必须成功恢复到自定义凭据路径");

    // 绑定测试主工作区凭据到默认路径
    const savedLogin = commitWorkspaceLogin(
      app,
      {
        owner_id: "7001",
        owner_name: "张三",
        session_id: "sess_r8_main",
        cookie_version: 1,
        cookies: [{ name: "session", value: "valid_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
        updated_at: new Date().toISOString(),
      },
      { allowUnverifiedOwner: true },
    );
    const client = await FeishuWebClient.connect(savedLogin, {
      endpoints: mock.endpoints,
      onSessionConfirmed: (u, d) => svc.personalWeb.loginStore.saveIfSessionMatches(u, d),
    });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三" }));

    // 5) [R8 P1-2] 回复草稿提示词遵守当前群范围：移除白名单后，即使群里还有普通消息（含 35 条更新普通消息），草稿提示词只包含真实 @我 而绝不包含范围外普通群消息
    app.cfg.context.groups_allow = [];
    const draftObsList: Obs[] = [
      {
        id: "pw:r8_draft_atme",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9801",
        conv_name: "已移除白名单群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now - 40_000,
        text: "@张三 麻烦确认下排期",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r8_draft_atme", native_chat_id: "9801", native_root_id: "r8_draft_atme", chat_type: "group", at_me: true },
      },
      ...Array.from({ length: 35 }, (_, i) => ({
        id: `pw:r8_draft_ord_${i}`,
        source: "im" as const,
        kind: "group",
        conv: "pw_chat:9801",
        conv_name: "已移除白名单群",
        actor_id: "7003",
        actor_name: "赵六",
        is_me: false,
        time: now - 35_000 + i * 500,
        text: `范围外普通敏感消息_${i}`,
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: `r8_draft_ord_${i}`, native_chat_id: "9801", chat_type: "group" },
      })),
    ];
    svc.store.addObs(draftObsList);
    svc.store.markProcessed(draftObsList.map((o) => o.id));
    const { item: draftScopeItem } = svc.store.upsertItem({ title: "确认排期", kind: "ask_me", priority: "high", source: "im" });
    svc.store.addEvidence("item", draftScopeItem.id, "pw:r8_draft_atme", "麻烦确认下排期", now - 40_000);
    fs.writeFileSync(callsLog, "");
    await svc.drafter.forItem(draftScopeItem.id, "reply");
    const draftCalls = fs.readFileSync(callsLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { prompt: string });
    assert.equal(draftCalls.length, 1);
    assert.ok(draftCalls[0].prompt.includes("麻烦确认下排期"), "草稿提示词必须保留合法的触发 @我");
    assert.ok(!draftCalls[0].prompt.includes("范围外普通敏感消息"), "草稿提示词绝不能混入已被移出白名单的普通群消息");

    // 6) [R8 P1-3] 推理期间含普通消息+@我的混合群被移出白名单：validateBeforeApply 逐条复核精确 prompt 输入，整体丢弃本批并保留 @我 待下轮单独重跑
    app.cfg.context.groups_allow = ["oc_r8_mix"];
    svc.store.addObs([
      {
        id: "im:r8_mix_ord",
        source: "im",
        kind: "group",
        conv: "oc_r8_mix",
        conv_name: "混合批次群",
        actor_id: "ou_x",
        actor_name: "某人",
        is_me: false,
        time: now - 10_000,
        text: "普通群消息机密项目X",
        url: "",
        meta: { chat_type: "group" },
      },
      {
        id: "im:r8_mix_atme",
        source: "im",
        kind: "at_me",
        conv: "oc_r8_mix",
        conv_name: "混合批次群",
        actor_id: "ou_y",
        actor_name: "李四",
        is_me: false,
        time: now - 5_000,
        text: "@张三 请看下混合批次提及",
        url: "",
        meta: { chat_type: "group", at_me: true },
      },
    ]);
    fs.writeFileSync(
      responseJsonFile,
      JSON.stringify({
        projects: [{ name: "机密项目X" }],
        items: [{ title: "混合批次事项", kind: "ask_me", project: "机密项目X", priority: "high", evidence: [{ obs_id: "im:r8_mix_atme", quote: "混合批次提及" }] }],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      }),
    );
    fs.writeFileSync(gateFlagFile, "hold");
    fs.rmSync(enteredFlagFile, { force: true });
    const mixPromise = svc.cycle("work:r8-mix-mid-remove");
    await waitUntil(() => fs.existsSync(enteredFlagFile), 5_000);
    // 在模型推理中途将 oc_r8_mix 移出白名单（此时 @我 仍然合法，但同批送入模型的普通消息不再允许！）
    app.cfg.context.groups_allow = [];
    fs.rmSync(gateFlagFile, { force: true });
    const mixRep = await mixPromise;
    assert.equal(mixRep.created, 0, "含现已越界普通消息的混合批次必须整体丢弃，即使批内仍有合法 @我");
    assert.equal(svc.store.findProject("机密项目X"), undefined, "越界混合批次绝不能写入任何派生项目");
    assert.equal(svc.store.obsPending("im:r8_mix_atme"), true, "幸存的合法 @我 必须保留 pending 待下轮干净批次重跑");
    // 下轮重跑：只送 @我，绝不再送普通消息
    fs.writeFileSync(callsLog, "");
    fs.writeFileSync(
      responseJsonFile,
      JSON.stringify({
        projects: [],
        items: [{ title: "干净批次提及事项", kind: "ask_me", priority: "high", evidence: [{ obs_id: "im:r8_mix_atme", quote: "混合批次提及" }] }],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      }),
    );
    const cleanRep = await svc.cycle("work:r8-mix-clean-rerun");
    assert.equal(cleanRep.created, 1);
    const cleanPrompts = fs.readFileSync(callsLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { prompt: string });
    assert.ok(cleanPrompts.every((c) => !c.prompt.includes("普通群消息机密项目X")), "重跑批次绝不能再带入范围外普通消息");
    assert.ok(cleanPrompts.some((c) => c.prompt.includes("混合批次提及")), "重跑批次应干净处理合法 @我");

    // 7) [R8 P2-10] 先按资格筛选再截断 pending 窗口：范围外群前面积压 65 条普通待处理消息，第 66 条 @我 仍能立刻进入常规周期且不带普通消息
    const starveObs: Obs[] = [
      ...Array.from({ length: 65 }, (_, i) => ({
        id: `im:r8_starve_ord_${i}`,
        source: "im" as const,
        kind: "group",
        conv: "oc_r8_starve",
        conv_name: "积压范围外群",
        actor_id: "ou_x",
        actor_name: "某人",
        is_me: false,
        time: now - 100_000 + i * 1000,
        text: `积压普通消息_${i}`,
        url: "",
        meta: { chat_type: "group" },
      })),
      {
        id: "im:r8_starve_atme_66",
        source: "im",
        kind: "at_me",
        conv: "oc_r8_starve",
        conv_name: "积压范围外群",
        actor_id: "ou_y",
        actor_name: "李四",
        is_me: false,
        time: now - 1_000,
        text: "@张三 第66条提及不能被饿死",
        url: "",
        meta: { chat_type: "group", at_me: true },
      },
    ];
    svc.store.addObs(starveObs);
    fs.writeFileSync(callsLog, "");
    fs.writeFileSync(
      responseJsonFile,
      JSON.stringify({
        projects: [],
        items: [{ title: "第66条提及事项", kind: "ask_me", priority: "high", evidence: [{ obs_id: "im:r8_starve_atme_66", quote: "第66条提及" }] }],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      }),
    );
    const starveRep = await svc.cycle("work:r8-starve-66");
    assert.equal(starveRep.created, 1, "65 条旧普通消息绝不能饿死第 66 条真实 @我");
    assert.equal(svc.store.obsPending("im:r8_starve_atme_66"), false);
    const starvePrompts = fs.readFileSync(callsLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { prompt: string });
    assert.ok(starvePrompts.some((c) => c.prompt.includes("第66条提及不能被饿死")));
    assert.ok(starvePrompts.every((c) => !c.prompt.includes("积压普通消息_")), "仅真实 @我 进入提示词，普通消息保持不送模型");

    // 8) [R8 P2-11] 共享生效选群榜单：allowlist 含名称被禁的 A 与正常 B 且 max_groups=1 时，B 不被 A 占坑；spoken 模式下超榜群仅放行 @我
    app.cfg.context.groups = "allowlist";
    app.cfg.context.max_groups = 1;
    app.cfg.context.groups_allow = ["oc_r8_denied_a", "oc_r8_ok_b"];
    app.cfg.context.groups_deny = ["摸鱼"];
    app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r8_denied_a: { name: "全员摸鱼群", at: now }, oc_r8_ok_b: { name: "核心研发群", at: now - 1000 } }));
    const effAllow = selectEffectiveOpenGroups({
      cfg: app.cfg,
      store: svc.store,
      spoken: JSON.parse(app.store.get("ctx.spoken_groups")!),
      now,
    });
    assert.deepEqual(effAllow.map(([id]) => id), ["oc_r8_ok_b"], "名称被排除的 A 不得占掉 B 的 max_groups=1 配额");
    const sampleB: Obs = { id: "im:r8_b_1", source: "im", kind: "group", conv: "oc_r8_ok_b", conv_name: "核心研发群", actor_id: "ou_x", actor_name: "X", is_me: false, time: now, text: "B 群普通消息", url: "", meta: { chat_type: "group" } };
    assert.equal(svc.personalWeb.filterWindowByCurrentScope("oc_r8_ok_b", [sampleB]).length, 1, "B 群在共享选群结果中，普通消息必须通过过滤");

    app.cfg.context.groups = "spoken";
    app.cfg.context.groups_deny = [];
    app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r8_top1: { name: "最热群", at: now }, oc_r8_drop2: { name: "次热群", at: now - 10_000 } }));
    const dropOrd: Obs = { id: "im:r8_drop_ord", source: "im", kind: "group", conv: "oc_r8_drop2", conv_name: "次热群", actor_id: "ou_x", actor_name: "X", is_me: false, time: now, text: "次热群普通消息", url: "", meta: { chat_type: "group" } };
    const dropAt: Obs = { id: "im:r8_drop_at", source: "im", kind: "at_me", conv: "oc_r8_drop2", conv_name: "次热群", actor_id: "ou_x", actor_name: "X", is_me: false, time: now, text: "@张三 次热群提及", url: "", meta: { chat_type: "group", at_me: true } };
    const filteredSpoken = svc.personalWeb.filterWindowByCurrentScope("oc_r8_drop2", [dropOrd, dropAt]);
    assert.deepEqual(filteredSpoken.map((o) => o.id), ["im:r8_drop_at"], "spoken 模式下跌出 top max_groups 的 oc_* 群必须剔除普通消息仅保留 @我");

    // 9) [R8 P1-5] 轮询期间选中群集合变更：allowlist 从 A 变为 B 时重启并只落库 B；连续变更则安全丢弃且不推进 cursor.im.groups
    app.cfg.context.groups = "allowlist";
    app.cfg.context.max_groups = 5;
    app.cfg.context.groups_allow = ["oc_r8_poll_a"];
    app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
    const origLarkRun = app.lark.run.bind(app.lark);
    let pollFlipMode: "once" | "always" = "once";
    let pollFlipCount = 0;
    app.lark.run = async (args: string[], opts?: Parameters<typeof origLarkRun>[1]) => {
      if (args[0] === "im" && args[1] === "+messages-search") return { messages: [] };
      if (args[0] === "im" && args[1] === "+chat-messages-list") {
        const cid = args[args.indexOf("--chat-id") + 1];
        if (pollFlipMode === "once" && cid === "oc_r8_poll_a") {
          app!.cfg.context.groups_allow = ["oc_r8_poll_b"];
          return {
            messages: [{ message_id: "om_r8_poll_a", chat_id: "oc_r8_poll_a", chat_name: "旧群A", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "旧群A消息" }],
          };
        }
        if (pollFlipMode === "once" && cid === "oc_r8_poll_b") {
          return {
            messages: [{ message_id: "om_r8_poll_b", chat_id: "oc_r8_poll_b", chat_name: "新群B", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "新群B消息" }],
          };
        }
        if (pollFlipMode === "always") {
          pollFlipCount++;
          app!.cfg.context.groups_allow = [`oc_r8_churn_${pollFlipCount}`];
          return {
            messages: [{ message_id: `om_r8_churn_${pollFlipCount}`, chat_id: cid, chat_name: "抖动群", chat_type: "group", create_time: String(nowSec), sender: { id: "ou_x", name: "X", sender_type: "user" }, content: "抖动消息" }],
          };
        }
      }
      return origLarkRun(args, opts);
    };
    try {
      const rRestart = await svc.connectors.pullIm();
      assert.equal(rRestart.count, 1);
      assert.equal(svc.store.obs("im:om_r8_poll_a"), undefined, "allowlist 变更后旧群 A 的消息绝不能落库");
      assert.ok(svc.store.obs("im:om_r8_poll_b"), "重启轮询后新群 B 的消息必须完整拉取落库");
      assert.equal(app.store.get("ctx.cursor.chat.oc_r8_poll_a"), undefined, "旧群 A 游标不得推进");
      assert.ok(app.store.get("ctx.cursor.chat.oc_r8_poll_b"), "新群 B 游标应正常推进");

      // 连续两轮都在拉取中变更 allowlist：必须放弃本轮且绝不推进 cursor.im.groups
      app.store.db.prepare("DELETE FROM kv WHERE k LIKE 'ctx.cursor.%'").run();
      pollFlipMode = "always";
      app.cfg.context.groups_allow = ["oc_r8_churn_0"];
      const rChurn = await svc.connectors.pullIm();
      assert.equal(rChurn.count, 0);
      assert.equal(app.store.get("ctx.cursor.im.groups"), undefined, "连续变更放弃本轮时绝不能推进 cursor.im.groups");
      assert.equal(app.store.get("ctx.cursor.im"), undefined);
    } finally {
      app.lark.run = origLarkRun;
    }

    // 10) [R8 P1-4] outbox 发包前二次核验目标未撤回（含 onBeforeSend 竞态）；已 created 的记录仍允许只读回读恢复
    svc.store.addObs([
      {
        id: "pw:r8_outbox_msg",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9802",
        conv_name: "范围外群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@张三 待撤回目标",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r8_outbox_msg", native_chat_id: "9802", native_root_id: "r8_outbox_msg", chat_type: "group", at_me: true },
      },
    ]);
    mock.addMessage(
      "r8_outbox_msg",
      buildNativeMessage({
        id: "r8_outbox_msg",
        chatId: "9802",
        actorId: "7002",
        createdAtSec: nowSec - 10,
        richBytes: encodeRichText([{ text: "@张三", mentionId: "7001" }, { text: " 待撤回目标" }]),
      }),
    );
    mock.setChatKind("9802", CHAT_KIND_GROUP);
    const sendsBeforeWithdrawn = mock.sentReplies.length;
    // 在 sendVerifiedReply 拉取 chatMode 之后、发包前（onBeforeSend）模拟目标消息被编辑撤回
    mock.setOnChatMode(() => {
      svc.store.retirePendingObs("pw:r8_outbox_msg");
    });
    try {
      await assert.rejects(
        () => svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9802", message_id: "r8_outbox_msg", text: "不应发出的回复", cid: "cid_r8_withdrawn_send" }),
        /撤回|移出/,
        "outbox 发包前目标观测已被撤回时必须中止发送",
      );
    } finally {
      mock.setOnChatMode(undefined);
    }
    assert.equal(mock.sentReplies.length, sendsBeforeWithdrawn, "目标撤回后绝不能向飞书发送回复");
    // 已 created 的投递在原消息撤回后仍允许只读回读确认
    mock.addMessage("sent_r8_created_ok", buildNativeMessage({ id: "sent_r8_created_ok", chatId: "9802", actorId: "7001", createdAtSec: nowSec, text: "已发出的回读内容", cid: "cid_r8_created_ok", rootId: "r8_outbox_msg", parentId: "r8_outbox_msg" }));
    const createdTextHash = crypto.createHash("sha256").update("已发出的回读内容").digest("hex");
    app.store.set(
      "pw.delivery.cid_r8_created_ok",
      JSON.stringify({ cid: "cid_r8_created_ok", state: "created", owner_id: "7001", chat_id: "9802", message_id: "r8_outbox_msg", root_id: "r8_outbox_msg", parent_id: "r8_outbox_msg", reply_id: "sent_r8_created_ok", text_hash: createdTextHash, threaded: false, updated_at: now }),
    );
    const readbackOk = await svc.personalWeb.sendVerifiedReply({ owner_id: "7001", chat_id: "9802", message_id: "r8_outbox_msg", text: "已发出的回读内容", cid: "cid_r8_created_ok" });
    assert.equal(readbackOk.replyId, "sent_r8_created_ok");
    assert.equal(mock.sentReplies.length, sendsBeforeWithdrawn, "已 created 记录只做回读确认不重发");

    // 11) [R8 P2-17] fastCycle 在首个异步资格查询期间收到取消信号时，必须立刻中止：不补读、不调模型、不发提醒
    svc.store.addObs([
      {
        id: "pw:r8_fast_cancel",
        source: "im",
        kind: "at_me",
        conv: "pw_chat:9803",
        conv_name: "取消测试群",
        actor_id: "7002",
        actor_name: "王五",
        is_me: false,
        time: now,
        text: "@张三 取消信号测试",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_message_id: "r8_fast_cancel", native_chat_id: "9803", chat_type: "group", at_me: true },
      },
    ]);
    const fastCtrl = new AbortController();
    const origFastCheck = svc.personalWeb.checkConvAllowedForUnderstand.bind(svc.personalWeb);
    const origHydrate = svc.personalWeb.hydrateContext.bind(svc.personalWeb);
    let hydrateCalled = false;
    svc.personalWeb.checkConvAllowedForUnderstand = async (...args) => {
      const res = await origFastCheck(...args);
      fastCtrl.abort();
      return res;
    };
    svc.personalWeb.hydrateContext = async (...args) => {
      hydrateCalled = true;
      return origHydrate(...args);
    };
    fs.writeFileSync(callsLog, "");
    try {
      await assert.rejects(
        () =>
          svc.fastCycle(
            "work:r8-fast-cancel",
            {
              conv: "pw_chat:9803",
              conv_name: "取消测试群",
              trigger_obs_id: "pw:r8_fast_cancel",
              anchor: { id: "r8_fast_cancel", conversationId: "9803", rootId: "", parentId: "", threadId: "", position: 1, createdAtMs: now },
            },
            fastCtrl.signal,
          ),
        /aborted/,
        "首个资格查询期间已中止的 signal 必须立刻中止 fastCycle",
      );
    } finally {
      svc.personalWeb.checkConvAllowedForUnderstand = origFastCheck;
      svc.personalWeb.hydrateContext = origHydrate;
    }
    assert.equal(hydrateCalled, false, "已取消的 fastCycle 不得继续补读历史");
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "已取消的 fastCycle 不得调用模型");

    // 12) [R8 P1-8 & P1-9] 主人变更后隐藏历史 context 审计消息与上下文委派派单（含描述、diff、步骤日志、列表、概览、命令与审计）
    const cfl = svc.store.addConflict({
      project_id: "",
      topic: "机密发布节奏",
      claims: [
        { claim: "主人A私密结论：周五灰度内部客户X", obs_id: "pw:r8_draft_atme", quote: "周五灰度", time: now },
        { claim: "延后到下周一", obs_id: "pw:r8_draft_atme", quote: "下周一", time: now },
      ],
    });
    await app.commands.exec("context.conflict_resolve", { id: cfl.id, choice: 0 }, { source: "web", actor: "owner" });
    // 通过 context.item_delegate 创建上下文派生派单（mock board.createTask + dispatcher.reconcile）
    const origCreateTask = app.board.createTask.bind(app.board);
    const origReconcile = app.dispatcher.reconcile.bind(app.dispatcher);
    let delegatedId = "";
    app.board.createTask = async (t) => {
      const guid = "task_r8_delegated";
      app!.ledger.enqueue({
        id: `dispatch:${guid}:1`,
        kind: "dispatch",
        ref: guid,
        state: "running",
        payload: { guid, summary: t.summary, description: t.description ?? "", harness: "mock_ctx", reviewer: "", verify: "", cwd: "", branch: "", base: "", round: 1, maxRounds: 1, checkpoints: {}, report: "", feedback: "", history: [] },
      });
      return guid;
    };
    app.dispatcher.reconcile = async () => ({ enqueued: 0, cancelled: 0, deferred: 0 });
    try {
      const delRes = await app.commands.exec("context.item_delegate", { id: draftScopeItem.id }, { source: "web", actor: "owner" });
      delegatedId = delRes.target ?? "";
    } finally {
      app.board.createTask = origCreateTask;
      app.dispatcher.reconcile = origReconcile;
    }
    assert.ok(delegatedId.startsWith("dispatch:task_r8_delegated:"));
    const delLogFile = path.join(recDir, "runs", "dispatch-r8-secret.log");
    fs.mkdirSync(path.dirname(delLogFile), { recursive: true });
    fs.writeFileSync(delLogFile, "worker log containing 麻烦确认下排期\n");
    const delStepId = app.ledger.startStep({ work_id: delegatedId, name: "worker#1", harness: "mock_ctx", log: delLogFile });
    app.ledger.endStep(delStepId, "ok", "done");

    // 切换工作区主人为 ou_owner_b：必须全面阻断历史 context 审计与上下文派生派单
    app.cfg.owner.open_id = "ou_owner_b";
    try {
      const auditB = Q.auditViews(app, undefined, 100);
      assert.ok(!auditB.some((a) => a.command.startsWith("context.")), "主人变更后 /api/audit 不得返回历史 context.* 审计消息");
      assert.ok(!auditB.some((a) => a.message.includes("内部客户X")), "主人变更后 /api/audit 绝不能泄漏旧主人冲突结论");
      assert.ok(!auditB.some((a) => a.target === delegatedId), "主人变更后 /api/audit 不得返回上下文派生派单的审计记录");
      assert.ok(!Q.listDispatches(app, {}).some((d) => d.id === delegatedId), "主人变更后派单列表必须隐藏旧主人上下文委派派单");
      assert.ok(!Q.overview(app).running.some((d) => d.id === delegatedId), "主人变更后概览必须隐藏旧主人上下文委派派单");
      await assert.rejects(() => Q.dispatchDetail(app!, delegatedId), /主人隔离|阻断/, "主人变更后 dispatchDetail 必须拒绝读取上下文派单描述");
      await assert.rejects(() => Q.dispatchDiff(app!, delegatedId), /主人隔离|阻断/, "主人变更后 dispatchDiff 必须拒绝访问");
      assert.throws(() => Q.stepLog(app!, delStepId, 0), /主人隔离|阻断/, "主人变更后 stepLog 必须拒绝读取上下文派单的 worker 日志");
      await assert.rejects(() => app!.commands.exec("dispatch.cancel", { id: delegatedId }, { source: "web", actor: "owner" }), /主人隔离|阻断/);
    } finally {
      app.cfg.owner.open_id = "ou_owner_a";
    }

    // 13) [R8 P2-16] 监听进入 needs_login 后，另一进程以相同 owner_id + session_id 写入更高 cookie_version 轮换凭据必须立刻唤醒恢复监听
    const rotMock = await startMockFeishuWebServer();
    try {
      const rotBridge = new PersonalWebBridge(app, svc.store, {
        onFastTrigger: () => undefined,
        onReconnect: () => undefined,
        onNeedsLogin: () => undefined,
        credentialWatchIntervalMs: 30,
        clientOptions: { endpoints: rotMock.endpoints },
      });
      // 先模拟一次 SessionNeedsLoginError 使 supervisor 休眠在 waitForCredentialChange，再以同 owner_id + session_id 写入 cookie_version=2
      const rotLogin = rotBridge.loginStore.save({
        owner_id: "7001",
        owner_name: "张三",
        session_id: "sess_r8_rotate_wake",
        cookie_version: 1,
        cookies: [{ name: "session", value: "expired_v1", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
        updated_at: new Date(Date.now() - 1000).toISOString(),
      });
      const origConnect = FeishuWebClient.connect;
      let connectCalls = 0;
      FeishuWebClient.connect = async (loginArg, opts, sig) => {
        connectCalls++;
        if ((loginArg.cookie_version ?? 1) < 2) {
          throw new SessionNeedsLoginError("cookie expired v1");
        }
        return origConnect.call(FeishuWebClient, loginArg, opts, sig);
      };
      const handle = rotBridge.start();
      try {
        await waitUntil(() => rotBridge.status().state === "needs_login" && connectCalls >= 1, 4_000);
        // 另一进程同会话轮换 Cookie（相同 owner_id & session_id，更高 cookie_version）
        const merged = rotBridge.loginStore.saveIfSessionMatches(
          {
            ...rotLogin,
            cookies: [{ name: "session", value: "fresh_v2", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
            updated_at: new Date().toISOString(),
          },
          {
            upserts: [{ name: "session", value: "fresh_v2", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
            deletes: [],
            baseValues: { "session\0internal-api-lark-api.feishu.cn\0/": "expired_v1" },
          },
        );
        assert.ok(merged && (merged.cookie_version ?? 0) >= 2, "同会话轮换 Cookie 必须递增 cookie_version");
        await waitUntil(() => rotBridge.status().state === "listening", 4_000);
        assert.ok(connectCalls >= 2, "同会话 cookie_version 递增后必须立即唤醒休眠监听并重新连上");
      } finally {
        handle.stop();
        FeishuWebClient.connect = origConnect;
      }
    } finally {
      await rotMock.close();
    }
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    app?.store.db.close();
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
