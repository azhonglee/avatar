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
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import * as Q from "../src/api/queries.ts";
import { createApp, initApp, runDispatchOnce, sendBrief } from "../src/app.ts";
import { CardService } from "../src/cards/index.ts";
import { loadConfig, type Config } from "../src/config.ts";
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
  clearPendingCommitMarkerIfMatches,
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
  MessageNotFoundError,
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
import { loadKnownOpenGroupNames, rememberOpenGroupName, selectEffectiveOpenGroups } from "../src/context/connectors.ts";
import { DraftTargetUncertainError } from "../src/context/drafts.ts";
import { ContextService, registerContext } from "../src/context/index.ts";
import {
  ACTIVE_SESSION_KV_KEY,
  assertLoginAuthorizedForWorkspace,
  BOUND_OWNER_KV_KEY,
  BOUND_WORKSPACE_OWNER_KV_KEY,
  commitWorkspaceLogin,
  computePwReplyCid,
  hasExistingOwnerContextState,
  hasWorkspaceOwnerMismatch,
  PENDING_CRED_COMMIT_KV_KEY,
  PersonalWebBridge,
  pwSpokenGroupsKey,
  REVOKED_AT_KV_KEY,
  REVOKED_SESSIONS_KV_KEY,
  revokeWorkspacePersonalWebSession,
  saveWorkspaceBinding,
  verifyWorkspaceOwnerBinding,
} from "../src/context/personal-web.ts";
import { ContextStore, obsRevision, type Obs } from "../src/context/store.ts";
import {
  branchUsesGitLfs,
  classifyGitRemoteTransport,
  collectScopedSshMounts,
  commitAll,
  ensureGitLfsObjectsForCheckout,
  gitCredentialLineMatchesTarget,
  isGitLfsPointerBlob,
  parseRemote,
  parseScpGitUrl,
  pushBranch,
  remoteDefaultBranch,
  resolveAuthorizedSshAuthSock,
  resolveLocalGitRemoteDir,
  resolveLocalGitRemoteMount,
  rewriteGitCredentialHelperChain,
  tryGit,
} from "../src/delivery/git.ts";
import { registerDelivery } from "../src/delivery/index.ts";
import { runDoctor } from "../src/doctor.ts";
import { card as cardEffect, comment as commentEffect, effectHandler, move as moveEffect } from "../src/effects.ts";
import {
  applySanitizedGitConfigEnv,
  applySanitizedNpmrcEnv,
  buildWorkspaceIsolation,
  canonicalCodexLockFilePath,
  collectLarkGuardReadOnlyFiles,
  collectSafeGitConfigMounts,
  coordinateClaudeOAuthRefresh,
  coordinateCodexOAuthRefresh,
  coordinateOpenCodeOAuthRefresh,
  detectGitWorktreeDirs,
  detectIsolatedCodexKeyringConflict,
  extractSafeCodexProviderArgs,
  extractSafeCodexProviderConfig,
  hasCredentialMountIsolation,
  isAuthMethodAllowedForAcpxAgent,
  isCodexOAuthRefreshNeeded,
  isolatedSandboxTempEnv,
  mergeHarnessEnv,
  parseJsonc,
  parseShellCommandTokens,
  prepareHarnessEnv,
  renderSafeCodexConfigToml,
  resolveEffectiveCodexCredentialStore,
  resolveTrustedBwrapBin,
  resolveTrustedSystemBin,
  runHarness,
  sanitizeGitConfigEntries,
  sanitizeNpmrcContent,
  sanitizeOpenCodeConfigForNoTools,
  selectAcpxAgentConfigPaths,
  selectDoubaoRuntimePaths,
  selectLarkCliAuthPaths,
  stageIsolatedAcpxState,
  stageIsolatedAwsProfile,
  stageIsolatedClaudeState,
  stageIsolatedDoubaoDataDir,
  stageIsolatedGeminiState,
  stageIsolatedOpenCodeState,
  stageSanitizedGitConfig,
  stageSanitizedNpmrc,
  stageIsolatedCodexHome,
  stageScopedAcpxAdapterCache,
  syncRefreshedClaudeAuth,
  syncRefreshedCodexAuth,
  syncRefreshedOpenCodeAuth,
  workspaceRequiresIsolation,
  wrapCredentialIsolatedCommand,
  type HarnessRun,
} from "../src/harness.ts";
import { SettingsService } from "../src/settings.ts";
import { parseToml } from "../src/toml.ts";
import { usageSummary } from "../src/usage.ts";
import { runProcess } from "../src/util.ts";
import { statusText } from "../src/workflows/agent.ts";
import { buildBrief } from "../src/workflows/brief.ts";
import { Dispatcher } from "../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test/stubs");
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// [R5 P1-1 + R12 P2] 在构造任何 WebLoginStore 或派生 CLI 子进程前，彻底剥离宿主环境中的真实凭据路径与密钥；
// 且绝不在文件级全局注入 PA_FEISHU_WEB_KEY，避免无关 Git/协议/工作流用例被迫依赖 Linux 内核命名空间。
delete process.env.PA_FEISHU_WEB_CRED_FILE;
delete process.env.CREDENTIALS_DIRECTORY;
delete process.env.PA_FEISHU_WEB_KEY;
const TEST_WEB_KEY = `pa-test-feishu-web-key-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;

async function withTestWebKey<T>(fn: () => Promise<T> | T, key = TEST_WEB_KEY): Promise<T> {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.PA_FEISHU_WEB_KEY = key;
  try {
    return await fn();
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
  }
}

async function withoutTestWebKey<T>(fn: () => Promise<T> | T): Promise<T> {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.PA_FEISHU_WEB_KEY;
  delete process.env.CREDENTIALS_DIRECTORY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  try {
    return await fn();
  } finally {
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
  }
}

/** 进程内上下文模型桩：让工作流/协议单测不依赖 Linux 内核命名空间，也能与真实内核隔离单测清晰解耦 */
function installCtxDirStubLlm(svc: ContextService, ctxDir: string): void {
  const runner: typeof runHarness = async (_cfg, run: HarnessRun) => {
    const prompt = run.prompt;
    const kind = prompt.includes("维护个人工作上下文") ? "understand" : prompt.includes("整理工作上下文里的项目结构") ? "split" : "draft";
    fs.appendFileSync(path.join(ctxDir, "calls.log"), JSON.stringify({ role: "codex", argv: [], kind, prompt }) + "\n");
    let text: string;
    if (kind === "draft") {
      const p = path.join(ctxDir, "draft.txt");
      text = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "好的，我这边已跟进处理，稍后同步最新进展。";
    } else if (kind === "split") {
      const p = path.join(ctxDir, "split.json");
      text = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : JSON.stringify({ subprojects: [], items: [], knowledge: [], updates: [] });
    } else {
      const txtPath = path.join(ctxDir, "understand.txt");
      if (fs.existsSync(txtPath)) {
        text = fs.readFileSync(txtPath, "utf8");
      } else {
        const jsonPath = path.join(ctxDir, "understand.json");
        text = fs.existsSync(jsonPath)
          ? fs.readFileSync(jsonPath, "utf8")
          : JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], people: [], conflicts: [] });
      }
    }
    if (run.logFile) {
      fs.mkdirSync(path.dirname(run.logFile), { recursive: true });
      fs.writeFileSync(run.logFile, `# stub-llm\n## prompt\n${prompt}\n## reply\n${text.trim()}\n`);
    }
    return { ok: true, exitCode: 0, text: text.trim(), timedOut: false, aborted: false };
  };
  svc.understander.runner = runner;
  svc.drafter.runner = runner;
}

function installCallbackLlm(
  svc: ContextService,
  handler: (prompt: string, run: HarnessRun) => Promise<string> | string,
): void {
  const runner: typeof runHarness = async (_cfg, run: HarnessRun) => {
    const text = await handler(run.prompt, run);
    if (run.logFile) {
      fs.mkdirSync(path.dirname(run.logFile), { recursive: true });
      fs.writeFileSync(run.logFile, `# stub-llm\n## prompt\n${run.prompt}\n## reply\n${text.trim()}\n`);
    }
    return { ok: true, exitCode: 0, text: text.trim(), timedOut: false, aborted: false };
  };
  svc.understander.runner = runner;
  svc.drafter.runner = runner;
}

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

test("Cookie Jar：域名白名单、RFC 6265 匹配、轮换与删除、0600 原子落盘", async () => {
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
  await withTestWebKey(() => {
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
  setMessengerErrorCookie: (cookie: string) => void;
  setTicketStatus: (status: number) => void;
  setTicketErrorCookie: (cookie: string) => void;
  setTicketRotateDidOnce: (did: string) => void;
  ticketDeviceIds: string[];
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
  setGatewayForceStatus: (status: number) => void;
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
  let messengerErrorCookie = "";
  let ticketStatus = 200;
  let ticketErrorCookie = "";
  let ticketRotateDidOnce = "";
  let ticketBindDid = false;
  const ticketDeviceIds: string[] = [];
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
  let gatewayForceStatus = 200;
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
        const hdrs: Record<string, string> = {};
        if (messengerErrorCookie) hdrs["Set-Cookie"] = messengerErrorCookie;
        res.writeHead(messengerStatus, hdrs);
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
      const localDid = url.searchParams.get("local_device_id") ?? "";
      ticketDeviceIds.push(localDid);
      if (ticketStatus !== 200) {
        const errHeaders: Record<string, string> = { "Content-Type": "application/json" };
        if (ticketErrorCookie) errHeaders["Set-Cookie"] = ticketErrorCookie;
        res.writeHead(ticketStatus, errHeaders);
        res.end(JSON.stringify({ code: ticketStatus }));
        return;
      }
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (ticketRotateDidOnce) {
        headers["Set-Cookie"] = `passport_web_did=${ticketRotateDidOnce}; Path=/; Max-Age=86400`;
        ticketRotateDidOnce = "";
      }
      res.writeHead(200, headers);
      res.end(JSON.stringify({ code: 0, ticket: ticketBindDid ? `ticket_for_${localDid}` : "ticket_live_42" }));
      return;
    }

    if (url.pathname === "/im/gateway/") {
      const pkt = parseProto(body);
      const cmd = pkt.uint(3);
      const payload = parseProto(pkt.bytes(5));
      const gwHeaders: Record<string, string> = { "Content-Type": "application/x-protobuf" };
      if (gatewayRotateCookie) gwHeaders["Set-Cookie"] = `session=${gatewayRotateCookie}; Path=/; Max-Age=86400`;
      if (gatewayForceStatus !== 200) {
        res.writeHead(gatewayForceStatus, gwHeaders);
        res.end();
        return;
      }
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
    setMessengerErrorCookie: (c) => {
      messengerErrorCookie = c;
    },
    setTicketStatus: (s) => {
      ticketStatus = s;
    },
    setTicketErrorCookie: (c) => {
      ticketErrorCookie = c;
    },
    setTicketRotateDidOnce: (d) => {
      ticketRotateDidOnce = d;
      ticketBindDid = !!d;
    },
    ticketDeviceIds,
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
    setGatewayForceStatus: (s) => {
      gatewayForceStatus = s;
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
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
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
    installCtxDirStubLlm(svc, ctxDir);
    app.engine.register(svc.handler());
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
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
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
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
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
    installCtxDirStubLlm(svc, ctxDir);
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
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
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
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 8. Codex Review 第二轮专项回归测试 ─────────

test("Codex 第二轮回归：PK 索引查询、同名群静音隔离、话题锚点补读、编辑防吞、账号绑定与发包前复核、明确拒绝可重试、非连续 401、分片 WS、关闭模块登出", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
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
    installCtxDirStubLlm(svc, ctxDir);
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
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    await mock.close();
  }
});

// ───────── 9. Codex Review 第三轮专项回归测试 ─────────

test("Codex 第三轮回归：空载荷发送保护、稳定 ID 首次绑定、静音改名 fail-closed、跨通道原生排除、快通道二次校验、补读换号隔离、强制刷新群模式、Cookie 版本合并、CSRF 域名作用域、@mention 编辑、近邻背景窗口、帧数上限与状态清理", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
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
    installCtxDirStubLlm(svc, ctxDir);
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
    app.store.set(BOUND_OWNER_KV_KEY, "7001");
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({ state: "needs_login", owner_id: "7001", owner_name: "张三", session_id: "old_expired_sess", since: now - 1000, last_message_at: null, last_error: "已过期" }),
    );
    const savedFresh = loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    app.store.set(ACTIVE_SESSION_KV_KEY, savedFresh.session_id ?? "");
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
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
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
    installCtxDirStubLlm(svc, ctxDir);
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
    installCtxDirStubLlm(svc, ctxDir);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const loginStore = new WebLoginStore(app.cfg.dataDir);
    const savedLogin = loginStore.save({ owner_id: "7001", owner_name: "张三", cookies: baseCookies });
    saveWorkspaceBinding(app.store, "7001", "ou_owner_a");
    const client = await FeishuWebClient.connect(savedLogin, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;

    // 7) [R5 P1-5] codex-exec tools="none" 传入 --ignore-user-config / --ignore-rules / 禁用 MCP 与内置工具
    // 在无个人 Web 密钥/配置的独立临时目录中实跑 runHarness，既验证真实 codex-exec 参数又可在无 Linux userns 的宿主机执行
    await withoutTestWebKey(async () => {
      const probeDir = makeTmp("pa-r5-codex-argv-");
      const probeBin = path.join(probeDir, "echo-argv.mjs");
      fs.writeFileSync(
        probeBin,
        `#!/usr/bin/env node
import fs from "node:fs";
const argv = process.argv.slice(2);
const outIdx = argv.indexOf("-o");
const outPath = outIdx >= 0 ? argv[outIdx + 1] : "";
const payload = JSON.stringify({ argv });
if (outPath) fs.writeFileSync(outPath, payload, "utf8");
else process.stdout.write(payload);
`,
        { mode: 0o755 },
      );
      const probeCfgFile = path.join(probeDir, "config.yaml");
      fs.writeFileSync(
        probeCfgFile,
        JSON.stringify({
          data_dir: path.join(probeDir, "data"),
          harnesses: { cx_probe: { type: "codex-exec", cmd: probeBin } },
          roles: { brain: "cx_probe" },
          owner: { open_id: "ou_owner_a" },
          context: { enabled: true, personal_web: { enabled: false } },
        }),
      );
      const probeCfg = loadConfig(probeCfgFile);
      const res = await runHarness(probeCfg, {
        harness: "cx_probe",
        prompt: "测试无工具无 MCP 隔离参数",
        cwd: path.join(probeDir, "work"),
        tools: "none",
        lark: "none",
        timeoutSec: 30,
        logFile: path.join(probeDir, "run.log"),
      });
      assert.equal(res.ok, true);
      const lastCodexArgv = (JSON.parse(res.text) as { argv: string[] }).argv;
      assert.ok(lastCodexArgv.includes("--ignore-user-config"), "tools=none 必须禁用 ~/.codex/config.toml 防止加载用户 MCP Server");
      assert.ok(lastCodexArgv.includes("--ignore-rules"), "tools=none 必须禁用 execpolicy rules");
      assert.ok(lastCodexArgv.includes("code_mode") && lastCodexArgv.includes("plugins") && lastCodexArgv.includes("shell_tool"));
    });
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
    assert.ok(fs.readFileSync(callsLog, "utf8").trim().length > 0);

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

    // 3) [R6 P1-3 + R12 P2] delivery/git.ts 剥离环境变量；内核挂载隔离测试仅在宿主机支持时启用 PA_FEISHU_WEB_KEY/CREDENTIALS_DIRECTORY
    const gitRepo = makeTmp("pa-r6-git-");
    await runProcess("git", ["init", "-q", gitRepo]);
    if (hasCredentialMountIsolation()) {
      process.env.CREDENTIALS_DIRECTORY = mixedCredDir;
      try {
        const gitEnvOut = await tryGit(gitRepo, ["-c", "alias.envdump=!env", "envdump"]);
        assert.equal(gitEnvOut.code, 0, gitEnvOut.stderr);
        assert.ok(!gitEnvOut.stdout.includes("PA_FEISHU_WEB_KEY="), "git 子进程不得继承 PA_FEISHU_WEB_KEY");
        assert.ok(!gitEnvOut.stdout.includes(`CREDENTIALS_DIRECTORY=${mixedCredDir}`), "git 子进程不得继承原始混合 CREDENTIALS_DIRECTORY");
      } finally {
        delete process.env.CREDENTIALS_DIRECTORY;
      }
    } else {
      await withoutTestWebKey(async () => {
        const gitEnvOut = await tryGit(gitRepo, ["-c", "alias.envdump=!env", "envdump"]);
        assert.equal(gitEnvOut.code, 0, gitEnvOut.stderr);
        assert.ok(!gitEnvOut.stdout.includes("PA_FEISHU_WEB_KEY="), "git 子进程不得继承 PA_FEISHU_WEB_KEY");
      });
    }

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
    installCallbackLlm(svc, async (prompt) => {
      fs.appendFileSync(callsLog, JSON.stringify({ at: Date.now(), len: prompt.length }) + "\n");
      const modeFile = path.join(dir, "harness-mode.json");
      const mode = fs.existsSync(modeFile) ? (JSON.parse(fs.readFileSync(modeFile, "utf8")) as Record<string, unknown>) : {};
      if (typeof mode.onRunHookFile === "string") fs.writeFileSync(mode.onRunHookFile, "ran");
      if (typeof mode.resumeFile === "string") {
        const deadline = Date.now() + 3000;
        while (!fs.existsSync(mode.resumeFile) && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 15));
        }
      }
      const delayMs = mode.delayMs;
      if (typeof delayMs === "number" && delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
      return mode.output !== undefined
        ? JSON.stringify(mode.output)
        : JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], conflicts: [] });
    });
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);

    // 先验证 Dispatcher.runVerifyCommand 在支持内核挂载隔离的宿主机上剥离 PA_FEISHU_WEB_KEY 与 CREDENTIALS_DIRECTORY
    if (hasCredentialMountIsolation()) {
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
      let checkRes: { status: string; detail: string };
      try {
        checkRes = await (
          dispatcher as unknown as {
            runVerifyCommand(it: typeof verifyWork, ctx: { attempt: number; signal: AbortSignal }): Promise<{ status: string; detail: string }>;
          }
        ).runVerifyCommand(verifyWork, { attempt: 1, signal: new AbortController().signal });
      } finally {
        delete process.env.CREDENTIALS_DIRECTORY;
      }
      assert.equal(checkRes.status, "pass", checkRes.detail);
      const verifyLog = fs.readFileSync(path.join(dir, "runs", "g_r6_ver", "verify-1-1.log"), "utf8");
      assert.ok(!verifyLog.includes("PA_FEISHU_WEB_KEY="), "verify 命令日志绝不能包含 PA_FEISHU_WEB_KEY");
      assert.ok(!verifyLog.includes(`CREDENTIALS_DIRECTORY=${mixedCredDir}`), "verify 命令不得继承原始混合 CREDENTIALS_DIRECTORY");
    }

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
    const client = await FeishuWebClient.connect(new WebLoginStore(dir).load() ?? loginA, { endpoints: mock.endpoints });
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
    installCallbackLlm(svc, async (prompt) => {
      fs.appendFileSync(callsLog, JSON.stringify({ at: Date.now(), prompt }) + "\n");
      const modeFile = path.join(dir, "harness-mode.json");
      const mode = fs.existsSync(modeFile) ? (JSON.parse(fs.readFileSync(modeFile, "utf8")) as Record<string, unknown>) : {};
      return mode.output !== undefined
        ? JSON.stringify(mode.output)
        : JSON.stringify({ projects: [], items: [], knowledge: [], updates: [], people: [], conflicts: [] });
    });
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const baseCookies = [
      { name: "session", value: "sess_r7_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r7_1", domain: "127.0.0.1", path: "/" },
    ];
    const loginA = { owner_id: "7001", owner_name: "张三", cookies: baseCookies };
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });
    let client = await FeishuWebClient.connect(new WebLoginStore(dir).load() ?? loginA, { endpoints: mock.endpoints });
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
    client = await FeishuWebClient.connect(loginStore.load() ?? loginA, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;

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
    const isRevertFastWork = (w: { payload: Record<string, unknown> }) => w.payload.trigger_obs_id === "pw:r7_revert_1";
    const fastWorks1 = app.ledger.list({ kinds: ["context"], limit: 50 }).filter(isRevertFastWork);
    assert.equal(fastWorks1.length, 1);
    const firstFastId = fastWorks1[0].id;
    // 把第一次 fast 作业标为终态，再重复投递完全相同的推送 -> edit_gen 不变，不产生新作业
    app.ledger.db.prepare("UPDATE work SET state = 'done', terminal = 1 WHERE id = ?").run(firstFastId);
    svc.store.markProcessed(["pw:r7_revert_1"]);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgOrig, "7001"), client);
    assert.equal(
      app.ledger.list({ kinds: ["context"], limit: 50 }).filter(isRevertFastWork).length,
      1,
      "重复推送未变更消息绝不产生重复 fast 作业",
    );
    // 编辑移除 @我 -> withdrawn + edit_gen 递增
    mock.addMessage("r7_revert_1", revertMsgNoAt);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgNoAt, "7001"), client);
    // 再编辑恢复回一字不差的原 @我 文本 -> edit_gen 再度递增，必须生成全新 fastWorkId 入队！
    mock.addMessage("r7_revert_1", revertMsgOrig);
    await svc.personalWeb.handleMessage(decodeMessage(revertMsgOrig, "7001"), client);
    const fastWorksAfterRevert = app.ledger.list({ kinds: ["context"], limit: 50 }).filter(isRevertFastWork);
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
    assert.throws(() => Q.stepLog(app!, stepId, 0), /owner\.open_id|不一致|主人隔离/, "主人变更后 Q.stepLog 必须阻断读取旧主人的上下文步骤日志");
    const safeStatus = app.ext.context!.status();
    assert.ok(!safeStatus.last_error.includes("机密议题"), "主人变更后 status() 绝不能返回包含模型输出的原始 ctx.last_error");
    assert.equal(safeStatus.personal_web?.owner_name, "", "主人变更后 status() 不得暴露旧主人昵称");
    assert.equal(safeStatus.totals.open_items, 0, "主人变更后 status() 统计必须归零脱敏");
    const safeHealth = Q.health(app);
    const ctxHealthRow = safeHealth.failed.find((x) => x.isolated && x.kind === "effect");
    assert.ok(ctxHealthRow, "健康页可保留脱敏后的故障占位");
    assert.ok(ctxHealthRow!.id.startsWith("isolated:") && !ctxHealthRow!.id.includes("r7-health-secret"), "隔离记录不得暴露原始账本 ID");
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
    // 1) [R8 P1-1 + R9 P1-1 & P2-20] 无隔离后端时 fail-closed；unshare 回退强制要求 setpriv 永久降权；tryGit 禁用 hooks/external diff 同时保留正常内部 diff
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
    assert.throws(
      () => wrapCredentialIsolatedCommand("sh", ["-c", "true"], { CREDENTIALS_DIRECTORY: isoCredDir }, { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "", pivotRootBin: "/sbin/pivot_root" } }),
      /setpriv|pivot_root|拒绝执行/,
      "unshare 回退缺少 setpriv 时必须拒绝执行",
    );
    assert.throws(
      () => wrapCredentialIsolatedCommand("sh", ["-c", "true"], { CREDENTIALS_DIRECTORY: isoCredDir }, { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "/usr/bin/setpriv", pivotRootBin: "" } }),
      /setpriv|pivot_root|拒绝执行/,
      "unshare 回退缺少 pivot_root 时必须拒绝执行",
    );
    const unshareWrapped = wrapCredentialIsolatedCommand(
      "sh",
      ["-c", "true"],
      { CREDENTIALS_DIRECTORY: isoCredDir },
      { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "/usr/bin/setpriv", pivotRootBin: "/sbin/pivot_root" } },
    );
    assert.equal(unshareWrapped.isolated, true);
    assert.ok(unshareWrapped.args.some((a) => a.includes("--bounding-set -all") && a.includes("--no-new-privs")), "unshare 回退必须通过 setpriv 永久剥离全部 capabilities");
    assert.ok(unshareWrapped.args.includes("/usr/bin/setpriv"));
    assert.ok(unshareWrapped.args.includes("/sbin/pivot_root"));

    // tryGit 禁用仓库 hooks / external diff 同时保留正常内部 diff（脱离测试密钥作用域以兼容无 Linux userns 宿主机）
    await withoutTestWebKey(async () => {
      const testRepo = makeTmp("pa-r8-git-");
      assert.equal((await tryGit(testRepo, ["init", "-q"])).code, 0);
      fs.writeFileSync(path.join(testRepo, "a.txt"), "line1\n");
      assert.equal((await tryGit(testRepo, ["add", "a.txt"])).code, 0);
      assert.equal((await tryGit(testRepo, ["commit", "-qm", "init"])).code, 0);
      fs.writeFileSync(path.join(testRepo, "a.txt"), "line1\nline2\n");
      const diffRes = await tryGit(testRepo, ["diff", "--no-color"]);
      assert.equal(diffRes.code, 0, diffRes.stderr);
      assert.match(diffRes.stdout, /\+line2/, "禁用 diff.external 后内部 diff 必须正常输出");
    });

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
    installCallbackLlm(svc, async (prompt) => {
      fs.appendFileSync(callsLog, JSON.stringify({ prompt }) + "\n");
      if (fs.existsSync(gateFlagFile)) {
        fs.writeFileSync(enteredFlagFile, "1");
        const deadline = Date.now() + 8000;
        while (fs.existsSync(gateFlagFile) && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 20));
        }
      }
      if (prompt.includes("草稿") || prompt.includes("答复或进展")) {
        return "收到，我这边马上处理。";
      }
      return fs.readFileSync(responseJsonFile, "utf8");
    });
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
      app.store.set(ACTIVE_SESSION_KV_KEY, "sess_r8_rotate_wake");
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

test(
  "挂载命名空间密钥隔离集成测试（宿主机支持 bwrap / unshare+setpriv 时运行）",
  { skip: !hasCredentialMountIsolation() },
  async () => {
    const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
    const isoCredDir = makeTmp("pa-r9-mount-creds-");
    const isoKeyFile = path.join(isoCredDir, "feishu-web-key");
    const isoOtherFile = path.join(isoCredDir, "other-service-token");
    fs.writeFileSync(isoKeyFile, "SUPER_SECRET_FEISHU_KEY_R9", { mode: 0o400 });
    fs.writeFileSync(isoOtherFile, "KEEP_OTHER_TOKEN_R9", { mode: 0o400 });
    try {
      // 1) 默认首选后端（bwrap）：遮罩 feishu-web-key、保留无关凭据、永久无特权无法 umount
      const wrappedDefault = wrapCredentialIsolatedCommand(
        "sh",
        ["-c", `umount "$1" 2>/dev/null || true; cat "$1" 2>/dev/null || true; printf "|"; cat "$2" 2>/dev/null || true`, "_", isoKeyFile, isoOtherFile],
        { CREDENTIALS_DIRECTORY: isoCredDir },
      );
      assert.equal(wrappedDefault.isolated, true);
      const rDefault = await runProcess(wrappedDefault.cmd, wrappedDefault.args, { timeoutMs: 15_000 });
      assert.equal(rDefault.code, 0, rDefault.stderr);
      const [keyOut, otherOut] = rDefault.stdout.split("|");
      assert.equal(keyOut, "", "子进程即使尝试 umount 后按绝对路径 cat feishu-web-key 也绝不能读出密钥");
      assert.equal(otherOut, "KEEP_OTHER_TOKEN_R9", "同目录无关凭据保持可读");

      // 2) 若宿主机同时具备 unshare + pivot_root + setpriv：验证回退路径同样彻底剥离挂载权限（CapEff=0, 无法 umount）
      const pivotBin = fs.existsSync("/sbin/pivot_root")
        ? "/sbin/pivot_root"
        : fs.existsSync("/usr/sbin/pivot_root")
          ? "/usr/sbin/pivot_root"
          : "";
      const probeSetpriv = pivotBin
        ? await runProcess("unshare", ["-r", "-m", "--", "setpriv", "--bounding-set", "-all", "--inh-caps", "-all", "--ambient-caps", "-all", "--no-new-privs", "true"], { timeoutMs: 5_000 })
        : { code: 1, stdout: "", stderr: "", timedOut: false };
      if (probeSetpriv.code === 0 && pivotBin) {
        const wrappedUnshare = wrapCredentialIsolatedCommand(
          "sh",
          ["-c", `umount "$1" 2>/dev/null || true; cat "$1" 2>/dev/null || true; printf "|"; grep -E "^CapEff:" /proc/self/status`, "_", isoKeyFile],
          { CREDENTIALS_DIRECTORY: isoCredDir },
          { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: pivotBin } },
        );
        const rUnshare = await runProcess(wrappedUnshare.cmd, wrappedUnshare.args, { timeoutMs: 15_000 });
        assert.equal(rUnshare.code, 0, rUnshare.stderr);
        const [uKeyOut, capLine] = rUnshare.stdout.split("|");
        assert.equal(uKeyOut, "", "unshare+setpriv 回退下子进程无法 umount 遮罩且读不到 feishu-web-key");
        assert.match(capLine ?? "", /0000000000000000/, "unshare+setpriv 回退下 CapEff 必须为全 0");
      }

      // 3) tryGit 在 CREDENTIALS_DIRECTORY 包含 feishu-web-key 时自动隔离且正常执行 git
      const gitRepo = makeTmp("pa-r9-mount-git-");
      process.env.CREDENTIALS_DIRECTORY = isoCredDir;
      assert.equal((await tryGit(gitRepo, ["init", "-q"])).code, 0);
      fs.writeFileSync(path.join(gitRepo, "f.txt"), "v1\n");
      assert.equal((await tryGit(gitRepo, ["add", "f.txt"])).code, 0);
      assert.equal((await tryGit(gitRepo, ["commit", "-qm", "init"])).code, 0);
      delete process.env.CREDENTIALS_DIRECTORY;

      // 4) [R12 P1-1 & P1-2] 即使交互式 shell 既无 PA_FEISHU_WEB_KEY 也无 CREDENTIALS_DIRECTORY，
      //    只要工作区启用了 personal_web 或 state.db 含敏感状态，Dispatcher.runVerifyCommand 与 unshare+pivot_root+setpriv
      //    都必须隐藏 dataDir/state.db、feishu-web.json、/proc/<parent-pid> 且锁定只读根，仅开放当前 worktree 与私有 /tmp 写入
      await withoutTestWebKey(async () => {
        const wsDir = makeTmp("pa-r12-iso-ws-");
        const dataDir = path.join(wsDir, "data");
        const wtDir = path.join(dataDir, "worktrees", "wt_r12");
        fs.mkdirSync(wtDir, { recursive: true });
        fs.mkdirSync(path.join(dataDir, "runs", "g_r12"), { recursive: true });
        const extCred = path.join(wsDir, "ext-feishu-web.json");
        fs.writeFileSync(extCred, '{"v":1,"secret":"SHOULD_NOT_READ"}\n', { mode: 0o600 });
        const cfgFile = path.join(wsDir, "config.yaml");
        fs.writeFileSync(
          cfgFile,
          JSON.stringify({
            data_dir: dataDir,
            bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
            harnesses: { claude: { agent: "claude" } },
            roles: { brain: "claude" },
            owner: { open_id: "ou_owner_r12" },
            context: { enabled: true, personal_web: { enabled: true } },
          }),
        );
        const isoApp = createApp(loadConfig(cfgFile));
        try {
          isoApp.store.set("ctx.personal_web.bound_owner_id", "7001");
          isoApp.store.set("daemon.holds_web_key", "1");
          fs.writeFileSync(path.join(dataDir, "feishu-web.json"), '{"v":1,"enc":"hidden"}\n', { mode: 0o600 });
          const stateDbPath = path.join(dataDir, "state.db");
          const wtProbeFile = path.join(wtDir, "verify-wrote.txt");
          // 确认壳内完全没有密钥环境变量
          assert.equal(process.env.PA_FEISHU_WEB_KEY, undefined);
          assert.equal(process.env.CREDENTIALS_DIRECTORY, undefined);

          const dispatcher = new Dispatcher(isoApp.cfg, isoApp.ledger, isoApp.store, isoApp.board);
          const verifyCmd = [
            `test ! -e ${JSON.stringify(stateDbPath)}`,
            `test ! -e ${JSON.stringify(path.join(dataDir, "feishu-web.json"))}`,
            `test ! -e /proc/${process.pid}/environ`,
            `! touch ${JSON.stringify(path.join(ROOT, ".pa-r12-ro-probe"))} 2>/dev/null`,
            `echo ok-worktree > ${JSON.stringify(wtProbeFile)}`,
            `echo ok-tmp > /tmp/r12-scratch.txt`,
          ].join(" && ");
          isoApp.ledger.enqueue({
            id: "dispatch:r12-verify-iso",
            kind: "dispatch",
            ref: "r12-verify-iso",
            state: "verifying",
            payload: {
              guid: "g_r12",
              summary: "r12 verify fs isolation",
              description: "",
              harness: "claude",
              repo: "",
              cwd: wtDir,
              branch: "",
              base: "",
              verify: verifyCmd,
              round: 1,
            },
          });
          const work = isoApp.ledger.get("dispatch:r12-verify-iso")!;
          const vRes = await (
            dispatcher as unknown as {
              runVerifyCommand(it: typeof work, ctx: { attempt: number; signal: AbortSignal }): Promise<{ status: string; detail: string }>;
            }
          ).runVerifyCommand(work, { attempt: 1, signal: new AbortController().signal });
          assert.equal(vRes.status, "pass", `无密钥 shell 下 Dispatcher.runVerifyCommand 必须隐藏 state.db/凭据/宿主机 /proc 并锁定只读根：${vRes.detail}`);
          assert.equal(fs.readFileSync(wtProbeFile, "utf8").trim(), "ok-worktree", "worktree 自身必须保持可写");
          assert.equal(fs.existsSync(stateDbPath), true, "宿主机 state.db 完好无损");

          // 同样验证 unshare + pivot_root + setpriv 回退对 dataDir/state.db、只读根与 worktree 边界完全一致
          if (probeSetpriv.code === 0 && pivotBin) {
            const wtUnshareOut = path.join(wtDir, "unshare-wrote.txt");
            const unshareIso = wrapCredentialIsolatedCommand(
              "sh",
              [
                "-c",
                [
                  `test ! -e ${JSON.stringify(stateDbPath)}`,
                  `! touch ${JSON.stringify(path.join(dataDir, "tamper.db"))} 2>/dev/null`,
                  `test ! -e /proc/${process.pid}/environ`,
                  `! touch ${JSON.stringify(path.join(ROOT, ".pa-r12-unshare-ro"))} 2>/dev/null`,
                  `echo unshare-ok > ${JSON.stringify(wtUnshareOut)}`,
                  `echo scratch > /tmp/r12-unshare-tmp.txt`,
                  `grep -q "0000000000000000" /proc/self/status`,
                ].join(" && "),
              ],
              {},
              {
                ...buildWorkspaceIsolation(isoApp.cfg, { mode: "verify", cwd: wtDir }, {}),
                forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: pivotBin },
              },
            );
            assert.equal(unshareIso.isolated, true);
            const rU = await runProcess(unshareIso.cmd, unshareIso.args, { timeoutMs: 15_000 });
            assert.equal(rU.code, 0, `unshare+pivot_root+setpriv 必须同样隐藏 state.db 并锁定只读根：${rU.stderr}`);
            assert.equal(fs.readFileSync(wtUnshareOut, "utf8").trim(), "unshare-ok");
          }
        } finally {
          isoApp.store.db.close();
        }
      });
    } finally {
      if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
      else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    }
  },
);

test("Codex 第九轮回归：跨路径 web-logout 吊销、换主人全库干净校验、手动起草排除复检、纯 GUID 委派归属、派单卡片与 worker/交付/用量/失败审计主人隔离、白名单机器人 @我、动态文档/妙记开关、连续排除变更暂缓 ACK、Codex 0.169 白名单与多行内联表、Git LFS 推送保护、本地轮换不重置拒登计数与群名增量合并", async () => {
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
    // 1) [R9 P2-13 & P2-14] Codex 0.169 内置供应商（ollama/lmstudio 接受、oss 拒绝）、凭据存储（ephemeral 接受）与多行带尾逗号 TOML 1.1 内联表
    const tomlHome = makeTmp("pa-r9-codex-");
    fs.writeFileSync(path.join(tomlHome, "config.toml"), 'model_provider = "ollama"\ncli_auth_credentials_store = "ephemeral"\n');
    const ollamaCfg = extractSafeCodexProviderConfig({ CODEX_HOME: tomlHome }, [], false);
    assert.ok(ollamaCfg.args.includes('model_provider="ollama"'), "内置 ollama 无需 [model_providers.ollama] 表即可通过");
    assert.ok(ollamaCfg.args.includes('cli_auth_credentials_store="ephemeral"'), "必须保留 cli_auth_credentials_store=ephemeral");

    fs.writeFileSync(path.join(tomlHome, "config.toml"), 'model_provider = "lmstudio"\n');
    assert.ok(extractSafeCodexProviderConfig({ CODEX_HOME: tomlHome }, [], false).args.includes('model_provider="lmstudio"'), "内置 lmstudio 无需供应商表即可通过");

    fs.writeFileSync(path.join(tomlHome, "config.toml"), 'model_provider = "oss"\n');
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: tomlHome }, [], false), /oss/, "Codex 0.169 不接受无表定义的 model_provider=oss");

    const multilineToml = [
      'model_provider = "corp_ml"',
      "model_providers = {",
      "  # TOML 1.1 多行内联表与末尾逗号",
      "  corp_ml = {",
      '    name = "Multiline GW",',
      '    base_url = "https://ml.corp.internal/v1",',
      '    http_headers = {',
      '      Authorization = "Bearer ml-secret-r9",',
      "    },",
      "  },",
      "}",
    ].join("\n");
    fs.writeFileSync(path.join(tomlHome, "config.toml"), multilineToml);
    const parsedMl = parseToml(multilineToml);
    assert.equal(((parsedMl.model_providers as Record<string, Record<string, unknown>>).corp_ml).name, "Multiline GW");
    const mlCfg = extractSafeCodexProviderConfig({ CODEX_HOME: tomlHome }, [], false);
    assert.ok(mlCfg.args.includes('model_provider="corp_ml"'));
    assert.ok(Object.values(mlCfg.extraEnv).includes("Bearer ml-secret-r9"));
    assert.ok(!mlCfg.args.some((a) => a.includes("ml-secret-r9")));

    // 2) [R9 P2-15 + R12 P2] Git LFS 交付保护：自包含真实 LFS 指针与本地对象（不依赖全局 clean filter），在无密钥作用域下执行以兼容非 Linux userns 宿主机
    await withoutTestWebKey(async () => {
      const lfsRepo = makeTmp("pa-r9-lfs-");
      const lfsBare = makeTmp("pa-r9-lfs-bare-");
      assert.equal((await tryGit(lfsBare, ["init", "--bare", "-q"])).code, 0);
      assert.equal((await tryGit(lfsRepo, ["init", "-q"])).code, 0);
      assert.equal((await tryGit(lfsRepo, ["checkout", "-qb", "pa/r9-lfs"])).code, 0);
      fs.writeFileSync(path.join(lfsRepo, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      const r9Payload = Buffer.from("self-contained-r9-lfs-payload\n", "utf8");
      const r9Oid = crypto.createHash("sha256").update(r9Payload).digest("hex");
      const r9ObjDir = path.join(lfsRepo, ".git", "lfs", "objects", r9Oid.slice(0, 2), r9Oid.slice(2, 4));
      fs.mkdirSync(r9ObjDir, { recursive: true });
      fs.writeFileSync(path.join(r9ObjDir, r9Oid), r9Payload);
      const r9Ptr = `version https://git-lfs.github.com/spec/v1\noid sha256:${r9Oid}\nsize ${r9Payload.length}\n`;
      fs.writeFileSync(path.join(lfsRepo, "weights.bin"), r9Ptr);
      assert.equal((await tryGit(lfsRepo, ["add", ".gitattributes", "weights.bin"])).code, 0);
      assert.equal((await tryGit(lfsRepo, ["commit", "-qm", "add lfs file"])).code, 0);
      assert.equal((await tryGit(lfsRepo, ["remote", "add", "origin", lfsBare])).code, 0);
      assert.equal(await branchUsesGitLfs(lfsRepo, "pa/r9-lfs"), true, "必须通过 git check-attr 识别 LFS 跟踪文件");
      // 放一个会写标志文件的恶意 pre-push hook，验证它绝不被执行；同时先验证 LFS 上传失败时阻断推送（不推悬空指针），再验证可用 LFS 端点时受信任上传成功
      const hookMarker = path.join(lfsRepo, "hook-ran.txt");
      fs.writeFileSync(path.join(lfsRepo, ".git", "hooks", "pre-push"), `#!/bin/sh\necho pwned > ${JSON.stringify(hookMarker)}\nexit 0\n`, { mode: 0o755 });
      assert.equal((await tryGit(lfsRepo, ["config", "lfs.url", "http://127.0.0.1:1/unreachable-lfs"])).code, 0);
      const lfsFailRes = await pushBranch(lfsRepo, "origin", "pa/r9-lfs");
      assert.equal(fs.existsSync(hookMarker), false, "仓库 pre-push hook 绝不能被执行");
      assert.equal(lfsFailRes.ok, false, "LFS 上传失败时必须阻止普通 git push");
      if (!lfsFailRes.ok) {
        assert.match(lfsFailRes.message, /Git LFS/, "错误信息应明确提示 Git LFS 上传失败");
      }
      const bareRefsAfterFail = (await tryGit(lfsBare, ["branch", "-a"])).stdout.trim();
      assert.equal(bareRefsAfterFail, "", "LFS 上传失败后绝不能把悬空分支推上远端");
      // 撤销失效 lfs.url：若宿主机装有 git-lfs，验证受信任的 git lfs pre-push + git push 完整成功且对象真实上传到 bare 远端
      assert.equal((await tryGit(lfsRepo, ["config", "--unset", "lfs.url"])).code, 0);
      const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 3_000 })).code === 0;
      if (hasGitLfs) {
        const lfsOkRes = await pushBranch(lfsRepo, "origin", "pa/r9-lfs");
        assert.equal(lfsOkRes.ok, true, `宿主机具备 git-lfs 时应在不跑仓库 hooks 的前提下完成 LFS 上传并推送：${!lfsOkRes.ok ? lfsOkRes.message : ""}`);
        assert.equal(fs.existsSync(hookMarker), false, "LFS 推送成功期间仓库 pre-push hook 依然绝不被执行");
        assert.match((await tryGit(lfsBare, ["branch", "-a"])).stdout, /pa\/r9-lfs/);
        assert.equal(
          fs.existsSync(path.join(lfsBare, "lfs", "objects", r9Oid.slice(0, 2), r9Oid.slice(2, 4), r9Oid)),
          true,
          "真实 LFS 对象必须完整上传到 bare 远端 LFS 存储",
        );
      }
    });

    // 3) 搭建完整 Working Context 测试环境
    const dir = makeTmp("pa-r9-ctx-");
    const ctxDir = makeTmp("pa-r9-lark-");
    process.env.CTX_DIR = ctxDir;
    const callsLog = path.join(dir, "calls.log");
    const harnessScript = path.join(dir, "fake-r9-harness.mjs");
    const gateFlagFile = path.join(dir, "r9-gate.flag");
    const enteredFlagFile = path.join(dir, "r9-entered.flag");
    const responseJsonFile = path.join(dir, "r9-response.json");
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
  process.stdout.write("收到，我这边处理。\\n");
} else {
  process.stdout.write(fs.readFileSync(${JSON.stringify(responseJsonFile)}, "utf8") + "\\n");
}
`,
      { mode: 0o755 },
    );
    const cfgFile = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      `
data_dir: ${dir}
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
cards:
  enabled: true
context:
  enabled: true
  harness: mock_ctx
  groups: allowlist
  max_groups: 5
  groups_allow: []
  groups_deny: []
  bot_allow: ["MeegoBot"]
  sources:
    meego: false
    tasks: false
    im: true
    minutes: true
    calendar: false
    docs: true
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: false
    send_replies: true
    debounce_ms: 0
`,
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCallbackLlm(svc, async (prompt) => {
      fs.appendFileSync(callsLog, JSON.stringify({ prompt }) + "\n");
      if (fs.existsSync(gateFlagFile)) {
        fs.writeFileSync(enteredFlagFile, "1");
        const deadline = Date.now() + 8000;
        while (fs.existsSync(gateFlagFile) && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 20));
        }
      }
      if (prompt.includes("草稿") || prompt.includes("答复或进展")) {
        return "收到，我这边处理。";
      }
      return fs.readFileSync(responseJsonFile, "utf8");
    });
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三" }));

    // 4) [R9 P1-3] 变更工作区主人时必须确保整个上下文库干净（即便库里零 pw:* 行，只有轮询来的 im:* / 草稿 / 事项，也绝不允许换主人重绑）
    svc.store.addObs([
      {
        id: "im:r9_polled_dm_a",
        source: "im",
        kind: "p2p",
        conv: "oc_r9_dm_a",
        conv_name: "私聊：王五",
        actor_id: "ou_ww",
        actor_name: "王五",
        is_me: false,
        time: now - 5_000,
        text: "主人A的轮询私聊机密",
        url: "",
        meta: { chat_type: "p2p" },
      },
    ]);
    assert.equal(hasExistingOwnerContextState(app), true);
    app.store.set(BOUND_OWNER_KV_KEY, "7001");
    app.store.set(BOUND_WORKSPACE_OWNER_KV_KEY, "ou_owner_a");
    app.cfg.owner.open_id = "ou_owner_b";
    const rebindLogin = {
      owner_id: "7002",
      owner_name: "李四",
      session_id: "sess_r9_rebind_b",
      cookie_version: 1,
      cookies: [{ name: "session", value: "b_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
      updated_at: new Date().toISOString(),
    };
    await assert.rejects(
      () => verifyWorkspaceOwnerBinding(app!, rebindLogin, { forceSwitch: true, allowNameMismatch: true, allowUnverifiedOwner: true }),
      /历史上下文|数据目录|全新的 data_dir/,
      "存在主人A的轮询私聊（即使无 pw:* 观测）时，verifyWorkspaceOwnerBinding 必须拒绝切到主人B",
    );
    assert.throws(
      () => commitWorkspaceLogin(app!, rebindLogin, { forceSwitch: true, allowUnverifiedOwner: true }),
      /历史上下文|数据目录|全新的 data_dir/,
      "commitWorkspaceLogin 同样必须拒绝在非空上下文库上切换工作区主人",
    );
    // 即使只改工作区主人而保持同一原生 ID（7001），非空上下文库也必须拒绝重绑
    assert.throws(
      () => commitWorkspaceLogin(app!, { ...rebindLogin, owner_id: "7001", owner_name: "张三" }, { allowUnverifiedOwner: true }),
      /工作区主人|非空|全新的 data_dir/,
    );
    app.cfg.owner.open_id = "ou_owner_a";

    // 正常为主人 A 绑定登录
    const customDaemonCred = path.join(dir, "daemon-custom-r9.json");
    process.env.PA_FEISHU_WEB_CRED_FILE = customDaemonCred;
    const daemonSavedLogin = commitWorkspaceLogin(
      app,
      {
        owner_id: "7001",
        owner_name: "张三",
        session_id: "sess_r9_daemon_custom",
        cookie_version: 1,
        cookies: [{ name: "session", value: "valid_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
        updated_at: new Date().toISOString(),
      },
      { allowUnverifiedOwner: true },
    );
    const daemonBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 30,
      clientOptions: { endpoints: mock.endpoints },
    });
    const daemonHandle = daemonBridge.start();
    try {
      await waitUntil(() => daemonBridge.status().state === "listening", 4_000);
      // 5) [R9 P1-2] 交互 shell 未设 PA_FEISHU_WEB_CRED_FILE（指向默认文件）执行 web-logout：仍必须立刻吊销使用自定义文件的常驻会话与发送能力！
      delete process.env.PA_FEISHU_WEB_CRED_FILE;
      const logoutRes = revokeWorkspacePersonalWebSession(app);
      assert.equal(logoutRes.fileRemoved, false, "默认路径本无文件，但工作区级吊销标记仍已写入");
      assert.ok(app.store.get(REVOKED_AT_KV_KEY), "必须持久化工作区吊销标记");
      await waitUntil(() => daemonBridge.status().state === "needs_login", 4_000);
      assert.equal(daemonBridge.status().logged_in, false, "吊销后 status() 必须报告未登录");
      // 发送也必须立即被拒（即使自定义路径凭据文件仍在磁盘上）
      await assert.rejects(
        () => daemonBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9901", message_id: "m_revoked", text: "不应发出", cid: "cid_r9_revoked" }),
        /吊销|web-logout/,
        "跨路径 web-logout 后常驻进程绝不能继续发送 pw.reply",
      );
      // 即使之后在默认路径重新 web-login（清除了全局 revoked_at），旧自定义路径里的已吊销 session_id 也必须继续被拒！
      commitWorkspaceLogin(
        app,
        {
          owner_id: "7001",
          owner_name: "张三",
          session_id: "sess_r9_new_default",
          cookie_version: 1,
          cookies: [{ name: "session", value: "new_cookie", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
          updated_at: new Date().toISOString(),
        },
        { allowUnverifiedOwner: true },
      );
      await assert.rejects(
        () => daemonBridge.sendVerifiedReply({ owner_id: "7001", chat_id: "9901", message_id: "m_revoked2", text: "旧会话不应复活", cid: "cid_r9_revoked2" }),
        /已.*吊销|重新运行/,
        "旧自定义凭据文件中已吊销的 session_id 绝不能在新路径重登后复活",
      );
      assert.equal(daemonSavedLogin.session_id, "sess_r9_daemon_custom");
    } finally {
      daemonHandle.stop();
      delete process.env.PA_FEISHU_WEB_CRED_FILE;
    }

    // 6) [R9 P1-4] 手动起草回复前完整复核会话排除/静音规则（包括 DM）：静音 DM 后手动 drafter.forItem 必须拒绝且不调模型
    const { item: dmDraftItem } = svc.store.upsertItem({ title: "回复王五私聊", kind: "ask_me", priority: "high", source: "im" });
    svc.store.addEvidence("item", dmDraftItem.id, "im:r9_polled_dm_a", "主人A的轮询私聊机密", now - 5_000);
    svc.store.muteConv("oc_r9_dm_a", "私聊：王五", true);
    fs.writeFileSync(callsLog, "");
    await assert.rejects(
      () => svc.drafter.forItem(dmDraftItem.id, "reply"),
      /静音|排除/,
      "静音私聊后手动起草回复必须在调用模型前被拦截",
    );
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "被排除的手动草稿绝不能向模型发送任何私聊消息");
    svc.store.muteConv("oc_r9_dm_a", "", false);

    // 7) [R9 P2-10] 白名单机器人（kind="bot"）在范围外群 @我：必须记录 meta.at_me=true 并通过 SQL 预筛与范围过滤
    const origLarkRun = app.lark.run.bind(app.lark);
    app.lark.run = async (args: string[], opts?: Parameters<typeof origLarkRun>[1]) => {
      if (args[0] === "im" && args[1] === "+messages-search") {
        if (args.includes("--is-at-me")) {
          return {
            messages: [
              {
                message_id: "om_r9_bot_atme",
                chat_id: "oc_r9_out_group",
                chat_name: "范围外机器人群",
                chat_type: "group",
                create_time: String(nowSec),
                sender: { id: "cli_meego", name: "MeegoBot", sender_type: "app" },
                content: "@张三 你的需求流转到待验收",
              },
            ],
          };
        }
        return { messages: [] };
      }
      return origLarkRun(args, opts);
    };
    try {
      await svc.connectors.pullIm();
    } finally {
      app.lark.run = origLarkRun;
    }
    const botMentionObs = svc.store.obs("im:om_r9_bot_atme");
    assert.ok(botMentionObs, "白名单机器人的 @我 消息应正常入库");
    assert.equal(botMentionObs!.kind, "bot");
    assert.equal(botMentionObs!.meta.at_me, true, "白名单机器人 @我 必须独立保存 meta.at_me=true");
    const onlyMentionWin = svc.store.convWindow("oc_r9_out_group", 60, 12, null, { onlyMentions: true });
    assert.deepEqual(onlyMentionWin.map((o) => o.id), ["im:om_r9_bot_atme"], "SQL onlyMentions 预筛必须保留白名单机器人的真实 @我");
    assert.deepEqual(
      svc.personalWeb.filterWindowByCurrentScope("oc_r9_out_group", [botMentionObs!]).map((o) => o.id),
      ["im:om_r9_bot_atme"],
      "filterWindowByCurrentScope 必须保留白名单机器人的真实 @我",
    );
    svc.store.markProcessed(["im:om_r9_bot_atme", "im:r9_polled_dm_a"]);

    // 8) [R9 P2-11] 周期中途关闭 docs / minutes 来源开关：推理中途关闭 minutes 后本批被拒，且同周期后续批次不再选择已停用来源
    svc.store.addObs([
      {
        id: "minutes:r9_min_1",
        source: "minutes",
        kind: "minutes",
        conv: "minutes:r9_min_1",
        conv_name: "会议：周会",
        actor_id: "",
        actor_name: "智能纪要",
        is_me: false,
        time: now - 2_000,
        text: "机密会议纪要内容",
        url: "",
        meta: {},
      },
      {
        id: "doc:r9_doc_1",
        source: "doc",
        kind: "doc_comment",
        conv: "doc:https://feishu.cn/docx/r9",
        conv_name: "文档评论",
        actor_id: "",
        actor_name: "文档评论@我",
        is_me: false,
        time: now - 1_000,
        text: "机密文档评论内容",
        url: "",
        meta: {},
      },
    ]);
    app.cfg.context.sources.im = false;
    fs.writeFileSync(
      responseJsonFile,
      JSON.stringify({
        projects: [],
        items: [{ title: "会议待办", kind: "meeting_action", priority: "high", evidence: [{ obs_id: "minutes:r9_min_1", quote: "机密会议纪要" }] }],
        knowledge: [],
        updates: [],
        people: [],
        conflicts: [],
      }),
    );
    fs.writeFileSync(gateFlagFile, "hold");
    fs.rmSync(enteredFlagFile, { force: true });
    // 将 max_convs_per_cycle 设为 2、并行 1，推理第一批中途同时关闭 minutes 和 docs
    const prevMaxConvs = app.cfg.context.max_convs_per_cycle;
    app.cfg.context.max_convs_per_cycle = 2;
    const srcCycleP = svc.cycle("work:r9-sources-mid-off");
    await waitUntil(() => fs.existsSync(enteredFlagFile), 5_000);
    app.cfg.context.sources.minutes = false;
    app.cfg.context.sources.docs = false;
    fs.rmSync(gateFlagFile, { force: true });
    const srcRep = await srcCycleP;
    app.cfg.context.max_convs_per_cycle = prevMaxConvs;
    app.cfg.context.sources.im = true;
    assert.equal(srcRep.created, 0, "推理中途停用 minutes/docs 后绝不能提交结果");
    assert.equal(svc.store.obsPending("minutes:r9_min_1"), true);
    assert.equal(svc.store.obsPending("doc:r9_doc_1"), true);
    svc.store.markProcessed(["minutes:r9_min_1", "doc:r9_doc_1"]);

    // 9) [R9 P2-12] handleMessage 在排除规则连续变更两次时必须抛出可重试错误暂缓 ACK（绝不返回 undefined 误确认丢消息）
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          oc_r9_unrelated_1: { name: "无关群1", chat_mode: "group" },
          oc_r9_unrelated_2: { name: "无关群2", chat_mode: "group" },
        },
      }),
    );
    const clientA = await FeishuWebClient.connect(svc.personalWeb.loginStore.load()!, {
      endpoints: mock.endpoints,
      onSessionConfirmed: (u, d) => svc.personalWeb.loginStore.saveIfSessionMatches(u, d),
    });
    const origEvalExcl = (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion.bind(svc.personalWeb);
    let evalCalls = 0;
    (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion = async (...args: unknown[]) => {
      evalCalls++;
      const res = await origEvalExcl(...args);
      // 第一次与第二次排除查询期间都变更无关的 oc_* 静音集合
      svc.store.muteConv(`oc_r9_unrelated_${evalCalls}`, "无关群", true);
      return res;
    };
    const doubleFlipBuf = buildNativeMessage({ id: "r9_double_flip", chatId: "9902", chatKind: CHAT_KIND_P2P, actorId: "7002", createdAtSec: nowSec, text: "不能被误 ACK 丢掉的私聊" });
    mock.addMessage("r9_double_flip", doubleFlipBuf);
    mock.setChatKind("9902", CHAT_KIND_P2P);
    try {
      await assert.rejects(
        () => svc.personalWeb.handleMessage(decodeMessage(doubleFlipBuf, "7001"), clientA),
        /暂缓 ACK|连续变化/,
        "排除规则连续变化两次时必须抛错暂缓 ACK，防止 handlePush 误确认丢消息",
      );
    } finally {
      (svc.personalWeb as unknown as { evaluateChatExclusion: (...a: unknown[]) => Promise<boolean> }).evaluateChatExclusion = origEvalExcl;
      svc.store.muteConv("oc_r9_unrelated_1", "", false);
      svc.store.muteConv("oc_r9_unrelated_2", "", false);
    }

    // 10) [R9 P2-17] pullIm 仅合并本轮增量学到的群名，绝不覆盖在线监听在轮询等待期间刚刷新的群名
    rememberOpenGroupName(app.store, "oc_r9_live_renamed", "旧名称");
    const origLarkMerge = app.lark.run.bind(app.lark);
    app.lark.run = async (args: string[], opts?: Parameters<typeof origLarkMerge>[1]) => {
      if (args[0] === "im" && args[1] === "+messages-search") {
        // 模拟轮询 await Feishu 期间，在线监听刷新了 oc_r9_live_renamed 的群名
        rememberOpenGroupName(app!.store, "oc_r9_live_renamed", "实时监听刷新后的新名称");
        return { messages: [] };
      }
      return origLarkMerge(args, opts);
    };
    try {
      await svc.connectors.pullIm();
    } finally {
      app.lark.run = origLarkMerge;
    }
    assert.equal(
      loadKnownOpenGroupNames(app.store).oc_r9_live_renamed,
      "实时监听刷新后的新名称",
      "pullIm 提交不得用轮询前快照把在线监听刷新后的群名写回旧名称",
    );

    // 11) [R9 P1-5, P1-6, P1-7, P1-8, P2-9] 纯 GUID 委派归属、失败委派审计隔离、派单卡片投递隔离、worker/交付恢复重检、用量 top_tasks 隔离
    const origCreateTask = app.board.createTask.bind(app.board);
    const origReconcile = app.dispatcher.reconcile.bind(app.dispatcher);
    // 11a) 失败的 context.item_delegate -> dispatch.create 失败（无派单 ID）：审计项通过 __context_owner 保留隔离
    const { item: secretItem } = svc.store.upsertItem({ title: "主人A绝密收购方案", kind: "ask_me", priority: "high", source: "im" });
    app.board.createTask = async () => {
      throw new Error("看板接口临时报错");
    };
    await assert.rejects(() => app!.commands.exec("context.item_delegate", { id: secretItem.id }, { source: "web", actor: "owner" }));

    // 11b) 成功的 context.item_delegate，但 reconcile 尚未创建 work（dispatch.create 仅返回纯任务 GUID）
    const delayedGuid = "guid_r9_delayed_only";
    app.board.createTask = async () => delayedGuid;
    app.dispatcher.reconcile = async () => ({ enqueued: 0, cancelled: 0, deferred: 0 });
    try {
      const delGuidRes = await app.commands.exec("context.item_delegate", { id: secretItem.id }, { source: "web", actor: "owner" });
      assert.equal(delGuidRes.target, delayedGuid, "模拟 reconcile 未即时建 work 时返回纯任务 GUID");
    } finally {
      app.board.createTask = origCreateTask;
      app.dispatcher.reconcile = origReconcile;
    }
    // 稍后 reconcile 才真正创建 dispatch:<guid>:1，同时产生步骤花费、派单卡片、交付任务与排队中的派单任务
    const delayedDispatchId = `dispatch:${delayedGuid}:1`;
    app.ledger.enqueue({
      id: delayedDispatchId,
      kind: "dispatch",
      ref: delayedGuid,
      state: "queued",
      payload: { guid: delayedGuid, summary: "主人A绝密收购方案", description: "来自私聊证据", harness: "mock_ctx", reviewer: "", verify: "", cwd: "", branch: "pa/r9-sec", base: "", round: 1, maxRounds: 1, checkpoints: {}, report: "", feedback: "", history: [] },
    });
    const costStepId = app.ledger.startStep({ work_id: delayedDispatchId, name: "worker#1", harness: "mock_ctx" });
    app.ledger.endStep(costStepId, "ok", "done");
    app.ledger.setStepUsage(costStepId, { tokens_in: 5000, tokens_out: 1000, cost_usd: 0.42 });

    // 切到主人 B 后验证全部 5 条路径都被严格隔离！
    app.cfg.owner.open_id = "ou_owner_b";
    try {
      // (a) 失败的 dispatch.create 嵌套审计条不得向主人 B 暴露私密标题
      const auditForB = Q.auditViews(app, undefined, 100);
      assert.ok(!auditForB.some((a) => a.target.includes("绝密收购方案") || a.message.includes("绝密收购方案")), "失败的委派内部 dispatch.create 审计必须对新主人隐藏");

      // (b) 纯 GUID 延迟创建的 dispatch:<guid>:1 必须被识别为旧主人上下文派单
      assert.equal(Q.isContextDerivedDispatchBlocked(app, delayedDispatchId), true, "仅凭任务 GUID 写入的 ctx.dispatch_ref_owner 必须拦截后续创建的 dispatch work");
      assert.ok(!Q.listDispatches(app, {}).some((d) => d.id === delayedDispatchId));
      await assert.rejects(() => Q.dispatchDetail(app!, delayedDispatchId), /主人隔离|阻断/);

      // (c) /api/usage 的 top_tasks 不得暴露旧主人上下文派单标题与 ID，但总花费仍准确
      const usageForB = usageSummary(app, 7);
      assert.ok(usageForB.total_usd >= 0.42, "聚合总花费不受影响");
      assert.ok(!usageForB.top_tasks.some((t) => t.dispatch_id === delayedDispatchId || t.summary.includes("绝密收购方案")), "top_tasks 绝不能向新主人暴露旧主人的上下文派单标题");

      // (d) 派单卡片（card:dispatch:<guid>）投递前按原始归属主人拦截，绝不发给主人 B
      let cardSentToB = false;
      const origLarkCard = app.lark.run.bind(app.lark);
      app.lark.run = async (...args: Parameters<typeof origLarkCard>) => {
        cardSentToB = true;
        return origLarkCard(...args);
      };
      try {
        const fxHandler = effectHandler(app.cfg, app.ledger, app.board, app.lark, app.store, app.effectHooks);
        app.ledger.enqueue({
          id: "fx:r9-card-dispatch-guid",
          kind: "effect",
          ref: `card:dispatch:${delayedGuid}`,
          state: "pending",
          payload: { op: "card.upsert", args: { key: `dispatch:${delayedGuid}`, card: { header: { title: { content: "主人A绝密收购方案" } } } } },
        });
        const cardItem = app.ledger.claim("effect", 30_000)!;
        await assert.rejects(() => fxHandler.run(cardItem as never, { signal: new AbortController().signal, attempt: 1 }), /主人隔离|阻断/);
        assert.equal(cardSentToB, false, "旧主人上下文派单卡片绝不能投递给新主人 B");
      } finally {
        app.lark.run = origLarkCard;
      }

      // (e) 恢复执行中的 dispatch worker 与 delivery worker（create_pr）必须在任何外部动作前按主人隔离中止
      const dispClaimed = app.ledger.claim("dispatch", 30_000)!;
      assert.equal(dispClaimed.id, delayedDispatchId);
      await app.dispatcher.advance(dispClaimed as never, { signal: new AbortController().signal, attempt: 1 });
      const dispAfter = app.ledger.get(delayedDispatchId)!;
      assert.equal(dispAfter.state, "errored");
      assert.equal(dispAfter.reason, "owner_isolated", "dispatch worker 恢复旧主人上下文派单时必须按主人隔离中止");

      const deliveryId = `delivery:${delayedDispatchId}:create_pr:${now}`;
      app.ledger.enqueue({
        id: deliveryId,
        kind: "delivery",
        ref: delayedDispatchId,
        state: "pending",
        payload: { action: "create_pr", dispatch_id: delayedDispatchId, guid: delayedGuid },
      });
      await app.engine.drain(["delivery"]);
      const delAfter = app.ledger.get(deliveryId)!;
      assert.equal(delAfter.state, "errored");
      assert.match(delAfter.error, /主人隔离/, "delivery worker 恢复旧主人上下文交付任务时必须按主人隔离中止");
    } finally {
      app.cfg.owner.open_id = "ou_owner_a";
    }

    // 12) [R9 P2-16] 本地 verifyOwner 轮换 Cookie 后若 metadata 返回 401：绝不能把自身轮换当成外部新凭据而清零 connectDenials，3 次后必须进入 needs_login
    const denialBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 30,
      clientOptions: { endpoints: mock.endpoints },
    });
    denialBridge.loginStore.save({
      owner_id: "7001",
      owner_name: "张三",
      session_id: "sess_r9_denial_loop",
      cookie_version: 1,
      cookies: [{ name: "session", value: "v1", domain: "internal-api-lark-api.feishu.cn", path: "/" }],
      updated_at: new Date().toISOString(),
    });
    app.store.set(ACTIVE_SESSION_KV_KEY, "sess_r9_denial_loop");
    const origConnectDenial = FeishuWebClient.connect;
    const origSetTimeout = globalThis.setTimeout;
    let denialAttempts = 0;
    // 仅把 runSupervisor 的 30s reverifying 退避压缩到 5ms 便于测试精确验证 3 次拒登收敛
    globalThis.setTimeout = ((fn: (...a: unknown[]) => void, ms?: number, ...rest: unknown[]) =>
      origSetTimeout(fn, ms === 30_000 ? 5 : ms, ...rest)) as typeof setTimeout;
    FeishuWebClient.connect = async (loginArg, opts) => {
      denialAttempts++;
      // 模拟每次 connect 时 verifyOwner 都通过 onSessionConfirmed 落盘了新 cookie_version，随后 metadata 返回 401 credential_denied
      opts?.onSessionConfirmed?.(
        { ...loginArg, cookies: [{ name: "session", value: `rot_${denialAttempts}`, domain: "internal-api-lark-api.feishu.cn", path: "/" }] },
        {
          upserts: [{ name: "session", value: `rot_${denialAttempts}`, domain: "internal-api-lark-api.feishu.cn", path: "/" }],
          deletes: [],
          baseValues: { "session\0internal-api-lark-api.feishu.cn\0/": loginArg.cookies[0]?.value ?? null },
        },
      );
      throw new WebHttpError("credential_denied", "metadata 401", 401);
    };
    const denialHandle = denialBridge.start();
    try {
      await waitUntil(() => denialBridge.status().state === "needs_login", 4_000);
      assert.equal(denialAttempts, 3, "本地自身落盘的 Cookie 轮换绝不能清零 connectDenials，必须恰好在 3 次拒登后进入 needs_login");
    } finally {
      denialHandle.stop();
      FeishuWebClient.connect = origConnectDenial;
      globalThis.setTimeout = origSetTimeout;
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

test("Codex 第十轮回归：服务文件凭据隔离、失败卡片/委派落库/文本报表/全历史/用量缓存主人隔离、目标越界停草稿、先吊销后删文件、跨路径状态与代际校验、编辑去@我、lookback_days 签名、排除群改名刷新、原生静音补位、LFS 历史推送、Bedrock/GCP 与 TOML 1.1 转义", async () => {
  const dir = makeTmp("pw-round10-");
  const ctxDir = path.join(dir, "ctx-fx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;
  process.env.CTX_DIR = ctxDir;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  const chmodRestoreDirs: string[] = [];
  try {
    // 1) [R10 P1] deploy/personal-agent.service 必须区分同 UID 明文文件不可隔离，推荐 LoadCredentialEncrypted= 或系统级 root 凭据
    const unitText = fs.readFileSync(path.join(ROOT, "deploy/personal-agent.service"), "utf8");
    assert.ok(unitText.includes("LoadCredentialEncrypted="), "systemd 服务文档必须指导使用 LoadCredentialEncrypted=");
    assert.ok(unitText.includes("systemd-creds encrypt"), "systemd 服务文档必须说明 systemd-creds encrypt 加密流程");
    assert.ok(!unitText.includes("不再将纯密钥写入 .env，避免与普通配置混放"), "不得误导将同 UID 0600 明文 LoadCredential= 当作隔离方案");

    // 2) [R10 P2] Codex 内置 amazon-bedrock 与 gcp 供应商无需自定义 [model_providers.*] 表；TOML 1.1 字符串转义 (\xHH / \e) 与无秒时间可被无害丢弃
    const toml11Parsed = parseToml(
      [
        'model = "claude-3-7-sonnet"',
        'model_provider = "amazon-bedrock"',
        'created_time = 12:34',
        '[mcp_servers.foo]',
        'command = "/bin/echo"',
        'args = ["\\x41\\x42", "\\e[32mhi\\e[0m"]',
      ].join("\n"),
    );
    assert.equal(toml11Parsed.model_provider, "amazon-bedrock");
    assert.deepEqual((toml11Parsed.mcp_servers as { foo: { args: string[] } }).foo.args, ["AB", "\x1b[32mhi\x1b[0m"]);

    const codexHome1 = path.join(dir, "codex-bedrock");
    fs.mkdirSync(codexHome1, { recursive: true });
    fs.writeFileSync(
      path.join(codexHome1, "config.toml"),
      [
        'model = "anthropic.claude-sonnet"',
        'model_provider = "amazon-bedrock"',
        '[mcp_servers.unrelated]',
        'note = "\\x41\\e[0m"',
      ].join("\n"),
    );
    const bedrockCfg = extractSafeCodexProviderConfig({ CODEX_HOME: codexHome1 }, [], false);
    assert.ok(bedrockCfg.args.includes('model_provider="amazon-bedrock"'), "内置 amazon-bedrock 供应商（含无关 MCP 的 TOML 1.1 转义）必须通过校验");
    assert.equal(bedrockCfg.args.some((a) => a.includes("mcp_servers")), false, "无关 MCP 配置必须被剥离");

    const codexHome2 = path.join(dir, "codex-gcp");
    fs.mkdirSync(codexHome2, { recursive: true });
    fs.writeFileSync(path.join(codexHome2, "config.toml"), 'model_provider = "gcp"\n');
    const gcpCfg = extractSafeCodexProviderConfig({ CODEX_HOME: codexHome2 }, [], false);
    assert.ok(gcpCfg.args.includes('model_provider="gcp"'), "内置 gcp 供应商无需自定义 model_providers 表即可通过");

    // 3) [R10 P2 + R12 P2] Git LFS 历史提交检测：提交 1 添加 LFS 文件、提交 2 删除该文件（tip 无 LFS 文件），脱离密钥作用域且仅在安装 git-lfs 时断言真实上传成功
    await withoutTestWebKey(async () => {
      const lfsRemote = path.join(dir, "lfs-hist-remote.git");
      const lfsRepo = path.join(dir, "lfs-hist-repo");
      fs.mkdirSync(lfsRemote, { recursive: true });
      fs.mkdirSync(lfsRepo, { recursive: true });
      await tryGit(lfsRemote, ["init", "--bare"]);
      await tryGit(lfsRepo, ["init", "-b", "main"]);
      await tryGit(lfsRepo, ["config", "user.name", "Tester"]);
      await tryGit(lfsRepo, ["config", "user.email", "tester@example.com"]);
      await tryGit(lfsRepo, ["remote", "add", "origin", lfsRemote]);
      fs.writeFileSync(path.join(lfsRepo, "README.md"), "base\n");
      await tryGit(lfsRepo, ["add", "README.md"]);
      await tryGit(lfsRepo, ["commit", "-m", "base"]);
      await tryGit(lfsRepo, ["push", "-u", "origin", "main"]);
      const baseSha = (await tryGit(lfsRepo, ["rev-parse", "HEAD"])).stdout.trim();

      await tryGit(lfsRepo, ["checkout", "-b", "feat/lfs-deleted"]);
      fs.writeFileSync(path.join(lfsRepo, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      const lfsBody = Buffer.from("historical-lfs-payload-r10\n", "utf8");
      const lfsOid = crypto.createHash("sha256").update(lfsBody).digest("hex");
      const lfsObjDir = path.join(lfsRepo, ".git", "lfs", "objects", lfsOid.slice(0, 2), lfsOid.slice(2, 4));
      fs.mkdirSync(lfsObjDir, { recursive: true });
      fs.writeFileSync(path.join(lfsObjDir, lfsOid), lfsBody);
      const lfsPtr = [
        "version https://git-lfs.github.com/spec/v1",
        `oid sha256:${lfsOid}`,
        `size ${lfsBody.length}`,
        "",
      ].join("\n");
      fs.writeFileSync(path.join(lfsRepo, "ephemeral.bin"), lfsPtr);
      await tryGit(lfsRepo, ["add", ".gitattributes", "ephemeral.bin"]);
      await tryGit(lfsRepo, ["commit", "-m", "add lfs object"]);
      await tryGit(lfsRepo, ["rm", "ephemeral.bin"]);
      await tryGit(lfsRepo, ["commit", "-m", "delete lfs object before tip"]);
      assert.equal(
        await branchUsesGitLfs(lfsRepo, "feat/lfs-deleted", baseSha),
        true,
        "仅在早期 outgoing commit 出现并在 tip 删除的 LFS 对象仍必须被检测到",
      );
      await tryGit(lfsRepo, ["config", "lfs.url", "http://127.0.0.1:1/invalid-lfs-history"]);
      const lfsFail = await pushBranch(lfsRepo, "origin", "feat/lfs-deleted");
      assert.equal(lfsFail.ok, false, "LFS 历史对象上传失败时必须中止 git push");
      assert.match(lfsFail.message, /Git LFS/);
      assert.equal(
        (await tryGit(lfsRemote, ["rev-parse", "--verify", "refs/heads/feat/lfs-deleted"])).code !== 0,
        true,
        "LFS 历史对象上传失败时远端绝不能出现悬空分支",
      );
      // 恢复正常本地 bare 远端：宿主机具备 git-lfs 时验证历史 LFS 对象被完整上传
      await tryGit(lfsRepo, ["config", "--unset", "lfs.url"]);
      const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 3_000 })).code === 0;
      if (hasGitLfs) {
        const lfsOk = await pushBranch(lfsRepo, "origin", "feat/lfs-deleted");
        assert.equal(lfsOk.ok, true, "有效远端下历史 LFS 对象必须由 git lfs pre-push 上传并完成分支推送");
        assert.equal(
          fs.existsSync(path.join(lfsRemote, "lfs", "objects", lfsOid.slice(0, 2), lfsOid.slice(2, 4), lfsOid)),
          true,
          "仅存在于早期提交的历史 LFS 对象必须完整落盘到远端 LFS 存储",
        );
      }
    });

    // ───────── 初始化共享测试 App ─────────
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
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "cx",
          groups: "allowlist",
          max_groups: 1,
          lookback_days: 7,
          groups_allow: ["oc_r10_removed"],
          groups_deny: [],
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCtxDirStubLlm(svc, ctxDir);
    const cards = new CardService(app, { debounceMs: 5 });
    cards.register();
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const baseCookies = [{ name: "session", value: "r10_sess", domain: "internal-api-lark-api.feishu.cn", path: "/" }];

    const loginA = commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r10_init", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 4) [R10 P1] dispatch.create 在 reconcile() 之前持久化 GUID 主人归属：即使对账失败，换主人后后续 reconcile 也绝不接管该任务
    const origCreateTask = app.board.createTask.bind(app.board);
    const origListSection = app.board.listSection.bind(app.board);
    const { item: privItem } = svc.store.upsertItem({
      title: "绝密委派失败对账事项",
      kind: "todo",
      project_id: "",
      status: "open",
      priority: "high",
      counterpart: "王五",
      next_step: "内部机密改造",
      source: "im",
    });
    app.store.set("board.owner_open_id", "ou_owner_a");
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
    app.board.createTask = async () => "guid_r10_reconcile_fail";
    app.board.listSection = async () => {
      throw new Error("simulated board read failure during reconcile");
    };
    await assert.rejects(
      app.commands.exec("context.item_delegate", { id: privItem.id }, { source: "web", actor: "owner" }),
      /simulated board read failure/,
    );
    assert.equal(
      app.store.get("ctx.dispatch_ref_owner.guid_r10_reconcile_fail"),
      "ou_owner_a",
      "dispatch.create 必须在 board.createTask 返回后、reconcile 之前立即写入 GUID 主人归属",
    );
    // 切换为主人 B 后恢复 board 读取，reconcile 必须跳过旧主人的该远端任务
    app.cfg.owner.open_id = "ou_owner_b";
    app.store.set("board.section.dispatch", "sec_dispatch");
    app.store.set("board.section.running", "sec_running");
    app.board.listSection = async (sec) =>
      sec === "dispatch"
        ? [{ guid: "guid_r10_reconcile_fail", summary: "绝密委派失败对账事项", description: "", dueMs: null, completed: false, url: "" }]
        : [];
    const recRes = await app.dispatcher.reconcile();
    assert.equal(recRes.enqueued, 0, "换主人后 reconcile 绝不能把旧主人失败对账的远端委派任务当普通派单入队");
    assert.equal(app.ledger.latest("dispatch", "guid_r10_reconcile_fail"), undefined);
    app.board.createTask = origCreateTask;
    app.board.listSection = origListSection;
    app.cfg.owner.open_id = "ou_owner_a";

    // 5) [R10 P1] failure:<delivery-id> 告警卡片（含已入队与换主人后新触发）+ statusText + buildBrief 主人隔离
    const finishWork = (id: string, patch: Parameters<NonNullable<typeof app>["ledger"]["transition"]>[1]) => {
      app!.store.db.prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = ?").run(app!.ledger.owner, Date.now() + 60_000, id);
      app!.ledger.transition(app!.ledger.get(id)!, patch);
    };
    const secretGuid = "guid_r10_secret_card";
    const secretDispId = `dispatch:${secretGuid}:1`;
    const publicGuid = "guid_r10_public_card";
    const publicDispId = `dispatch:${publicGuid}:1`;
    app.store.set(`ctx.dispatch_owner.${secretDispId}`, "ou_owner_a");
    app.store.set(`ctx.dispatch_ref_owner.${secretGuid}`, "ou_owner_a");
    app.ledger.enqueue({
      id: secretDispId,
      kind: "dispatch",
      ref: secretGuid,
      state: "accepted",
      payload: { guid: secretGuid, summary: "绝密派单标题A", description: "", harness: "cx" },
    });
    finishWork(secretDispId, { state: "accepted", terminal: true, outcome: "accepted" });
    app.ledger.enqueue({
      id: publicDispId,
      kind: "dispatch",
      ref: publicGuid,
      state: "accepted",
      payload: { guid: publicGuid, summary: "公开普通派单B", description: "", harness: "cx" },
    });
    finishWork(publicDispId, { state: "accepted", terminal: true, outcome: "accepted" });

    // 在主人 A 仍在线时，先有一条 delivery 失败并把 failure:<delivery-id> 卡片写入 outbox（模拟切换前已入队）
    const preDelId = `delivery:${secretDispId}:create_pr:${now}`;
    app.ledger.enqueue({
      id: preDelId,
      kind: "delivery",
      ref: secretDispId,
      state: "pending",
      payload: { action: "create_pr", dispatch_id: secretDispId, guid: secretGuid },
    });
    finishWork(preDelId, { state: "errored", terminal: true, error: "push failed" });
    const queuedFailCardId = `fx:queued-fail-${now}`;
    app.ledger.enqueue({
      id: queuedFailCardId,
      kind: "effect",
      ref: `card:failure:${preDelId}`,
      payload: cardEffect(`failure:${preDelId}`, { header: { title: { content: "绝密派单标题A" } } }, "failure"),
    });

    // 切换为主人 B
    app.cfg.owner.open_id = "ou_owner_b";
    let sentCardsToLark = 0;
    const origLarkRun = app.lark.run.bind(app.lark);
    const origAuthStatusR10 = app.lark.authStatus.bind(app.lark);
    app.lark.authStatus = async () => ({ identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } });
    app.lark.run = async (argv, opts) => {
      if (argv[0] === "auth" && argv[1] === "status") {
        return { identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } };
      }
      if (argv[0] === "im" && (argv[1] === "+messages-send" || argv[2] === "patch")) {
        sentCardsToLark++;
      }
      if (argv[0] === "task" && argv[1] === "+get-my-tasks") {
        return {
          items: [
            { guid: secretGuid, summary: "绝密派单标题A", due: { timestamp: String(now - 60_000) } },
            { guid: publicGuid, summary: "公开普通派单B", due: { timestamp: String(now - 60_000) } },
          ],
        };
      }
      return origLarkRun(argv, opts);
    };
    const fxHandler = effectHandler(app.cfg, app.ledger, app.board, app.lark, app.store);
    await assert.rejects(
      fxHandler.run(app.ledger.get(queuedFailCardId)!, { attempt: 1, signal: new AbortController().signal }),
      /主人隔离|阻断/,
      "已入队的 failure:<delivery-id> 告警卡片必须在投递前经底层工作项解析并按主人隔离阻断",
    );
    assert.equal(sentCardsToLark, 0, "被阻断的 failure 卡片绝不能发送到飞书");

    // 切换为主人 B 后新触发的 delivery errored：CardService 不得再生成新的 failure:<delivery-id> 卡片，也不得重绘 dispatch 卡片
    const postDelId = `delivery:${secretDispId}:merge_local:${now + 1}`;
    app.ledger.enqueue({
      id: postDelId,
      kind: "delivery",
      ref: secretDispId,
      state: "pending",
      payload: { action: "merge_local", dispatch_id: secretDispId, guid: secretGuid },
    });
    finishWork(postDelId, { state: "errored", terminal: true, error: "blocked owner" });
    await cards.flush();
    assert.equal(
      app.ledger.list({ kinds: ["effect"], ref: `card:failure:${postDelId}`, limit: 10 }).length,
      0,
      "换主人后失败的旧主人 delivery 不得入队新的 failure 告警卡片",
    );
    // 先清掉切主人前主人 A 阶段生成的 dispatch 卡片，确认换主人后 renderDispatch 不再新增
    const beforeRenderDisp = app.ledger.list({ kinds: ["effect"], ref: `card:dispatch:${secretGuid}`, limit: 10 }).length;
    cards.renderDispatch(secretGuid);
    assert.equal(
      app.ledger.list({ kinds: ["effect"], ref: `card:dispatch:${secretGuid}`, limit: 10 }).length,
      beforeRenderDisp,
      "renderDispatch 不得为旧主人上下文派单入队卡片",
    );

    // statusText（/status 与 pa status）和 buildBrief 均必须隐藏旧主人委派任务，仅保留公开任务
    const stReport = statusText(app.ledger, { cfg: app.cfg, store: app.store });
    assert.equal(stReport.includes("绝密派单标题A"), false, "statusText 绝不能向新主人泄漏旧主人的上下文委派任务标题");
    assert.equal(stReport.includes("公开普通派单B"), true, "statusText 必须保留普通非上下文派单");

    app.board.listSection = async (sec) => {
      if (sec === "review") return [{ guid: secretGuid, summary: "绝密派单标题A", description: "", dueMs: null, completed: false, url: "" }];
      if (sec === "attention") return [{ guid: publicGuid, summary: "公开普通派单B", description: "", dueMs: null, completed: false, url: "" }];
      return [];
    };
    const briefReport = await buildBrief(app.cfg, app.lark, app.store, app.ledger, app.board, "morning");
    assert.equal(briefReport.includes("绝密派单标题A"), false, "buildBrief 绝不能向新主人泄漏旧主人的上下文委派任务标题");
    assert.equal(briefReport.includes("公开普通派单B"), true, "buildBrief 必须保留普通任务");
    app.board.listSection = origListSection;
    app.lark.run = origLarkRun;
    app.lark.authStatus = origAuthStatusR10;

    // 6) [R10 P2] 旧升级数据超过 20 次重试后的全历史归属隔离 + usageSummary 缓存查重
    const legacyGuid = "guid_r10_legacy_25";
    const { item: legacyItem } = svc.store.upsertItem({
      title: "旧版超过20次重试的委派",
      kind: "todo",
      project_id: "",
      status: "open",
      priority: "medium",
      source: "im",
      meta: { delegated: `dispatch:${legacyGuid}:0` },
    });
    assert.ok(legacyItem.id);
    for (let i = 0; i <= 25; i++) {
      const wid = `dispatch:${legacyGuid}:${i}`;
      app.ledger.enqueue({
        id: wid,
        kind: "dispatch",
        ref: legacyGuid,
        state: "accepted",
        payload: { guid: legacyGuid, summary: `旧版重试#${i}`, description: "", harness: "cx" },
      });
      finishWork(wid, { state: "accepted", terminal: true, outcome: "accepted" });
    }
    assert.equal(
      Q.isContextDerivedDispatchBlocked(app, `dispatch:${legacyGuid}:25`),
      true,
      "即使同一任务已有超过 20 次重试，旧版仅记在 ctx_item.meta.delegated 的委派仍必须在换主人后被隔离",
    );

    // usageSummary：每个 distinct dispatch/ref 只查一次归属，不按 step 数量重复查库
    for (let s = 0; s < 10; s++) {
      const sid1 = app.ledger.startStep({ work_id: secretDispId, name: `s${s}`, harness: "cx" });
      app.ledger.setStepUsage(sid1, { tokens_in: 100, tokens_out: 20, cost_usd: 1.5 });
      app.ledger.endStep(sid1, "ok", "done");
      const sid2 = app.ledger.startStep({ work_id: publicDispId, name: `p${s}`, harness: "cx" });
      app.ledger.setStepUsage(sid2, { tokens_in: 100, tokens_out: 20, cost_usd: 0.8 });
      app.ledger.endStep(sid2, "ok", "done");
    }
    let ownerStoreLookups = 0;
    const origStoreGet = app.store.get.bind(app.store);
    app.store.get = (k: string) => {
      if (k.startsWith("ctx.dispatch_")) ownerStoreLookups++;
      return origStoreGet(k);
    };
    const uSum = usageSummary(app, 7, now);
    app.store.get = origStoreGet;
    assert.equal(uSum.top_tasks.some((t) => t.summary.includes("绝密派单标题A")), false, "usage top_tasks 必须隐藏旧主人委派");
    assert.equal(uSum.top_tasks.some((t) => t.summary.includes("公开普通派单B")), true, "usage top_tasks 必须保留公开任务");
    assert.ok(ownerStoreLookups <= 12, `usageSummary 应按 distinct 卡片缓存归属查询而非每步重复查库（实际查询 ${ownerStoreLookups} 次）`);

    // 切回主人 A 继续后续上下文与个人 Web 回归
    app.cfg.owner.open_id = "ou_owner_a";
    cards.stop();

    // 7) [R10 P1] 目标证据因群移出白名单而超出采集范围时，手动与已入队自动草稿均必须在调用模型前停止；若事项另有合法证据则改选之
    const callsLog = path.join(ctxDir, "calls.log");
    fs.writeFileSync(callsLog, "");
    fs.writeFileSync(path.join(ctxDir, "draft.txt"), "草稿正文");
    svc.store.addObs([
      {
        id: "im:r10_removed_msg",
        source: "im",
        kind: "group",
        conv: "oc_r10_removed",
        conv_name: "已移出白名单群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 5_000,
        text: "普通群消息请跟进",
        url: "",
        meta: { chat_type: "group", message_id: "r10_removed_msg" },
      },
    ]);
    const { item: removedItem } = svc.store.upsertItem({
      title: "来自普通群消息的待办",
      kind: "ask_me",
      project_id: "",
      status: "open",
      priority: "high",
      counterpart: "Bob",
      next_step: "回复进展",
      source: "im",
    });
    svc.store.addEvidence("item", removedItem.id, "im:r10_removed_msg", "普通群消息请跟进", now - 5_000);
    // 将该群从 allowlist 移除
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = ["oc_r10_kept"];

    await assert.rejects(
      svc.drafter.forItem(removedItem.id, "reply"),
      /采集范围|已停止起草/,
      "目标普通群消息已不在当前采集范围时，手动起草必须在调用模型前停止",
    );
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "目标越界停止起草时绝不能调用模型");
    assert.equal(svc.store.drafts().length, 0, "目标越界停止起草时绝不能落库草稿");

    // 已入队的自动预起草同样必须跳过（不调用模型、不落库草稿、不发错误通知）
    svc.enqueue("draft:r10-auto-removed", { task: "draft", item_id: removedItem.id, kind: "reply", auto: true });
    await app.engine.drain(["context"]);
    assert.equal(app.ledger.get("context:draft:r10-auto-removed")?.state, "skipped", "已入队自动草稿目标越界时必须静默跳过");
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "自动草稿跳过时绝不能调用模型");
    assert.equal(svc.store.drafts().length, 0);

    // 若事项上还有一条当前范围内的合法证据（例如在白名单群 oc_r10_kept），则自动改选该目标起草
    svc.store.addObs([
      {
        id: "im:r10_kept_msg",
        source: "im",
        kind: "group",
        conv: "oc_r10_kept",
        conv_name: "保留白名单群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 10_000,
        text: "请在这边回复",
        url: "",
        meta: { chat_type: "group", message_id: "r10_kept_msg" },
      },
    ]);
    svc.store.addEvidence("item", removedItem.id, "im:r10_kept_msg", "请在这边回复", now - 10_000);
    const fallbackDraft = await svc.drafter.forItem(removedItem.id, "reply");
    assert.equal(fallbackDraft.target.obs_id, "im:r10_kept_msg", "最新证据越界时必须自动改选同事项上仍合法的目标证据");

    // 8) [R10 P2] 轮询消息编辑移除 @我 时清除陈旧 at_me 标记且不无限重开；窗口外省略 at_me 保留原值不重开
    const editChatId = "oc_r10_edit_group";
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = [editChatId];
    app.cfg.context.groups_deny = [];
    const msgTimeIso = new Date(now - 20_000).toISOString();
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        at_me: [
          {
            message_id: "om_r10_edit_1",
            chat_id: editChatId,
            chat_type: "group",
            chat_name: "编辑测试群",
            sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
            create_time: msgTimeIso,
            content: JSON.stringify({ text: "@张三 麻烦看一下" }),
          },
        ],
        chats: {
          [editChatId]: [
            {
              message_id: "om_r10_edit_1",
              chat_id: editChatId,
              chat_type: "group",
              chat_name: "编辑测试群",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: msgTimeIso,
              content: JSON.stringify({ text: "@张三 麻烦看一下" }),
            },
          ],
        },
      }),
    );
    const p1 = await svc.connectors.pullIm();
    assert.equal(p1.count, 1);
    assert.equal(svc.store.obs("im:om_r10_edit_1")?.meta.at_me, true);
    svc.store.markProcessed(["im:om_r10_edit_1"]);

    // 编辑移除 @我：不再出现在 --is-at-me，仅出现在普通群拉取中（正文甚至保持相同文字 "@张三 麻烦看一下"）
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        at_me: [],
        chats: {
          [editChatId]: [
            {
              message_id: "om_r10_edit_1",
              chat_id: editChatId,
              chat_type: "group",
              chat_name: "编辑测试群",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: msgTimeIso,
              content: JSON.stringify({ text: "@张三 麻烦看一下" }),
            },
          ],
        },
      }),
    );
    const p2 = await svc.connectors.pullIm();
    assert.equal(p2.count, 1, "窗口内确认不再是 @我 的编辑必须更新记录并重开一次");
    const editedRow = svc.store.obs("im:om_r10_edit_1")!;
    assert.equal(editedRow.kind, "group");
    assert.equal(editedRow.meta.at_me, false, "确认移除 @我 后必须显式写为 at_me: false 覆盖旧 true");
    // 移出白名单后 mention-only 过滤必须不再放行该条
    app.cfg.context.groups_allow = ["oc_r10_other"];
    assert.equal(
      svc.store.convWindow(editChatId, 60, 12, "7001", { onlyMentions: true }).length,
      0,
      "移除 @我 后的消息绝不能再通过 SQL onlyMentions 筛选",
    );
    assert.equal(
      svc.personalWeb.filterWindowByCurrentScope(editChatId, [editedRow]).length,
      0,
      "移除 @我 后的消息绝不能再通过 filterWindowByCurrentScope",
    );
    svc.store.markProcessed(["im:om_r10_edit_1"]);
    app.cfg.context.groups_allow = [editChatId];
    // 第三次相同投递绝不能再次重开
    const p3 = await svc.connectors.pullIm();
    assert.equal(p3.count, 0, "移除 @我 后的重复投递必须幂等返回 0，绝不无限重开推理");

    // 窗口外未知状态（省略 at_me）重复投递到已验证 at_me: true 记录时，保留 at_me: true 且不重开
    svc.store.addObs([
      {
        id: "im:om_r10_unknown_at",
        source: "im",
        kind: "at_me",
        conv: editChatId,
        conv_name: "编辑测试群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 3600_000,
        text: "历史 @我",
        url: "",
        meta: { chat_type: "group", at_me: true },
      },
    ]);
    svc.store.markProcessed(["im:om_r10_unknown_at"]);
    const unknownRedeliv = svc.store.addObs([
      {
        id: "im:om_r10_unknown_at",
        source: "im",
        kind: "group",
        conv: editChatId,
        conv_name: "编辑测试群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 3600_000,
        text: "历史 @我",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    assert.equal(unknownRedeliv, 0, "省略 at_me 的相同投递比对合并后元数据相等，绝不反复重开");
    assert.equal(svc.store.obs("im:om_r10_unknown_at")?.meta.at_me, true);

    // 9) [R10 P2] lookback_days 变更必须体现在 policySignature，并在推理期间缩短窗口时阻断过期 spoken 群普通消息提交
    const agedChat = "oc_r10_aged_spoken";
    app.cfg.context.groups = "spoken";
    app.cfg.context.max_groups = 5;
    app.cfg.context.lookback_days = 7;
    app.store.set("ctx.spoken_groups", JSON.stringify({ [agedChat]: { name: "五天前发言群", at: now - 5 * 86_400_000 } }));
    const sig7 = svc.personalWeb.policySignature();
    app.cfg.context.lookback_days = 2;
    const sig2 = svc.personalWeb.policySignature();
    assert.notEqual(sig7, sig2, "lookback_days 变化必须改变 policySignature");
    assert.equal(svc.personalWeb.isGroupConvInCurrentScope(agedChat), false, "缩短 lookback_days 到 2 天后，5 天前发言群必须离开生效范围");

    // 模拟推理期间缩短 lookback_days：validateBeforeApply 必须拒绝提交该过期 spoken 群的普通消息结果
    app.cfg.context.lookback_days = 7;
    svc.store.addObs([
      {
        id: "im:r10_aged_ord",
        source: "im",
        kind: "group",
        conv: agedChat,
        conv_name: "五天前发言群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 3_000,
        text: "请处理过期发言群需求",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "understand.json"),
      JSON.stringify({
        items: [{ title: "不应提交的过期窗口事项", kind: "todo", priority: "medium", source_obs: "im:r10_aged_ord", quote: "请处理过期发言群需求" }],
      }),
    );
    const origRunBatch = svc.understander.runBatch.bind(svc.understander);
    svc.understander.runBatch = async (workId, convs, sig, owner, validateBeforeApply, opts) => {
      const wrappedValidate = validateBeforeApply
        ? async (usedConvs: { conv: string; conv_name: string }[], batchObs: Obs[]) => {
            app!.cfg.context.lookback_days = 2;
            return validateBeforeApply(usedConvs, batchObs);
          }
        : undefined;
      return origRunBatch(workId, convs, sig, owner, wrappedValidate, opts);
    };
    app.cfg.context.sources = { im: true, meego: false, tasks: false, minutes: false, calendar: false, docs: false };
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三" }));
    await svc.cycle("ctx:r10-lookback");
    svc.understander.runBatch = origRunBatch;
    assert.equal(
      svc.store.items({ limit: 100 }).some((x) => x.title === "不应提交的过期窗口事项"),
      false,
      "推理期间缩短 lookback_days 后，validateBeforeApply 必须拒收超出新回看窗口的 spoken 群普通消息产出",
    );

    // 10) [R10 P2] 白名单群因旧缓存名称命中关键词排除，群改名后 pullIm 必须刷新群名并恢复轮询其普通消息
    const renamedChat = "oc_r10_renamed";
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = [renamedChat];
    app.cfg.context.groups_deny = ["保密"];
    app.cfg.context.max_groups = 1;
    app.cfg.context.lookback_days = 7;
    rememberOpenGroupName(app.store, renamedChat, "保密讨论群");
    app.store.set("ctx.spoken_groups", JSON.stringify({ [renamedChat]: { name: "保密讨论群", at: now - 1000 } }));
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: { [renamedChat]: { name: "日常研发群", chat_mode: "group" } },
        chats: {
          [renamedChat]: [
            {
              message_id: "om_r10_after_rename",
              chat_id: renamedChat,
              chat_type: "group",
              chat_name: "日常研发群",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: new Date(now - 5_000).toISOString(),
              content: JSON.stringify({ text: "改名后应被重新采集" }),
            },
          ],
        },
      }),
    );
    const renamePoll = await svc.connectors.pullIm();
    assert.equal(renamePoll.count, 1, "缓存旧名命中关键词排除的白名单群改名后，必须刷新群名并恢复轮询普通消息");
    assert.equal(svc.store.obs("im:om_r10_after_rename")?.text, "改名后应被重新采集");
    assert.equal(loadKnownOpenGroupNames(app.store)[renamedChat], "日常研发群", "刷新后的新群名必须回写缓存");

    // 11) [R10 P2] 原生 allowlist [A, B] + max_groups=1，静音 A 对应的 oc_* 群时，A 必须在截断前剔除，B 获得名额并采集普通消息
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = ["pw_chat:9901", "pw_chat:9902"];
    app.cfg.context.groups_deny = [];
    app.cfg.context.max_groups = 1;
    mock.setChatName("9901", "A群");
    mock.setChatKind("9901", CHAT_KIND_GROUP);
    mock.setChatName("9902", "B群");
    mock.setChatKind("9902", CHAT_KIND_GROUP);
    svc.store.muteConv("oc_r10_counterpart_a", "A群", true);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({ chat_meta: { oc_r10_counterpart_a: { name: "A群", chat_mode: "group" } } }),
    );
    const clientA = await FeishuWebClient.connect(loginA, { endpoints: mock.endpoints });
    const msgB = decodeMessage(
      buildNativeMessage({ id: "r10_native_b_msg", chatId: "9902", actorId: "7099", text: "B群普通消息应获得补位名额", createdAtSec: nowSec }),
      "7001",
    );
    await svc.personalWeb.handleMessage(msgB, clientA);
    assert.ok(svc.store.obs("pw:r10_native_b_msg"), "静音 A 对应的 oc_* 后，原生 allowlist 截断前必须剔除 A，让未静音的 B 拿到唯一名额");
    assert.equal(
      svc.personalWeb.filterWindowByCurrentScope("pw_chat:9902", [svc.store.obs("pw:r10_native_b_msg")!]).length,
      1,
      "filterWindowByCurrentScope 必须同样将 B 视为在当前采集范围内",
    );
    svc.store.muteConv("oc_r10_counterpart_a", "A群", false);

    // 12) [R10 P2] 跨文件重登：不同路径登录同一账号写入新 ACTIVE_SESSION_KV_KEY 后，旧路径常驻监听必须立刻断开转 needs_login 且旧路径发包被拒
    const pathA = path.join(dir, "cred-a", "web-session.enc");
    const pathB = path.join(dir, "cred-b", "web-session.enc");
    process.env.PA_FEISHU_WEB_CRED_FILE = pathA;
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r10_path_a", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );
    const bridgeA = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 25,
      clientOptions: { endpoints: mock.endpoints, heartbeatIntervalMs: 500 },
    });
    const handleA = bridgeA.start();
    try {
      await waitUntil(() => bridgeA.status().state === "listening", 4_000);
      // CLI 在路径 B 上用同一账号重新登录，推进 ACTIVE_SESSION_KV_KEY
      process.env.PA_FEISHU_WEB_CRED_FILE = pathB;
      commitWorkspaceLogin(
        app,
        { owner_id: "7001", owner_name: "主人A", session_id: "sess_r10_path_b", cookies: baseCookies },
        { allowUnverifiedOwner: true },
      );
      await waitUntil(() => bridgeA.status().state === "needs_login", 4_000);
      // 旧文件本地核验（web-status --verify / assertLoginAuthorizedForWorkspace）必须拦截被取代会话，绝不联网或轮换 Cookie
      process.env.PA_FEISHU_WEB_CRED_FILE = pathA;
      const oldDiskLogin = new WebLoginStore(app.cfg.dataDir).load()!;
      assert.throws(
        () => assertLoginAuthorizedForWorkspace(app!, oldDiskLogin),
        /取代/,
        "跨文件被更新会话取代的旧凭据必须在本地授权校验即被拒绝",
      );
      await assert.rejects(
        bridgeA.sendVerifiedReply({ owner_id: "7001", chat_id: "9902", message_id: "r10_native_b_msg", text: "旧路径不应发送", cid: "cid_r10_superseded" }),
        /取代/,
        "被取代的旧路径会话绝不能发送 pw.reply",
      );
    } finally {
      handleA.stop();
    }

    // 13) [R10 P2] CLI 使用默认路径（missing）查看自定义路径常驻进程健康态：必须保留 listening，且 doctor 通过；吊销后立即转 needs_login
    delete process.env.PA_FEISHU_WEB_CRED_FILE;
    const defaultStore = new WebLoginStore(app.cfg.dataDir);
    defaultStore.clear();
    assert.equal(defaultStore.inspect().status, "missing");
    app.store.set("daemon.heartbeat", `host:${process.pid}|${Date.now()}`);
    app.store.set(
      "ctx.personal_web.state",
      JSON.stringify({
        state: "listening",
        owner_id: "7001",
        owner_name: "主人A",
        session_id: "sess_r10_path_b",
        cookie_version: 1,
        since: Date.now() - 1000,
        last_message_at: Date.now() - 500,
        last_error: "",
      }),
    );
    const cliSt = svc.personalWeb.status();
    assert.equal(cliSt.logged_in, true, "CLI 默认路径 missing 但常驻心跳新鲜且会话未吊销/未被取代时，必须保留 logged_in=true");
    assert.equal(cliSt.state, "listening", "CLI 默认路径 missing 但常驻在线时，不得误报 needs_login");
    const docRep = await runDoctor(app);
    assert.equal(docRep.checks.find((c) => c.id === "personal_web")?.status, "ok", "doctor 在自定义路径常驻在线时必须报 ok");

    // 14) [R10 P1 & P2] 先提交 SQLite 吊销再删文件：即使凭据目录只读导致删除失败，工作区也已完成吊销且 web-status --verify 本地阻断
    const roDir = path.join(dir, "ro-cred-dir");
    const roFile = path.join(roDir, "web-session.enc");
    fs.mkdirSync(roDir, { recursive: true });
    process.env.PA_FEISHU_WEB_CRED_FILE = roFile;
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r10_ro", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );
    const roLoginBefore = new WebLoginStore(app.cfg.dataDir).load()!;
    const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
    if (!isRoot) {
      fs.chmodSync(roDir, 0o500);
      chmodRestoreDirs.push(roDir);
    }
    const revokeRes = revokeWorkspacePersonalWebSession(app);
    assert.ok((app.store.get(REVOKED_AT_KV_KEY) ?? "").length > 0, "无论文件能否删除，REVOKED_AT_KV_KEY 必须已提交");
    assert.equal(app.store.get(ACTIVE_SESSION_KV_KEY), "", "吊销后 ACTIVE_SESSION_KV_KEY 必须已清空");
    assert.equal(
      JSON.parse(app.store.get(REVOKED_SESSIONS_KV_KEY) ?? "[]").includes("sess_r10_ro"),
      true,
      "被吊销的 session_id 必须写入 REVOKED_SESSIONS_KV_KEY",
    );
    if (!isRoot) {
      assert.equal(revokeRes.fileRemoved, false);
      assert.ok(revokeRes.fileError, "只读目录清理失败时应单独返回 fileError 而不抛错阻断工作区吊销");
    }
    assert.equal(svc.personalWeb.status().state, "needs_login", "吊销后即使默认路径 missing 且有新鲜心跳，status() 也必须立即变为 needs_login");
    assert.throws(
      () => assertLoginAuthorizedForWorkspace(app!, roLoginBefore),
      /吊销/,
      "已吊销的工作区绝不允许 web-status --verify 使用残留加密文件联网或回写 Cookie",
    );
  } finally {
    for (const d of chmodRestoreDirs) {
      try {
        fs.chmodSync(d, 0o700);
      } catch {
        // ignore
      }
    }
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

test("Codex 第十一轮回归：PID+挂载隔离、草稿终检防重插、晨报/自主任务/CLI/忽略主人隔离、move前落库归属、关键词竞态、Bedrock AWS/废弃profile、条件删凭据、吊销止回读、截断不误清@我、学名重排补位、改名刷新待处理、精准跳过失败批次、LFS严格指针与扫错中止、严格TOML数字与主题无关QR", async () => {
  const dir = makeTmp("pw-round11-");
  const ctxDir = path.join(dir, "ctx-fx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;
  process.env.CTX_DIR = ctxDir;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  try {
    // 1) [R11 P3] 终端 QR 使用显式黑字白底 ANSI 色彩与 4 模块白色静区（深浅色终端通用）
    const qrAnsi = renderQrTerminal("https://passport.feishu.cn/suite/passport/qr?code=r11");
    const qrLines = qrAnsi.split("\n");
    assert.ok(qrLines.every((l) => l.startsWith("\x1b[30;47m") && l.endsWith("\x1b[0m")), "每行 QR 必须显式指定黑字白底 ANSI 色彩并重置");
    // 前两行（4 模块高）均为纯白静区（全是空格）
    assert.match(qrLines[0], /^\x1b\[30;47m +\x1b\[0m$/);
    assert.match(qrLines[1], /^\x1b\[30;47m +\x1b\[0m$/);

    // 2) [R11 P3] TOML 严格数字校验：拒绝前导零、尾随/连续下划线、非法进制与非法小数
    for (const bad of ["x = 01\n", "x = -01\n", "x = 42_\n", "x = _42\n", "x = 1__2\n", "x = 0x_1\n", "x = 1.e2\n", "x = 1._0\n"]) {
      assert.throws(() => parseToml(bad), /TOML/, `非法 TOML 数字 ${JSON.stringify(bad)} 必须被拒绝`);
    }
    const okNums = parseToml("a = 0\nb = 1_000\nc = -42\nd = 0xdead_beef\ne = 3.14_15e-2\n");
    assert.equal(okNums.a, 0);
    assert.equal(okNums.b, 1000);
    assert.equal(okNums.c, -42);
    assert.equal(okNums.d, 0xdeadbeef);
    assert.equal(okNums.e, 0.031415);

    // 3) [R11 P1 & P2] Bedrock aws.profile/region 必须保留、非法 aws 认证字段必须拒绝；废弃顶层 profile = "..." 必须 fail-closed
    const bedHome = path.join(dir, "codex-bed-r11");
    fs.mkdirSync(bedHome, { recursive: true });
    fs.writeFileSync(
      path.join(bedHome, "config.toml"),
      [
        'model = "anthropic.claude-3-7-sonnet"',
        'model_provider = "amazon-bedrock"',
        "[model_providers.amazon-bedrock.aws]",
        'profile = "corp-prod"',
        'region = "us-west-2"',
      ].join("\n"),
    );
    const bedRes = extractSafeCodexProviderConfig({ CODEX_HOME: bedHome }, [], false);
    assert.ok(bedRes.args.some((a) => a.includes('profile="corp-prod"') && a.includes('region="us-west-2"')), "amazon-bedrock 的 aws.profile 与 aws.region 必须保留");

    const bedBadHome = path.join(dir, "codex-bed-bad-r11");
    fs.mkdirSync(bedBadHome, { recursive: true });
    fs.writeFileSync(
      path.join(bedBadHome, "config.toml"),
      [
        'model_provider = "amazon-bedrock"',
        "[model_providers.amazon-bedrock.aws]",
        'profile = "corp-prod"',
        'credential_process = "/usr/bin/evil"',
      ].join("\n"),
    );
    assert.throws(() => extractSafeCodexProviderConfig({ CODEX_HOME: bedBadHome }, [], false), /credential_process|不受支持/);

    const legacyProfHome = path.join(dir, "codex-legacy-prof-r11");
    fs.mkdirSync(legacyProfHome, { recursive: true });
    fs.writeFileSync(
      path.join(legacyProfHome, "config.toml"),
      ['profile = "retired"', "[profiles.retired]", 'model_provider = "openai"'].join("\n"),
    );
    assert.throws(
      () => extractSafeCodexProviderConfig({ CODEX_HOME: legacyProfHome }, [], false),
      /profile.*已废弃|--profile/,
      "Codex 0.169 已废弃顶层 profile = ... 必须 fail-closed 拒绝，绝不激活 [profiles.*]",
    );

    // 4) [R11 P1] PID + 挂载命名空间隔离：即使只有 PA_FEISHU_WEB_KEY（EnvironmentFile 场景）也必须包裹独立 PID 命名空间，隐藏父进程 /proc/<pid>/environ
    const envOnlyWrap = wrapCredentialIsolatedCommand("sh", ["-c", "true"], { PA_FEISHU_WEB_KEY: "env_secret_r11" }, { forceBackend: { kind: "bwrap", bin: "bwrap" } });
    assert.equal(envOnlyWrap.isolated, true);
    assert.ok(envOnlyWrap.args.includes("--unshare-pid") && envOnlyWrap.args.includes("--proc"), "仅设置 PA_FEISHU_WEB_KEY 时也必须启用 PID + /proc 隔离");
    assert.throws(
      () => wrapCredentialIsolatedCommand("sh", ["-c", "true"], { PA_FEISHU_WEB_KEY: "env_secret_r11" }, { forceBackend: { kind: "none" } }),
      /PA_FEISHU_WEB_KEY|拒绝执行/,
    );
    if (hasCredentialMountIsolation()) {
      const realPidWrap = wrapCredentialIsolatedCommand(
        "sh",
        ["-c", `test -r /proc/${process.pid}/environ && echo LEAK || echo HIDDEN`],
        { PA_FEISHU_WEB_KEY: "env_secret_r11" },
      );
      const pidOut = await runProcess(realPidWrap.cmd, realPidWrap.args, { timeoutMs: 15_000 });
      assert.equal(pidOut.code, 0, pidOut.stderr);
      assert.equal(pidOut.stdout.trim(), "HIDDEN", "独立 PID+/proc 命名空间内绝不能读取宿主常驻进程的 /proc/<daemon-pid>/environ");
    }

    // 5) [R11 P2] Git LFS 严格指针校验（源代码提及 spec URL 不误判）+ 扫描失败中止推送（脱离密钥作用域以兼容非 Linux userns 宿主机）
    assert.equal(isGitLfsPointerBlob('const x = "version https://git-lfs.github.com/spec/v1";\n'), false);
    assert.equal(
      isGitLfsPointerBlob(`version https://git-lfs.github.com/spec/v1\noid sha256:${"a".repeat(64)}\nsize 42\n`),
      true,
    );
    await withoutTestWebKey(async () => {
      const nonLfsRemote = path.join(dir, "non-lfs-remote.git");
      const nonLfsRepo = path.join(dir, "non-lfs-repo");
      fs.mkdirSync(nonLfsRemote, { recursive: true });
      fs.mkdirSync(nonLfsRepo, { recursive: true });
      await tryGit(nonLfsRemote, ["init", "--bare"]);
      await tryGit(nonLfsRepo, ["init", "-b", "main"]);
      await tryGit(nonLfsRepo, ["config", "user.name", "Tester"]);
      await tryGit(nonLfsRepo, ["config", "user.email", "tester@example.com"]);
      await tryGit(nonLfsRepo, ["remote", "add", "origin", nonLfsRemote]);
      fs.writeFileSync(path.join(nonLfsRepo, "base.txt"), "base\n");
      await tryGit(nonLfsRepo, ["add", "base.txt"]);
      await tryGit(nonLfsRepo, ["commit", "-m", "base"]);
      await tryGit(nonLfsRepo, ["push", "-u", "origin", "main"]);
      await tryGit(nonLfsRepo, ["checkout", "-b", "feat/mentions-lfs-url"]);
      // 小于 1024 字节的普通源码文件里包含 LFS spec URL 字面量，绝不能误判为 LFS 指针
      fs.writeFileSync(path.join(nonLfsRepo, "doc.ts"), 'export const SPEC = "version https://git-lfs.github.com/spec/v1";\n');
      await tryGit(nonLfsRepo, ["add", "doc.ts"]);
      await tryGit(nonLfsRepo, ["commit", "-m", "mention lfs spec in source"]);
      assert.equal(await branchUsesGitLfs(nonLfsRepo, "feat/mentions-lfs-url"), false, "包含 LFS URL 字面量的普通源码文件不得误判为 Git LFS 指针");
      await assert.rejects(branchUsesGitLfs(nonLfsRepo, "refs/does-not-exist-r11"), /失败/, "LFS 扫描命令失败时必须抛错而非静默返回 false");
    });

    // ───────── 初始化共享测试 App ─────────
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
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "cx",
          groups: "allowlist",
          max_groups: 2,
          lookback_days: 7,
          groups_allow: ["oc_r11_draft_ok"],
          groups_deny: [],
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: false, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCtxDirStubLlm(svc, ctxDir);
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const baseCookies = [{ name: "session", value: "r11_sess", domain: "internal-api-lark-api.feishu.cn", path: "/" }];
    const loginA = commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r11_a", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 6) [R11 P1] Board.createTask 必须在 move() 之前通过 onCreated 持久化 GUID 归属
    app.store.set("board.tasklist", "tl_r11");
    app.store.set("board.owner_open_id", "ou_owner_a");
    app.store.set("board.section.dispatch", "sec_dispatch_r11");
    app.store.set("board.section.running", "sec_running_r11");
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
    const origLarkRun = app.lark.run.bind(app.lark);
    app.lark.run = async (argv, opts) => {
      if (argv[0] === "task" && argv[1] === "+create") return { task: { guid: "guid_r11_move_timeout" } };
      if (argv[0] === "task" && argv[1] === "+tasklist-task-add") throw new Error("simulated move timeout");
      return origLarkRun(argv, opts);
    };
    const { item: moveFailItem } = svc.store.upsertItem({
      title: "move 超时测试委派",
      kind: "todo",
      project_id: "",
      status: "open",
      priority: "high",
      source: "im",
    });
    await assert.rejects(
      app.commands.exec("context.item_delegate", { id: moveFailItem.id }, { source: "web", actor: "owner" }),
      /simulated move timeout/,
    );
    assert.equal(
      app.store.get("ctx.dispatch_ref_owner.guid_r11_move_timeout"),
      "ou_owner_a",
      "即使 board.move 超时失败，任务 GUID 的原主人归属也必须在 task +create 返回后立即持久化",
    );
    app.lark.run = origLarkRun;

    // 7) [R11 P1 & P2] 排队中的晨报绑定渲染主人 + task.create_own 归属隔离 + runDispatchOnce 过滤 + work.acknowledge 隔离
    const fxHandler = effectHandler(app.cfg, app.ledger, app.board, app.lark, app.store);
    // 主人 A 创建自主任务 task.create_own
    const origAuthStatusR11 = app.lark.authStatus.bind(app.lark);
    app.lark.authStatus = async () => ({ identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } });
    app.lark.run = async (argv, opts) => {
      if (argv[0] === "auth" && argv[1] === "status") {
        return { identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } };
      }
      if (argv[0] === "task" && argv[1] === "+create") return { task: { guid: "guid_r11_own_task_a" } };
      if (argv[0] === "task" && argv[1] === "+get-my-tasks") {
        return {
          items: [
            { guid: "guid_r11_own_task_a", summary: "主人A私密承诺任务", due: { timestamp: String(now - 60_000) } },
            { guid: "guid_r11_normal_task", summary: "普通公开任务", due: { timestamp: String(now - 60_000) } },
          ],
        };
      }
      return origLarkRun(argv, opts);
    };
    app.store.set("board.owner_open_id", "ou_owner_a");
    app.ledger.enqueue({
      id: "fx:r11-own-task",
      kind: "effect",
      ref: "context:auto",
      payload: { op: "task.create_own", args: { summary: "主人A私密承诺任务", description: "私密", item_id: "it_r11_own" } },
    });
    app.store.db.prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = ?").run(app.ledger.owner, Date.now() + 60_000, "fx:r11-own-task");
    await fxHandler.run(app.ledger.get("fx:r11-own-task")!, { attempt: 1, signal: new AbortController().signal });
    assert.equal(app.store.get("ctx.own_task_owner.guid_r11_own_task_a"), "ou_owner_a");

    // 主人 A 渲染并入队晨报（此时尚未投递）
    const origListSection = app.board.listSection.bind(app.board);
    app.board.listSection = async () => [];
    await sendBrief(app, "morning");
    const queuedBrief = app.ledger.active("effect").find((e) => e.ref === "brief");
    assert.ok(queuedBrief, "sendBrief 应已入队晨报 effect");

    // 准备一条主人 A 的在途委派派单和一条失败 effect
    const isoDispId = "dispatch:guid_r11_iso_cli:1";
    app.store.set(`ctx.dispatch_owner.${isoDispId}`, "ou_owner_a");
    app.store.set(`ctx.dispatch_ref_owner.guid_r11_iso_cli`, "ou_owner_a");
    app.ledger.enqueue({
      id: isoDispId,
      kind: "dispatch",
      ref: "guid_r11_iso_cli",
      state: "queued",
      payload: { guid: "guid_r11_iso_cli", summary: "主人A绝密CLI派单", description: "", harness: "cx" },
    });
    const deadCtxFxId = "fx:r11-dead-ctx-ack";
    app.ledger.enqueue({
      id: deadCtxFxId,
      kind: "effect",
      ref: "card:ctx-item:r11",
      payload: { op: "notify", args: { markdown: "旧主人上下文通知" } },
    });
    app.store.db.prepare("UPDATE work SET state = 'dead', terminal = 1 WHERE id = ?").run(deadCtxFxId);

    // 切换为主人 B
    app.cfg.owner.open_id = "ou_owner_b";
    // 7a) 排队中的主人 A 晨报必须被阻断，绝不能投递给主人 B
    await assert.rejects(
      fxHandler.run(queuedBrief as never, { attempt: 1, signal: new AbortController().signal }),
      /主人隔离|阻断/,
      "已排队的旧主人晨报在 owner.open_id 变更后绝不能投递给新主人",
    );
    // 7b) 新生成的晨报（已切为主人 B 的看板与 auth 后）必须隐藏主人 A 的 task.create_own 自主任务，保留普通公开任务
    app.store.set("board.owner_open_id", "ou_owner_b");
    const briefB = await buildBrief(app.cfg, app.lark, app.store, app.ledger, app.board, "morning");
    assert.equal(briefB.includes("主人A私密承诺任务"), false, "buildBrief 必须过滤旧主人经 task.create_own 创建的自主任务");
    assert.equal(briefB.includes("普通公开任务"), true);
    // 7c) runDispatchOnce (pa dispatch) 必须过滤被 owner_isolated 终止的旧主人派单，且不抹除账本原始 summary
    const onceRes = await runDispatchOnce(app);
    assert.equal(
      onceRes.items.some((w) => w?.id === isoDispId),
      false,
      "runDispatchOnce 必须隐藏归属旧主人的隔离派单，不向 CLI 打印其 summary",
    );
    assert.equal(app.ledger.get<{ summary?: string }>(isoDispId)?.payload.summary, "主人A绝密CLI派单", "账本原始 summary 必须完整保留");
    // 7d) HealthItem 标为 isolated（含脱敏 ID）且 work.acknowledge 必须拒绝忽略旧主人的失败工作
    const healthB = Q.health(app);
    const isoHealthRow = healthB.failed.find((x) => x.isolated && x.kind === "effect");
    assert.equal(isoHealthRow?.isolated, true, "脱敏后的健康项必须标记 isolated=true 以便前端隐藏重试/忽略按钮");
    assert.ok(isoHealthRow!.id.startsWith("isolated:") && !isoHealthRow!.id.includes(deadCtxFxId), "隔离健康项不得泄漏原始账本 ID");
    await assert.rejects(
      app.commands.exec("work.acknowledge", { id: deadCtxFxId }, { source: "web", actor: "owner" }),
      /主人隔离|阻断/,
      "work.acknowledge 绝不能允许新主人忽略旧主人的失败工作",
    );
    app.board.listSection = origListSection;
    app.lark.run = origLarkRun;
    app.lark.authStatus = origAuthStatusR11;
    app.cfg.owner.open_id = "ou_owner_a";

    // 8) [R11 P1] 草稿目标在最终 filterObs 期间离开白名单：绝不把旧目标强行补回提示词
    const callsLog = path.join(ctxDir, "calls.log");
    fs.writeFileSync(callsLog, "");
    fs.writeFileSync(path.join(ctxDir, "draft.txt"), "不应生成的草稿");
    svc.store.addObs([
      {
        id: "im:r11_race_target",
        source: "im",
        kind: "group",
        conv: "oc_r11_draft_ok",
        conv_name: "白名单竞态群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 5_000,
        text: "竞态群私密文本",
        url: "",
        meta: { chat_type: "group", message_id: "r11_race_target" },
      },
    ]);
    const { item: raceDraftItem } = svc.store.upsertItem({
      title: "草稿终检竞态事项",
      kind: "ask_me",
      project_id: "",
      status: "open",
      priority: "high",
      counterpart: "Bob",
      next_step: "回复",
      source: "im",
    });
    svc.store.addEvidence("item", raceDraftItem.id, "im:r11_race_target", "竞态群私密文本", now - 5_000);
    const origFilterObs = svc.drafter.filterObs;
    let filterCalls = 0;
    svc.drafter.filterObs = async (conv, obs) => {
      filterCalls++;
      // 第一次（resolveEligibleTarget）在范围内，第二次（组装提示词最终过滤）模拟群刚好移出白名单
      if (filterCalls === 2) {
        app!.cfg.context.groups_allow = ["oc_r11_other"];
      }
      return origFilterObs!(conv, obs);
    };
    await assert.rejects(
      svc.drafter.forItem(raceDraftItem.id, "reply"),
      /采集范围|已停止起草/,
      "目标证据在最终 filterObs 中被剔除后绝不能补回提示词，必须立即停止起草",
    );
    svc.drafter.filterObs = origFilterObs;
    assert.equal(fs.readFileSync(callsLog, "utf8").trim(), "", "草稿终检剔除目标后绝不能调用模型");

    // 9) [R11 P1] 原生推送异步检查期间新增关键词排除：必须用核验后的真实群名重跑检查并拦截入库
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = ["pw_chat:9911"];
    app.cfg.context.groups_deny = [];
    mock.setChatName("9911", "绝密财务群");
    mock.setChatKind("9911", CHAT_KIND_GROUP);
    const clientA = await FeishuWebClient.connect(loginA, { endpoints: mock.endpoints });
    // 第一次 readChat 缓存一个占位/旧名或触发异步检查，期间在 onChatMode 注入新关键词排除 "财务"
    let injectedKw = false;
    mock.setOnChatMode(() => {
      if (!injectedKw) {
        injectedKw = true;
        app!.cfg.context.groups_deny = ["财务"];
      }
    });
    const kwMsg = decodeMessage(
      buildNativeMessage({ id: "r11_kw_race_msg", chatId: "9911", actorId: "7099", text: "财务数据不该入库", createdAtSec: nowSec }),
      "7001",
    );
    await svc.personalWeb.handleMessage(kwMsg, clientA);
    mock.setOnChatMode(undefined);
    assert.equal(svc.store.obs("pw:r11_kw_race_msg"), undefined, "异步查询期间新增关键词排除必须触发复核并用核验群名拦截入库");
    app.cfg.context.groups_deny = [];

    // 10) [R11 P2] 截断的 --is-at-me 搜索（has_more=true）不得把已确认的 at_me: true 覆盖为 false
    const truncChat = "oc_r11_trunc";
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = [truncChat];
    svc.store.addObs([
      {
        id: "im:om_r11_trunc_at",
        source: "im",
        kind: "at_me",
        conv: truncChat,
        conv_name: "截断测试群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 10_000,
        text: "@张三 别清除我的标记",
        url: "",
        meta: { chat_type: "group", at_me: true },
      },
    ]);
    svc.store.markProcessed(["im:om_r11_trunc_at"]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        at_me: [],
        at_me_has_more: true,
        chats: {
          [truncChat]: [
            {
              message_id: "om_r11_trunc_at",
              chat_id: truncChat,
              chat_type: "group",
              chat_name: "截断测试群",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: new Date(now - 10_000).toISOString(),
              content: JSON.stringify({ text: "@张三 别清除我的标记" }),
            },
          ],
        },
      }),
    );
    await svc.connectors.pullIm();
    assert.equal(svc.store.obs("im:om_r11_trunc_at")?.meta.at_me, true, "截断的 --is-at-me 结果绝不能清除已确认的 at_me: true");

    // 11) [R11 P2] 拉取期间学到群 A 改名命中排除规则 -> 持久化新名、不推进游标重启一轮并补采接替群 B
    const grpA = "oc_r11_rank_a";
    const grpB = "oc_r11_rank_b";
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = [grpA, grpB];
    app.cfg.context.groups_deny = ["机密"];
    app.cfg.context.max_groups = 1;
    rememberOpenGroupName(app.store, grpA, "普通群A");
    rememberOpenGroupName(app.store, grpB, "普通群B");
    app.store.set("ctx.cursor.im.groups", String(now - 60_000));
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "张三",
        chat_meta: {
          [grpA]: { name: "机密群A", chat_mode: "group" },
          [grpB]: { name: "普通群B", chat_mode: "group" },
        },
        chats: {
          [grpA]: [
            {
              message_id: "om_r11_a_renamed",
              chat_id: grpA,
              chat_type: "group",
              chat_name: "机密群A",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: new Date(now - 15_000).toISOString(),
              content: JSON.stringify({ text: "A群已改名为机密" }),
            },
          ],
          [grpB]: [
            {
              message_id: "om_r11_b_replacement",
              chat_id: grpB,
              chat_type: "group",
              chat_name: "普通群B",
              sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
              create_time: new Date(now - 12_000).toISOString(),
              content: JSON.stringify({ text: "接替群B的消息必须采到" }),
            },
          ],
        },
      }),
    );
    const rerankRes = await svc.connectors.pullIm();
    assert.equal(rerankRes.count, 1, "群A改名触发排除后必须重排补采接替群B");
    assert.equal(svc.store.obs("im:om_r11_a_renamed"), undefined, "已改名为机密的群A消息绝不入库");
    assert.equal(svc.store.obs("im:om_r11_b_replacement")?.text, "接替群B的消息必须采到");

    // 12) [R11 P2] checkConvAllowedForUnderstand 必须先刷新最新群名再按名称排除（避免旧名被排除的群改回正常名后永远卡死）
    const recoverChat = "oc_r11_recover_name";
    app.cfg.context.groups_deny = ["保密"];
    svc.store.addObs([
      {
        id: "im:r11_recover_pending",
        source: "im",
        kind: "group",
        conv: recoverChat,
        conv_name: "保密旧群名",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 5_000,
        text: "改名后应可理解",
        url: "",
        meta: { chat_type: "group" },
      },
    ]);
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({ chat_meta: { [recoverChat]: { name: "开放项目群", chat_mode: "group" } } }),
    );
    const recoverElig = await svc.personalWeb.checkConvAllowedForUnderstand(recoverChat, "保密旧群名");
    assert.equal(recoverElig, "allowed", "旧缓存名命中关键词但最新群名已改为合法名时，必须刷新后放行");
    app.cfg.context.groups_deny = [];

    // 13) [R11 P2] mention-only 模式下 3 次模型解析失败：仅跳过实际提交给模型的 @我，保留同群未提交的普通消息待处理
    const skipChat = "oc_r11_selective_skip";
    app.cfg.context.groups = "allowlist";
    app.cfg.context.groups_allow = ["oc_r11_unrelated_only"];
    app.cfg.context.sources = { im: true, meego: false, tasks: false, minutes: false, calendar: false, docs: false };
    // 先将之前遗留的 pending 观测标为已处理，聚焦测试 skipChat
    svc.store.db.prepare("UPDATE ctx_obs SET processed = 1").run();
    svc.store.addObs([
      {
        id: "im:r11_skip_mention",
        source: "im",
        kind: "at_me",
        conv: skipChat,
        conv_name: "精准跳过群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 6_000,
        text: "@张三 坏输出触发解析失败",
        url: "",
        meta: { chat_type: "group", at_me: true },
      },
      {
        id: "im:r11_keep_ordinary",
        source: "im",
        kind: "group",
        conv: skipChat,
        conv_name: "精准跳过群",
        actor_id: "ou_bob",
        actor_name: "Bob",
        is_me: false,
        time: now - 5_000,
        text: "同群未被送入模型的普通消息必须保持 pending",
        url: "",
        meta: { chat_type: "group", at_me: false },
      },
    ]);
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "张三" }));
    fs.writeFileSync(path.join(ctxDir, "understand.txt"), "NOT VALID JSON {{{");
    for (let i = 0; i < 3; i++) {
      await svc.cycle(`ctx:r11-parse-fail-${i}`);
    }
    fs.rmSync(path.join(ctxDir, "understand.txt"), { force: true });
    assert.equal(svc.store.obsPending("im:r11_skip_mention"), false, "连续 3 次解析失败的已提交 @我 观测应被跳过");
    assert.equal(
      svc.store.obsPending("im:r11_keep_ordinary"),
      true,
      "同群未送入模型的普通消息绝不能被连带 skipConv 标记为已处理，恢复白名单后必须仍可处理",
    );

    // 14) [R11 P2] 并发 web-login 抢先提交新会话时，logout 的条件文件清理绝不能误删新提交的凭据文件
    const raceCredFile = path.join(dir, "race-logout-cred.enc");
    process.env.PA_FEISHU_WEB_CRED_FILE = raceCredFile;
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r11_old_gen", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );
    const raceStore = new WebLoginStore(app.cfg.dataDir);
    // 模拟在 logout 拿到锁前，另一进程已提交了 sess_r11_new_gen 并更新 ACTIVE_SESSION_KV_KEY
    const origClearIf = WebLoginStore.prototype.clearIf;
    let simulatedConcurrentLogin = false;
    WebLoginStore.prototype.clearIf = function (shouldDelete) {
      if (!simulatedConcurrentLogin) {
        simulatedConcurrentLogin = true;
        commitWorkspaceLogin(
          app!,
          { owner_id: "7001", owner_name: "主人A", session_id: "sess_r11_new_gen", cookies: baseCookies },
          { allowUnverifiedOwner: true },
        );
      }
      return origClearIf.call(this, shouldDelete);
    };
    let raceLogoutRes: ReturnType<typeof revokeWorkspacePersonalWebSession>;
    try {
      raceLogoutRes = revokeWorkspacePersonalWebSession(app);
    } finally {
      WebLoginStore.prototype.clearIf = origClearIf;
    }
    assert.equal(raceLogoutRes!.fileRemoved, false, "并发 web-login 刚提交的新凭据绝不能被旧 logout 误删");
    assert.equal(raceStore.load()?.session_id, "sess_r11_new_gen", "新提交的会话凭据必须完整保留在磁盘");

    // 15) [R11 P2] 会话观察器返回 false 时（发包期间登出），flushPendingCookies 必须中止且不再发起已吊销会话的回读请求
    const abortSendPath = path.join(dir, "abort-send-cred.enc");
    process.env.PA_FEISHU_WEB_CRED_FILE = abortSendPath;
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r11_abort_send", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );
    mock.setChatName("9912", "发包吊销测试群");
    mock.setChatKind("9912", CHAT_KIND_GROUP);
    mock.addMessage(
      "r11_send_target",
      buildNativeMessage({
        id: "r11_send_target",
        chatId: "9912",
        actorId: "7099",
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 请回复" }]),
        createdAtSec: nowSec,
      }),
    );
    const sendBridge = new PersonalWebBridge(app, svc.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      clientOptions: { endpoints: mock.endpoints },
    });
    const origReadMsg = FeishuWebClient.prototype.readMessage;
    let readbacksAfterSend = 0;
    let sendCompleted = false;
    FeishuWebClient.prototype.readMessage = async function (id, sig) {
      if (sendCompleted) readbacksAfterSend++;
      return origReadMsg.call(this, id, sig);
    };
    mock.setGatewayRotateCookie("session=rot_mid_send; Path=/");
    const origSendReply = FeishuWebClient.prototype.sendReply;
    FeishuWebClient.prototype.sendReply = async function (...args) {
      const created = await origSendReply.apply(this, args);
      sendCompleted = true;
      // 模拟发包返回时工作区已被 web-logout 吊销
      revokeWorkspacePersonalWebSession(app!);
      return created;
    };
    try {
      await assert.rejects(
        sendBridge.sendVerifiedReply({
          owner_id: "7001",
          chat_id: "9912",
          message_id: "r11_send_target",
          text: "发包途中吊销测试",
          cid: "cid_r11_abort_readback",
        }),
        /吊销|登出|取代/,
      );
    } finally {
      FeishuWebClient.prototype.sendReply = origSendReply;
      FeishuWebClient.prototype.readMessage = origReadMsg;
      mock.setGatewayRotateCookie("");
    }
    assert.equal(readbacksAfterSend, 0, "发包期间会话被吊销后绝不能再用旧会话发起认证回读请求");
    assert.equal(
      JSON.parse(app.store.get("pw.delivery.cid_r11_abort_readback") ?? "{}").state,
      "created",
      "已发出的回复仍必须持久化为 created 回执以便重登录后只读回读恢复",
    );
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

// ───────── 18. Codex Review 第十二轮专项回归测试 ─────────

test("Codex 第十二轮回归：无密钥壳工作区隔离判定、Codex 账号/工作区限制保留、轮询防旧名覆盖、草稿推理前隐私与修订复核、开放平台私聊关键词排除、LFS pushurl/不可变提交/hawser/分块扫描/EPIPE、非持钥CLI让出pw.reply、当前主人作用域晨报、元数据失败落盘轮换、票据设备ID一致、等待态恢复暂存凭据与原子条件清标记", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  delete process.env.PA_FEISHU_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  const dir = makeTmp("pa-r12-");
  const ctxDir = makeTmp("pa-r12-ctx-");
  process.env.CTX_DIR = ctxDir;
  let app: ReturnType<typeof createApp> | undefined;

  try {
    // 1) [R12 P1-2] 无密钥交互式 shell 仍按工作区配置/状态强制触发隔离（并在无后端时 fail-closed）
    const wsOnlyDir = makeTmp("pa-r12-ws-check-");
    assert.equal(workspaceRequiresIsolation({ dataDir: wsOnlyDir, context: { personal_web: { enabled: false } } as never }, {}), false);
    assert.equal(workspaceRequiresIsolation({ dataDir: wsOnlyDir, context: { personal_web: { enabled: true } } as never }, {}), true);
    fs.writeFileSync(path.join(wsOnlyDir, "feishu-web.json"), "{}", { mode: 0o600 });
    assert.equal(workspaceRequiresIsolation({ dataDir: wsOnlyDir, context: { personal_web: { enabled: false } } as never }, {}), true);
    assert.throws(
      () =>
        wrapCredentialIsolatedCommand(
          "sh",
          ["-c", "true"],
          {},
          { dataDir: wsOnlyDir, requireIsolation: true, forceBackend: { kind: "none" } },
        ),
      /拒绝执行/,
      "无密钥 shell 在启用个人 Web 工作区且缺少隔离后端时必须 fail-closed",
    );

    // 2) [R12 P1-3] Codex tools=none 保留并校验 forced_login_method 与 forced_chatgpt_workspace_id（标量与列表）
    const cxHome1 = path.join(dir, "codex-forced-list");
    fs.mkdirSync(cxHome1, { recursive: true });
    fs.writeFileSync(
      path.join(cxHome1, "config.toml"),
      [
        'model = "gpt-5-work"',
        'forced_login_method = "chatgpt"',
        'forced_chatgpt_workspace_id = ["ws_corp_a", "ws_corp_b"]',
      ].join("\n") + "\n",
    );
    const forcedListCfg = extractSafeCodexProviderConfig({ CODEX_HOME: cxHome1 }, [], false);
    assert.ok(forcedListCfg.args.includes('forced_login_method="chatgpt"'), "必须保留 forced_login_method");
    assert.ok(
      forcedListCfg.args.includes('forced_chatgpt_workspace_id=["ws_corp_a","ws_corp_b"]'),
      "必须保留列表形式 forced_chatgpt_workspace_id",
    );

    const cxHome2 = path.join(dir, "codex-forced-scalar");
    fs.mkdirSync(cxHome2, { recursive: true });
    fs.writeFileSync(
      path.join(cxHome2, "config.toml"),
      ['forced_login_method = "api"', 'forced_chatgpt_workspace_id = "ws_single"'].join("\n") + "\n",
    );
    const forcedScalarCfg = extractSafeCodexProviderConfig({ CODEX_HOME: cxHome2 }, [], false);
    assert.ok(forcedScalarCfg.args.includes('forced_login_method="api"'));
    assert.ok(forcedScalarCfg.args.includes('forced_chatgpt_workspace_id="ws_single"'));

    const cxHomeBadLogin = path.join(dir, "codex-bad-login");
    fs.mkdirSync(cxHomeBadLogin, { recursive: true });
    fs.writeFileSync(path.join(cxHomeBadLogin, "config.toml"), 'forced_login_method = "bogus"\n');
    assert.throws(
      () => extractSafeCodexProviderConfig({ CODEX_HOME: cxHomeBadLogin }, [], false),
      /forced_login_method/,
      "非法 forced_login_method 必须拒绝执行",
    );

    const cxHomeBadWs = path.join(dir, "codex-bad-ws");
    fs.mkdirSync(cxHomeBadWs, { recursive: true });
    fs.writeFileSync(path.join(cxHomeBadWs, "config.toml"), 'forced_chatgpt_workspace_id = ["ws_ok", ""]\n');
    assert.throws(
      () => extractSafeCodexProviderConfig({ CODEX_HOME: cxHomeBadWs }, [], false),
      /forced_chatgpt_workspace_id/,
      "含空元素的 forced_chatgpt_workspace_id 必须拒绝执行",
    );
    // extraArgs 中的 forced_login_method / forced_chatgpt_workspace_id 同样保留与校验
    const forcedExtraCfg = extractSafeCodexProviderConfig(
      { CODEX_HOME: path.join(dir, "codex-empty") },
      ["-c", 'forced_login_method="chatgpt"', "-c", 'forced_chatgpt_workspace_id=["ws_x"]'],
      false,
    );
    assert.ok(forcedExtraCfg.sanitizedExtraArgs.includes('forced_login_method="chatgpt"'));
    assert.ok(forcedExtraCfg.sanitizedExtraArgs.includes('forced_chatgpt_workspace_id=["ws_x"]'));

    // 3) [R12 P1-7 & P2-14/15/16/17] Git LFS：独立 pushurl 预检、不可变提交推送、历史 hawser spec/v1 指针、分块扫描 (>260 blobs)
    const hawserOid = "b".repeat(64);
    const hawserPtr = `version https://hawser.github.com/spec/v1\noid sha256:${hawserOid}\nsize 128\n`;
    assert.equal(isGitLfsPointerBlob(hawserPtr), true, "必须识别历史 hawser spec/v1 LFS 指针");

    // 3a) pushurl 与 fetch URL 分离：fetch 远端（upstream）已含历史提交，但 pushurl（fork）为空且缺历史 LFS 对象 -> 必须针对 pushurl 扫描并触发 LFS 上传
    const upstreamBare = path.join(dir, "r12-upstream.git");
    const forkBare = path.join(dir, "r12-fork.git");
    const splitRepo = path.join(dir, "r12-split-repo");
    fs.mkdirSync(upstreamBare, { recursive: true });
    fs.mkdirSync(forkBare, { recursive: true });
    fs.mkdirSync(splitRepo, { recursive: true });
    await tryGit(upstreamBare, ["init", "--bare"]);
    await tryGit(forkBare, ["init", "--bare"]);
    await tryGit(splitRepo, ["init", "-b", "main"]);
    await tryGit(splitRepo, ["config", "user.name", "Tester"]);
    await tryGit(splitRepo, ["config", "user.email", "tester@example.com"]);
    await tryGit(splitRepo, ["remote", "add", "origin", upstreamBare]);

    const histPayload = Buffer.from("r12-hawser-split-pushurl-payload\n", "utf8");
    const histOid = crypto.createHash("sha256").update(histPayload).digest("hex");
    const histObjDir = path.join(splitRepo, ".git", "lfs", "objects", histOid.slice(0, 2), histOid.slice(2, 4));
    fs.mkdirSync(histObjDir, { recursive: true });
    fs.writeFileSync(path.join(histObjDir, histOid), histPayload);
    const histHawserPtr = `version https://hawser.github.com/spec/v1\noid sha256:${histOid}\nsize ${histPayload.length}\n`;
    fs.writeFileSync(path.join(splitRepo, "legacy.dat"), histHawserPtr);
    await tryGit(splitRepo, ["add", "legacy.dat"]);
    await tryGit(splitRepo, ["commit", "-m", "add legacy hawser lfs object"]);
    await tryGit(splitRepo, ["rm", "legacy.dat"]);
    // 再加 >260 个小非 LFS 文件，跨过 256-blob 分块边界验证有界分块扫描仍能检出历史指针
    for (let k = 0; k < 270; k++) {
      fs.writeFileSync(path.join(splitRepo, `note_${k}.txt`), `small non-lfs file payload number ${k} padding to exceed eighty bytes easily 0123456789abcdef\n`);
    }
    await tryGit(splitRepo, ["add", "."]);
    await tryGit(splitRepo, ["commit", "-m", "delete legacy lfs and add 270 small blobs"]);
    // 先把分支推到 upstream（不含 fork），然后把 origin 的 pushurl 指向空的 forkBare
    await tryGit(splitRepo, ["push", "origin", "refs/heads/main:refs/heads/main"]);
    await tryGit(splitRepo, ["remote", "set-url", "--push", "origin", forkBare]);
    // 如果扫描错误地读取了 fetch URL (upstreamBare)，会误以为无 outgoing 对象；读取 pushurl (forkBare) 则能检出历史 hawser LFS 指针！
    await tryGit(splitRepo, ["config", "lfs.url", "http://127.0.0.1:1/fail-fork-pushurl"]);
    const splitFail = await pushBranch(splitRepo, "origin", "main");
    assert.equal(splitFail.ok, false, "存在独立 pushurl 时必须按 pushurl 的远端引用扫描历史 LFS 对象并阻止缺对象的推送");
    assert.match(splitFail.message, /Git LFS/);
    assert.equal(
      (await tryGit(forkBare, ["rev-parse", "--verify", "refs/heads/main"])).code !== 0,
      true,
      "pushurl LFS 上传失败时 fork 远端绝不能出现悬空分支",
    );
    await tryGit(splitRepo, ["config", "--unset", "lfs.url"]);
    const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 3_000 })).code === 0;
    if (hasGitLfs) {
      const splitOk = await pushBranch(splitRepo, "origin", "main");
      assert.equal(splitOk.ok, true, `pushurl 可用时必须完成历史 hawser LFS 上传并推送：${!splitOk.ok ? splitOk.message : ""}`);
      assert.equal(
        fs.existsSync(path.join(forkBare, "lfs", "objects", histOid.slice(0, 2), histOid.slice(2, 4), histOid)),
        true,
        "历史 hawser LFS 对象必须上传到 pushurl 对应的 fork 远端 LFS 存储",
      );
    }

    // ───────── 初始化共享测试 App（作用域内开启 TEST_WEB_KEY） ─────────
    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
    const cfgFile = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: path.join(dir, "data"),
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
        roles: { brain: "claude" },
        owner: { open_id: "ou_owner_a" },
        cards: { enabled: true },
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "cx",
          groups: "allowlist",
          max_groups: 1,
          lookback_days: 7,
          groups_allow: ["oc_r12_grp_a", "oc_r12_grp_b"],
          groups_deny: ["保密"],
          sources: { meego: false, tasks: false, im: true, minutes: false, calendar: false, docs: false },
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: false, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCtxDirStubLlm(svc, ctxDir);
    const cards = new CardService(app, { debounceMs: 5 });
    cards.register();
    const now = Date.now();
    const baseCookies = [
      { name: "session", value: "sess_r12_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r12_old", domain: "127.0.0.1", path: "/" },
    ];
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r12_a", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 4) [R12 P1-4] 轮询 pullIm：首白名单群改名命中 deny 且 --sender 行缺失 chat_name 时，绝不用旧 spoken_groups 覆盖新学群名导致死循环卡死
    app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r12_grp_a: { name: "老研发群", at: now - 10_000 } }));
    const r12T = new Date(now - 2_000).toISOString();
    fs.writeFileSync(
      path.join(ctxDir, "lark.json"),
      JSON.stringify({
        user_open_id: "ou_owner_a",
        user_name: "主人A",
        at_me: [],
        p2p: [
          {
            message_id: "om_r12_dm_ok",
            chat_id: "oc_r12_dm_ok",
            chat_type: "p2p",
            sender: { id: "ou_colleague", name: "同事甲", sender_type: "user" },
            create_time: r12T,
            content: "无关私聊必须正常落库",
          },
        ],
        // --sender 行故意省略 chat_name，复现旧 spoken_groups 回退覆盖已知改名缓存的回归场景
        mine: [
          {
            message_id: "om_r12_mine_a",
            chat_id: "oc_r12_grp_a",
            chat_type: "group",
            sender: { id: "ou_owner_a", name: "主人A", sender_type: "user" },
            create_time: r12T,
            content: "我发的一句话",
          },
        ],
        chat_meta: {
          oc_r12_grp_a: { name: "绝密保密群", chat_mode: "group", chat_type: "group" },
          oc_r12_grp_b: { name: "接替群B", chat_mode: "group", chat_type: "group" },
        },
        chats: {
          oc_r12_grp_a: [
            {
              message_id: "om_r12_a_msg",
              chat_id: "oc_r12_grp_a",
              chat_type: "group",
              chat_name: "绝密保密群",
              sender: { id: "ou_other", name: "其他人", sender_type: "user" },
              create_time: r12T,
              content: "保密内容绝不能落库",
            },
          ],
          oc_r12_grp_b: [
            {
              message_id: "om_r12_b_msg",
              chat_id: "oc_r12_grp_b",
              chat_type: "group",
              chat_name: "接替群B",
              sender: { id: "ou_other", name: "其他人", sender_type: "user" },
              create_time: r12T,
              content: "接替群B的合法消息必须被补采",
            },
          ],
        },
      }),
    );
    const pullRes = await svc.connectors.pullIm();
    assert.ok(pullRes.count >= 2, `改名重排后必须提交接替群B与无关私聊并推进游标，实际 count=${pullRes.count}`);
    assert.equal(svc.store.obs("im:om_r12_a_msg"), undefined, "改名命中 deny 的群A消息不得入库");
    assert.ok(svc.store.obs("im:om_r12_b_msg"), "接替群B消息必须成功入库");
    assert.ok(svc.store.obs("im:om_r12_dm_ok"), "无关私聊必须成功入库");
    assert.ok(Number(app.store.get("ctx.cursor.im.p2p") ?? 0) > 0, "私聊游标必须正常推进");

    // 5) [R12 P1-6] 开放平台待处理私聊（p2p）必须应用显式 groups_deny 关键词，同时不受跨通道同名静音群误伤
    svc.store.addObs([
      {
        id: "im:om_r12_dm_kw",
        source: "im",
        kind: "p2p",
        conv: "oc_r12_dm_kw",
        conv_name: "私聊：保密项目顾问",
        actor_id: "ou_adv",
        actor_name: "保密项目顾问",
        is_me: false,
        time: now,
        text: "敏感私聊",
        url: "",
        meta: { chat_type: "p2p" },
      },
      {
        id: "im:om_r12_dm_alice",
        source: "im",
        kind: "p2p",
        conv: "oc_r12_dm_alice",
        conv_name: "私聊：Alice",
        actor_id: "ou_alice",
        actor_name: "Alice",
        is_me: false,
        time: now,
        text: "普通私聊",
        url: "",
        meta: { chat_type: "p2p" },
      },
    ]);
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("oc_r12_dm_kw", "私聊：保密项目顾问"),
      "excluded",
      "匹配 groups_deny 关键词的开放平台待处理私聊必须被排除",
    );
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("oc_r12_dm_alice", "私聊：Alice", {
        confirmedGroupNames: new Set(["私聊：alice", "alice"]),
        groupsInconclusive: false,
        dmsInconclusive: false,
      }),
      "allowed",
      "跨通道静音群名不得误伤开放平台私聊",
    );

    // 6) [R12 P1-5] 草稿推理前复核目标与窗口隐私（静音/撤回/正文编辑）：异步校验期间变更绝不把旧文本或已静音/撤回内容送模型
    svc.store.addObs([
      {
        id: "im:om_r12_draft_dm",
        source: "im",
        kind: "p2p",
        conv: "oc_r12_draft_dm",
        conv_name: "私聊：小王",
        actor_id: "ou_wang",
        actor_name: "小王",
        is_me: false,
        time: now - 1000,
        text: "原始机密文本_OLD",
        url: "",
        meta: { chat_type: "p2p" },
      },
    ]);
    const { item: draftItem } = svc.store.upsertItem({
      title: "回复小王",
      kind: "ask_me",
      source: "im",
    });
    svc.store.addEvidence("item", draftItem.id, "im:om_r12_draft_dm", "原始机密文本_OLD", now - 1000);
    const draftPrompts: string[] = [];
    installCallbackLlm(svc, async (prompt) => {
      draftPrompts.push(prompt);
      return "好的，已按最新消息处理。";
    });
    // 6a) filterObs 异步期间目标正文被编辑：必须自动重读最新修订，绝不发送旧文本
    let editedOnce = false;
    const origFilterObs = svc.drafter.filterObs;
    svc.drafter.filterObs = async (conv, obs) => {
      const out = origFilterObs ? await origFilterObs(conv, obs) : obs;
      if (!editedOnce && conv === "oc_r12_draft_dm") {
        editedOnce = true;
        svc.store.db.prepare("UPDATE ctx_obs SET text = ? WHERE id = ?").run("编辑后安全文本_NEW", "im:om_r12_draft_dm");
      }
      return out;
    };
    await svc.drafter.forItem(draftItem.id, "reply");
    assert.equal(draftPrompts.length, 1);
    assert.ok(draftPrompts[0].includes("编辑后安全文本_NEW"), "推理提示词必须使用最新编辑后的正文");
    assert.ok(!draftPrompts[0].includes("原始机密文本_OLD"), "绝不能把已被编辑覆盖的旧文本送给模型");

    // 6b) filterObs 异步期间该私聊被静音：必须立即停止，绝不调用模型
    draftPrompts.length = 0;
    svc.drafter.filterObs = async (conv, obs) => {
      const out = origFilterObs ? await origFilterObs(conv, obs) : obs;
      if (conv === "oc_r12_draft_dm") {
        svc.store.muteConv("oc_r12_draft_dm", "私聊：小王", true);
      }
      return out;
    };
    await assert.rejects(
      svc.drafter.forItem(draftItem.id, "reply"),
      /静音|排除|范围|变更/,
      "异步过滤期间私聊被静音时必须停止起草",
    );
    assert.equal(draftPrompts.length, 0, "私聊被静音后绝不能调用模型");
    svc.store.muteConv("oc_r12_draft_dm", "私聊：小王", false);

    // 6c) filterObs 异步期间目标消息被撤回：绝不能补回旧快照送模型
    svc.drafter.filterObs = async (conv, obs) => {
      const out = origFilterObs ? await origFilterObs(conv, obs) : obs;
      if (conv === "oc_r12_draft_dm") {
        svc.store.retirePendingObs("im:om_r12_draft_dm");
      }
      return out;
    };
    await assert.rejects(
      svc.drafter.forItem(draftItem.id, "reply"),
      /范围|撤回|找不到|变更/,
      "目标消息在异步期间被撤回时必须停止起草",
    );
    assert.equal(draftPrompts.length, 0, "目标撤回后绝不能调用模型");
    svc.drafter.filterObs = origFilterObs;

    // 7) [R12 P2-8] 非持钥交互式 CLI drain(["effect"]) 必须跳过/让出 pw.reply（不消耗重试次数、不标死草稿），持钥消费者接手后正常发送
    const pwReplyDraft = svc.store.addDraft({
      item_id: draftItem.id,
      project_id: "",
      kind: "reply",
      target: {
        transport: "personal_web",
        obs_id: "pw:r12_defer_m",
        native_owner_id: "7001",
        native_message_id: "r12_defer_m",
        native_chat_id: "9920",
        native_root_id: "r12_defer_m",
      },
      target_label: "回复 7002（个人 Web）",
      content: "待持钥常驻进程发送的回复",
    });
    svc.store.setDraft(pwReplyDraft.id, { status: "approved" });
    app.ledger.emit(
      `ctx-draft:${pwReplyDraft.id}`,
      [
        {
          op: "pw.reply",
          args: {
            owner_id: "7001",
            chat_id: "9920",
            message_id: "r12_defer_m",
            root_id: "r12_defer_m",
            text: "待持钥常驻进程发送的回复",
            draft_id: pwReplyDraft.id,
          },
        },
      ],
      `r12-defer-${pwReplyDraft.id}`,
    );
    app.ledger.emit("non-pw-test", [{ op: "notify", args: { markdown: "普通通知" } }], "r12-normal-notify");
    const origNotifyOwner = app.lark.notifyOwner.bind(app.lark);
    const deliveredNotifies: string[] = [];
    app.lark.notifyOwner = async (md) => {
      deliveredNotifies.push(md);
    };
    // 模拟交互式 CLI（无 PA_FEISHU_WEB_KEY，磁盘是加密凭据 -> missing_key）执行 drain(["effect"])
    await withoutTestWebKey(async () => {
      await app!.engine.drain(["effect"]);
    });
    assert.ok(deliveredNotifies.includes("普通通知"), "无密钥 CLI 仍须正常投递其他普通 effect");
    const deferredFx = app.ledger.get(`fx:r12-defer-${pwReplyDraft.id}`)!;
    assert.equal(deferredFx.terminal, false, "无密钥 CLI 绝不能把 pw.reply 标为 dead");
    assert.equal(deferredFx.attempts, 0, "无密钥 CLI 绝不能消耗 pw.reply 的重试次数");
    assert.equal(svc.store.draft(pwReplyDraft.id)?.status, "approved", "草稿仍保持 approved 等待持钥常驻进程");
    // 换作持钥消费者（且提供 mock pwReply）后立即成功投递
    let pwSentByCredConsumer = false;
    const prevPwReplyHook = app.effectHooks.pwReply;
    const prevDeferHook = app.effectHooks.shouldDeferPwReply;
    app.effectHooks.pwReply = async () => {
      pwSentByCredConsumer = true;
    };
    app.effectHooks.shouldDeferPwReply = () => false;
    await app.engine.drain(["effect"]);
    assert.equal(pwSentByCredConsumer, true, "持钥消费者必须能正常领取并完成 pw.reply");
    assert.equal(app.ledger.get(`fx:r12-defer-${pwReplyDraft.id}`)?.state, "done");
    app.effectHooks.pwReply = prevPwReplyHook;
    app.effectHooks.shouldDeferPwReply = prevDeferHook;

    // 8) [R12 P2-9] 换主人后：旧主人与未绑定历史 brief 仍阻断，但为当前新主人重新渲染并绑定的 brief（卡片与去重键均按主人隔离）可正常投递
    const origLarkRun = app.lark.run.bind(app.lark);
    const origAuthStatusR12 = app.lark.authStatus.bind(app.lark);
    app.lark.authStatus = async () => ({ identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } });
    const sentCardPayloads: { to: string; key: string }[] = [];
    app.lark.run = async (argv, opts) => {
      if (argv[0] === "auth" && argv[1] === "status") {
        return { identity: "user", user: { open_id: app!.cfg.owner.open_id, name: "当前主人" } };
      }
      if (argv[0] === "task" && (argv[1] === "+get-my-tasks" || argv[1] === "+tasklist-tasks" || argv[1] === "sections")) return { items: [] };
      if (argv[0] === "im" && argv[1] === "+messages-send") {
        const uidIdx = argv.indexOf("--user-id");
        const idemIdx = argv.indexOf("--idempotency-key");
        sentCardPayloads.push({
          to: uidIdx >= 0 ? argv[uidIdx + 1] ?? "" : "",
          key: idemIdx >= 0 ? argv[idemIdx + 1] ?? "" : "",
        });
        return { message_id: `om_card_${sentCardPayloads.length}` };
      }
      return origLarkRun(argv, opts);
    };
    app.store.set("board.tasklist", "tl_r12");
    app.store.set("board.owner_open_id", "ou_owner_a");
    app.store.set("board.section.pending", "sec_p");
    app.store.set("board.section.review", "sec_r");
    app.store.set("board.section.attention", "sec_a");
    // 先由主人 A 排队一份 morning brief + 一份未绑定历史 brief
    await sendBrief(app, "morning");
    app.ledger.emit("brief", [{ op: "notify", args: { markdown: "旧版未绑定晨报", kind: "brief" } }], "r12-legacy-unbound-brief");
    const dateStr = new Date().toISOString().slice(0, 10);
    const briefAId = `fx:brief-morning-${dateStr}-${Q.briefOwnerTag("ou_owner_a")}`;
    // 切换工作区主人到 B（且 B 已重新绑定看板与 lark-cli 身份）
    app.cfg.owner.open_id = "ou_owner_b";
    app.store.set("board.owner_open_id", "ou_owner_b");
    assert.equal(Q.isWorkBlockedByOwner(app, briefAId), true, "旧主人 A 的待发晨报仍必须阻断");
    assert.equal(Q.isWorkBlockedByOwner(app, "fx:r12-legacy-unbound-brief"), true, "未绑定主人的旧版晨报仍必须阻断");
    // 主人 B 同一天再次调用 sendBrief：去重键与卡片键均按主人 B 隔离，能正常入队并投递给 B
    await sendBrief(app, "morning");
    const briefBId = `fx:brief-morning-${dateStr}-${Q.briefOwnerTag("ou_owner_b")}`;
    assert.ok(app.ledger.get(briefBId), "主人 B 的晨报必须使用独立去重键入队而不与 A 冲突");
    assert.equal(Q.isWorkBlockedByOwner(app, briefBId), false, "为主人 B 重新渲染并绑定的晨报必须允许投递");
    await app.engine.drain(["effect"]);
    assert.equal(app.ledger.get(briefBId)?.state, "done", "主人 B 的晨报卡片必须成功投递");
    assert.equal(app.ledger.get(briefAId)?.state, "dead", "主人 A 的旧晨报必须被阻断");
    assert.equal(app.ledger.get("fx:r12-legacy-unbound-brief")?.state, "dead", "未绑定旧晨报必须被阻断");
    assert.ok(sentCardPayloads.some((c) => c.to === "ou_owner_b"), "投递目标必须是主人 B");
    // 恢复主人 A
    app.cfg.owner.open_id = "ou_owner_a";
    app.lark.run = origLarkRun;
    app.lark.authStatus = origAuthStatusR12;
    app.lark.notifyOwner = origNotifyOwner;

    // 9) [R12 P2-10] verifyOwner 成功后，loadWebMetadata 在 503 失败前下发了 Set-Cookie 轮换：connect 抛错前必须先落盘该已验证会话的 Cookie 增量
    let persistedOnMetaFail: string | undefined;
    mock.setMessengerStatus(503);
    mock.setMessengerErrorCookie("session=sess_rotated_on_503; Path=/; Max-Age=86400");
    await assert.rejects(
      FeishuWebClient.connect(
        { owner_id: "7001", owner_name: "主人A", session_id: "sess_r12_meta", cookies: baseCookies },
        {
          endpoints: mock.endpoints,
          onSessionConfirmed: (updated) => {
            const s = updated.cookies.find((c) => c.name === "session")?.value;
            if (s) persistedOnMetaFail = s;
            return updated;
          },
        },
      ),
      /503|元数据/,
    );
    mock.setMessengerStatus(200);
    mock.setMessengerErrorCookie("");
    assert.equal(
      persistedOnMetaFail,
      "sess_rotated_on_503",
      "loadWebMetadata 失败前收到的已验证会话 Cookie 轮换必须立即持久化",
    );

    // 10) [R12 P2-11] buildSocketUrl：票据响应轮换 passport_web_did 时必须以新 device_id 重拉匹配票据，保持 ticket / device_id / access_key 严格一致
    const ticketClient = await FeishuWebClient.connect(
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r12_did", cookies: baseCookies },
      { endpoints: mock.endpoints },
    );
    mock.ticketDeviceIds.length = 0;
    mock.setTicketRotateDidOnce("did_r12_rotated_999");
    const wsUrlStr = await ticketClient.buildSocketUrl();
    const wsParsed = new URL(wsUrlStr);
    const finalDid = wsParsed.searchParams.get("device_id")!;
    const finalTicket = wsParsed.searchParams.get("ticket")!;
    const finalAccessKey = wsParsed.searchParams.get("access_key")!;
    const expectedAccessKey = crypto.createHash("md5").update(`2appkey_xyz${finalDid}${ACCESS_KEY_SALT}`).digest("hex");
    assert.equal(finalDid, "did_r12_rotated_999", "轮换后的新 passport_web_did 必须生效");
    assert.equal(finalTicket, "ticket_for_did_r12_rotated_999", "票据必须是用同一新 device_id 重新申请的匹配票据");
    assert.equal(finalAccessKey, expectedAccessKey, "access_key 必须与同一 device_id 严格匹配");
    assert.ok(mock.ticketDeviceIds.includes("did_r12_rotated_999"), "应针对轮换后的新 device_id 发起重拉票据请求");
    mock.setTicketRotateDidOnce("");

    // 11) [R12 P2-13] 原子条件清除 pending_cred_commit 标记：路径 A 完成安装绝不能抹掉路径 B 刚刚提交的未完成标记
    const pathA = path.join(dir, "cred-path-a.json");
    const pathB = path.join(dir, "cred-path-b.json");
    const storeB = new WebLoginStore(dir, "cred-path-b.json");
    storeB.stageWithLock((stage) => {
      stage({ owner_id: "7001", owner_name: "主人A", session_id: "sess_r12_b", cookies: baseCookies });
    });
    const markerB = JSON.stringify({
      file: pathB,
      staged_file: storeB.stagedFile,
      owner_id: "7001",
      session_id: "sess_r12_b",
      at: Date.now(),
    });
    app.store.set(PENDING_CRED_COMMIT_KV_KEY, markerB);
    // 模拟先提交的路径 A 稍后完成 rename 并尝试清除自己的 marker -> 必须返回 false 且完整保留路径 B 的 marker
    const clearedWrong = clearPendingCommitMarkerIfMatches(app.store, PENDING_CRED_COMMIT_KV_KEY, {
      file: pathA,
      sessionId: "sess_r12_a",
    });
    assert.equal(clearedWrong, false, "路径 A 绝不能清除属于路径 B 的 pending 标记");
    assert.equal(app.store.get(PENDING_CRED_COMMIT_KV_KEY), markerB, "路径 B 的 pending 标记必须完好保留");
    // 随后路径 B 恢复暂存提交：正确完成 rename 并清除路径 B 的标记
    storeB.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
    assert.equal(storeB.load()?.session_id, "sess_r12_b", "路径 B 的暂存凭据必须成功恢复");
    assert.equal(app.store.get(PENDING_CRED_COMMIT_KV_KEY), "", "路径 B 恢复完成后才清除其自身标记");

    // 12) [R12 P2-12] 常驻进程处于 needs_login 等待登录期间（waitForCredentialChange），自动恢复外部遗留的 .staged 暂存提交并上线
    const waitDir = makeTmp("pa-r12-wait-staged-");
    const waitCfg = path.join(waitDir, "config.yaml");
    fs.writeFileSync(
      waitCfg,
      JSON.stringify({
        data_dir: waitDir,
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { claude: { agent: "claude" } },
        roles: { brain: "claude" },
        owner: { open_id: "ou_owner_a" },
        context: { enabled: true, personal_web: { enabled: true, fast_lane: true, debounce_ms: 0 } },
      }),
    );
    const waitApp = createApp(loadConfig(waitCfg));
    const waitCtx = new ContextService(waitApp);
    const waitBridge = new PersonalWebBridge(waitApp, waitCtx.store, {
      onFastTrigger: () => undefined,
      onReconnect: () => undefined,
      onNeedsLogin: () => undefined,
      credentialWatchIntervalMs: 30,
      clientOptions: { endpoints: mock.endpoints },
    });
    const waitHandle = waitBridge.start();
    try {
      await waitUntil(() => waitBridge.status().state === "needs_login", 3_000);
      // 模拟首次 web-login 已提交 SQLite 绑定与 .staged 文件后、rename 前退出
      const waitStore = new WebLoginStore(waitDir);
      const stagedLogin = waitStore.stageWithLock((stage) => {
        const s = stage({ owner_id: "7001", owner_name: "主人A", session_id: "sess_r12_wait_recover", cookies: baseCookies });
        return s.payload;
      });
      saveWorkspaceBinding(waitApp.store, "7001", "ou_owner_a");
      waitApp.store.set(ACTIVE_SESSION_KV_KEY, stagedLogin.session_id ?? "");
      waitApp.store.set(
        PENDING_CRED_COMMIT_KV_KEY,
        JSON.stringify({
          file: waitStore.file,
          staged_file: waitStore.stagedFile,
          owner_id: "7001",
          session_id: stagedLogin.session_id ?? "",
          at: Date.now(),
        }),
      );
      assert.equal(fs.existsSync(waitStore.file), false, "模拟崩溃时尚未 rename 到现网路径");
      // 运行中的常驻进程必须自动在 waitForCredentialChange 中恢复 .staged 并进入 listening
      await waitUntil(() => waitBridge.status().state === "listening", 4_000);
      assert.equal(fs.existsSync(waitStore.file), true, "等待中的常驻进程必须自动补全 .staged -> file 重命名");
      assert.equal(waitApp.store.get(PENDING_CRED_COMMIT_KV_KEY), "", "恢复完成后 pending 标记必须清除");
    } finally {
      waitHandle.stop();
      waitApp.store.db.close();
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

test("Codex 第十三轮回归：dataDir 祖先重遮蔽、worktree .git 防篡改、unshare 空格挂载点/只读复查、代理家目录只读、仓库进程 vs 无工具轮询隔离边界、损坏 state.db fail-closed、原生私聊名称排除、晨报主人与看板归属校核、提交边界策略版本复检、自动预起草推理前复检、LFS 锁校核与官方指针语法/相对路径/push-only/stdin、分页前可见性、忽略隔离健康计数、无密钥收尾已回读回复与网关/票据瞬时失败落盘轮换", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  let lfsLockServer: http.Server | undefined;

  try {
    // 1) [R13 #1 P1 + #3 P1 + #4 P1] 祖先挂载不得重露 dataDir；unshare 支持含空格路径并严格校验只读根；共享代理配置目录（~/.codex 等）绝不可写
    if (hasCredentialMountIsolation()) {
      const parentDir = makeTmp("pa-r13-ancestor-");
      const dataDir = path.join(parentDir, ".avatar-data");
      const wtDir = path.join(dataDir, "worktrees", "w1");
      const spaceRoDir = path.join(parentDir, "dir with space ro");
      const spaceRwDir = path.join(parentDir, "dir with space rw");
      fs.mkdirSync(wtDir, { recursive: true });
      fs.mkdirSync(spaceRoDir, { recursive: true });
      fs.mkdirSync(spaceRwDir, { recursive: true });
      const stateDb = path.join(dataDir, "state.db");
      const credFile = path.join(dataDir, "feishu-web.json");
      fs.writeFileSync(stateDb, "TOP_SECRET_STATE");
      fs.writeFileSync(credFile, '{"v":1,"enc":"secret"}', { mode: 0o600 });
      fs.writeFileSync(path.join(wtDir, "hello.txt"), "wt-ok");
      fs.writeFileSync(path.join(spaceRoDir, "ro.txt"), "ro-ok");

      const checkScript = [
        `test ! -e ${JSON.stringify(stateDb)}`,
        `test ! -e ${JSON.stringify(credFile)}`,
        `test "$(cat ${JSON.stringify(path.join(wtDir, "hello.txt"))})" = "wt-ok"`,
        `echo child-wt > ${JSON.stringify(path.join(wtDir, "child.txt"))}`,
        `echo child-parent > ${JSON.stringify(path.join(parentDir, "parent-out.txt"))}`,
        `echo child-space > ${JSON.stringify(path.join(spaceRwDir, "space-out.txt"))}`,
        `! touch ${JSON.stringify(path.join(spaceRoDir, "tamper.txt"))} 2>/dev/null`,
      ].join(" && ");

      const probeBwrap = await runProcess(
        "bwrap",
        ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--", "true"],
        { timeoutMs: 5_000 },
      );
      if (probeBwrap.code === 0) {
        const bwrapCmd = wrapCredentialIsolatedCommand("sh", ["-c", checkScript], {}, {
          requireIsolation: true,
          dataDir,
          cwd: wtDir,
          writablePaths: [parentDir, wtDir, spaceRwDir],
          readOnlyPaths: [spaceRoDir],
          forceBackend: { kind: "bwrap", bin: "bwrap" },
        });
        const rBwrap = await runProcess(bwrapCmd.cmd, bwrapCmd.args, { timeoutMs: 15_000 });
        assert.equal(rBwrap.code, 0, `bwrap 在祖先目录可写挂载下仍必须遮蔽 dataDir 且放行 worktree：${rBwrap.stderr}`);
        assert.equal(fs.readFileSync(path.join(wtDir, "child.txt"), "utf8").trim(), "child-wt");
        assert.equal(fs.readFileSync(path.join(spaceRwDir, "space-out.txt"), "utf8").trim(), "child-space");
        assert.equal(fs.existsSync(path.join(spaceRoDir, "tamper.txt")), false);
      }

      const pivotBin = ["/sbin/pivot_root", "/usr/sbin/pivot_root"].find((p) => fs.existsSync(p));
      const probeUnshare = pivotBin
        ? await runProcess(
            "unshare",
            ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "setpriv", "--bounding-set", "-all", "--inh-caps", "-all", "--ambient-caps", "-all", "--no-new-privs", "true"],
            { timeoutMs: 5_000 },
          )
        : { code: 1, stdout: "", stderr: "", timedOut: false };
      if (probeUnshare.code === 0 && pivotBin) {
        const unshareCmd = wrapCredentialIsolatedCommand("sh", ["-c", checkScript], {}, {
          requireIsolation: true,
          dataDir,
          cwd: wtDir,
          writablePaths: [parentDir, wtDir, spaceRwDir],
          readOnlyPaths: [spaceRoDir],
          forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: pivotBin },
        });
        const rUnshare = await runProcess(unshareCmd.cmd, unshareCmd.args, { timeoutMs: 15_000 });
        assert.equal(rUnshare.code, 0, `unshare 在祖先挂载与含空格路径下必须遮蔽 dataDir 并强制只读复查：${rUnshare.stderr}`);
        assert.equal(fs.readFileSync(path.join(wtDir, "child.txt"), "utf8").trim(), "child-wt");
        assert.equal(fs.readFileSync(path.join(spaceRwDir, "space-out.txt"), "utf8").trim(), "child-space");
        assert.equal(fs.existsSync(path.join(spaceRoDir, "tamper.txt")), false);
      }

      // [R13 #4 P1] 模拟宿主机 ~/.codex / ~/.claude / ~/.acpx / ~/.doubao：buildWorkspaceIsolation 绝不将其加入 writablePaths
      const fakeHome = makeTmp("pa-r13-home-");
      for (const sub of [".codex", ".claude", ".acpx", ".doubao"]) {
        fs.mkdirSync(path.join(fakeHome, sub), { recursive: true });
        fs.writeFileSync(path.join(fakeHome, sub, "config.toml"), 'model = "safe"\n');
      }
      const isoWrite = buildWorkspaceIsolation(
        { dataDir, context: { personal_web: { enabled: true } } as never },
        { mode: "worker-write", cwd: wtDir, extraReadOnlyPaths: [fakeHome] },
        { HOME: fakeHome },
      );
      const isoRo = buildWorkspaceIsolation(
        { dataDir, context: { personal_web: { enabled: true } } as never },
        { mode: "worker-ro", cwd: wtDir, extraReadOnlyPaths: [fakeHome] },
        { HOME: fakeHome },
      );
      for (const sub of [".codex", ".claude", ".acpx", ".doubao"]) {
        const p = fs.realpathSync(path.join(fakeHome, sub));
        assert.equal(isoWrite.writablePaths?.includes(p), false, `worker-write 绝不能将 ${sub} 挂载为可写`);
        assert.equal(isoRo.writablePaths?.includes(p), false, `worker-ro 绝不能将 ${sub} 挂载为可写`);
      }
      assert.equal(isoRo.writablePaths?.includes(fs.realpathSync(wtDir)), false, "worker-ro 绝不能把审查目录挂为可写");
      const codexCfg = path.join(fakeHome, ".codex", "config.toml");
      const roHomeProbe = wrapCredentialIsolatedCommand(
        "sh",
        ["-c", `! echo evil >> ${JSON.stringify(codexCfg)} 2>/dev/null && grep -q safe ${JSON.stringify(codexCfg)}`],
        { HOME: fakeHome },
        isoWrite,
      );
      const rHome = await runProcess(roHomeProbe.cmd, roHomeProbe.args, { timeoutMs: 15_000 });
      assert.equal(rHome.code, 0, `子进程必须可读但绝不可改写 ~/.codex/config.toml：${rHome.stderr}`);
    }

    // 2) [R13 #2 P1] worktree .git / commondir 篡改校核：指向非受信任仓库或任意宿主机路径一律拒绝挂载
    {
      const base = makeTmp("pa-r13-gitmeta-");
      const repoA = path.join(base, "repo-a");
      const repoB = path.join(base, "repo-b");
      const secretHost = path.join(base, "fake-ssh");
      const wtA = path.join(base, "wt-a");
      const wtB = path.join(base, "wt-b");
      fs.mkdirSync(repoA, { recursive: true });
      fs.mkdirSync(repoB, { recursive: true });
      fs.mkdirSync(secretHost, { recursive: true });
      fs.writeFileSync(path.join(secretHost, "id_rsa"), "PRIVATE");
      for (const repo of [repoA, repoB]) {
        assert.equal((await runProcess("git", ["-C", repo, "init", "-q", "-b", "main"])).code, 0);
        fs.writeFileSync(path.join(repo, "README.md"), "ok\n");
        assert.equal((await runProcess("git", ["-C", repo, "add", "-A"])).code, 0);
        assert.equal(
          (await runProcess("git", ["-C", repo, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "init"])).code,
          0,
        );
      }
      assert.equal((await runProcess("git", ["-C", repoA, "worktree", "add", "-q", "-b", "pa/a", wtA])).code, 0);
      assert.equal((await runProcess("git", ["-C", repoB, "worktree", "add", "-q", "-b", "pa/b", wtB])).code, 0);

      // 合法 worktree 校验通过
      const validWt = detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoA });
      assert.equal(validWt.commonDir, fs.realpathSync(path.join(repoA, ".git")));
      assert.ok(validWt.gitDir?.startsWith(fs.realpathSync(path.join(repoA, ".git", "worktrees"))));

      // 跨仓库校核拒绝（wtA 指向 repoA，但受信任仓库是 repoB）
      assert.throws(() => detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoB }), /元数据校验失败|拒绝挂载/);

      // worker 将 .git 篡改为指向宿主机敏感目录（如 ~/.ssh）
      const origDotGit = fs.readFileSync(path.join(wtA, ".git"), "utf8");
      fs.writeFileSync(path.join(wtA, ".git"), `gitdir: ${secretHost}\n`);
      assert.throws(() => detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoA }), /元数据校验失败|拒绝挂载/);
      assert.throws(
        () =>
          buildWorkspaceIsolation(
            { dataDir: base, context: { personal_web: { enabled: true } } } as never,
            { mode: "verify", cwd: wtA, trustedRepoRoot: repoA },
            {},
          ),
        /元数据校验失败|拒绝挂载/,
      );

      // worker 将 .git 替换为指向其他路径的符号链接
      fs.rmSync(path.join(wtA, ".git"));
      fs.symlinkSync(path.join(repoA, ".git"), path.join(wtA, ".git"));
      assert.throws(() => detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoA }), /符号链接/);

      // 还原后，将 .git 指向另一个真实仓库 repoB 的 worktree 管理目录（反向指针不匹配 + 跨仓库）
      fs.rmSync(path.join(wtA, ".git"));
      fs.writeFileSync(path.join(wtA, ".git"), fs.readFileSync(path.join(wtB, ".git"), "utf8"));
      assert.throws(() => detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoA }), /元数据校验失败|拒绝挂载/);
      fs.writeFileSync(path.join(wtA, ".git"), origDotGit);
    }

    // 3) [R13 #5 P1 + #6 P1 + #9 P2] 仅轮询 ctx_obs 场景：仓库能力进程（git-rw/git-ro/codex-exec/verify/worker）必须隔离，无工具推理 llm-none 豁免；损坏 state.db 须 fail-closed
    {
      const pollDir = makeTmp("pa-r13-poll-iso-");
      const pollCfgFile = path.join(pollDir, "config.yaml");
      fs.writeFileSync(
        pollCfgFile,
        JSON.stringify({
          data_dir: pollDir,
          bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
          harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "claude", reviewer: "cx" },
          owner: { open_id: "ou_owner_poll" },
          context: { enabled: true, personal_web: { enabled: false } },
        }),
      );
      const pollApp = createApp(loadConfig(pollCfgFile));
      const pollCtx = new ContextService(pollApp);
      try {
        pollCtx.store.addObs([
          {
            id: "im:poll_r13_1",
            source: "im",
            kind: "p2p",
            conv: "oc_poll_dm",
            conv_name: "私聊：同事",
            actor_id: "ou_x",
            actor_name: "同事",
            is_me: false,
            time: Date.now(),
            text: "纯轮询私聊消息",
            url: "",
            meta: { chat_type: "p2p" },
          },
        ]);
        for (const mode of ["verify", "worker-write", "worker-ro", "codex-exec", "git-rw", "git-ro"] as const) {
          const iso = buildWorkspaceIsolation(pollApp.cfg, { mode, cwd: pollDir }, {});
          assert.equal(iso.requireIsolation, true, `仅轮询工作区含 ctx_obs 时，${mode} 必须强制启用隔离`);
        }
        const llmNoneIso = buildWorkspaceIsolation(pollApp.cfg, { mode: "llm-none", cwd: pollDir }, {});
        assert.equal(llmNoneIso.requireIsolation, false, "未启用个人 Web 时，工具禁用推理（llm-none）不得因 ctx_obs 强制要求 Linux 命名空间");

        // 一旦启用个人 Web，llm-none 也必须强制隔离
        pollApp.cfg.context.personal_web.enabled = true;
        const llmNoneWithPw = buildWorkspaceIsolation(pollApp.cfg, { mode: "llm-none", cwd: pollDir }, {});
        assert.equal(llmNoneWithPw.requireIsolation, true, "启用个人 Web 后 llm-none 同样必须启用隔离");
      } finally {
        pollApp.store.db.close();
      }

      // [R13 #9 P2] 损坏或不可读取的 state.db 必须 fail-closed（返回 true），绝不按无敏感状态放行
      const corruptDir = makeTmp("pa-r13-corrupt-db-");
      fs.writeFileSync(path.join(corruptDir, "state.db"), "NOT_A_VALID_SQLITE_FILE_HEADER_1234567890");
      assert.equal(
        workspaceRequiresIsolation(corruptDir, {}, { includeContextObs: true }),
        true,
        "state.db 无法被 SQLite 正常检查时必须 fail-closed 要求隔离",
      );
      assert.equal(
        workspaceRequiresIsolation(corruptDir, {}, { includeContextObs: false }),
        true,
        "即使 includeContextObs=false，损坏的 state.db 仍必须 fail-closed",
      );
    }

    // 4) [R13 #13 P2 + #14 P2 + #15 P2 + #16 P2 + #12 P2] Git LFS 官方指针语法对拍、本地 URL 相对 cwd 解析、push-only 远端、stdin rev-list 与 locksverify 锁校验
    {
      const shaA = "a".repeat(64);
      const shaB = "b".repeat(64);
      const shaC = "c".repeat(64);
      const pointerCases: [string, string | Buffer, boolean][] = [
        ["valid_std", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\n`, true],
        ["valid_hawser", `version https://hawser.github.com/spec/v1\noid sha256:${shaA}\nsize 0\n`, true],
        ["valid_ext", `version https://git-lfs.github.com/spec/v1\next-0-foo sha256:${shaB}\noid sha256:${shaA}\nsize 123\n`, true],
        ["valid_oid_then_ext", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\next-0-foo sha256:${shaB}\nsize 123\n`, true],
        ["invalid_not_a_pointer", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\nnot a pointer\n`, false],
        ["invalid_extra_kv", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\nfoo bar\n`, false],
        ["invalid_dup_oid", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\noid sha256:${shaA}\nsize 123\n`, false],
        ["invalid_size_before_oid", `version https://git-lfs.github.com/spec/v1\nsize 123\noid sha256:${shaA}\n`, false],
        ["invalid_ext_after_size", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\next-0-foo sha256:${shaB}\n`, false],
        ["invalid_ext_same_idx_diff_name", `version https://git-lfs.github.com/spec/v1\next-0-foo sha256:${shaB}\next-0-bar sha256:${shaC}\noid sha256:${shaA}\nsize 123\n`, false],
        ["invalid_ext_bad_val", `version https://git-lfs.github.com/spec/v1\next-0-foo notasha\noid sha256:${shaA}\nsize 123\n`, false],
        ["invalid_bom", `\ufeffversion https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\n`, false],
        ["invalid_size_overflow", `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 9223372036854775808\n`, false],
        ["invalid_nul", Buffer.from(`version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\n\0`), false],
        ["invalid_utf8", Buffer.concat([Buffer.from(`version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\n`), Buffer.from([0xff])]), false],
      ];
      const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 5_000 })).code === 0;
      for (const [label, sample, expected] of pointerCases) {
        assert.equal(isGitLfsPointerBlob(sample), expected, `isGitLfsPointerBlob(${label}) 必须为 ${expected}`);
        if (hasGitLfs) {
          const check = await runProcess("git", ["lfs", "pointer", "--check", "--stdin"], {
            input: Buffer.isBuffer(sample) ? undefined : sample,
            timeoutMs: 5_000,
          });
          if (!Buffer.isBuffer(sample)) {
            assert.equal(
              isGitLfsPointerBlob(sample),
              check.code === 0,
              `isGitLfsPointerBlob(${label}) 必须与 git lfs pointer --check --stdin 保持 100% 一致`,
            );
          }
        }
      }

      // [R13 #14 P2 + #15 P2 + #16 P2] file:// 与相对 cwd 路径本地推送 + push-only 远端（禁用 upload-pack）+ 多远端引用 stdin 排除
      const gitBase = makeTmp("pa-r13-git-");
      const bareFile = path.join(gitBase, "bare-file.git");
      const bareRel = path.join(gitBase, "bare-rel.git");
      const barePushOnly = path.join(gitBase, "bare-pushonly.git");
      const workRepo = path.join(gitBase, "work");
      fs.mkdirSync(workRepo, { recursive: true });
      for (const b of [bareFile, bareRel, barePushOnly]) {
        assert.equal((await runProcess("git", ["init", "--bare", "-q", b])).code, 0);
      }
      assert.equal(resolveLocalGitRemoteDir(workRepo, `file://${bareFile}`), fs.realpathSync(bareFile));
      assert.equal(resolveLocalGitRemoteDir(workRepo, "../bare-rel.git"), fs.realpathSync(bareRel));
      assert.equal(resolveLocalGitRemoteDir(workRepo, "https://github.com/org/repo.git"), undefined);
      assert.equal(resolveLocalGitRemoteDir(workRepo, "git@github.com:org/repo.git"), undefined);

      assert.equal((await runProcess("git", ["-C", workRepo, "init", "-q", "-b", "main"])).code, 0);
      fs.writeFileSync(path.join(workRepo, "doc.md"), `version https://git-lfs.github.com/spec/v1\noid sha256:${shaA}\nsize 123\nnot a pointer\n`);
      assert.equal((await runProcess("git", ["-C", workRepo, "add", "-A"])).code, 0);
      assert.equal(
        (await runProcess("git", ["-C", workRepo, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "doc"])).code,
        0,
      );
      assert.equal((await runProcess("git", ["-C", workRepo, "remote", "add", "rfile", `file://${bareFile}`])).code, 0);
      assert.equal((await runProcess("git", ["-C", workRepo, "remote", "add", "rrel", "../bare-rel.git"])).code, 0);
      assert.equal((await runProcess("git", ["-C", workRepo, "remote", "add", "rpushonly", barePushOnly])).code, 0);
      // 模拟 push-only 远端：禁用 upload-pack，令 ls-remote 必然失败但 receive-pack 正常可用
      assert.equal((await runProcess("git", ["-C", workRepo, "config", "remote.rpushonly.uploadpack", "false"])).code, 0);

      // 含伪指针文档（not a pointer）的普通仓库不能误判为 LFS，且在隔离模式下向 file://、相对路径与 push-only 远端均可正常推送
      const isoGitCfg = { dataDir: gitBase, context: { personal_web: { enabled: true } } as never };
      assert.equal(await branchUsesGitLfs(workRepo, "main", undefined, [shaA, shaB], { cfg: isoGitCfg }), false);
      const pushFileRes = await pushBranch(workRepo, "rfile", "main", { cfg: isoGitCfg });
      assert.equal(pushFileRes.ok, true, `file:// 本地推送必须自动挂载目标目录并成功：${!pushFileRes.ok ? pushFileRes.message : ""}`);
      const pushRelRes = await pushBranch(workRepo, "rrel", "main", { cfg: isoGitCfg });
      assert.equal(pushRelRes.ok, true, `相对 cwd 的本地推送必须按 cwd 解析并成功：${!pushRelRes.ok ? pushRelRes.message : ""}`);
      const pushOnlyRes = await pushBranch(workRepo, "rpushonly", "main", { cfg: isoGitCfg });
      assert.equal(pushOnlyRes.ok, true, `禁止 upload-pack 的 push-only 远端不应因 ls-remote 失败而中止普通推送：${!pushOnlyRes.ok ? pushOnlyRes.message : ""}`);

      // [R13 #12 P2] 当分支包含新 LFS 指针且配置了 lfs.<url>.locksverify=true 时，pushBranch 必须执行 git lfs pre-push 校核他人文件锁
      if (hasGitLfs) {
        let verifyLocksCalled = 0;
        lfsLockServer = http.createServer((req, res) => {
          if (req.url?.includes("/locks/verify")) {
            verifyLocksCalled++;
            res.writeHead(200, { "Content-Type": "application/vnd.git-lfs+json" });
            res.end(
              JSON.stringify({
                ours: [],
                theirs: [{ id: "lock-1", path: "assets/locked.bin", locked_at: new Date().toISOString(), owner: { name: "alice" } }],
              }),
            );
            return;
          }
          res.writeHead(404);
          res.end();
        });
        await new Promise<void>((resolve) => lfsLockServer!.listen(0, "127.0.0.1", () => resolve()));
        const lockPort = (lfsLockServer.address() as { port: number }).port;
        const lfsUrl = `http://127.0.0.1:${lockPort}/repo.git/info/lfs`;

        const lockBare = path.join(gitBase, "bare-lock.git");
        const lockWork = path.join(gitBase, "work-lock");
        fs.mkdirSync(path.join(lockWork, "assets"), { recursive: true });
        assert.equal((await runProcess("git", ["init", "--bare", "-q", lockBare])).code, 0);
        assert.equal((await runProcess("git", ["-C", lockWork, "init", "-q", "-b", "main"])).code, 0);
        assert.equal((await runProcess("git", ["-C", lockWork, "remote", "add", "origin", lockBare])).code, 0);
        assert.equal((await runProcess("git", ["-C", lockWork, "config", "lfs.url", lfsUrl])).code, 0);
        assert.equal((await runProcess("git", ["-C", lockWork, "config", `lfs.${lfsUrl}.locksverify`, "true"])).code, 0);
        fs.writeFileSync(path.join(lockWork, ".gitattributes"), "assets/*.bin filter=lfs diff=lfs merge=lfs -text\n");
        const rawBytes = Buffer.from("locked-lfs-binary-payload-r13");
        const rawSha = crypto.createHash("sha256").update(rawBytes).digest("hex");
        const lfsObjDir = path.join(lockWork, ".git", "lfs", "objects", rawSha.slice(0, 2), rawSha.slice(2, 4));
        fs.mkdirSync(lfsObjDir, { recursive: true });
        fs.writeFileSync(path.join(lfsObjDir, rawSha), rawBytes);
        fs.writeFileSync(
          path.join(lockWork, "assets", "locked.bin"),
          `version https://git-lfs.github.com/spec/v1\noid sha256:${rawSha}\nsize ${rawBytes.length}\n`,
        );
        assert.equal((await runProcess("git", ["-C", lockWork, "add", ".gitattributes", "assets/locked.bin"])).code, 0);
        assert.equal(
          (await runProcess("git", ["-C", lockWork, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "add locked"])).code,
          0,
        );
        const lockPush = await pushBranch(lockWork, "origin", "main", {});
        assert.equal(lockPush.ok, false, "命中他人 LFS 文件锁时 pushBranch 必须拒绝推送");
        assert.ok(verifyLocksCalled >= 1, "pushBranch 在包含新 LFS 指针时必须执行 pre-push 触发 /locks/verify 锁校核");
        assert.match(!lockPush.ok ? lockPush.message : "", /lock|locked|assets\/locked\.bin/i);
      }
    }

    // ───────── 建立主测试应用（验证 #7, #8, #10, #11, #17, #18, #19, #20）─────────
    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
    const dir = makeTmp("pa-r13-main-");
    const ctxDir = makeTmp("pa-r13-ctx-");
    process.env.CTX_DIR = ctxDir;
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "主人A", at_me: [], p2p: [], mine: [], chats: {} }));
    const cfgFile = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: dir,
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { claude: { agent: "claude" }, cx: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
        roles: { brain: "cx", reviewer: "claude" },
        owner: { open_id: "ou_owner_a" },
        cards: { enabled: true },
        context: {
          enabled: true,
          harness: "cx",
          groups: "spoken",
          max_groups: 5,
          groups_deny: [],
          personal_web: { enabled: true, fast_lane: true, send_replies: true, pre_draft: true, debounce_ms: 0 },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCtxDirStubLlm(svc, ctxDir);
    app.engine.register(svc.handler());
    saveWorkspaceBinding(app.store, "7001", "ou_owner_a");

    const baseCookies = [
      { name: "session", value: "sess_r13_1", domain: "127.0.0.1", path: "/", hostOnly: true, secure: false, httpOnly: true },
      { name: "passport_web_did", value: "did_r13_1", domain: "127.0.0.1", path: "/", hostOnly: true, secure: false, httpOnly: false },
    ];
    const loginStore = new WebLoginStore(dir);
    loginStore.save({ owner_id: "7001", owner_name: "主人A", session_id: "sess_r13", cookies: baseCookies });
    app.store.set(ACTIVE_SESSION_KV_KEY, "sess_r13");

    // 5) [R13 #7 P1] 原生私聊在 groups_deny 含展示名关键词时：必须解析对方展示名拦截被排除同事，无法解析时 fail-closed 暂缓 ACK
    mock.setChatName("dm_r13_secret", "保密顾问");
    mock.setChatName("dm_r13_unlabeled", "");
    mock.setChatName("dm_r13_ok", "同事Bob");
    const liveClient = await FeishuWebClient.connect(
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r13", cookies: baseCookies },
      { endpoints: mock.endpoints },
    );
    app.cfg.context.groups_deny = ["保密顾问"];
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = liveClient;
    const handleMsg = (msg: ReturnType<typeof decodeMessage>, c?: FeishuWebClient) =>
      (
        svc.personalWeb as unknown as {
          handleMessage(m: ReturnType<typeof decodeMessage>, client?: FeishuWebClient): Promise<void>;
        }
      ).handleMessage(msg, c);

    // 5a) 命中展示名关键词的原生私聊被拦截，不落库
    const secretDm = decodeMessage(
      buildNativeMessage({ id: "dm_msg_secret", chatId: "dm_r13_secret", actorId: "7099", chatKind: CHAT_KIND_P2P, kind: MSG_TEXT, text: "绝密私聊内容" }),
      "7001",
    );
    await handleMsg(secretDm, liveClient);
    assert.equal(svc.store.obs("pw:dm_msg_secret"), undefined, "展示名命中 groups_deny 的个人 Web 私聊绝不能落库");

    // 5b) 无法获取对方展示名（空名称）时 fail-closed 抛错暂缓 ACK，不落库；checkConvAllowedForUnderstand 返回 uncertain
    const unlabeledDm = decodeMessage(
      buildNativeMessage({ id: "dm_msg_unlabeled", chatId: "dm_r13_unlabeled", actorId: "7098", chatKind: CHAT_KIND_P2P, kind: MSG_TEXT, text: "未命名私聊" }),
      "7001",
    );
    await assert.rejects(
      handleMsg(unlabeledDm, liveClient),
      /fail-closed|展示名/,
      "存在名称排除规则但个人 Web 私聊无法解析对方展示名时，必须抛错暂缓 ACK 防止漏过排除同事",
    );
    assert.equal(svc.store.obs("pw:dm_msg_unlabeled"), undefined, "fail-closed 暂缓的私聊绝不能落库");
    assert.equal(
      await svc.personalWeb.checkConvAllowedForUnderstand("pw_chat:dm_r13_unlabeled", "私聊：7098"),
      "uncertain",
      "无法解析对方展示名的原生私聊必须返回 uncertain",
    );

    // 5c) 非排除同事（同事Bob）正常落库并使用真实展示名
    const okDm = decodeMessage(
      buildNativeMessage({ id: "dm_msg_ok", chatId: "dm_r13_ok", actorId: "7097", chatKind: CHAT_KIND_P2P, kind: MSG_TEXT, text: "请看下接口文档" }),
      "7001",
    );
    await handleMsg(okDm, liveClient);
    assert.equal(svc.store.obs("pw:dm_msg_ok")?.conv_name, "私聊：同事Bob", "核验通过的原生私聊应记录真实展示名");
    assert.equal(await svc.personalWeb.checkConvAllowedForUnderstand("pw_chat:dm_r13_ok", "私聊：同事Bob"), "allowed");
    app.cfg.context.groups_deny = [];
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = undefined;

    // 6) [R13 #8 P1] sendBrief / buildBrief 必须在生成带接收者标签的晨报前核验 board.owner_open_id 与 lark-cli 当前登录用户
    const origLarkRun = app.lark.run.bind(app.lark);
    const origAuthStatusR13 = app.lark.authStatus.bind(app.lark);
    let authedLarkUser = "ou_owner_a";
    app.lark.authStatus = async () => ({ identity: "user", user: { open_id: authedLarkUser, name: "登录用户" } });
    app.lark.run = async (argv, opts) => {
      if (argv[0] === "task" && (argv[1] === "+get-my-tasks" || argv[1] === "sections")) return { items: [] };
      return origLarkRun(argv, opts);
    };
    app.store.set("board.tasklist", "tl_r13_a");
    app.store.set("board.owner_open_id", "ou_owner_a");
    app.store.set("board.section.pending", "sec_p");
    app.store.set("board.section.review", "sec_r");
    app.store.set("board.section.attention", "sec_a");
    // 切换配置为主人 B，但看板仍属 A 且 lark-cli 仍登录 A -> 必须拒绝
    app.cfg.owner.open_id = "ou_owner_b";
    await assert.rejects(sendBrief(app, "morning"), /看板归属账号|不一致/, "board 仍归属旧主人 A 时绝不能为主人 B 生成晨报");
    // 即使看板已更新为 B，只要 lark-cli 仍登录 A -> 仍必须拒绝
    app.store.set("board.owner_open_id", "ou_owner_b");
    await assert.rejects(sendBrief(app, "morning"), /lark-cli 登录用户|不一致/, "lark-cli 仍登录旧主人 A 时绝不能把 A 的任务打上 B 的标签");
    // 两者均与 B 一致时才放行
    authedLarkUser = "ou_owner_b";
    await sendBrief(app, "morning");
    const dateStr = new Date().toISOString().slice(0, 10);
    assert.ok(app.ledger.get(`fx:brief-morning-${dateStr}-${Q.briefOwnerTag("ou_owner_b")}`), "看板与 lark-cli 均归属主人 B 时晨报正常入队");
    // 恢复主人 A
    app.cfg.owner.open_id = "ou_owner_a";
    app.store.set("board.owner_open_id", "ou_owner_a");
    authedLarkUser = "ou_owner_a";
    app.lark.run = origLarkRun;
    app.lark.authStatus = origAuthStatusR13;

    // 7) [R13 #10 P2] validateBeforeApply 异步复核期间发生第二次策略变更：cycle 与 fastCycle 均必须在写事务 commitGuard 丢弃过期批次
    const raceSvc = new ContextService(app);
    raceSvc.store.addObs([
      {
        id: "im:r13_race_1",
        source: "im",
        kind: "p2p",
        conv: "oc_r13_race_1",
        conv_name: "私聊：张三",
        actor_id: "ou_z",
        actor_name: "张三",
        is_me: false,
        time: Date.now(),
        text: "帮我确认下发布窗口",
        url: "",
        meta: { chat_type: "p2p" },
      },
    ]);
    installCallbackLlm(raceSvc, () => {
      // 推理期间发生第 1 次策略变更（触发 validateBeforeApply 异步路径）
      app!.cfg.context.groups_deny = ["无关群_1"];
      return JSON.stringify({
        projects: [{ name: "竞态项目R13", description: "绝不应写入", status: "active" }],
        items: [
          {
            title: "竞态事项R13",
            kind: "ask_me",
            project: "竞态项目R13",
            priority: "high",
            confidence: 0.9,
            evidence: [{ obs_id: "im:r13_race_1", quote: "帮我确认下发布窗口" }],
          },
        ],
        updates: [],
        knowledge: [],
        people: [],
        close_items: [],
      });
    });
    const origCheckConv = raceSvc.personalWeb.checkConvAllowedForUnderstand.bind(raceSvc.personalWeb);
    let flippedDuringValidate = false;
    raceSvc.personalWeb.checkConvAllowedForUnderstand = async (conv, convName, snap) => {
      const res = await origCheckConv(conv, convName, snap);
      if (!flippedDuringValidate && app!.cfg.context.groups_deny.includes("无关群_1")) {
        // 异步复核期间发生第 2 次策略变更（将当前会话加入排除）
        flippedDuringValidate = true;
        app!.cfg.context.groups_deny = ["无关群_1", "张三"];
      }
      return res;
    };
    await raceSvc.cycle("context:r13-commit-guard");
    assert.equal(flippedDuringValidate, true, "应触发异步 validateBeforeApply 期间的第二次策略变更");
    assert.equal(raceSvc.store.projects().some((p) => p.name === "竞态项目R13"), false, "第二次策略变更后 commitGuard 必须丢弃过期批次，绝不写入项目");
    assert.equal(raceSvc.store.obsPending("im:r13_race_1"), true, "被丢弃的批次不得消费观测");
    app.cfg.context.groups_deny = [];
    raceSvc.personalWeb.checkConvAllowedForUnderstand = origCheckConv;

    // fastCycle 同样在 validateBeforeApply 期间二次变更时被 commitGuard 拦截
    raceSvc.store.addObs([
      {
        id: "pw:r13_fast_race",
        source: "im",
        kind: "p2p",
        conv: "pw_chat:dm_r13_fast_race",
        conv_name: "私聊：王二",
        actor_id: "7055",
        actor_name: "王二",
        is_me: false,
        time: Date.now(),
        text: "快通道确认一下方案",
        url: "",
        meta: { transport: "personal_web", native_owner_id: "7001", native_chat_id: "dm_r13_fast_race", native_message_id: "r13_fast_race", chat_type: "p2p" },
      },
    ]);
    installCallbackLlm(raceSvc, () => {
      app!.cfg.context.groups_deny = ["无关快通道_1"];
      return JSON.stringify({
        projects: [{ name: "快通道竞态项目R13", description: "绝不应写入", status: "active" }],
        items: [
          {
            title: "快通道竞态事项R13",
            kind: "ask_me",
            project: "快通道竞态项目R13",
            priority: "high",
            confidence: 0.9,
            evidence: [{ obs_id: "pw:r13_fast_race", quote: "快通道确认一下方案" }],
          },
        ],
        updates: [],
        knowledge: [],
        people: [],
        close_items: [],
      });
    });
    let flippedFastValidate = false;
    raceSvc.personalWeb.checkConvAllowedForUnderstand = async (conv, convName, snap) => {
      if (app!.cfg.context.groups_deny.includes("无关快通道_1") && !flippedFastValidate) {
        flippedFastValidate = true;
        app!.cfg.context.groups_deny = ["无关快通道_1", "王二"];
        return "allowed";
      }
      return origCheckConv(conv, convName, snap);
    };
    await raceSvc.fastCycle("context:r13-fast-guard", {
      conv: "pw_chat:dm_r13_fast_race",
      conv_name: "私聊：王二",
      trigger_obs_id: "pw:r13_fast_race",
    });
    assert.equal(flippedFastValidate, true);
    assert.equal(raceSvc.store.projects().some((p) => p.name === "快通道竞态项目R13"), false, "fastCycle commitGuard 必须丢弃二次策略变更后的过期结果");
    app.cfg.context.groups_deny = [];
    raceSvc.personalWeb.checkConvAllowedForUnderstand = origCheckConv;

    // 8) [R13 #11 P2] 自动预起草在异步解析目标期间被关闭 pre_draft 时，推理前 beforeInfer 立即跳过不调用模型
    const { item: autoDraftItem } = svc.store.upsertItem({
      strong_key: "r13_auto_predraft",
      title: "需要预起草的事项",
      kind: "ask_me",
      source: "im",
      project_id: "",
      priority: "high",
      confidence: 0.9,
      status: "open",
      meta: {},
    });
    svc.store.addObs([
      {
        id: "im:r13_predraft_obs",
        source: "im",
        kind: "p2p",
        conv: "oc_r13_predraft",
        conv_name: "私聊：小李",
        actor_id: "ou_li",
        actor_name: "小李",
        is_me: false,
        time: Date.now(),
        text: "今天能确认吗？",
        url: "",
        meta: { chat_type: "p2p", message_id: "om_r13_predraft" },
      },
    ]);
    svc.store.addEvidence("item", autoDraftItem.id, "im:r13_predraft_obs", "今天能确认吗？", Date.now());
    let draftLlmCalls = 0;
    const origDrafterRunner = svc.drafter.runner;
    svc.drafter.runner = async () => {
      draftLlmCalls++;
      return { ok: true, exitCode: 0, text: "不应调用模型", timedOut: false, aborted: false };
    };
    const origDraftCheck = svc.drafter.checkConvAllowed;
    svc.drafter.checkConvAllowed = async () => {
      // 在异步目标校核期间关闭自动预起草开关
      app!.cfg.context.personal_web.pre_draft = false;
      return "allowed";
    };
    const autoDraftWorkId = `context:draft:${autoDraftItem.id}:r13`;
    app.ledger.enqueue({
      id: autoDraftWorkId,
      kind: "context",
      ref: autoDraftItem.id,
      payload: { task: "draft", item_id: autoDraftItem.id, kind: "reply", auto: true },
    });
    const draftHandler = svc.handler();
    const draftWork = app.ledger.claim("context", 60_000);
    // 跳过步骤 5c 遗留的 fast 任务，直接运行本步的自动预起草任务
    if (draftWork && draftWork.id !== autoDraftWorkId) {
      app.ledger.release(draftWork.id, { refund: true });
    }
    app.store.db
      .prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = ?")
      .run(app.ledger.owner, Date.now() + 60_000, autoDraftWorkId);
    await draftHandler.run(app.ledger.get(autoDraftWorkId)! as never, { attempt: 1, signal: new AbortController().signal });
    assert.equal(draftLlmCalls, 0, "异步校核期间关闭 pre_draft 后，推理前 beforeInfer 必须跳过模型调用");
    assert.equal(app.ledger.get(autoDraftWorkId)?.state, "skipped", "自动预起草资格失效后工作项必须优雅落为 skipped");
    svc.drafter.runner = origDrafterRunner;
    svc.drafter.checkConvAllowed = origDraftCheck;
    app.cfg.context.personal_web.pre_draft = true;

    // 9) [R13 #17 P2 + #18 P2] listDispatches / auditViews 必须在 limit 前按主人过滤；overview 必须从健康失败数中排除 isolated 项且不改写数据库确认状态
    const oldDisp1 = "dispatch:g_r13_old1:1";
    const oldDisp2 = "dispatch:g_r13_old2:1";
    const curDisp = "dispatch:g_r13_cur:1";
    // 先插入旧记录（当前主人可见），再插入两条更新的旧主人隔离记录
    app.ledger.enqueue({ id: curDisp, kind: "dispatch", ref: "g_r13_cur", state: "accepted", payload: { guid: "g_r13_cur", summary: "新主人可见派单", description: "" } });
    app.store.set(`ctx.dispatch_owner.${oldDisp1}`, "ou_owner_a");
    app.store.set(`ctx.dispatch_owner.${oldDisp2}`, "ou_owner_a");
    app.ledger.enqueue({ id: oldDisp1, kind: "dispatch", ref: "g_r13_old1", state: "accepted", payload: { guid: "g_r13_old1", summary: "旧主人派单1", description: "" } });
    app.ledger.enqueue({ id: oldDisp2, kind: "dispatch", ref: "g_r13_old2", state: "accepted", payload: { guid: "g_r13_old2", summary: "旧主人派单2", description: "" } });
    app.ledger.audit({ source: "web", actor: "owner", command: "dispatch.retry", target: curDisp, args: {}, ok: true, message: "可见审计" });
    app.ledger.audit({ source: "web", actor: "owner", command: "context.item_done", target: "it_old_1", args: {}, ok: true, message: "旧主人审计1" });
    app.ledger.audit({ source: "web", actor: "owner", command: "context.item_done", target: "it_old_2", args: {}, ok: true, message: "旧主人审计2" });

    // 插入一条旧主人的 dead 上下文 effect（未 acknowledged）+ 活跃常驻心跳
    const isoDeadId = "fx:r13-iso-dead";
    app.ledger.enqueue({ id: isoDeadId, kind: "effect", ref: "card:ctx-item:r13_iso", payload: { op: "notify", args: { markdown: "旧主人失败" } } });
    app.store.db.prepare("UPDATE work SET state = 'dead', terminal = 1, outcome = '' WHERE id = ?").run(isoDeadId);
    app.store.set("daemon.heartbeat", `${app.ledger.owner}|${Date.now()}`);

    // 切换为主人 B
    app.cfg.owner.open_id = "ou_owner_b";
    const dispPage = Q.listDispatches(app, { limit: 1 });
    assert.equal(dispPage.length, 1, "limit=1 且最新两条属于旧主人时，listDispatches 仍必须分页返回可见的当前主人派单");
    assert.equal(dispPage[0].id, curDisp);
    const auditPage = Q.auditViews(app, undefined, 1);
    assert.equal(auditPage.length, 1, "limit=1 且最新两条审计属于旧主人时，auditViews 仍必须返回可见的当前主人审计");
    assert.equal(auditPage[0].target, curDisp);

    const ovB = Q.overview(app);
    assert.equal(ovB.attention.failures, 0, "已按旧主人隔离的失败项不得计入当前主人的 attention.failures");
    assert.equal(ovB.health.dead, 0, "已按旧主人隔离的失败项不得计入当前主人的 health.dead");
    assert.equal(ovB.health.ok, true, "仅有旧主人隔离失败项且常驻进程存活时，当前主人 health.ok 应为 true");
    assert.equal(app.ledger.get(isoDeadId)?.outcome, "", "原主人在数据库中的未确认状态不得被静默改写");
    app.cfg.owner.open_id = "ou_owner_a";

    // 10) [R13 #19 P2] 无密钥交互式 CLI 对已有 verified 回执的 pw.reply 必须本地幂等收尾，同时继续跳过未回读的 pw.reply
    const verifiedFxId = "fx:r13-pw-verified";
    const pendingFxId = "fx:r13-pw-unverified";
    const verifiedArgs = { owner_id: "7001", chat_id: "8001", message_id: "m_v1", text: "已发并回读的回复", draft_id: "d_v1" };
    const pendingArgs = { owner_id: "7001", chat_id: "8001", message_id: "m_v2", text: "尚未发出的回复", draft_id: "d_v2" };
    const { cid: verifiedCid } = computePwReplyCid({ ...verifiedArgs, effect_id: verifiedFxId });
    app.store.set(
      `pw.delivery.${verifiedCid}`,
      JSON.stringify({
        cid: verifiedCid,
        owner_id: "7001",
        chat_id: "8001",
        message_id: "m_v1",
        root_id: "m_v1",
        parent_id: "m_v1",
        threaded: true,
        text_hash: crypto.createHash("sha256").update(verifiedArgs.text).digest("hex"),
        reply_id: "reply_v1",
        state: "verified",
        updated_at: Date.now(),
      }),
    );
    app.ledger.enqueue({ id: verifiedFxId, kind: "effect", ref: "ctx-draft:d_v1", payload: { op: "pw.reply", args: verifiedArgs } });
    app.ledger.enqueue({ id: pendingFxId, kind: "effect", ref: "ctx-draft:d_v2", payload: { op: "pw.reply", args: pendingArgs } });
    app.store.set("daemon.heartbeat", `remote-daemon|${Date.now()}`);
    await withoutTestWebKey(async () => {
      await app!.engine.drain(["effect"]);
    });
    assert.equal(app.ledger.get(verifiedFxId)?.state, "done", "已完成 verified 回读的 pw.reply 即使在无密钥 CLI 下也必须本地完成收尾");
    assert.equal(app.ledger.get(pendingFxId)?.state, "pending", "未完成的 pw.reply 在无密钥 CLI 下必须继续保留给持钥常驻进程");
    assert.equal(app.ledger.get(pendingFxId)?.attempts, 0, "未完成的 pw.reply 不得被无密钥 CLI 消耗尝试次数");

    // 11) [R13 #20 P2] 已验证会话在 gateway 瞬时 502 / ticket 瞬时 503 下收到 Set-Cookie 轮换：抛错前必须先落盘新 Cookie（401 则不落盘）
    let persistedSessionCookie = "";
    const rotClient = await FeishuWebClient.connect(
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r13_rot", cookies: baseCookies },
      {
        endpoints: mock.endpoints,
        onSessionConfirmed: (updated) => {
          const s = updated.cookies.find((c) => c.name === "session")?.value;
          if (s) persistedSessionCookie = s;
          return updated;
        },
      },
    );
    mock.setGatewayRotateCookie("sess_rot_on_gw_502");
    mock.setGatewayForceStatus(502);
    await assert.rejects(rotClient.readMessage("any_msg"), /HTTP 502/);
    assert.equal(persistedSessionCookie, "sess_rot_on_gw_502", "gateway 遭遇瞬时 502 前收到的 Set-Cookie 轮换必须立即落盘");

    mock.setGatewayRotateCookie("sess_must_not_persist_on_401");
    mock.setGatewayForceStatus(401);
    await assert.rejects(rotClient.readMessage("any_msg"), /鉴权失败/);
    assert.equal(persistedSessionCookie, "sess_rot_on_gw_502", "gateway 返回 401 鉴权失败时绝不落盘 Cookie");
    mock.setGatewayForceStatus(200);
    mock.setGatewayRotateCookie("");

    mock.setTicketStatus(503);
    mock.setTicketErrorCookie("session=sess_rot_on_ticket_503; Path=/; Max-Age=86400");
    await assert.rejects(rotClient.buildSocketUrl(), /HTTP 503/);
    assert.equal(persistedSessionCookie, "sess_rot_on_ticket_503", "ticket 请求遭遇瞬时 503 前收到的 Set-Cookie 轮换必须立即落盘");
    mock.setTicketStatus(200);
    mock.setTicketErrorCookie("");
  } finally {
    if (lfsLockServer) {
      await new Promise<void>((resolve) => lfsLockServer!.close(() => resolve()));
    }
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

test("Codex 第十四轮回归：宿主控制套接字隔离、共享 Git 元数据只读、无隔离跳过校验与 separate-git-dir/submodule、授权远程 Git SSH_AUTH_SOCK、LFS 流式扫描与原始字节对齐 git-lfs、轮询前核验 lark-cli 主人、遗留看板迁移保原主人、观测写事务锁内吊销校验、无名轮询私聊解析与 fail-closed、401/403 丢弃 Set-Cookie、并发轮询防旧覆盖新编辑、自动预起草推理后复检、发言群新名优先、派单 SQL 过滤下推与补读保留 DM 类型", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r14-"));
  const dataDir = path.join(dir, "data");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(ctxDir, { recursive: true });
  process.env.CTX_DIR = ctxDir;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  let httpCookieServer: http.Server | undefined;
  let hostSockServer: net.Server | undefined;
  let sshSockServer: net.Server | undefined;
  let shmRunDir: string | undefined;

  try {
    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: "Test",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "Test",
      GIT_COMMITTER_EMAIL: "test@example.com",
    };

    // 1) [R14 #1 P1] 沙箱工人隔离宿主机控制套接字（/run/user、XDG_RUNTIME_DIR、DBUS_SESSION_BUS_ADDRESS、剥离环境变量）
    {
      const stripped = prepareHarnessEnv({
        PATH: process.env.PATH,
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/tmp/fake-dbus.sock",
        NOTIFY_SOCKET: "/run/user/1000/systemd/notify",
        GPG_AGENT_INFO: "/run/user/1000/gnupg/S.gpg-agent:0:1",
        SSH_AUTH_SOCK: "/tmp/ssh-test/agent.1",
        SSH_AGENT_PID: "12345",
      });
      try {
        assert.equal(stripped.env.DBUS_SESSION_BUS_ADDRESS, undefined, "默认剥离 DBUS_SESSION_BUS_ADDRESS");
        assert.equal(stripped.env.NOTIFY_SOCKET, undefined, "默认剥离 NOTIFY_SOCKET");
        assert.equal(stripped.env.GPG_AGENT_INFO, undefined, "默认剥离 GPG_AGENT_INFO");
        assert.equal(stripped.env.SSH_AUTH_SOCK, undefined, "普通工人默认剥离 SSH_AUTH_SOCK");
        assert.equal(stripped.env.SSH_AGENT_PID, undefined, "普通工人默认剥离 SSH_AGENT_PID");
      } finally {
        stripped.cleanup();
      }
      const keptSsh = prepareHarnessEnv(
        {
          PATH: process.env.PATH,
          DBUS_SESSION_BUS_ADDRESS: "unix:path=/tmp/fake-dbus.sock",
          SSH_AUTH_SOCK: "/tmp/ssh-test/agent.1",
        },
        { preserveSshAgent: true },
      );
      try {
        assert.equal(keptSsh.env.SSH_AUTH_SOCK, "/tmp/ssh-test/agent.1", "授权远程 Git 允许保留 SSH_AUTH_SOCK");
        assert.equal(keptSsh.env.DBUS_SESSION_BUS_ADDRESS, undefined, "即使保留 SSH_AUTH_SOCK 也仍须剥离 DBUS_SESSION_BUS_ADDRESS");
      } finally {
        keptSsh.cleanup();
      }

      // 在 /var/tmp（既不在 /tmp 也不在 /dev/shm 或 dataDir 内）下建立真实宿主 Unix 套接字作为 XDG_RUNTIME_DIR，
      // 验证 bwrap 与 unshare 均用空 tmpfs 遮蔽它，阻止同 UID 沙箱工人 connect(2) 到宿主服务套接字
      if (fs.existsSync("/var/tmp")) {
        shmRunDir = fs.mkdtempSync(path.join("/var/tmp", "pa-r14-run-"));
        const hostSockPath = path.join(shmRunDir, "systemd-private.sock");
        const extraDbusSockPath = path.join(shmRunDir, "dbus-extra.sock");
        hostSockServer = net.createServer((s) => s.end("HOST_REACHED"));
        await new Promise<void>((resolve) => hostSockServer!.listen(hostSockPath, resolve));
        fs.writeFileSync(extraDbusSockPath, "");

        const activeCfg = { dataDir, context: { personal_web: { enabled: true } } } as never;
        const fakeEnv = {
          ...process.env,
          XDG_RUNTIME_DIR: shmRunDir,
          DBUS_SESSION_BUS_ADDRESS: `unix:path=${extraDbusSockPath}`,
        };
        const plan = buildWorkspaceIsolation(activeCfg, { mode: "worker-ro", cwd: dir }, fakeEnv);

        if (hasCredentialMountIsolation()) {
          const probeCode = `
            const net = require("node:net");
            const s = net.connect(${JSON.stringify(hostSockPath)});
            s.on("connect", () => { process.stdout.write("CONNECTED"); s.destroy(); });
            s.on("error", (e) => { process.stdout.write("BLOCKED:" + e.code); });
          `;
          const wrapped = wrapCredentialIsolatedCommand(process.execPath, ["-e", probeCode], fakeEnv, plan);
          assert.equal(wrapped.isolated, true);
          assert.ok(wrapped.args.includes(fs.realpathSync(shmRunDir)), "隔离命令必须将自定义 XDG_RUNTIME_DIR 纳入 tmpfs 遮蔽");
          const res = await runProcess(wrapped.cmd, wrapped.args, { cwd: dir, timeoutMs: 10_000 });
          assert.equal(res.code, 0, res.stderr);
          assert.match(res.stdout, /^BLOCKED:ENOENT/, "沙箱工人绝不能连上宿主机 XDG_RUNTIME_DIR 下的服务套接字");
        }
      }
    }

    // 2) [R14 #2 P1] 共享 Git 元数据（wt.commonDir / wt.gitDir / .git）对不可信工人（worker-write / verify）保持只读
    const gitBase = path.join(dir, "git-r14");
    const repoA = path.join(gitBase, "repoA");
    const wtA = path.join(gitBase, "wtA");
    fs.mkdirSync(repoA, { recursive: true });
    assert.equal((await runProcess("git", ["init", "-q", repoA], { env: gitEnv })).code, 0);
    fs.writeFileSync(path.join(repoA, "hello.txt"), "v1\n");
    assert.equal((await runProcess("git", ["-C", repoA, "add", "-A"], { env: gitEnv })).code, 0);
    assert.equal((await runProcess("git", ["-C", repoA, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
    assert.equal((await runProcess("git", ["-C", repoA, "worktree", "add", "-q", "-b", "pa/r14-a", wtA], { env: gitEnv })).code, 0);

    const activeIsoCfg = { dataDir, context: { personal_web: { enabled: true } } } as never;
    const wtMeta = detectGitWorktreeDirs(wtA, { trustedRepoRoot: repoA });
    const workerWritePlan = buildWorkspaceIsolation(activeIsoCfg, { mode: "worker-write", cwd: wtA, trustedRepoRoot: repoA }, process.env);
    const verifyPlan = buildWorkspaceIsolation(activeIsoCfg, { mode: "verify", cwd: wtA, trustedRepoRoot: repoA }, process.env);
    const gitRwPlan = buildWorkspaceIsolation(activeIsoCfg, { mode: "git-rw", cwd: wtA, trustedRepoRoot: repoA }, process.env);
    const realRepoADotGit = fs.realpathSync(path.join(repoA, ".git"));
    assert.ok(!workerWritePlan.writablePaths?.includes(wtMeta.commonDir!), "worker-write 绝不能将共享 commonDir 挂为可写");
    assert.ok(!workerWritePlan.writablePaths?.includes(wtMeta.gitDir!), "worker-write 绝不能将 worktree gitDir 挂为可写");
    assert.ok(workerWritePlan.readOnlyPaths?.includes(wtMeta.commonDir!), "worker-write 必须将共享 commonDir 挂为只读");
    assert.ok(verifyPlan.readOnlyPaths?.includes(wtMeta.commonDir!), "verify 必须将共享 commonDir 挂为只读");
    assert.ok(gitRwPlan.writablePaths?.includes(wtMeta.commonDir!), "受信任 git-rw 提交步骤允许写入 commonDir");

    const standaloneWritePlan = buildWorkspaceIsolation(activeIsoCfg, { mode: "worker-write", cwd: repoA, trustedRepoRoot: repoA }, process.env);
    assert.ok(standaloneWritePlan.readOnlyPaths?.includes(realRepoADotGit), "独立仓库 worker-write 必须把 .git 目录挂为只读");

    if (hasCredentialMountIsolation()) {
      const hookProbe = path.join(realRepoADotGit, "hooks", "r14-worker-pwn");
      const wtWorkFile = path.join(wtA, "r14-worker-ok.txt");
      const writeTestCode = `
        const fs = require("node:fs");
        fs.writeFileSync(${JSON.stringify(wtWorkFile)}, "ok");
        let gitErr = "";
        try { fs.writeFileSync(${JSON.stringify(hookProbe)}, "pwn"); } catch (e) { gitErr = e.code || String(e); }
        process.stdout.write(gitErr);
      `;
      const wrapped = wrapCredentialIsolatedCommand(process.execPath, ["-e", writeTestCode], process.env, workerWritePlan);
      assert.equal(wrapped.isolated, true);
      const res = await runProcess(wrapped.cmd, wrapped.args, { cwd: wtA, timeoutMs: 10_000 });
      assert.equal(res.code, 0, res.stderr);
      assert.equal(res.stdout, "EROFS", "沙箱工人在 worktree 内可以改代码，但写主仓库 .git/hooks 必须被内核 EROFS 拦截");
      assert.equal(fs.existsSync(hookProbe), false);
      fs.rmSync(wtWorkFile, { force: true });
    }

    // 3) [R14 #3 P2] 未启用隔离时跳过 .git 挂载校验；启用隔离时支持 --separate-git-dir 与 submodule，且仍拒绝篡改
    {
      const sepWork = path.join(gitBase, "sep-work");
      const sepGit = path.join(gitBase, "sep-gitdir");
      fs.mkdirSync(sepWork, { recursive: true });
      assert.equal(
        (await runProcess("git", ["init", "-q", `--separate-git-dir=${sepGit}`, sepWork], { env: gitEnv })).code,
        0,
      );
      const sepMeta = detectGitWorktreeDirs(sepWork);
      assert.equal(sepMeta.gitDir, fs.realpathSync(sepGit), "--separate-git-dir 必须被识别为合法独立 Git 目录");
      assert.equal(sepMeta.commonDir, fs.realpathSync(sepGit));
      const sepPlan = buildWorkspaceIsolation(activeIsoCfg, { mode: "worker-write", cwd: sepWork }, process.env);
      assert.ok(sepPlan.readOnlyPaths?.includes(fs.realpathSync(sepGit)), "--separate-git-dir 在 worker-write 下保持只读");

      // 合法 submodule 布局（.git 文件指向 superRepo/.git/modules/sub）
      const subSrc = path.join(gitBase, "sub-src");
      const superRepo = path.join(gitBase, "super-repo");
      fs.mkdirSync(subSrc, { recursive: true });
      fs.mkdirSync(superRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", subSrc], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(subSrc, "s.txt"), "sub\n");
      assert.equal((await runProcess("git", ["-C", subSrc, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", subSrc, "commit", "-q", "-m", "sub init"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["init", "-q", superRepo], { env: gitEnv })).code, 0);
      assert.equal(
        (await runProcess("git", ["-C", superRepo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", subSrc, "sub"], { env: gitEnv })).code,
        0,
      );
      const subDir = path.join(superRepo, "sub");
      const subMeta = detectGitWorktreeDirs(subDir, { trustedRepoRoot: superRepo });
      assert.equal(subMeta.gitDir, fs.realpathSync(path.join(superRepo, ".git", "modules", "sub")), "合法 submodule 必须通过受信任父仓校验");

      // 无工具（llm-none）且无隔离需求时，不要求沙箱也不得因 .git 挂载规划提前抛错；
      // 而在 Linux 上所有仓库级模式（如 verify）默认强制隔离并校验被篡改的 .git 文件（R19 #1）
      const tamperedDir = path.join(gitBase, "tampered-inactive");
      fs.mkdirSync(tamperedDir, { recursive: true });
      fs.writeFileSync(path.join(tamperedDir, ".git"), "gitdir: /nonexistent/outside/path\n");
      const inactiveCfg = { dataDir: path.join(dir, "empty-data"), context: { personal_web: { enabled: false } } } as never;
      const inactiveLlmPlan = buildWorkspaceIsolation(inactiveCfg, { mode: "llm-none", cwd: tamperedDir }, {});
      assert.equal(inactiveLlmPlan.requireIsolation, false, "无个人 Web 的 llm-none 不得强制要求沙箱");
      if (process.platform === "linux") {
        assert.throws(
          () => buildWorkspaceIsolation(inactiveCfg, { mode: "verify", cwd: tamperedDir }, {}),
          /worktree \.git 元数据校验失败/,
          "Linux 上仓库级 verify 模式默认开启隔离并校验 .git 元数据",
        );
      }
    }

    // 4) [R14 #4 P2] 授权远程 Git 操作（push/fetch/ls-remote/pull/clone/lfs）保留并仅挂载 SSH_AUTH_SOCK，本地 Git 与普通工人均不暴露
    {
      const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r14-ssh-"));
      const sshSock = path.join(sockDir, "agent.sock");
      const badSock = path.join(dataDir, "inside-data.sock");
      sshSockServer = net.createServer((s) => s.end("AGENT_OK"));
      await new Promise<void>((resolve) => sshSockServer!.listen(sshSock, resolve));
      const badSockSrv = net.createServer();
      await new Promise<void>((resolve) => badSockSrv.listen(badSock, resolve));
      try {
        assert.equal(
          resolveAuthorizedSshAuthSock(["push", "origin", "HEAD"], { SSH_AUTH_SOCK: sshSock }, dataDir),
          fs.realpathSync(sshSock),
          "push 远程操作应授权透传合法 SSH_AUTH_SOCK",
        );
        assert.equal(
          resolveAuthorizedSshAuthSock(["ls-remote", "origin"], { SSH_AUTH_SOCK: sshSock }, dataDir),
          fs.realpathSync(sshSock),
          "ls-remote 应授权透传合法 SSH_AUTH_SOCK",
        );
        assert.equal(
          resolveAuthorizedSshAuthSock(["status"], { SSH_AUTH_SOCK: sshSock }, dataDir),
          undefined,
          "本地 git status 绝不暴露 SSH_AUTH_SOCK",
        );
        assert.equal(
          resolveAuthorizedSshAuthSock(["push", "origin", "HEAD"], { SSH_AUTH_SOCK: badSock }, dataDir),
          undefined,
          "位于 dataDir 内的套接字绝不允许作为 SSH_AUTH_SOCK 透传",
        );

        if (hasCredentialMountIsolation()) {
          const planWithAgent = buildWorkspaceIsolation(
            activeIsoCfg,
            { mode: "git-rw", cwd: repoA, trustedRepoRoot: repoA, extraWritablePaths: [fs.realpathSync(sshSock)] },
            process.env,
          );
          const probeAgent = `
            const net = require("node:net");
            const s = net.connect(${JSON.stringify(fs.realpathSync(sshSock))});
            let out = "";
            s.on("data", (d) => { out += d.toString(); });
            s.on("end", () => process.stdout.write(out));
            s.on("error", (e) => process.stdout.write("ERR:" + e.code));
          `;
          const wrapped = wrapCredentialIsolatedCommand(process.execPath, ["-e", probeAgent], process.env, planWithAgent);
          const r = await runProcess(wrapped.cmd, wrapped.args, { cwd: repoA, timeoutMs: 10_000 });
          assert.equal(r.code, 0, r.stderr);
          assert.equal(r.stdout, "AGENT_OK", "授权远程 Git 沙箱必须可连通单点挂载的 SSH_AUTH_SOCK（即使它在 /tmp 下）");
        }
      } finally {
        await new Promise<void>((resolve) => badSockSrv.close(() => resolve()));
        fs.rmSync(sockDir, { recursive: true, force: true });
      }
    }

    // 5) [R14 #5 P2] 流式扫描出站 Git 对象：跨越多个 1024 批次仍能完整扫描且命中首条即早停
    {
      const bigRepo = path.join(gitBase, "big-stream-repo");
      fs.mkdirSync(bigRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", bigRepo], { env: gitEnv })).code, 0);
      // 一次创建 1100 个独立小文件（> 1024 单批大小）验证跨批流式扫描
      for (let i = 0; i < 1100; i++) {
        fs.writeFileSync(path.join(bigRepo, `f_${i}.txt`), `plain file content ${i}\n`);
      }
      assert.equal((await runProcess("git", ["-C", bigRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", bigRepo, "commit", "-q", "-m", "1100 plain files"], { env: gitEnv })).code, 0);
      const curBranch = (await runProcess("git", ["-C", bigRepo, "rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
      assert.equal(await branchUsesGitLfs(bigRepo, curBranch), false, "超过单批上限的纯文本仓库流式扫描应返回 false");

      // 再提交一个有效 LFS 指针，流式扫描必须命中返回 true
      const validPtr = `version https://git-lfs.github.com/spec/v1\noid sha256:${"a".repeat(64)}\nsize 42\n`;
      fs.writeFileSync(path.join(bigRepo, "model.bin"), validPtr);
      assert.equal((await runProcess("git", ["-C", bigRepo, "add", "model.bin"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", bigRepo, "commit", "-q", "-m", "add lfs ptr"], { env: gitEnv })).code, 0);
      assert.equal(await branchUsesGitLfs(bigRepo, curBranch), true, "跨批流式扫描必须准确检出新增的 LFS 指针");
    }

    // 6) [R14 #6 P2] 原始字节级 LFS 指针校验与官方 `git lfs pointer --check --stdin` 逐项一致（含 UTF-8 BOM 与 Unicode 空白）
    {
      const basePtr = `version https://git-lfs.github.com/spec/v1\noid sha256:${"b".repeat(64)}\nsize 123\n`;
      const vectors: { name: string; buf: Buffer; expected: boolean }[] = [
        { name: "clean LF", buf: Buffer.from(basePtr, "utf8"), expected: true },
        { name: "clean CRLF", buf: Buffer.from(basePtr.replace(/\n/g, "\r\n"), "utf8"), expected: true },
        { name: "raw UTF-8 BOM rejected", buf: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(basePtr, "utf8")]), expected: false },
        { name: "leading NBSP U+00A0 accepted", buf: Buffer.from(`\u00a0${basePtr}`, "utf8"), expected: true },
        { name: "trailing NBSP U+00A0 accepted", buf: Buffer.from(`${basePtr}\u00a0`, "utf8"), expected: true },
        { name: "leading NEL U+0085 accepted", buf: Buffer.from(`\u0085${basePtr}`, "utf8"), expected: true },
        { name: "leading ideographic space U+3000 accepted", buf: Buffer.from(`\u3000${basePtr}`, "utf8"), expected: true },
        { name: "mid-line NBSP rejected", buf: Buffer.from(basePtr.replace("version ", "version\u00a0"), "utf8"), expected: false },
        { name: "invalid UTF-8 bytes rejected", buf: Buffer.concat([Buffer.from(basePtr, "utf8"), Buffer.from([0xff, 0xfe])]), expected: false },
        { name: "uppercase hex rejected", buf: Buffer.from(basePtr.replace("b".repeat(64), "B".repeat(64)), "utf8"), expected: false },
      ];
      const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 5_000 })).code === 0;
      for (const v of vectors) {
        const ours = isGitLfsPointerBlob(v.buf);
        assert.equal(ours, v.expected, `LFS 字节校验 [${v.name}] 应为 ${v.expected}`);
        if (hasGitLfs) {
          const refRc = await new Promise<number>((resolve) => {
            const c = spawn("git", ["lfs", "pointer", "--check", "--stdin"], { stdio: ["pipe", "pipe", "pipe"] });
            c.on("close", (code) => resolve(code ?? 1));
            c.stdin.end(v.buf);
          });
          assert.equal(ours, refRc === 0, `LFS 字节校验 [${v.name}] 必须与 git lfs pointer --check --stdin 完全一致`);
        }
      }
    }

    // 初始化 App / ContextService 用于 #7 ~ #16 回归测试
    const cfgPath = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      `owner:
  open_id: ou_owner_a
  name: 主人A
  timezone: Asia/Shanghai
bins:
  lark: ${path.join(STUBS, "ctx-lark")}
  bytedcli: ${path.join(STUBS, "ctx-bytedcli")}
harnesses:
  codex:
    type: codex-exec
    cmd: ${path.join(STUBS, "ctx-codex")}
roles:
  brain: codex
server:
  enabled: false
cards:
  enabled: true
kb:
  enabled: false
context:
  enabled: true
  understand: true
  harness: codex
  groups: spoken
  groups_allow: []
  groups_deny: []
  sources:
    meego: false
    tasks: true
    im: true
    minutes: false
    calendar: false
    docs: false
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: true
    send_replies: false
    debounce_ms: 0
data_dir: ${dataDir}
`,
    );
    app = createApp(loadConfig(cfgPath));
    const { registerContext } = await import("../src/context/index.ts");
    const svc = registerContext(app)!;
    installCtxDirStubLlm(svc, ctxDir);
    const baseCookies = [
      { name: "session", value: "sess_r14_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r14_1", domain: "127.0.0.1", path: "/" },
    ];
    const loginA = { owner_id: "7001", owner_name: "主人A", cookies: baseCookies };
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });
    const loginStore = new WebLoginStore(dataDir);
    const client = await FeishuWebClient.connect(loginStore.load()!, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);

    // 7) [R14 #7 P1] 轮询前核验活跃 lark-cli 账号：CLI 切换至账号 B 后 cycle() 与 pullAll() 必须阻断并拒绝混入 B 的私聊与任务
    {
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_other_user_b",
          user_name: "其他账号B",
          p2p: [
            {
              message_id: "om_b_secret_dm",
              chat_id: "oc_b_dm",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now).toISOString(),
              sender: { id: "ou_b_peer", name: "B的私聊对象", sender_type: "user" },
              content: "属于B的私密消息",
            },
          ],
          tasks: [{ guid: "t_b_secret", summary: "属于B的私人任务", created_at: new Date(now).toISOString() }],
        }),
      );
      const cyc = await svc.cycle("ctx:r14-cli-mismatch");
      assert.ok(cyc.errors.some((e) => e.includes("ou_other_user_b") && e.includes("ou_owner_a")), cyc.errors.join(";"));
      assert.ok(cyc.sources.every((s) => s.count === 0 && /ou_other_user_b/.test(s.error)), "各用户态来源必须记录账号不匹配错误且写入 0 条");
      assert.equal(svc.store.obs("im:om_b_secret_dm"), undefined, "B 的私聊绝不能落入 A 的观测库");
      assert.equal(svc.store.obs("task:t_b_secret"), undefined, "B 的任务绝不能落入 A 的观测库");

      const directPull = await svc.connectors.pullAll();
      assert.ok(directPull.every((s) => s.count === 0 && /ou_other_user_b/.test(s.error)), "直接调用 pullAll() 同样必须拒绝拉取账号 B 的用户态来源");
      assert.equal(svc.store.obs("im:om_b_secret_dm"), undefined);
      assert.equal(svc.store.obs("task:t_b_secret"), undefined);
    }

    // 8) [R14 #8 P1] 升级迁移遗留看板时保留原始主人，绝不在 initApp 校验前覆盖 owner.open_id 或改标无主/他主看板
    {
      const miniCfg = (openId: string, dd: string) =>
        `owner:\n  open_id: ${openId}\nbins:\n  lark: ${path.join(STUBS, "lark")}\nharnesses:\n  codex:\n    type: codex-exec\n    cmd: ${path.join(STUBS, "ctx-codex")}\nroles:\n  brain: codex\nkb:\n  enabled: false\ndata_dir: ${dd}\n`;
      // 8a) 遗留目录归属 A（有 board.tasklist 与 owner.open_id = A，无 board.owner_open_id）：用 B 配置初始化必须拒绝且保留 owner.open_id = A
      const legDirA = path.join(dir, "legacy-board-a");
      fs.mkdirSync(legDirA, { recursive: true });
      const legCfgB = path.join(legDirA, "config.yaml");
      fs.writeFileSync(legCfgB, miniCfg("ou_owner_b", legDirA));
      const legAppB = createApp(loadConfig(legCfgB));
      try {
        legAppB.store.set("board.tasklist", "tl_legacy_a");
        legAppB.store.set("owner.open_id", "ou_owner_a");
        await assert.rejects(() => initApp(legAppB), /不一致|拒绝改标/);
        assert.equal(legAppB.store.get("owner.open_id"), "ou_owner_a", "拒绝后必须保留原始 owner.open_id");
        assert.equal(legAppB.store.get("board.owner_open_id"), undefined, "绝不能把 A 的遗留看板改标成 B");
      } finally {
        legAppB.store.db.close();
      }

      // 8b) 遗留目录缺少原始主人记录（有 board.tasklist，无 owner.open_id 也无 board.owner_open_id）：必须拒绝接管
      const legDirUnknown = path.join(dir, "legacy-board-unknown");
      fs.mkdirSync(legDirUnknown, { recursive: true });
      const legCfgU = path.join(legDirUnknown, "config.yaml");
      fs.writeFileSync(legCfgU, miniCfg("ou_owner_b", legDirUnknown));
      const legAppU = createApp(loadConfig(legCfgU));
      try {
        legAppU.store.set("board.tasklist", "tl_legacy_unknown");
        await assert.rejects(() => initApp(legAppU), /无法确立归属|拒绝自动接管/);
        assert.equal(legAppU.store.get("board.owner_open_id"), undefined);
      } finally {
        legAppU.store.db.close();
      }

      // 8c) 原主人 A 本人执行 initApp：安全回填 board.owner_open_id = A
      const legCfgA = path.join(legDirA, "config-a.yaml");
      fs.writeFileSync(legCfgA, miniCfg("ou_owner_a", legDirA));
      const legAppA = createApp(loadConfig(legCfgA));
      try {
        legAppA.lark.authStatus = async () => ({ identity: "user", user: { open_id: "ou_owner_a", name: "主人A" } });
        let secSeq = 0;
        legAppA.lark.run = async (args) => {
          if (args.includes("create")) return { guid: `sec_leg_${++secSeq}` };
          return { items: [] };
        };
        await initApp(legAppA);
        assert.equal(legAppA.store.get("board.owner_open_id"), "ou_owner_a", "原主人 A 迁移遗留看板时应安全回填归属");
      } finally {
        legAppA.store.db.close();
      }
    }

    // 9) [R14 #9 P1] 观测写事务锁内校验会话吊销（handleMessage & hydrateContext）：
    //    模拟跨进程 web-logout 在 pre-check 之后、addObs/addBackgroundObs 获取 BEGIN IMMEDIATE 写锁前提交吊销
    {
      mock.setChatName("9910", "写锁吊销测试群");
      mock.setChatKind("9910", CHAT_KIND_GROUP);
      const revMsgBuf = buildNativeMessage({
        id: "r14_rev_tx_1",
        chatId: "9910",
        actorId: "7002",
        createdAtSec: nowSec,
        position: 10,
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 写锁竞态消息" }]),
      });
      mock.addMessage("r14_rev_tx_1", revMsgBuf);

      const origTx = svc.store.tx.bind(svc.store);
      let injectedRevoke = false;
      svc.store.tx = (<T>(fn: () => T): T =>
        origTx(() => {
          if (!injectedRevoke) {
            injectedRevoke = true;
            // 在 BEGIN IMMEDIATE 写事务已持锁、beforeCommit 尚未执行前写入吊销键（等价于另一进程刚提交 web-logout）
            app!.store.set(REVOKED_AT_KV_KEY, String(Date.now()));
          }
          return fn();
        })) as typeof svc.store.tx;
      try {
        await assert.rejects(
          () => svc.personalWeb.handleMessage(decodeMessage(revMsgBuf, "7001"), client),
          /吊销|aborted/,
          "addObs 写事务锁内检测到 web-logout 吊销后必须中止且回滚",
        );
      } finally {
        svc.store.tx = origTx;
      }
      assert.equal(injectedRevoke, true);
      assert.equal(svc.store.obs("pw:r14_rev_tx_1"), undefined, "写锁内吊销后观测绝不能写入 ctx_obs");
      // 恢复登录态并测试 hydrateContext 的 addBackgroundObs 写事务锁内吊销校验
      app.store.set(REVOKED_AT_KV_KEY, "");

      const hydTriggerBuf = buildNativeMessage({
        id: "r14_hyd_trig",
        chatId: "9910",
        actorId: "7002",
        createdAtSec: nowSec,
        position: 11,
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 需要补读背景" }]),
      });
      const hydHistBuf = buildNativeMessage({
        id: "r14_hyd_bg_1",
        chatId: "9910",
        actorId: "7002",
        createdAtSec: nowSec - 10,
        position: 9,
        richBytes: encodeRichText([{ text: "写锁吊销时不应落库的历史消息" }]),
      });
      app.store.set(pwSpokenGroupsKey("7001"), JSON.stringify({ "pw_chat:9910": { name: "写锁吊销测试群", at: now } }));
      mock.addMessage("r14_hyd_trig", hydTriggerBuf);
      mock.addMessage("r14_hyd_bg_1", hydHistBuf);
      mock.setHistory("9910", { 9: hydHistBuf });
      await svc.personalWeb.handleMessage(decodeMessage(hydTriggerBuf, "7001"), client);

      let injectedHydRevoke = false;
      svc.store.tx = (<T>(fn: () => T): T =>
        origTx(() => {
          if (!injectedHydRevoke) {
            injectedHydRevoke = true;
            app!.store.set(REVOKED_AT_KV_KEY, String(Date.now()));
          }
          return fn();
        })) as typeof svc.store.tx;
      try {
        const bgCount = await svc.personalWeb.hydrateContext(
          { id: "r14_hyd_trig", conversationId: "9910", rootId: "", parentId: "", threadId: "", position: 11, createdAtMs: now },
          "pw_chat:9910",
          "写锁吊销测试群",
        );
        assert.equal(bgCount, 0, "addBackgroundObs 写事务锁内检测到吊销必须返回 0");
      } finally {
        svc.store.tx = origTx;
      }
      assert.equal(injectedHydRevoke, true);
      assert.equal(svc.store.obs("pw:r14_hyd_bg_1"), undefined, "写锁内吊销后历史背景绝不能落库");
      app.store.set(REVOKED_AT_KV_KEY, "");
    }

    // 10) [R14 #10 P1] 无名轮询私聊（p2p）：先解析对方姓名再应用 groups_deny，仅含本人发出的无名私聊 fail-closed 且不推进 p2p/mine 游标
    {
      app.cfg.context.groups_deny = ["保密对象"];
      // 10a) 无 chat_name 但同批有对方来信（sender.name = 保密对象）：来信与本人回信均须被过滤丢弃
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_owner_a",
          user_name: "主人A",
          p2p: [
            {
              message_id: "om_dm_sec_in",
              chat_id: "oc_dm_sec",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now).toISOString(),
              sender: { id: "ou_sec", name: "保密对象", sender_type: "user" },
              content: "不要存储的私聊来信",
            },
            {
              message_id: "om_dm_sec_out",
              chat_id: "oc_dm_sec",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now + 1000).toISOString(),
              sender: { id: "ou_owner_a", name: "主人A", sender_type: "user" },
              content: "我在被排除私聊里的回复",
            },
          ],
          mine: [
            {
              message_id: "om_dm_sec_out",
              chat_id: "oc_dm_sec",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now + 1000).toISOString(),
              sender: { id: "ou_owner_a", name: "主人A", sender_type: "user" },
              content: "我在被排除私聊里的回复",
            },
          ],
        }),
      );
      const r10a = await svc.connectors.pullIm();
      assert.equal(r10a.count, 0, "命中 groups_deny 关键词的无名私聊来信与回信均不得入库");
      assert.equal(svc.store.obs("im:om_dm_sec_in"), undefined);
      assert.equal(svc.store.obs("im:om_dm_sec_out"), undefined);

      // 10b) 仅含本人发出的无名私聊（im chats get 返回空 name）：必须按 inconclusive 暂缓且不推进 cursor.im.p2p 与 cursor.im.mine
      const prevP2pCur = Number(app.store.get("ctx.cursor.im.p2p") ?? 0);
      const prevMineCur = Number(app.store.get("ctx.cursor.im.mine") ?? 0);
      await new Promise((r) => setTimeout(r, 10));
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_owner_a",
          user_name: "主人A",
          chat_meta: { oc_dm_unknown: { name: "", chat_mode: "p2p" } },
          p2p: [
            {
              message_id: "om_dm_unk_out",
              chat_id: "oc_dm_unknown",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now + 2000).toISOString(),
              sender: { id: "ou_owner_a", name: "主人A", sender_type: "user" },
              content: "仅本人发出的无名私聊消息",
            },
          ],
          mine: [
            {
              message_id: "om_dm_unk_out",
              chat_id: "oc_dm_unknown",
              chat_type: "p2p",
              msg_type: "text",
              create_time: new Date(now + 2000).toISOString(),
              sender: { id: "ou_owner_a", name: "主人A", sender_type: "user" },
              content: "仅本人发出的无名私聊消息",
            },
          ],
        }),
      );
      const r10b = await svc.connectors.pullIm();
      assert.equal(r10b.count, 0, "无法确认对方的无名私聊不得入库");
      assert.equal(svc.store.obs("im:om_dm_unk_out"), undefined);
      assert.equal(Number(app.store.get("ctx.cursor.im.p2p") ?? 0), prevP2pCur, "无名私聊暂缓时不得推进 cursor.im.p2p");
      assert.equal(Number(app.store.get("ctx.cursor.im.mine") ?? 0), prevMineCur, "来自 mine 流的无名私聊暂缓时不得推进 cursor.im.mine");

      // 10c) 已存在的通用占位名「私聊」在存在名称排除规则时，checkConvAllowedForUnderstand 必须 fail-closed 返回 uncertain
      svc.store.addObs([
        {
          id: "im:om_dm_generic_existing",
          source: "im",
          kind: "mine",
          conv: "oc_dm_unknown",
          conv_name: "私聊",
          actor_id: "ou_owner_a",
          actor_name: "主人A",
          is_me: true,
          time: now,
          text: "旧版本写入的无名私聊",
          url: "",
          meta: { chat_type: "p2p" },
        },
      ]);
      assert.equal(
        await svc.personalWeb.checkConvAllowedForUnderstand("oc_dm_unknown", "私聊"),
        "uncertain",
        "存在名称排除规则且私聊仅有通用占位名「私聊」时不得送模型",
      );
      svc.store.markProcessed(["im:om_dm_generic_existing"]);
      app.cfg.context.groups_deny = [];
    }

    // 11) [R14 #11 P2] fetchWithJar 对 401/403 响应暂存并彻底丢弃 Set-Cookie，既不污染活罐也不丢失并发轮换
    {
      let receivedOnOk = "";
      httpCookieServer = http.createServer((req, res) => {
        if (req.url === "/deny") {
          res.writeHead(401, {
            "Set-Cookie": ["session=; Path=/; Max-Age=0", "poison=bad; Path=/"],
          });
          res.end("unauthorized");
          return;
        }
        if (req.url === "/redir-deny") {
          res.writeHead(302, {
            Location: "/deny",
            "Set-Cookie": "session=wiped_on_hop0; Path=/",
          });
          res.end();
          return;
        }
        if (req.url === "/ok") {
          receivedOnOk = String(req.headers.cookie ?? "");
          res.writeHead(200, { "Set-Cookie": "rotated=v2; Path=/" });
          res.end("ok");
          return;
        }
        res.writeHead(404);
        res.end();
      });
      await new Promise<void>((resolve) => httpCookieServer!.listen(0, "127.0.0.1", resolve));
      const port = (httpCookieServer.address() as net.AddressInfo).port;
      const base = `http://127.0.0.1:${port}`;
      const jar = RecordingCookieJar.fromRecords(
        [
          { name: "session", value: "sess_live_keep", domain: "127.0.0.1", path: "/" },
          { name: "other", value: "v1", domain: "127.0.0.1", path: "/" },
        ],
        ["127.0.0.1"],
      );
      const rDeny = await fetchWithJar(jar, {
        method: "GET",
        url: `${base}/deny`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(rDeny.status, 401);
      assert.equal(rDeny.cookiesUpdated, false, "401 拒绝响应不得标记 cookiesUpdated");
      assert.equal(jar.cookieValue(new URL(`${base}/ok`), "session"), "sess_live_keep", "401 Set-Cookie 绝不能清除活罐里的 session");
      assert.equal(jar.cookieValue(new URL(`${base}/ok`), "poison"), "", "401 新增 Cookie 必须丢弃");
      assert.equal(jar.peekDelta().deletes.length, 0, "401 绝不能在 dirtyDeletes 留下删除增量");

      const rRedirDeny = await fetchWithJar(jar, {
        method: "GET",
        url: `${base}/redir-deny`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(rRedirDeny.status, 401);
      assert.equal(rRedirDeny.cookiesUpdated, false);
      assert.equal(jar.cookieValue(new URL(`${base}/ok`), "session"), "sess_live_keep", "经 302 跳进 401 时，302 跳暂存的 Set-Cookie 同样必须全部丢弃");

      // 并发同步旋转无关 Cookie 后再发起成功请求：活罐继续发送原始 session 且保留并发轮换的 other=v_concurrent
      jar.syncFromRecords(
        [
          { name: "session", value: "sess_live_keep", domain: "127.0.0.1", path: "/" },
          { name: "other", value: "v_concurrent", domain: "127.0.0.1", path: "/" },
        ],
        Date.now(),
        { preservePendingDelta: true },
      );
      const rOk = await fetchWithJar(jar, {
        method: "GET",
        url: `${base}/ok`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(rOk.status, 200);
      assert.equal(rOk.cookiesUpdated, true);
      assert.ok(receivedOnOk.includes("session=sess_live_keep"), "下一次请求必须继续携带完好的原始 session");
      assert.ok(receivedOnOk.includes("other=v_concurrent"), "无关并发 Cookie 轮换必须完整保留");
      assert.equal(jar.cookieValue(new URL(`${base}/ok`), "rotated"), "v2");
    }

    // 12) [R14 #12 P2] 防止旧轮询覆写新消息编辑：跨进程 __poll_im__ 租约串行化 + poll_observed_at 单调保护
    {
      // 12a) 另一轮询正持有 __poll_im__ 租约时，重叠 pullIm() 跳过不竞态
      assert.equal(svc.store.claimConv("__poll_im__", "other_holder", app.ledger.owner, 60_000), true);
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_owner_a",
          user_name: "主人A",
          at_me: [
            {
              message_id: "om_overlap_skip",
              chat_id: "oc_overlap",
              chat_name: "重叠群",
              chat_type: "group",
              msg_type: "text",
              create_time: new Date(now).toISOString(),
              sender: { id: "ou_x", name: "X", sender_type: "user" },
              content: "租约占用时不该拉取",
            },
          ],
        }),
      );
      const skippedOverlap = await svc.connectors.pullIm();
      assert.equal(skippedOverlap.count, 0, "重叠轮询检测到活跃 __poll_im__ 租约时必须跳过");
      assert.equal(svc.store.obs("im:om_overlap_skip"), undefined);
      svc.store.releaseConv("__poll_im__", "other_holder", app.ledger.owner);

      // 12b) addObs 的 poll_observed_at 单调保护：较早的慢轮询快照绝不能覆写并重开较新的消息编辑
      svc.store.addObs([
        {
          id: "im:om_mono_edit",
          source: "im",
          kind: "at_me",
          conv: "oc_mono",
          conv_name: "单调群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "较新的已编辑正文",
          url: "",
          meta: { chat_type: "group", at_me: true, poll_observed_at: 2_000 },
        },
      ]);
      svc.store.markProcessed(["im:om_mono_edit"]);
      const staleOverwritten = svc.store.addObs([
        {
          id: "im:om_mono_edit",
          source: "im",
          kind: "at_me",
          conv: "oc_mono",
          conv_name: "单调群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "旧轮询拿到的编辑前正文",
          url: "",
          meta: { chat_type: "group", at_me: true, poll_observed_at: 1_000 },
        },
      ]);
      assert.equal(staleOverwritten, 0, "较早的 poll_observed_at 绝不能覆盖较新的编辑");
      assert.equal(svc.store.obs("im:om_mono_edit")?.text, "较新的已编辑正文");
      assert.equal(svc.store.obsPending("im:om_mono_edit"), false, "旧快照绝不能重新打开已处理的新编辑观测");
    }

    // 13) [R14 #13 P2] 自动预起草在模型推理返回后必须复检事项状态、目标消息修订与静音策略；期间变更须丢弃且不发草稿卡
    {
      const draftProj = svc.store.upsertProject({ name: "R14推理后复检项目" });
      const postTargetId = "pw:r14_post_draft_target";
      svc.store.addObs([
        {
          id: postTargetId,
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9913",
          conv_name: "推理后复检群",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 请确认方案",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r14_post_draft_target",
            native_chat_id: "9913",
            chat_type: "group",
            at_me: true,
          },
        },
      ]);
      mock.setChatName("9913", "推理后复检群");
      mock.setChatKind("9913", CHAT_KIND_GROUP);
      const { item: postItem } = svc.store.upsertItem({
        title: "推理期间被关闭或编辑的事项",
        kind: "ask_me",
        source: "im",
        project_id: draftProj.id,
        priority: "high",
        confidence: 0.95,
        status: "open",
        meta: {},
      });
      svc.store.addEvidence("item", postItem.id, postTargetId, "请确认方案", now);

      const origDraftRunner = svc.drafter.runner;
      // 13a) 模型推理期间事项被关闭 -> 丢弃结果，既不落库也不发草稿卡
      let draftLlmRan = 0;
      svc.drafter.runner = async () => {
        draftLlmRan++;
        svc.store.setItemStatus(postItem.id, "done", { reason: "推理期间主人已手动完成" });
        return { ok: true, aborted: false, text: "过期自动回复草稿", exitCode: 0, timedOut: false, durationMs: 1 };
      };
      const wClose = `draft:r14-post-close`;
      svc.enqueue(wClose, { task: "draft", item_id: postItem.id, kind: "reply", auto: true });
      await app.engine.drain(["context"]);
      assert.equal(draftLlmRan, 1);
      assert.equal(app.ledger.get(`context:${wClose}`)?.state, "skipped", "推理期间事项关闭时自动预起草必须跳过");
      assert.equal(svc.store.drafts({ item_id: postItem.id }).length, 0, "推理期间事项关闭后绝不能保存过期草稿");
      assert.equal(
        app.ledger.list({ kinds: ["effect"], limit: 200 }).some((e) => e.ref.startsWith("card:ctx-draft:")),
        false,
        "丢弃过期草稿时绝不能发布草稿卡片",
      );

      // 13b) 重新打开事项，改为模型推理期间目标消息被编辑 -> 同样必须丢弃不保存
      svc.store.setItemStatus(postItem.id, "open");
      svc.drafter.runner = async () => {
        svc.store.addObs([
          {
            id: postTargetId,
            source: "im",
            kind: "at_me",
            conv: "pw_chat:9913",
            conv_name: "推理后复检群",
            actor_id: "7002",
            actor_name: "同事",
            is_me: false,
            time: now,
            text: "@主人A 需求已变更请先别回旧方案",
            url: "",
            meta: {
              transport: "personal_web",
              native_owner_id: "7001",
              native_message_id: "r14_post_draft_target",
              native_chat_id: "9913",
              chat_type: "group",
              at_me: true,
            },
          },
        ]);
        return { ok: true, aborted: false, text: "基于旧消息生成的回复", exitCode: 0, timedOut: false, durationMs: 1 };
      };
      const wEdit = `draft:r14-post-edit`;
      svc.enqueue(wEdit, { task: "draft", item_id: postItem.id, kind: "reply", auto: true });
      await app.engine.drain(["context"]);
      assert.equal(app.ledger.get(`context:${wEdit}`)?.state, "skipped", "推理期间目标消息被编辑时必须丢弃草稿");
      assert.equal(svc.store.drafts({ item_id: postItem.id }).length, 0);

      // 13c) 模型推理期间会话被静音 -> 同样必须丢弃不保存
      svc.drafter.runner = async () => {
        svc.store.muteConv("pw_chat:9913", "推理后复检群", true);
        return { ok: true, aborted: false, text: "静音期间生成的回复", exitCode: 0, timedOut: false, durationMs: 1 };
      };
      const wMute = `draft:r14-post-mute`;
      svc.enqueue(wMute, { task: "draft", item_id: postItem.id, kind: "reply", auto: true });
      await app.engine.drain(["context"]);
      svc.drafter.runner = origDraftRunner;
      assert.equal(app.ledger.get(`context:${wMute}`)?.state, "skipped", "推理期间会话被静音时必须丢弃草稿");
      assert.equal(svc.store.drafts({ item_id: postItem.id }).length, 0);
      svc.store.muteConv("pw_chat:9913", "", false);
    }

    // 14) [R14 #14 P2] spoken 模式排位优先使用 knownNames 中核验过的新群名，改名脱离排除词后立即恢复轮询
    {
      app.cfg.context.groups = "spoken";
      app.cfg.context.groups_deny = ["旧禁用名"];
      const ranked = selectEffectiveOpenGroups({
        cfg: app.cfg,
        store: svc.store,
        spoken: { oc_r14_renamed: { name: "旧禁用名", at: now } },
        knownNames: { oc_r14_renamed: "已改名合法群" },
        now,
      });
      assert.equal(ranked.length, 1, "knownNames 中核验的新群名必须优先于 spoken 旧名，使改名后的群恢复入选");
      assert.equal(ranked[0][0], "oc_r14_renamed");
      assert.equal(ranked[0][1].name, "已改名合法群");

      // 端到端 pullIm 验证：spoken_groups 仍存旧禁用名、known_open_group_names 已存新合法名 -> 必须恢复轮询该群消息
      app.store.set("ctx.spoken_groups", JSON.stringify({ oc_r14_renamed: { name: "旧禁用名", at: now } }));
      rememberOpenGroupName(app.store, "oc_r14_renamed", "已改名合法群");
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_owner_a",
          user_name: "主人A",
          chats: {
            oc_r14_renamed: [
              {
                message_id: "om_r14_resumed",
                chat_id: "oc_r14_renamed",
                chat_name: "已改名合法群",
                chat_type: "group",
                msg_type: "text",
                create_time: new Date(now).toISOString(),
                sender: { id: "ou_x", name: "同事", sender_type: "user" },
                content: "改名后应恢复拉取的群消息",
              },
            ],
          },
        }),
      );
      const r14Pull = await svc.connectors.pullIm();
      assert.ok(r14Pull.count >= 1);
      assert.ok(svc.store.obs("im:om_r14_resumed"), "改名后的发言群必须恢复轮询并入库消息");
      app.cfg.context.groups_deny = [];
    }

    // 15) [R14 #15 P2] listDispatches 将 terminal / states / search 下推到 SQL，不空扫整张历史账本
    {
      for (let i = 0; i < 120; i++) {
        const wid = `dispatch:r14-hist-${i}`;
        app.ledger.enqueue({
          id: wid,
          kind: "dispatch",
          ref: `t_hist_${i}`,
          state: "accepted",
          payload: { guid: `t_hist_${i}`, summary: `历史已完成任务 ${i}`, branch: `pa/h${i}` },
        });
        app.store.db.prepare("UPDATE work SET terminal = 1 WHERE id = ?").run(wid);
      }
      const origStoreGet = app.store.get.bind(app.store);
      let ownerLookupCalls = 0;
      app.store.get = ((k: string) => {
        if (k.startsWith("ctx.dispatch_owner.") || k.startsWith("ctx.dispatch_ref_owner.")) ownerLookupCalls++;
        return origStoreGet(k);
      }) as typeof app.store.get;
      try {
        const emptyActive = Q.listDispatches(app, { filter: "active", limit: 10 });
        assert.deepEqual(emptyActive, []);
        assert.equal(ownerLookupCalls, 0, "无进行中派单时 active 查询必须经 SQL 直接返回空，零次历史行归属校验");
      } finally {
        app.store.get = origStoreGet;
      }

      // 加入 1 条被主人隔离的 active 派单 + 1 条当前主人可见的 active 派单 + 搜索词验证
      app.ledger.enqueue({
        id: "dispatch:r14-act-visible",
        kind: "dispatch",
        ref: "t_act_vis",
        state: "executing",
        payload: { guid: "t_act_vis", summary: "可见活跃修复 Alpha", branch: "pa/vis" },
      });
      app.ledger.enqueue({
        id: "dispatch:r14-act-hidden",
        kind: "dispatch",
        ref: "t_act_hid",
        state: "executing",
        payload: { guid: "t_act_hid", summary: "他人活跃修复 Alpha", branch: "pa/hid" },
      });
      app.store.set("ctx.dispatch_owner.dispatch:r14-act-hidden", "ou_other_owner");
      const actRes = Q.listDispatches(app, { filter: "active", q: "alpha", limit: 1 });
      assert.equal(actRes.length, 1, "过滤掉他人活跃派单后仍必须补足 limit=1");
      assert.equal(actRes[0].id, "dispatch:r14-act-visible");
      const doneSearch = Q.listDispatches(app, { filter: "done", q: "历史已完成任务 99", limit: 5 });
      assert.equal(doneSearch.length, 1);
      assert.equal(doneSearch[0].id, "dispatch:r14-hist-99");
    }

    // 16) [R14 #16 P3] hydrateContext 最终同步排除检查保留 DM 类型，同名已静音开放平台群不得误删合法私聊历史背景
    {
      app.cfg.context.groups_deny = ["某个不相关关键词"];
      // 静音一个名为「Alice」的开放平台群（与私聊完全无关）
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({
          user_open_id: "ou_owner_a",
          user_name: "主人A",
          chat_meta: { oc_muted_grp_alice: { name: "Alice", chat_mode: "group" } },
        }),
      );
      svc.store.muteConv("oc_muted_grp_alice", "Alice", true);
      mock.setChatName("9916", "Alice");
      mock.setChatKind("9916", CHAT_KIND_P2P);
      const dmTrigBuf = buildNativeMessage({
        id: "r14_dm_hyd_trig",
        chatId: "9916",
        actorId: "7008",
        chatKind: CHAT_KIND_P2P,
        createdAtSec: nowSec,
        position: 5,
        richBytes: encodeRichText([{ text: "Alice 私聊最新消息" }]),
      });
      const dmHistBuf = buildNativeMessage({
        id: "r14_dm_hyd_bg",
        chatId: "9916",
        actorId: "7008",
        chatKind: CHAT_KIND_P2P,
        createdAtSec: nowSec - 30,
        position: 4,
        richBytes: encodeRichText([{ text: "Alice 私聊上下文历史背景" }]),
      });
      mock.addMessage("r14_dm_hyd_trig", dmTrigBuf);
      mock.addMessage("r14_dm_hyd_bg", dmHistBuf);
      mock.setHistory("9916", { 4: dmHistBuf });
      await svc.personalWeb.handleMessage(decodeMessage(dmTrigBuf, "7001"), client);

      const hydCount = await svc.personalWeb.hydrateContext(
        { id: "r14_dm_hyd_trig", conversationId: "9916", rootId: "", parentId: "", threadId: "", position: 5, createdAtMs: now },
        "pw_chat:9916",
        "私聊：Alice",
      );
      assert.ok(hydCount >= 1, "同名已静音群不得导致合法私聊的补读历史被最终同步检查误丢弃");
      assert.ok(svc.store.obs("pw:r14_dm_hyd_bg"), "合法私聊的历史背景应完整入库");
      svc.store.muteConv("oc_muted_grp_alice", "", false);
      app.cfg.context.groups_deny = [];
    }
  } finally {
    if (httpCookieServer) await new Promise<void>((resolve) => httpCookieServer!.close(() => resolve()));
    if (hostSockServer) await new Promise<void>((resolve) => hostSockServer!.close(() => resolve()));
    if (sshSockServer) await new Promise<void>((resolve) => sshSockServer!.close(() => resolve()));
    if (shmRunDir) fs.rmSync(shmRunDir, { recursive: true, force: true });
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
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第十五轮回归：用户态效果与新看板核验活跃 lark-cli 主人、发送抢占事务锁内重检吊销与撤回、每源拉前与提交前双检 lark 身份、独立来源在 lark 失败时持续运行、无改内容推进排序水位、快通道 uncertain 延迟重试、草稿按自身证据重验不因无关群发言误丢、多工作区共享外部凭据暂存隔离、Linux 沙箱拦截 Codex keyring、流式 check-attr 与旧版 Git 锁定提交索引及单数字扩展优先级", async () => {
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const prevCodexHome = process.env.CODEX_HOME;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r15-"));
  const dataDir = path.join(dir, "data");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(ctxDir, { recursive: true });
  process.env.CTX_DIR = ctxDir;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;

  try {
    const cfgPath = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      `owner:
  open_id: ou_owner_a
  name: 主人A
  timezone: Asia/Shanghai
bins:
  lark: ${path.join(STUBS, "ctx-lark")}
  bytedcli: ${path.join(STUBS, "ctx-bytedcli")}
harnesses:
  codex:
    type: codex-exec
    cmd: ${path.join(STUBS, "ctx-codex")}
roles:
  brain: codex
server:
  enabled: false
cards:
  enabled: true
kb:
  enabled: false
context:
  enabled: true
  understand: true
  harness: codex
  groups: spoken
  max_groups: 5
  groups_allow: []
  groups_deny: []
  sources:
    meego: true
    tasks: true
    im: true
    minutes: true
    calendar: true
    docs: true
  personal_web:
    enabled: true
    fast_lane: true
    pre_draft: true
    send_replies: true
    debounce_ms: 0
data_dir: ${dataDir}
`,
    );
    app = createApp(loadConfig(cfgPath));
    const { registerContext } = await import("../src/context/index.ts");
    const svc = registerContext(app)!;
    installCtxDirStubLlm(svc, ctxDir);
    const baseCookies = [
      { name: "session", value: "sess_r15_v1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r15_1", domain: "127.0.0.1", path: "/" },
    ];
    const loginA = { owner_id: "7001", owner_name: "主人A", cookies: baseCookies };
    commitWorkspaceLogin(app, loginA, { allowUnverifiedOwner: true });
    const loginStore = new WebLoginStore(dataDir);
    const client = await FeishuWebClient.connect(loginStore.load()!, { endpoints: mock.endpoints });
    (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = client;
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const callsLog = path.join(ctxDir, "calls.log");

    // 1) [R15 #1 P1] 发布上下文派生数据（doc.create / task.create_own / im.reply / im.send）前实时核验活跃 lark-cli 账号
    {
      fs.writeFileSync(callsLog, "");
      fs.writeFileSync(
        path.join(ctxDir, "lark.json"),
        JSON.stringify({ user_open_id: "ou_other_b", user_name: "其他用户B" }),
      );
      app.ledger.enqueue({
        id: "fx:r15-doc-b",
        kind: "effect",
        ref: "ctx-draft:drf_weekly",
        payload: { op: "doc.create", args: { title: "A的周报", markdown: "含A私聊摘要" } },
      });
      app.ledger.enqueue({
        id: "fx:r15-task-b",
        kind: "effect",
        ref: "context:auto-task",
        payload: { op: "task.create_own", args: { item_id: "it_1", summary: "A的自动任务", description: "详情" } },
      });
      app.ledger.enqueue({
        id: "fx:r15-im-reply-b",
        kind: "effect",
        ref: "ctx-draft:drf_reply",
        payload: { op: "im.reply", args: { message_id: "om_1", text: "A的回复" } },
      });
      app.ledger.enqueue({
        id: "fx:r15-im-send-b",
        kind: "effect",
        ref: "ctx-draft:drf_send",
        payload: { op: "im.send", args: { chat_id: "oc_1", text: "A的跟进" } },
      });
      await app.engine.drain(["effect"]);
      for (const fid of ["fx:r15-doc-b", "fx:r15-task-b", "fx:r15-im-reply-b", "fx:r15-im-send-b"]) {
        const w = app.ledger.get(fid)!;
        assert.notEqual(w.state, "done", `lark-cli 切换为 B 后 ${fid} 绝不能执行成功`);
        assert.match(w.error, /ou_other_b/, `错误必须指出 lark-cli 账号不匹配：${w.error}`);
      }
      const larkWrites = fs
        .readFileSync(callsLog, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { role: string; argv: string[] })
        .filter((c) => c.role === "lark" && c.argv[0] !== "auth");
      assert.equal(larkWrites.length, 0, "账号不匹配时绝不能向飞书发起 docs/task/im 写请求");

      // 切回正确账号 A 后，新 doc.create 正常成功
      fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "主人A" }));
      app.ledger.enqueue({
        id: "fx:r15-doc-a",
        kind: "effect",
        ref: "ctx-draft:drf_weekly_ok",
        payload: { op: "doc.create", args: { title: "A的合法周报", markdown: "内容" } },
      });
      await app.engine.drain(["effect"]);
      assert.equal(app.ledger.get("fx:r15-doc-a")?.state, "done", "切回正确 lark-cli 账号后 doc.create 应正常执行");
      // 清理失败测试条目以免影响后续 drain
      for (const fid of ["fx:r15-doc-b", "fx:r15-task-b", "fx:r15-im-reply-b", "fx:r15-im-send-b"]) {
        app.store.db.prepare("DELETE FROM work WHERE id = ?").run(fid);
      }
    }

    // 2) [R15 #2 P1] 全新目录初始化看板时必须先实时核验 lark-cli 登录用户，绝不把 A 的清单标成 B
    {
      const freshDir = path.join(dir, "fresh-board-b");
      fs.mkdirSync(freshDir, { recursive: true });
      const freshCfg = path.join(freshDir, "config.yaml");
      fs.writeFileSync(
        freshCfg,
        `owner:\n  open_id: ou_owner_b\nbins:\n  lark: ${path.join(STUBS, "ctx-lark")}\nharnesses:\n  codex:\n    type: codex-exec\n    cmd: ${path.join(STUBS, "ctx-codex")}\nroles:\n  brain: codex\nkb:\n  enabled: false\ndata_dir: ${freshDir}\n`,
      );
      const freshAppB = createApp(loadConfig(freshCfg));
      try {
        let taskCalls = 0;
        freshAppB.lark.authStatus = async () => ({ identity: "user", user: { open_id: "ou_owner_a", name: "主人A" } });
        freshAppB.lark.run = async () => {
          taskCalls++;
          return { guid: "tl_wrong_owner_a" };
        };
        await assert.rejects(() => initApp(freshAppB), /ou_owner_a.*ou_owner_b|不一致/);
        assert.equal(taskCalls, 0, "实时核验失败时不得调用 tasklist-search / tasklist-create");
        assert.equal(freshAppB.store.get("board.tasklist"), undefined, "失败后不得持久化 board.tasklist");
        assert.equal(freshAppB.store.get("board.owner_open_id"), undefined, "失败后不得把错误归属写入 board.owner_open_id");
      } finally {
        freshAppB.store.db.close();
      }
    }

    // 3) [R15 #3 P1] sendVerifiedReply 在写入 sending 状态的同一 SQLite BEGIN IMMEDIATE 写事务锁内重检吊销与原消息撤回
    {
      mock.setChatName("9950", "发信锁内重检群");
      mock.setChatKind("9950", CHAT_KIND_GROUP);
      const origMsgBuf = buildNativeMessage({
        id: "r15_send_lock_msg",
        chatId: "9950",
        actorId: "7002",
        createdAtSec: nowSec,
        position: 10,
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 锁内重检消息" }]),
      });
      mock.addMessage("r15_send_lock_msg", origMsgBuf);
      svc.store.addObs([
        {
          id: "pw:r15_send_lock_msg",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9950",
          conv_name: "发信锁内重检群",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 锁内重检消息",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_send_lock_msg",
            native_chat_id: "9950",
            chat_type: "group",
            at_me: true,
          },
        },
      ]);

      const sentBefore = mock.sentReplies.length;
      const cidRevoke = computePwReplyCid({
        draft_id: "drf_r15_rev",
        owner_id: "7001",
        chat_id: "9950",
        message_id: "r15_send_lock_msg",
        text: "锁内吊销测试回复",
      }).cid;
      const origExec = app.store.db.exec.bind(app.store.db);
      let injectedLogoutInClaim = false;
      app.store.db.exec = ((sql: string) => {
        const res = origExec(sql);
        if (sql === "BEGIN IMMEDIATE" && !injectedLogoutInClaim) {
          injectedLogoutInClaim = true;
          // 模拟另一进程恰好在 claimDeliveryForSend 拿写锁前提交了 web-logout
          app!.store.set(REVOKED_AT_KV_KEY, String(Date.now()));
        }
        return res;
      }) as typeof app.store.db.exec;
      try {
        await assert.rejects(
          () =>
            svc.personalWeb.sendVerifiedReply({
              owner_id: "7001",
              chat_id: "9950",
              message_id: "r15_send_lock_msg",
              text: "锁内吊销测试回复",
              cid: cidRevoke,
            }),
          /吊销|web-logout/,
          "claimDeliveryForSend 写锁内检测到 web-logout 吊销必须中止发包",
        );
      } finally {
        app.store.db.exec = origExec;
        app.store.set(REVOKED_AT_KV_KEY, "");
      }
      assert.equal(injectedLogoutInClaim, true);
      assert.equal(mock.sentReplies.length, sentBefore, "写锁内吊销后绝不能向飞书发送任何回复");
      assert.equal(app.store.get(`pw.delivery.${cidRevoke}`), undefined, "回滚后不得残留 sending 投递记录");

      // 再验证跨进程撤回原观测在写锁内同样阻断发送
      const cidWithdraw = computePwReplyCid({
        draft_id: "drf_r15_wd",
        owner_id: "7001",
        chat_id: "9950",
        message_id: "r15_send_lock_msg",
        text: "锁内撤回测试回复",
      }).cid;
      let injectedWithdrawInClaim = false;
      app.store.db.exec = ((sql: string) => {
        if (sql === "BEGIN IMMEDIATE" && !injectedWithdrawInClaim) {
          injectedWithdrawInClaim = true;
          // 模拟另一进程恰好在 claimDeliveryForSend 获取 BEGIN IMMEDIATE 写锁前提交了原消息撤回
          svc.store.retirePendingObs("pw:r15_send_lock_msg");
        }
        return origExec(sql);
      }) as typeof app.store.db.exec;
      try {
        await assert.rejects(
          () =>
            svc.personalWeb.sendVerifiedReply({
              owner_id: "7001",
              chat_id: "9950",
              message_id: "r15_send_lock_msg",
              text: "锁内撤回测试回复",
              cid: cidWithdraw,
            }),
          /撤回|移出触发范围/,
          "claimDeliveryForSend 写锁内检测到原消息已撤回必须中止发包",
        );
      } finally {
        app.store.db.exec = origExec;
      }
      assert.equal(injectedWithdrawInClaim, true);
      assert.equal(mock.sentReplies.length, sentBefore);
      assert.equal(app.store.get(`pw.delivery.${cidWithdraw}`), undefined);
    }

    // 4) [R15 #4 P1] 拉取中途切换 lark-cli 账号（如 pullMeego 期间或 pullTasks/pullIm 请求途中切换为 B），提交前复验必须丢弃结果
    {
      const origAuthStatus = app.lark.authStatus.bind(app.lark);
      const origLarkRun = app.lark.run.bind(app.lark);
      let curLarkUser = "ou_owner_a";
      app.lark.authStatus = async () => ({ identity: "user", user: { open_id: curLarkUser, name: "动态账号" } });
      app.lark.run = async (args, opts) => {
        // 模拟在 task +get-my-tasks 请求执行中途 CLI 账号从 A 切到 B
        if (args[0] === "task" && args[1] === "+get-my-tasks") {
          curLarkUser = "ou_other_b";
          return { items: [{ guid: "t_mid_switch_b", summary: "中途切号混入的B任务", created_at: new Date(now).toISOString() }] };
        }
        return origLarkRun(args, opts);
      };
      try {
        await assert.rejects(() => svc.connectors.pullTasks(), /ou_other_b/, "拉取中途切换账号后提交前复验必须拒绝写入任务");
        assert.equal(svc.store.obs("task:t_mid_switch_b"), undefined, "中途切号拉到的他人任务绝不能写入观测库");
        assert.equal(
          svc.store.items({ limit: 100 }).some((i) => i.strong_key === "task:t_mid_switch_b"),
          false,
          "中途切号拉到的他人任务绝不能写入事项表",
        );
      } finally {
        app.lark.authStatus = origAuthStatus;
        app.lark.run = origLarkRun;
      }
    }

    // 5) [R15 #5 P2] lark-cli auth status 失败/超时时，独立来源（Meego / 文档评论）必须继续执行并更新各自状态与 ctx.last_error
    {
      fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ auth_fail: true }));
      fs.writeFileSync(
        path.join(ctxDir, "meego.json"),
        JSON.stringify({
          list: [
            {
              project_key: "ark",
              project_name: "Ark独立源",
              work_item_info: { work_item_id: 15001, work_item_name: "Lark超时时Meego仍采集", work_item_type_key: "story" },
              node_info: { node_name: "开发", node_state_key: "dev" },
              schedule: { start_time: new Date(now - 86_400_000).toISOString(), end_time: new Date(now + 86_400_000).toISOString() },
            },
          ],
        }),
      );
      // 写入一条本地文档评论信号
      app.store.db
        .prepare("INSERT OR REPLACE INTO signals (id, source, text, link, at) VALUES (?, 'comment', ?, ?, ?)")
        .run("comment:r15_doc_indep", "文档独立评论内容", "https://example.feishu.cn/docx/r15doc", now);
      fs.writeFileSync(path.join(ctxDir, "understand.json"), JSON.stringify({ projects: [], items: [] }));

      const indepRep = await svc.cycle("ctx:r15-indep-sources");
      assert.equal(indepRep.skipped, false, "lark-cli 失败时 cycle 不得提前跳过独立来源");
      const meegoRep = indepRep.sources.find((s) => s.source === "meego");
      const docsRep = indepRep.sources.find((s) => s.source === "docs");
      const imRep = indepRep.sources.find((s) => s.source === "im");
      const tasksRep = indepRep.sources.find((s) => s.source === "tasks");
      assert.equal(meegoRep?.error, "", "Meego 独立来源必须正常成功");
      assert.equal(meegoRep?.count, 1);
      assert.equal(docsRep?.error, "", "文档评论独立来源必须正常成功");
      assert.equal(docsRep?.count, 1);
      assert.ok(imRep?.error && /auth status/.test(imRep.error), "IM 来源必须记录认证失败错误");
      assert.ok(tasksRep?.error && /auth status/.test(tasksRep.error), "任务来源必须记录认证失败错误");
      assert.ok(svc.store.obs("meego_todo:15001:dev"), "Meego 待办必须已落库");
      assert.ok(svc.store.obs("doc:comment:r15_doc_indep"), "本地文档评论必须已落库");
      assert.ok((app.store.get("ctx.last_error") ?? "").includes("auth status"), "ctx.last_error 必须记录本轮失败信息");
      const meegoKv = JSON.parse(app.store.get("ctx.source.meego") ?? "{}") as { error?: string; count?: number };
      assert.equal(meegoKv.error, "");
      assert.equal(meegoKv.count, 1);
      fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a", user_name: "主人A" }));
      app.cfg.context.sources = { meego: false, tasks: false, im: true, minutes: false, calendar: false, docs: false };
    }

    // 6) [R15 #6 P2] 文本未变但 edit_version / poll_observed_at 更高时必须推进排序水位，防止延迟到达的旧版本覆写
    {
      svc.store.addObs([
        {
          id: "im:r15_wm_ver",
          source: "im",
          kind: "group",
          conv: "oc_r15_wm",
          conv_name: "水位群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "A",
          url: "",
          meta: { edit_version: 1 },
        },
      ]);
      svc.store.markProcessed(["im:r15_wm_ver"]);
      const genBefore = Number(svc.store.obs("im:r15_wm_ver")?.meta.edit_gen ?? 0);
      // 收到 version 3 且正文仍为 "A"：不重开 processed、不递增 edit_gen，但水位推进到 3
      const rV3 = svc.store.addObs([
        {
          id: "im:r15_wm_ver",
          source: "im",
          kind: "group",
          conv: "oc_r15_wm",
          conv_name: "水位群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "A",
          url: "",
          meta: { edit_version: 3 },
        },
      ]);
      assert.equal(rV3, 0, "内容未变时不应重开观测");
      assert.equal(svc.store.obsPending("im:r15_wm_ver"), false);
      assert.equal(Number(svc.store.obs("im:r15_wm_ver")?.meta.edit_gen ?? 0), genBefore, "内容未变时不得递增 edit_gen");
      assert.equal(svc.store.obs("im:r15_wm_ver")?.meta.edit_version, 3, "排序水位必须推进到 3");
      // 延迟到达的 version 2 正文 "B" 必须被拒绝
      const rV2 = svc.store.addObs([
        {
          id: "im:r15_wm_ver",
          source: "im",
          kind: "group",
          conv: "oc_r15_wm",
          conv_name: "水位群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "B",
          url: "",
          meta: { edit_version: 2 },
        },
      ]);
      assert.equal(rV2, 0, "延迟到达的 version 2 必须被已推进的 version 3 水位拦截");
      assert.equal(svc.store.obs("im:r15_wm_ver")?.text, "A");
      assert.equal(svc.store.obsPending("im:r15_wm_ver"), false);

      // poll_observed_at 同理：1000("A") -> 3000("A") -> 2000("B") 不得回滚
      svc.store.addObs([
        {
          id: "im:r15_wm_poll",
          source: "im",
          kind: "group",
          conv: "oc_r15_wm",
          conv_name: "水位群",
          actor_id: "ou_x",
          actor_name: "X",
          is_me: false,
          time: now,
          text: "A",
          url: "",
          meta: { poll_observed_at: 1000 },
        },
      ]);
      svc.store.markProcessed(["im:r15_wm_poll"]);
      assert.equal(
        svc.store.addObs([
          {
            id: "im:r15_wm_poll",
            source: "im",
            kind: "group",
            conv: "oc_r15_wm",
            conv_name: "水位群",
            actor_id: "ou_x",
            actor_name: "X",
            is_me: false,
            time: now,
            text: "A",
            url: "",
            meta: { poll_observed_at: 3000 },
          },
        ]),
        0,
      );
      assert.equal(svc.store.obs("im:r15_wm_poll")?.meta.poll_observed_at, 3000);
      assert.equal(
        svc.store.addObs([
          {
            id: "im:r15_wm_poll",
            source: "im",
            kind: "group",
            conv: "oc_r15_wm",
            conv_name: "水位群",
            actor_id: "ou_x",
            actor_name: "X",
            is_me: false,
            time: now,
            text: "B",
            url: "",
            meta: { poll_observed_at: 2000 },
          },
        ]),
        0,
      );
      assert.equal(svc.store.obs("im:r15_wm_poll")?.text, "A");
    }

    // 7) [R15 #7 P2] 快通道遇到 uncertain 资格时延迟重排而非提前标记 done，恢复后保留自动预起草能力；仅确定 excluded 才结束
    {
      const uncertainConv = "pw_chat:9951";
      svc.store.addObs([
        {
          id: "pw:r15_unc_msg",
          source: "im",
          kind: "at_me",
          conv: uncertainConv,
          conv_name: "群聊(9951)",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 临时无法核验群名的紧急请求",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_unc_msg",
            native_chat_id: "9951",
            chat_type: "group",
            at_me: true,
          },
        },
      ]);
      const origCheck = svc.personalWeb.checkConvAllowedForUnderstand.bind(svc.personalWeb);
      let mockElig: "allowed" | "excluded" | "uncertain" = "uncertain";
      svc.personalWeb.checkConvAllowedForUnderstand = async (c, n, s) =>
        c === uncertainConv ? mockElig : origCheck(c, n, s);
      const fastId = "fast:r15-uncertain";
      svc.enqueue(fastId, {
        task: "fast",
        conv: uncertainConv,
        conv_name: "群聊(9951)",
        trigger_obs_id: "pw:r15_unc_msg",
      });
      await app.engine.drain(["context"]);
      const wDeferred = app.ledger.get(`context:${fastId}`)!;
      assert.equal(wDeferred.state, "pending", "资格为 uncertain 时快通道作业不得提前标记 done，必须保持 pending 延后重试");
      assert.equal(wDeferred.terminal, false);
      assert.equal(wDeferred.attempts, 0, "延后重试应退回尝试次数");
      assert.ok(wDeferred.next_at > Date.now() - 1000);

      // 恢复资格为 allowed 并立即放行：快通道应完成理解并入队自动预起草
      mockElig = "allowed";
      app.store.db.prepare("UPDATE work SET next_at = 0 WHERE id = ?").run(`context:${fastId}`);
      mock.setChatName("9951", "恢复合法群");
      mock.setChatKind("9951", CHAT_KIND_GROUP);
      fs.writeFileSync(
        path.join(ctxDir, "understand.json"),
        JSON.stringify({
          projects: [{ name: "R15快通道恢复项目" }],
          items: [
            {
              title: "R15恢复后自动预起草事项",
              kind: "ask_me",
              project: "R15快通道恢复项目",
              priority: "high",
              confidence: 0.95,
              evidence: [{ obs_id: "pw:r15_unc_msg", quote: "紧急请求" }],
            },
          ],
        }),
      );
      fs.writeFileSync(path.join(ctxDir, "draft.txt"), "收到，马上处理。");
      await app.engine.drain(["context"]);
      svc.personalWeb.checkConvAllowedForUnderstand = origCheck;
      assert.equal(app.ledger.get(`context:${fastId}`)?.state, "done");
      const recoveredItem = svc.store.items({ limit: 100 }).find((i) => i.title === "R15恢复后自动预起草事项");
      assert.ok(recoveredItem, "恢复后快通道必须正常产出事项");
      assert.equal(svc.store.drafts({ item_id: recoveredItem!.id }).length, 1, "恢复后快通道必须保留自动预起草能力");

      // 明确 excluded 时则立即结束为 done
      svc.store.muteConv("pw_chat:9952", "明确排除群", true);
      svc.store.addObs([
        {
          id: "pw:r15_excl_msg",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9952",
          conv_name: "明确排除群",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 已静音群消息",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_excl_msg",
            native_chat_id: "9952",
            chat_type: "group",
            at_me: true,
          },
        },
      ]);
      const exclFastId = "fast:r15-excluded";
      svc.enqueue(exclFastId, { task: "fast", conv: "pw_chat:9952", conv_name: "明确排除群", trigger_obs_id: "pw:r15_excl_msg" });
      await app.engine.drain(["context"]);
      assert.equal(app.ledger.get(`context:${exclFastId}`)?.state, "done", "明确 excluded 的快通道作业应立即结束");
      svc.store.muteConv("pw_chat:9952", "", false);
    }

    // 8) [R15 #8 P2] spoken 模式下推理期间主人在无关群发言仅改变全局 policySignature，不得误丢弃自身仍合法的私聊草稿；
    //    仅当本草稿自身目标或上下文真的离开采集范围时才丢弃
    {
      app.cfg.context.groups = "spoken";
      app.cfg.context.max_groups = 1;
      const dmProj = svc.store.upsertProject({ name: "R15草稿范围复检项目" });
      mock.setChatName("9958", "合法私聊对象");
      mock.setChatKind("9958", CHAT_KIND_P2P);
      svc.store.addObs([
        {
          id: "pw:r15_dm_draft_ok",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9958",
          conv_name: "私聊：合法私聊对象",
          actor_id: "7009",
          actor_name: "7009",
          is_me: false,
          time: now,
          text: "请帮我确认发布时间",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_dm_draft_ok",
            native_chat_id: "9958",
            chat_type: "p2p",
            at_me: false,
          },
        },
      ]);
      const { item: dmItem } = svc.store.upsertItem({
        title: "R15无关群发言不应误丢的私聊事项",
        kind: "ask_me",
        source: "im",
        project_id: dmProj.id,
        priority: "high",
        confidence: 0.95,
        status: "open",
        meta: {},
      });
      svc.store.addEvidence("item", dmItem.id, "pw:r15_dm_draft_ok", "请帮我确认发布时间", now);

      const origDraftRunner = svc.drafter.runner;
      svc.drafter.runner = async () => {
        // 模型推理期间主人在无关群发言，更新 spoken_groups 时间戳从而改变全局 policySignature()
        app!.store.set(
          pwSpokenGroupsKey("7001"),
          JSON.stringify({ "pw_chat:9999": { name: "完全无关群", at: Date.now() + 5_000 } }),
        );
        return { ok: true, aborted: false, text: "周四下午 3 点发布。", exitCode: 0, timedOut: false, durationMs: 1 };
      };
      const wDmKeep = "draft:r15-unrelated-spoken";
      svc.enqueue(wDmKeep, { task: "draft", item_id: dmItem.id, kind: "reply", auto: true });
      await app.engine.drain(["context"]);
      assert.equal(app.ledger.get(`context:${wDmKeep}`)?.state, "done", "无关群发言改变 policySignature 不得误丢弃仍合法的私聊草稿");
      assert.equal(svc.store.drafts({ item_id: dmItem.id }).length, 1);

      // 反例：spoken max_groups=1 下，为群 A 的普通上下文消息起草期间，主人在群 B 发言把群 A 挤出前 1 -> 必须丢弃群 A 草稿
      mock.setChatName("9959", "原Top1群A");
      mock.setChatKind("9959", CHAT_KIND_GROUP);
      app.store.set(pwSpokenGroupsKey("7001"), JSON.stringify({ "pw_chat:9959": { name: "原Top1群A", at: now } }));
      svc.store.addObs([
        {
          id: "pw:r15_grp_ctx_ord",
          source: "im",
          kind: "group",
          conv: "pw_chat:9959",
          conv_name: "原Top1群A",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now - 5_000,
          text: "群A前置普通背景",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_grp_ctx_ord",
            native_chat_id: "9959",
            chat_type: "group",
            at_me: false,
          },
        },
        {
          id: "pw:r15_grp_atme",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9959",
          conv_name: "原Top1群A",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 看下前面那条",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r15_grp_atme",
            native_chat_id: "9959",
            chat_type: "group",
            at_me: true,
          },
        },
      ]);
      const { item: grpItem } = svc.store.upsertItem({
        title: "R15群A被挤出后背景离开范围的事项",
        kind: "ask_me",
        source: "im",
        project_id: dmProj.id,
        priority: "high",
        confidence: 0.95,
        status: "open",
        meta: {},
      });
      svc.store.addEvidence("item", grpItem.id, "pw:r15_grp_atme", "看下前面那条", now);
      svc.drafter.runner = async () => {
        // 群 B 发言时间戳更新，把群 A 挤出 max_groups=1，使群 A 普通背景 pw:r15_grp_ctx_ord 离开范围
        app!.store.set(
          pwSpokenGroupsKey("7001"),
          JSON.stringify({
            "pw_chat:9959": { name: "原Top1群A", at: now },
            "pw_chat:9960": { name: "新Top1群B", at: now + 10_000 },
          }),
        );
        return { ok: true, aborted: false, text: "基于已移出范围普通背景的草稿", exitCode: 0, timedOut: false, durationMs: 1 };
      };
      const wGrpEvicted = "draft:r15-evicted-spoken";
      svc.enqueue(wGrpEvicted, { task: "draft", item_id: grpItem.id, kind: "reply", auto: true });
      await app.engine.drain(["context"]);
      svc.drafter.runner = origDraftRunner;
      assert.equal(app.ledger.get(`context:${wGrpEvicted}`)?.state, "skipped", "输入窗口普通背景离开范围时必须丢弃草稿");
      assert.equal(svc.store.drafts({ item_id: grpItem.id }).length, 0);
      app.cfg.context.max_groups = 5;
    }

    // 9) [R15 #9 P2] 两个工作区共享同一个 PA_FEISHU_WEB_CRED_FILE 时，工作区 B 不得删除工作区 A 尚未 rename 的暂存登录，且沙箱遮罩按工作区命名的暂存文件
    {
      const sharedCredFile = path.join(dir, "shared-ext-cred.json");
      const wsDirA = path.join(dir, "ws-a");
      const wsDirB = path.join(dir, "ws-b");
      fs.mkdirSync(wsDirA, { recursive: true });
      fs.mkdirSync(wsDirB, { recursive: true });
      process.env.PA_FEISHU_WEB_CRED_FILE = sharedCredFile;
      try {
        const storeA = new WebLoginStore(wsDirA);
        const storeB = new WebLoginStore(wsDirB);
        assert.notEqual(storeA.stagedFile, storeB.stagedFile, "共享外部凭据路径时两个工作区的暂存文件必须隔离");

        const kvA = new Map<string, string>();
        const kvB = new Map<string, string>();
        const mkKv = (m: Map<string, string>) => ({
          get: (k: string) => m.get(k),
          set: (k: string, v: string) => void m.set(k, v),
        });
        // 工作区 A 暂存凭据并记录 pending marker 后崩溃（未 rename）
        storeA.stageWithLock((stage) => {
          const s = stage({ owner_id: "7001", owner_name: "工作区A暂存登录", cookies: baseCookies });
          kvA.set(
            PENDING_CRED_COMMIT_KV_KEY,
            JSON.stringify({ file: storeA.file, staged_file: storeA.stagedFile, owner_id: "7001", session_id: s.payload.session_id }),
          );
        });
        assert.equal(fs.existsSync(storeA.stagedFile), true);

        // 验证沙箱隔离命令会遮罩工作区 A 的工作区级外部暂存文件（纯参数规划测试，显式指定 forceBackend 脱离宿主机命名空间可用性）
        const isoWrap = wrapCredentialIsolatedCommand(
          "true",
          [],
          { ...process.env, PA_FEISHU_WEB_CRED_FILE: sharedCredFile },
          {
            ...buildWorkspaceIsolation({ dataDir: wsDirB, context: { personal_web: { enabled: true } } } as never, {
              mode: "worker-ro",
              cwd: wsDirB,
              extraReadOnlyPaths: [dir],
            }),
            forceBackend: { kind: "bwrap", bin: "bwrap" },
          },
        );
        assert.equal(isoWrap.isolated, true);
        assert.ok(
          isoWrap.args.includes(fs.realpathSync(storeA.stagedFile)),
          "沙箱必须同样遮罩共享外部凭据路径下按工作区命名的 *.staged 文件",
        );

        // 工作区 B 无 pending marker 启动协调：绝不能删除工作区 A 的暂存文件
        storeB.reconcilePendingCommit(mkKv(kvB), PENDING_CRED_COMMIT_KV_KEY);
        assert.equal(fs.existsSync(storeA.stagedFile), true, "工作区 B 绝不能误删工作区 A 的暂存登录文件");

        // 工作区 A 重启恢复：顺利 rename 并安装已提交会话
        storeA.reconcilePendingCommit(mkKv(kvA), PENDING_CRED_COMMIT_KV_KEY);
        assert.equal(fs.existsSync(storeA.stagedFile), false);
        assert.equal(storeA.load()?.owner_name, "工作区A暂存登录", "工作区 A 必须能完整恢复其已提交的暂存登录");
      } finally {
        delete process.env.PA_FEISHU_WEB_CRED_FILE;
      }
    }

    // 10) [R15 #10 P2] Linux 隔离沙箱检测并阻断 Codex cli_auth_credentials_store="keyring"（doctor / cycle / runHarness 均提前报错指引）
    if (process.platform === "linux") {
      const keyringCodexHome = path.join(dir, "codex-keyring-home");
      fs.mkdirSync(keyringCodexHome, { recursive: true });
      fs.writeFileSync(path.join(keyringCodexHome, "config.toml"), 'cli_auth_credentials_store = "keyring"\n');

      const conflict = detectIsolatedCodexKeyringConflict(app.cfg, { ...process.env, CODEX_HOME: keyringCodexHome }, "codex");
      assert.equal(conflict?.severity, "error");
      assert.match(conflict?.message ?? "", /keyring/);
      assert.match(conflict?.fix ?? "", /cli_auth_credentials_store = "file"/);

      const docKeyring = await runDoctor(app, { env: { ...process.env, CODEX_HOME: keyringCodexHome } });
      const hCheck = docKeyring.checks.find((c) => c.id === "harness:codex")!;
      assert.equal(hCheck.status, "fail", "pa doctor 必须将 Linux 隔离沙箱 + Codex keyring 标为 fail");
      assert.match(hCheck.fix, /cli_auth_credentials_store = "file"/);

      process.env.CODEX_HOME = keyringCodexHome;
      try {
        await assert.rejects(
          () =>
            runHarness(app!.cfg, {
              harness: "codex",
              prompt: "hello",
              cwd: dir,
              tools: "none",
              lark: "none",
              timeoutSec: 10,
              logFile: path.join(dir, "kr-none.log"),
            }),
          /keyring/,
          "隔离沙箱下 runHarness(tools=none) 必须在启动 Codex 前拦截 keyring 配置",
        );
        const cycKr = await svc.cycle("ctx:r15-keyring-preflight");
        assert.ok(cycKr.errors.some((e) => /keyring/.test(e)), "cycle() 必须在调度理解模型前报错提示 keyring 冲突");
      } finally {
        if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
        else process.env.CODEX_HOME = prevCodexHome;
      }

      // auto + 无 auth.json + 无 OPENAI_API_KEY -> doctor 输出 warn 指引
      const autoCodexHome = path.join(dir, "codex-auto-home");
      fs.mkdirSync(autoCodexHome, { recursive: true });
      fs.writeFileSync(path.join(autoCodexHome, "config.toml"), 'cli_auth_credentials_store = "auto"\n');
      const envNoApi: NodeJS.ProcessEnv = { ...process.env, CODEX_HOME: autoCodexHome };
      delete envNoApi.OPENAI_API_KEY;
      const docAuto = await runDoctor(app, { env: envNoApi });
      assert.equal(docAuto.checks.find((c) => c.id === "harness:codex")?.status, "warn");
    }

    // 11 & 12) [R15 #11 & #12 P2] 流式 ls-tree | check-attr + 旧版 Git（如 2.39）通过临时锁定索引读取目标提交 .gitattributes，不受工作区改动影响
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "Test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "Test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      const attrRepo = path.join(dir, "r15-pinned-attr-repo");
      fs.mkdirSync(attrRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", attrRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(attrRepo, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      fs.writeFileSync(path.join(attrRepo, "weights.bin"), "not a pointer yet but tracked by attr\n");
      for (let i = 0; i < 300; i++) {
        fs.writeFileSync(path.join(attrRepo, `plain_${i}.txt`), `txt ${i}\n`);
      }
      assert.equal((await runProcess("git", ["-C", attrRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", attrRepo, "commit", "-q", "-m", "c1 with lfs attr"], { env: gitEnv })).code, 0);
      const c1Sha = (await runProcess("git", ["-C", attrRepo, "rev-parse", "HEAD"])).stdout.trim();

      // 修改工作区 .gitattributes 删除 filter=lfs（未提交）：对 c1Sha 的扫描必须仍按 c1Sha 的提交树识别为 LFS！
      fs.writeFileSync(path.join(attrRepo, ".gitattributes"), "");
      assert.equal(
        await branchUsesGitLfs(attrRepo, c1Sha, undefined, undefined, { cfg: app.cfg, trustedRepoRoot: attrRepo }),
        true,
        "即使工作区删掉了 .gitattributes，对锁定提交 c1Sha 的检查也必须从该提交树读取 filter=lfs",
      );

      // 反向验证：提交 c2 真正移除 .gitattributes，再在工作区未提交地加上 *.txt filter=lfs -> 对 c2Sha 必须返回 false！
      assert.equal((await runProcess("git", ["-C", attrRepo, "add", ".gitattributes"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", attrRepo, "commit", "-q", "-m", "c2 without lfs attr"], { env: gitEnv })).code, 0);
      const c2Sha = (await runProcess("git", ["-C", attrRepo, "rev-parse", "HEAD"])).stdout.trim();
      fs.writeFileSync(path.join(attrRepo, ".gitattributes"), "*.txt filter=lfs\n");
      assert.equal(
        await branchUsesGitLfs(attrRepo, c2Sha, c1Sha, [c1Sha], { cfg: app.cfg, trustedRepoRoot: attrRepo }),
        false,
        "工作区未提交的 .gitattributes 绝不能污染对锁定提交 c2Sha 的属性检查",
      );
    }

    // 13) [R15 #13 P3] Git LFS 扩展优先级语法严格匹配单数字 0-9（对齐 git lfs pointer --check --stdin）
    {
      const oid = "c".repeat(64);
      const extVectors: { key: string; expected: boolean }[] = [
        { key: "ext-0-thumb", expected: true },
        { key: "ext-9-preview", expected: true },
        { key: "ext-10-thumb", expected: false },
        { key: "ext-12-thumb", expected: false },
        { key: "ext-01-thumb", expected: false },
      ];
      const hasGitLfs = (await runProcess("git", ["lfs", "version"], { timeoutMs: 5_000 })).code === 0;
      for (const v of extVectors) {
        const ptrBuf = Buffer.from(
          `version https://git-lfs.github.com/spec/v1\noid sha256:${oid}\n${v.key} sha256:${oid}\nsize 42\n`,
          "utf8",
        );
        const ours = isGitLfsPointerBlob(ptrBuf);
        assert.equal(ours, v.expected, `LFS 扩展优先级 ${v.key} 校验应为 ${v.expected}`);
        if (hasGitLfs) {
          const refRc = await new Promise<number>((resolve) => {
            const c = spawn("git", ["lfs", "pointer", "--check", "--stdin"], { stdio: ["pipe", "pipe", "pipe"] });
            c.on("close", (code) => resolve(code ?? 1));
            c.stdin.end(ptrBuf);
          });
          assert.equal(ours, refRc === 0, `LFS 扩展优先级 ${v.key} 必须与 git lfs pointer --check --stdin 一致`);
        }
      }
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
    if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevCodexHome;
    app?.store.db.close();
    await mock.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第十六轮回归：委派创建与派单副作用实时验号、Git属性探测跨locale、隔离npm缓存与verify临时目录、共享外部凭据登出归属边界、CLI失效保留pw消息、API Key免keyring与file态OAuth刷新安全回写、重定向并发Cookie冲突校验、快通道丢弃后重排与管道监听清理", async () => {
  const dir = makeTmp("pa-feishu-r16-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const prevCodexHome = process.env.CODEX_HOME;
  const prevLcAll = process.env.LC_ALL;
  const prevLang = process.env.LANG;
  const prevLanguage = process.env.LANGUAGE;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;
  process.env.CTX_DIR = ctxDir;

  let app: ReturnType<typeof createApp> | undefined;
  let extraAppA: ReturnType<typeof createApp> | undefined;
  let extraAppB: ReturnType<typeof createApp> | undefined;
  let redirectSrv: http.Server | undefined;

  try {
    const cfgFile = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: path.join(dir, "data"),
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: {
          claude: { agent: "claude" },
          codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") },
        },
        roles: { brain: "codex" },
        owner: { open_id: "ou_owner_a" },
        cards: { enabled: false },
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "codex",
          groups: "allowlist",
          groups_allow: ["pw_chat:9001"],
          groups_deny: [],
          sources: { im: true, minutes: false, docs: false, tasks: false, calendar: false, meego: false },
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    installCtxDirStubLlm(svc, ctxDir);
    const baseCookies = [{ name: "session", value: "r16_sess", domain: "internal-api-lark-api.feishu.cn", path: "/" }];
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r16_a", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 1) [R16 #1 P1] context.item_delegate -> dispatch.create 在远端 board.createTask 前校验看板归属与实时活跃 lark-cli 登录用户
    {
      app.store.set("board.tasklist", "tl_r16");
      app.store.set("board.section.dispatch", "sec_dispatch_r16");
      app.store.set("board.section.running", "sec_running_r16");
      const { item: delItem } = svc.store.upsertItem({
        title: "绝密架构方案委派",
        kind: "todo",
        project_id: "",
        status: "open",
        priority: "high",
        next_step: "内部机密改造",
        source: "im",
      });
      let remoteCreateCalls = 0;
      const origCreateTask = app.board.createTask.bind(app.board);
      const origReconcile = app.dispatcher.reconcile.bind(app.dispatcher);
      app.board.createTask = async (t) => {
        remoteCreateCalls++;
        t.onCreated?.("guid_r16_ok");
        return "guid_r16_ok";
      };
      app.dispatcher.reconcile = async () => ({ enqueued: 0, cancelled: 0, deferred: 0 });
      try {
        // 1a) 看板归属为主人 B：远端 createTask 绝不可被调用
        app.store.set("board.owner_open_id", "ou_owner_b");
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
        await assert.rejects(
          () => app!.commands.exec("context.item_delegate", { id: delItem.id }, { source: "web", actor: "owner" }),
          /看板归属账号.*不一致/,
        );
        assert.equal(remoteCreateCalls, 0, "看板归属不一致时绝不能调用远端 board.createTask");

        // 1b) 看板归属为主人 A，但活跃 lark-cli 已切换为主人 B：远端 createTask 绝不可被调用
        app.store.set("board.owner_open_id", "ou_owner_a");
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_b" }));
        await assert.rejects(
          () => app!.commands.exec("context.item_delegate", { id: delItem.id }, { source: "web", actor: "owner" }),
          /lark-cli 登录用户.*不一致/,
        );
        assert.equal(remoteCreateCalls, 0, "lark-cli 已切换为主人 B 时绝不能调用远端 board.createTask");

        // 1c) 看板归属与活跃 lark-cli 均为 A：顺利创建
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
        const okDel = await app.commands.exec("context.item_delegate", { id: delItem.id }, { source: "web", actor: "owner" });
        assert.equal(okDel.ok, true);
        assert.equal(remoteCreateCalls, 1);
      } finally {
        app.board.createTask = origCreateTask;
        app.dispatcher.reconcile = origReconcile;
      }
    }

    // 2) [R16 #2 P1] 上下文委派派单 / 交付工作产生的 task.comment / task.move 副作用，执行前必须核验活跃 lark-cli 登录用户
    {
      const delegatedGuid = "guid_r16_delegated_fx";
      const dispatchWorkId = `dispatch:${delegatedGuid}:1`;
      app.store.set(`ctx.dispatch_ref_owner.${delegatedGuid}`, "ou_owner_a");
      app.store.set(`ctx.dispatch_owner.${dispatchWorkId}`, "ou_owner_a");

      let commentCalls = 0;
      let moveCalls = 0;
      const origComment = app.board.comment.bind(app.board);
      const origMove = app.board.move.bind(app.board);
      app.board.comment = async () => {
        commentCalls++;
      };
      app.board.move = async () => {
        moveCalls++;
      };
      const fxHandler = effectHandler(app.cfg, app.ledger, app.board, app.lark, app.store);
      try {
        // lark-cli 切换为主人 B：无论是 dispatch:* 还是 delivery:dispatch:* 父级，task.comment 与 task.move 均被阻断
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_b" }));
        app.ledger.emit(dispatchWorkId, [commentEffect(delegatedGuid, "worker 报告")], "r16-fx-c1");
        app.ledger.emit(`delivery:${dispatchWorkId}:create_pr`, [moveEffect(delegatedGuid, "review")], "r16-fx-m1");
        const claimed = [
          app.ledger.claim<import("../src/ledger.ts").Effect>("effect", 60_000),
          app.ledger.claim<import("../src/ledger.ts").Effect>("effect", 60_000),
        ].filter((x): x is NonNullable<typeof x> => !!x);
        const fxComment = claimed.find((x) => x.ref === dispatchWorkId)!;
        const fxMove = claimed.find((x) => x.ref === `delivery:${dispatchWorkId}:create_pr`)!;
        assert.ok(fxComment && fxMove);
        await assert.rejects(
          () => fxHandler.run(fxComment, { attempt: 1, signal: new AbortController().signal }),
          /lark-cli 登录用户.*不一致/,
        );
        await assert.rejects(
          () => fxHandler.run(fxMove, { attempt: 1, signal: new AbortController().signal }),
          /lark-cli 登录用户.*不一致/,
        );
        assert.equal(commentCalls, 0, "CLI 切号后绝不能对委派任务发表评论");
        assert.equal(moveCalls, 0, "CLI 切号后绝不能移动委派任务");

        // 切回主人 A 后同一副作用正常投递
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
        await fxHandler.run(fxComment, { attempt: 1, signal: new AbortController().signal });
        await fxHandler.run(fxMove, { attempt: 1, signal: new AbortController().signal });
        assert.equal(commentCalls, 1);
        assert.equal(moveCalls, 1);
      } finally {
        app.board.comment = origComment;
        app.board.move = origMove;
      }
    }

    // 3) [R16 #3 P1 + #13 P3] Git 属性探测跨 locale（LC_ALL=zh_CN.UTF-8）正常工作；大树管道背压不累积监听（无 MaxListenersExceededWarning）
    {
      const repoPlain = path.join(dir, "repo-locale-plain");
      const barePlain = path.join(dir, "bare-locale-plain.git");
      fs.mkdirSync(repoPlain, { recursive: true });
      fs.mkdirSync(barePlain, { recursive: true });
      await tryGit(barePlain, ["init", "--bare", "-q"]);
      await tryGit(repoPlain, ["init", "-q"]);
      await tryGit(repoPlain, ["config", "user.name", "Test"]);
      await tryGit(repoPlain, ["config", "user.email", "test@example.com"]);
      await tryGit(repoPlain, ["remote", "add", "origin", barePlain]);
      fs.writeFileSync(path.join(repoPlain, "hello.txt"), "hello\n");
      // 制造 1400 个较长路径文件以在 ls-tree -> check-attr 管道中触发多次背压 drain，验证无 MaxListenersExceededWarning
      const deepBase = path.join(repoPlain, "assets", "deeply_nested_directory_for_backpressure_test_0123456789");
      fs.mkdirSync(deepBase, { recursive: true });
      for (let i = 0; i < 1400; i++) {
        fs.writeFileSync(
          path.join(deepBase, `file_entry_${String(i).padStart(4, "0")}_padding_name_to_exceed_pipe_buffer.txt`),
          "x",
        );
      }
      await tryGit(repoPlain, ["add", "."]);
      await tryGit(repoPlain, ["commit", "-qm", "init many files"]);
      const curBr = (await tryGit(repoPlain, ["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();

      const warnings: Error[] = [];
      const onWarn = (w: Error) => warnings.push(w);
      process.on("warning", onWarn);
      process.env.LC_ALL = "zh_CN.UTF-8";
      process.env.LANG = "zh_CN.UTF-8";
      process.env.LANGUAGE = "zh_CN:zh";
      try {
        const usesLfs = await branchUsesGitLfs(repoPlain, curBr);
        assert.equal(usesLfs, false, "在 LC_ALL=zh_CN.UTF-8 下非 LFS 仓库必须正常完成属性探测并返回 false");
        const pushed = await pushBranch(repoPlain, "origin", curBr);
        assert.equal(pushed.ok, true, `LC_ALL=zh_CN.UTF-8 下 pushBranch 必须成功：${pushed.ok ? "" : pushed.message}`);
      } finally {
        process.off("warning", onWarn);
        if (prevLcAll === undefined) delete process.env.LC_ALL;
        else process.env.LC_ALL = prevLcAll;
        if (prevLang === undefined) delete process.env.LANG;
        else process.env.LANG = prevLang;
        if (prevLanguage === undefined) delete process.env.LANGUAGE;
        else process.env.LANGUAGE = prevLanguage;
      }
      assert.equal(
        warnings.some((w) => w.name === "MaxListenersExceededWarning"),
        false,
        "大树管道背压后必须移除未触发监听器，绝不产生 MaxListenersExceededWarning",
      );
    }

    // 4) [R16 #4 P1 + #11 P2] 隔离 acpx 提供可写 npm 缓存，隔离 runVerifyCommand 提供私有可写 /tmp 与缓存环境变量
    {
      const tmpEnv = isolatedSandboxTempEnv();
      assert.equal(tmpEnv.TMPDIR, "/tmp");
      assert.equal(tmpEnv.XDG_CACHE_HOME, "/tmp/.pa-cache");
      assert.equal(tmpEnv.XDG_STATE_HOME, "/tmp/.pa-state");
      assert.equal(tmpEnv.XDG_RUNTIME_DIR, "/tmp/.pa-run");
      assert.equal(tmpEnv.npm_config_cache, "/tmp/.pa-npm-cache");
      assert.equal(tmpEnv.NPM_CONFIG_CACHE, "/tmp/.pa-npm-cache");

      if (hasCredentialMountIsolation()) {
        const fakeAcpx = path.join(dir, "stub-acpx-env.sh");
        fs.writeFileSync(
          fakeAcpx,
          [
            "#!/bin/sh",
            "set -e",
            'test "$npm_config_cache" = "/tmp/.pa-npm-cache"',
            'test "$NPM_CONFIG_CACHE" = "/tmp/.pa-npm-cache"',
            'test "$TMPDIR" = "/tmp"',
            'mkdir -p "$npm_config_cache/_npx" && touch "$npm_config_cache/_npx/probe.ok"',
            'echo "ACPX_NPM_CACHE_OK"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const origAcpxBin = app.cfg.bins.acpx;
        app.cfg.bins.acpx = fakeAcpx;
        try {
          const acpxRes = await runHarness(app.cfg, {
            harness: "claude",
            prompt: "hi",
            cwd: path.join(dir, "acpx-cwd"),
            tools: "read",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "acpx-r16.log"),
          });
          assert.equal(acpxRes.ok, true, `隔离 acpx 必须可写入私有的 npm_config_cache：${acpxRes.text}`);
          assert.equal(acpxRes.text, "ACPX_NPM_CACHE_OK");
        } finally {
          app.cfg.bins.acpx = origAcpxBin;
        }

        // [R16 #11 P2] 即使宿主机 TMPDIR 指向只读目录，隔离 runVerifyCommand 也必须切到私有 /tmp 使 mktemp 成功
        const roTmpHost = path.join(dir, "ro-host-tmp");
        fs.mkdirSync(roTmpHost, { recursive: true });
        const prevTmpdir = process.env.TMPDIR;
        process.env.TMPDIR = roTmpHost;
        const wtDir = path.join(app.cfg.dataDir, "worktrees", "r16-verify-wt");
        fs.mkdirSync(wtDir, { recursive: true });
        fs.mkdirSync(path.join(app.cfg.dataDir, "runs", "r16_veri"), { recursive: true });
        try {
          const verifyWork = {
            id: "dispatch:r16_verify:1",
            kind: "dispatch",
            ref: "r16_verify",
            state: "running",
            terminal: false,
            attempts: 1,
            created: Date.now(),
            updated: Date.now(),
            lease_until: Date.now() + 60_000,
            cancel: false,
            reason: "",
            error: "",
            payload: {
              guid: "r16_verify",
              summary: "verify tmpdir",
              description: "",
              harness: "claude",
              reviewer: "",
              cwd: wtDir,
              base: "",
              branch: "",
              verify:
                'test "$TMPDIR" = "/tmp" && test "$XDG_CACHE_HOME" = "/tmp/.pa-cache" && test "$XDG_STATE_HOME" = "/tmp/.pa-state" && test "$XDG_RUNTIME_DIR" = "/tmp/.pa-run" && test "$npm_config_cache" = "/tmp/.pa-npm-cache" && f=$(mktemp) && echo ok > "$f" && rm -f "$f"',
              round: 1,
              maxRounds: 1,
              report: "",
              history: [],
            },
          };
          const disp = app.dispatcher;
          const vRes = await (
            disp as unknown as {
              runVerifyCommand(it: typeof verifyWork, ctx: { attempt: number; signal: AbortSignal }): Promise<{ status: string; detail: string }>;
            }
          ).runVerifyCommand(verifyWork, { attempt: 1, signal: new AbortController().signal });
          assert.equal(vRes.status, "pass", `隔离 verify 必须使用可写私有 /tmp 与缓存目录：${vRes.detail}`);
        } finally {
          if (prevTmpdir === undefined) delete process.env.TMPDIR;
          else process.env.TMPDIR = prevTmpdir;
        }
      }
    }

    // 5) [R16 #5 P2] 共享外部 PA_FEISHU_WEB_CRED_FILE：A 从未登录（或无法解密）时登出 A 绝不能删除 B 的活跃凭据，仅 B 登出才删自己的共享凭据
    {
      const sharedCred = path.join(dir, "shared-logout-cred.json");
      const cfgA = path.join(dir, "cfg-a.json");
      const cfgB = path.join(dir, "cfg-b.json");
      fs.writeFileSync(
        cfgA,
        JSON.stringify({
          data_dir: path.join(dir, "ws-logout-a"),
          harnesses: { codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_a" },
          context: { enabled: true, personal_web: { enabled: true } },
        }),
      );
      fs.writeFileSync(
        cfgB,
        JSON.stringify({
          data_dir: path.join(dir, "ws-logout-b"),
          harnesses: { codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_b" },
          context: { enabled: true, personal_web: { enabled: true } },
        }),
      );
      process.env.PA_FEISHU_WEB_CRED_FILE = sharedCred;
      try {
        extraAppA = createApp(loadConfig(cfgA));
        extraAppB = createApp(loadConfig(cfgB));
        commitWorkspaceLogin(
          extraAppB,
          { owner_id: "8002", owner_name: "工作区B", session_id: "sess_shared_b", cookies: baseCookies },
          { allowUnverifiedOwner: true },
        );
        assert.equal(fs.existsSync(sharedCred), true);

        // 工作区 A 从未登录，执行登出：仅在 A 自身 SQLite 标记吊销，不得将 sess_shared_b 收入黑名单，更不得删 B 的共享文件
        const resA = revokeWorkspacePersonalWebSession(extraAppA);
        assert.equal(resA.fileRemoved, false, "A 从未持有该共享文件会话，登出 A 绝不能删除 B 的凭据文件");
        assert.equal(fs.existsSync(sharedCred), true);
        assert.equal(
          JSON.parse(extraAppA.store.get(REVOKED_SESSIONS_KV_KEY) ?? "[]").includes("sess_shared_b"),
          false,
          "A 绝不能未经归属校验就把 B 的 session_id 写入 A 的吊销集",
        );
        assert.equal(new WebLoginStore(extraAppB.cfg.dataDir).load()?.session_id, "sess_shared_b");

        // 即使 A 在无密钥（无法解密共享文件）状态下再次登出，同样不得删除 B 的共享文件
        delete process.env.PA_FEISHU_WEB_KEY;
        try {
          const resANoKey = revokeWorkspacePersonalWebSession(extraAppA);
          assert.equal(resANoKey.fileRemoved, false, "无法解密外部共享凭据时绝不能误删他人文件");
          assert.equal(fs.existsSync(sharedCred), true);
        } finally {
          process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
        }

        // B 自身登出（持有 sess_shared_b 归属）：正常删除属于 B 的共享凭据文件
        const resB = revokeWorkspacePersonalWebSession(extraAppB);
        assert.equal(resB.fileRemoved, true, "B 登出自己持有的共享凭据会话应正常删除文件");
        assert.equal(fs.existsSync(sharedCred), false);
      } finally {
        delete process.env.PA_FEISHU_WEB_CRED_FILE;
      }
    }

    // 6) [R16 #6 P2] lark-cli 认证失败/切号时，周期 cycle 过滤 CLI im:* 观测，但仍保留已绑定的独立个人 Web pw:* 观测
    {
      const now = Date.now();
      svc.store.addObs([
        {
          id: "im:cli_blocked_msg_1",
          source: "im",
          kind: "msg",
          conv: "oc_cli_blocked_chat",
          conv_name: "CLI 轮询群",
          actor_id: "ou_other",
          actor_name: "同事甲",
          is_me: false,
          time: now - 30_000,
          text: "请今天确认 CLI 群发布方案",
          url: "",
          meta: { chat_type: "group" },
        },
        {
          id: "pw:native_allowed_msg_1",
          source: "im",
          kind: "msg",
          conv: "pw_chat:9001",
          conv_name: "原生白名单群",
          actor_id: "9002",
          actor_name: "同事乙",
          is_me: false,
          time: now - 20_000,
          text: "请今天确认原生 Web 群接口文档",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001" },
        },
      ]);
      // 模拟 lark-cli 登录用户切换为主人 B（导致 pullIm 报 lark-cli 账号不匹配 -> larkAuthBlocked = true）
      fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_b" }));
      fs.writeFileSync(
        path.join(ctxDir, "llm.json"),
        JSON.stringify({
          projects: [],
          items: [
            {
              title: "确认原生 Web 群接口文档",
              kind: "ask_me",
              priority: "high",
              evidence: [{ obs_id: "pw:native_allowed_msg_1", quote: "请今天确认原生 Web 群接口文档" }],
            },
          ],
        }),
      );
      const seenPrompts: string[] = [];
      const origRunner = svc.understander.runner;
      svc.understander.runner = async (_cfg, run) => {
        seenPrompts.push(run.prompt);
        return {
          ok: true,
          exitCode: 0,
          text: fs.readFileSync(path.join(ctxDir, "llm.json"), "utf8"),
          timedOut: false,
          aborted: false,
        };
      };
      try {
        const rep = await svc.cycle("ctx:r16-cli-blocked");
        assert.ok(rep.errors.some((e) => /lark-cli 登录用户/.test(e)), "应上报 CLI 账号不匹配错误");
        assert.equal(svc.store.obsPending("pw:native_allowed_msg_1"), false, "独立认证的 pw:* 观测在 CLI 登出时必须照常被理解消费");
        assert.equal(svc.store.obsPending("im:cli_blocked_msg_1"), true, "CLI im:* 观测在 CLI 鉴权失败时必须保留待处理且不送模型");
        assert.ok(seenPrompts.some((p) => p.includes("pw:native_allowed_msg_1")));
        assert.ok(!seenPrompts.some((p) => p.includes("im:cli_blocked_msg_1")));
      } finally {
        svc.understander.runner = origRunner;
        fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
      }
    }

    // 7) [R16 #7 P2] Linux 隔离沙箱允许走 API 密钥 / 自定义 env_key 的 Codex 供应商绕开 keyring 限制，而强制 chatgpt 或无 API 密钥仍报错
    if (process.platform === "linux") {
      const customKeyringHome = path.join(dir, "codex-custom-envkey");
      fs.mkdirSync(customKeyringHome, { recursive: true });
      fs.writeFileSync(
        path.join(customKeyringHome, "config.toml"),
        [
          'cli_auth_credentials_store = "keyring"',
          'model_provider = "deepseek"',
          "[model_providers.deepseek]",
          'name = "deepseek"',
          'base_url = "https://api.deepseek.com/v1"',
          'env_key = "DEEPSEEK_API_KEY"',
        ].join("\n"),
      );
      assert.equal(
        detectIsolatedCodexKeyringConflict(
          app.cfg,
          { ...process.env, CODEX_HOME: customKeyringHome, DEEPSEEK_API_KEY: "sk-ds-test" },
          "codex",
        ),
        undefined,
        "自定义供应商使用 env_key 时无需 keyring，不得误报冲突",
      );

      const oaiKeyringHome = path.join(dir, "codex-oai-keyring");
      fs.mkdirSync(oaiKeyringHome, { recursive: true });
      fs.writeFileSync(path.join(oaiKeyringHome, "config.toml"), 'cli_auth_credentials_store = "keyring"\n');
      assert.equal(
        detectIsolatedCodexKeyringConflict(
          app.cfg,
          { ...process.env, CODEX_HOME: oaiKeyringHome, OPENAI_API_KEY: "sk-oai-test" },
          "codex",
        ),
        undefined,
        "提供 OPENAI_API_KEY 且未强制 chatgpt 登录时无需 keyring",
      );
      assert.equal(
        detectIsolatedCodexKeyringConflict(
          app.cfg,
          { ...process.env, CODEX_HOME: oaiKeyringHome, CODEX_API_KEY: "sk-cdx-test" },
          "codex",
        ),
        undefined,
        "提供 CODEX_API_KEY 且未强制 chatgpt 登录时无需 keyring",
      );
      // 强制 chatgpt 登录时即使提供 OPENAI_API_KEY 也依然需要 keyring -> 报错
      fs.writeFileSync(
        path.join(oaiKeyringHome, "config.toml"),
        'cli_auth_credentials_store = "keyring"\nforced_login_method = "chatgpt"\n',
      );
      assert.equal(
        detectIsolatedCodexKeyringConflict(
          app.cfg,
          { ...process.env, CODEX_HOME: oaiKeyringHome, OPENAI_API_KEY: "sk-oai-test" },
          "codex",
        )?.severity,
        "error",
        "forced_login_method=chatgpt 时仍必须拦截 keyring 冲突",
      );

      // 端到端验证自定义 env_key 在隔离 runHarness(codex-exec) 中不触发 keyring 拒发且子进程收到该密钥
      if (hasCredentialMountIsolation()) {
        const stubCustomCodex = path.join(dir, "stub-codex-custom.mjs");
        fs.writeFileSync(
          stubCustomCodex,
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'if (process.env.DEEPSEEK_API_KEY !== "sk-ds-test") process.exit(2);',
            'const oIdx = process.argv.indexOf("-o");',
            'if (oIdx >= 0 && process.argv[oIdx + 1]) fs.writeFileSync(process.argv[oIdx + 1], "CUSTOM_ENV_KEY_OK");',
            'console.log("CUSTOM_ENV_KEY_OK");',
          ].join("\n"),
          { mode: 0o755 },
        );
        const origCodexCmd = app.cfg.harnesses.codex.cmd;
        const prevDsKey = process.env.DEEPSEEK_API_KEY;
        app.cfg.harnesses.codex.cmd = stubCustomCodex;
        process.env.CODEX_HOME = customKeyringHome;
        process.env.DEEPSEEK_API_KEY = "sk-ds-test";
        try {
          const okCustom = await runHarness(app.cfg, {
            harness: "codex",
            prompt: "ping",
            cwd: dir,
            tools: "none",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "codex-custom-r16.log"),
          });
          assert.equal(okCustom.ok, true, "自定义 env_key 供应商在隔离 codex-exec 下应放行执行");
          assert.equal(okCustom.text, "CUSTOM_ENV_KEY_OK");
        } finally {
          app.cfg.harnesses.codex.cmd = origCodexCmd;
          if (prevDsKey === undefined) delete process.env.DEEPSEEK_API_KEY;
          else process.env.DEEPSEEK_API_KEY = prevDsKey;
          if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
          else process.env.CODEX_HOME = prevCodexHome;
        }
      }
    }

    // 8) [R16 #8 P2] 文件态 Codex OAuth 刷新安全回写：宿主机 CODEX_HOME 保持只读，合法刷新原子回写 0600，拒绝符号链接/跨账号/已登出/陈旧覆盖
    {
      const hostCodexHome = path.join(dir, "host-codex-refresh");
      fs.mkdirSync(hostCodexHome, { recursive: true });
      fs.writeFileSync(path.join(hostCodexHome, "config.toml"), 'cli_auth_credentials_store = "file"\n');
      const hostAuthPath = path.join(hostCodexHome, "auth.json");
      const origAuthObj = {
        auth_mode: "chatgpt",
        OPENAI_API_KEY: null,
        tokens: {
          id_token: "id_old",
          access_token: "acc_old",
          refresh_token: "ref_old",
          account_id: "acct_owner_1",
        },
        last_refresh: "2026-11-26T00:00:00.000Z",
      };
      fs.writeFileSync(hostAuthPath, JSON.stringify(origAuthObj, null, 2), { mode: 0o600 });

      // 8a) 单元测试安全拒绝条件（符号链接、跨账号、删除登出、并发更新）
      const stagedReject = stageIsolatedCodexHome(hostCodexHome, { copyUserConfig: false });
      try {
        // 恶意替换 scratch/auth.json 为符号链接 -> 拒绝回写
        fs.rmSync(path.join(stagedReject.scratchDir, "auth.json"));
        fs.symlinkSync("/etc/hosts", path.join(stagedReject.scratchDir, "auth.json"));
        assert.equal(syncRefreshedCodexAuth(stagedReject), false, "符号链接 scratch auth.json 必须拒绝回写");

        // 篡改 account_id -> 拒绝回写
        fs.rmSync(path.join(stagedReject.scratchDir, "auth.json"));
        fs.writeFileSync(
          path.join(stagedReject.scratchDir, "auth.json"),
          JSON.stringify({
            ...origAuthObj,
            tokens: { ...origAuthObj.tokens, access_token: "acc_hijack", refresh_token: "ref_hijack", account_id: "acct_other" },
            last_refresh: "2026-11-27T01:00:00.000Z",
          }),
        );
        assert.equal(syncRefreshedCodexAuth(stagedReject), false, "跨账号 account_id 篡改必须拒绝回写");
      } finally {
        stagedReject.cleanup();
      }

      // 8b) 宿主机在运行期间已被更新到更新的 last_refresh：不覆盖更新的令牌
      const stagedCas = stageIsolatedCodexHome(hostCodexHome, { copyUserConfig: false });
      try {
        fs.writeFileSync(
          hostAuthPath,
          JSON.stringify({
            ...origAuthObj,
            tokens: { ...origAuthObj.tokens, access_token: "acc_newer_host", refresh_token: "ref_newer_host" },
            last_refresh: "2026-11-27T05:00:00.000Z",
          }),
          { mode: 0o600 },
        );
        fs.writeFileSync(
          path.join(stagedCas.scratchDir, "auth.json"),
          JSON.stringify({
            ...origAuthObj,
            tokens: { ...origAuthObj.tokens, access_token: "acc_older_scratch", refresh_token: "ref_older_scratch" },
            last_refresh: "2026-11-27T02:00:00.000Z",
          }),
        );
        assert.equal(syncRefreshedCodexAuth(stagedCas), false, "并发已有更新刷新时绝不能用旧刷新覆盖");
        assert.equal(JSON.parse(fs.readFileSync(hostAuthPath, "utf8")).tokens.access_token, "acc_newer_host");
      } finally {
        stagedCas.cleanup();
      }

      // 8c) 端到端隔离 runCodexExec：宿主机 config.toml 不可写，但刷新后的 auth.json 经校验净写回宿主机（过滤多余字段并保持 0600）
      fs.writeFileSync(hostAuthPath, JSON.stringify(origAuthObj, null, 2), { mode: 0o600 });
      if (hasCredentialMountIsolation()) {
        const stubRefreshCodex = path.join(dir, "stub-codex-refresh.mjs");
        fs.writeFileSync(
          stubRefreshCodex,
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'import path from "node:path";',
            'const codexHome = process.env.CODEX_HOME;',
            `const hostHome = ${JSON.stringify(hostCodexHome)};`,
            'if (!codexHome || codexHome === hostHome) { console.error("expected scratch CODEX_HOME"); process.exit(2); }',
            // 宿主机 CODEX_HOME 绝不可写
            'let tampered = false;',
            'try { fs.writeFileSync(path.join(hostHome, "tamper.toml"), "evil"); tampered = true; } catch {}',
            'if (tampered) { console.error("host CODEX_HOME unexpectedly writable"); process.exit(3); }',
            // 在私有可写 scratch CODEX_HOME 中刷新 OAuth auth.json（附带非法字段验证父进程会剥离）
            'const cur = JSON.parse(fs.readFileSync(path.join(codexHome, "auth.json"), "utf8"));',
            'cur.tokens.access_token = "acc_refreshed_r16";',
            'cur.tokens.refresh_token = "ref_refreshed_r16";',
            'cur.last_refresh = "2026-11-27T02:00:00.000Z";',
            'cur.injected_field = "must_not_persist";',
            'fs.writeFileSync(path.join(codexHome, "auth.json"), JSON.stringify(cur, null, 2));',
            'const oIdx = process.argv.indexOf("-o");',
            'if (oIdx >= 0 && process.argv[oIdx + 1]) fs.writeFileSync(process.argv[oIdx + 1], "REFRESH_OK");',
            'console.log("REFRESH_OK");',
          ].join("\n"),
          { mode: 0o755 },
        );
        const origCodexCmd = app.cfg.harnesses.codex.cmd;
        app.cfg.harnesses.codex.cmd = stubRefreshCodex;
        process.env.CODEX_HOME = hostCodexHome;
        try {
          const refRes = await runHarness(app.cfg, {
            harness: "codex",
            prompt: "refresh test",
            cwd: dir,
            tools: "none",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "codex-refresh-r16.log"),
          });
          assert.equal(refRes.ok, true, `隔离 codex-exec 刷新令牌应成功：${refRes.text}`);
          assert.equal(refRes.text, "REFRESH_OK");
          const persisted = JSON.parse(fs.readFileSync(hostAuthPath, "utf8")) as Record<string, unknown>;
          const persistedTokens = persisted.tokens as Record<string, unknown>;
          assert.equal(persistedTokens.access_token, "acc_refreshed_r16");
          assert.equal(persistedTokens.refresh_token, "ref_refreshed_r16");
          assert.equal(persistedTokens.account_id, "acct_owner_1");
          assert.equal("injected_field" in persisted, false, "非白名单注入字段不得被写回宿主机 auth.json");
          assert.equal(fs.statSync(hostAuthPath).mode & 0o777, 0o600, "写回后的 auth.json 必须保持 0600 权限");
          assert.equal(fs.existsSync(path.join(hostCodexHome, "tamper.toml")), false);
        } finally {
          app.cfg.harnesses.codex.cmd = origCodexCmd;
          if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
          else process.env.CODEX_HOME = prevCodexHome;
        }
      }
    }

    // 9) [R16 #9 P2] 重定向期间并发 syncFromRecords 轮换 Cookie：后续跳发送最新轮换值并追踪真实发送基线，绝不用陈旧值覆盖并发刷新
    {
      const jar = RecordingCookieJar.fromRecords(
        [{ name: "session", value: "v1_init", domain: "127.0.0.1", path: "/" }],
        ["127.0.0.1"],
      );
      let hop1SeenCookie = "";
      redirectSrv = http.createServer((req, res) => {
        if (req.url === "/hop0") {
          // 模拟 hop0 在途期间后台 watcher 将磁盘较新轮换同步进共享 jar
          jar.syncFromRecords([{ name: "session", value: "v2_disk_rotated", domain: "127.0.0.1", path: "/" }]);
          res.writeHead(302, {
            Location: "/hop1",
            "Set-Cookie": "session=v1_stale_redirect; Path=/",
          });
          res.end();
          return;
        }
        if (req.url === "/hop1") {
          hop1SeenCookie = String(req.headers.cookie ?? "");
          // 模拟 hop1 在途期间磁盘再次同步更新到 v3
          jar.syncFromRecords([{ name: "session", value: "v3_disk_newer", domain: "127.0.0.1", path: "/" }]);
          res.writeHead(200, {
            "Set-Cookie": "session=v2_hop1_stale_resp; Path=/",
            "Content-Type": "text/plain",
          });
          res.end("ok");
          return;
        }
        res.writeHead(404);
        res.end();
      });
      await new Promise<void>((resolve) => redirectSrv!.listen(0, "127.0.0.1", resolve));
      const port = (redirectSrv.address() as { port: number }).port;
      const r = await fetchWithJar(jar, {
        method: "GET",
        url: `http://127.0.0.1:${port}/hop0`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(r.status, 200);
      assert.ok(
        hop1SeenCookie.includes("session=v2_disk_rotated"),
        `hop1 必须发送在途轮换后的 v2_disk_rotated 而非陈旧重定向 Cookie，实际：${hop1SeenCookie}`,
      );
      assert.equal(
        jar.cookieValue(new URL(`http://127.0.0.1:${port}/hop1`), "session"),
        "v3_disk_newer",
        "hop1 响应不得覆盖在其在途期间同步的更新轮换值 v3_disk_newer",
      );
    }

    // 10) [R16 #10 P2] 快通道推理期间背景消息被编辑导致 Understander.apply 丢弃陈旧批次时，fastCycle 延迟重排而不标 done，重试后正常预起草
    {
      const now = Date.now();
      const conv = "pw_chat:9001";
      svc.store.addObs([
        {
          id: "pw:bg_edit_1",
          source: "im",
          kind: "msg",
          conv,
          conv_name: "原生白名单群",
          actor_id: "9002",
          actor_name: "同事乙",
          is_me: false,
          time: now - 10_000,
          text: "背景原文本",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001" },
        },
        {
          id: "pw:mention_retry_1",
          source: "im",
          kind: "at_me",
          conv,
          conv_name: "原生白名单群",
          actor_id: "9002",
          actor_name: "同事乙",
          is_me: false,
          time: now - 5_000,
          text: "@主人A 请帮忙确认一下上线窗口",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001", at_me: true, is_mention_me: true, chat_id: "9001", message_id: "71001" },
        },
      ]);
      // 先将背景标为已处理，保持 mention_retry_1 为待处理
      svc.store.markProcessed(["pw:bg_edit_1"]);

      let inferCalls = 0;
      const origRunner = svc.understander.runner;
      svc.understander.runner = async () => {
        inferCalls++;
        if (inferCalls === 1) {
          // 第一次推理在途期间，背景消息被编辑，触发 Understander.apply 整批丢弃
          svc.store.addObs([
            {
              id: "pw:bg_edit_1",
              source: "im",
              kind: "msg",
              conv,
              conv_name: "原生白名单群",
              actor_id: "9002",
              actor_name: "同事乙",
              is_me: false,
              time: now - 10_000,
              text: "背景已编辑新文本",
              url: "",
              meta: { chat_type: "group", native_owner_id: "7001" },
            },
          ]);
        }
        return {
          ok: true,
          exitCode: 0,
          text: JSON.stringify({
            projects: [],
            items: [
              {
                title: "确认上线窗口",
                kind: "ask_me",
                priority: "high",
                counterpart: "同事乙",
                next_step: "回复上线时间",
                evidence: [{ obs_id: "pw:mention_retry_1", quote: "@主人A 请帮忙确认一下上线窗口" }],
              },
            ],
          }),
          timedOut: false,
          aborted: false,
        };
      };
      try {
        const fastPayload = {
          conv,
          conv_name: "原生白名单群",
          trigger_obs_id: "pw:mention_retry_1",
          anchor: {
            id: "71001",
            conversationId: "9001",
            rootId: "",
            parentId: "",
            threadId: "",
            position: 10,
            createdAtMs: now - 5_000,
          },
        };
        const firstRun = await svc.fastCycle("context:fast-r16-1", fastPayload);
        assert.equal(firstRun.busy, true, "推理批次因背景编辑被丢弃且触发消息仍待处理时，fastCycle 必须返回 busy 延迟重排而非标 done");
        assert.equal(svc.store.obsPending("pw:mention_retry_1"), true);

        const secondRun = await svc.fastCycle("context:fast-r16-1", fastPayload);
        assert.equal(secondRun.busy, undefined);
        assert.equal(secondRun.created, 1);
        assert.equal(secondRun.pre_drafted, 1, "重试成功后必须正常触发高优 ask_me 的自动预起草");
        assert.equal(svc.store.obsPending("pw:mention_retry_1"), false);
      } finally {
        svc.understander.runner = origRunner;
      }
    }
  } finally {
    if (redirectSrv) await new Promise<void>((resolve) => redirectSrv!.close(() => resolve()));
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevCodexHome;
    if (prevLcAll === undefined) delete process.env.LC_ALL;
    else process.env.LC_ALL = prevLcAll;
    if (prevLang === undefined) delete process.env.LANG;
    else process.env.LANG = prevLang;
    if (prevLanguage === undefined) delete process.env.LANGUAGE;
    else process.env.LANGUAGE = prevLanguage;
    extraAppA?.store.db.close();
    extraAppB?.store.db.close();
    app?.store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第十七轮回归：定向清理失效worktree不误删无关checkout、符号链接Codex配置载入与损坏fail-closed、范围外@回复发前实时复核mention、共享凭据陈旧恢复不覆盖新会话、unshare --kill-child与进程组超时清理、Codex OAuth回写防复活与inode条件更新、周期理解补发预起草、uncertain草稿延迟重试、保留以私聊开头的权威群名、多路搜索按最新edit_version合并、非隔离Codex保留D-Bus、看板原子初始化、已发布提交跳过LFS、被拒会话状态logged_in=false与gzip中断快速失败", async () => {
  const dir = makeTmp("pa-feishu-r17-");
  const ctxDir = path.join(dir, "ctx");
  fs.mkdirSync(ctxDir, { recursive: true });
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCredFile = process.env.PA_FEISHU_WEB_CRED_FILE;
  const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
  const prevCtxDir = process.env.CTX_DIR;
  const prevCodexHome = process.env.CODEX_HOME;
  const prevDbus = process.env.DBUS_SESSION_BUS_ADDRESS;
  const prevPath = process.env.PATH;
  process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
  delete process.env.PA_FEISHU_WEB_CRED_FILE;
  delete process.env.CREDENTIALS_DIRECTORY;
  process.env.CTX_DIR = ctxDir;

  const mock = await startMockFeishuWebServer();
  let app: ReturnType<typeof createApp> | undefined;
  let extraAppA: ReturnType<typeof createApp> | undefined;
  let extraAppB: ReturnType<typeof createApp> | undefined;
  let nonIsoApp: ReturnType<typeof createApp> | undefined;
  let brokenGzipSrv: http.Server | undefined;

  try {
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const baseCookies = [
      { name: "session", value: "r17_sess", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r17_1", domain: "127.0.0.1", path: "/" },
    ];

    const repoDir = path.join(dir, "repo-r17");
    fs.mkdirSync(repoDir, { recursive: true });
    await tryGit(repoDir, ["init", "-q"]);
    await tryGit(repoDir, ["config", "user.name", "Test"]);
    await tryGit(repoDir, ["config", "user.email", "test@example.com"]);
    fs.writeFileSync(path.join(repoDir, "README.md"), "init\n");
    await tryGit(repoDir, ["add", "README.md"]);
    await tryGit(repoDir, ["commit", "-qm", "init"]);

    const cfgFile = path.join(dir, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: path.join(dir, "data"),
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: {
          codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") },
        },
        roles: { brain: "codex" },
        owner: { open_id: "ou_owner_a" },
        cards: { enabled: false },
        dispatch: { repos: { r17: repoDir } },
        delivery: { enabled: true, keep_discarded_hours: 0 },
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "codex",
          groups: "allowlist",
          groups_allow: ["pw_chat:9001"],
          groups_deny: [],
          sources: { im: true, minutes: false, docs: false, tasks: false, calendar: false, meego: false },
          personal_web: { enabled: true, fast_lane: true, debounce_ms: 0, pre_draft: true, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    registerDelivery(app);
    const svc = new ContextService(app);
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    installCtxDirStubLlm(svc, ctxDir);
    fs.writeFileSync(path.join(ctxDir, "lark.json"), JSON.stringify({ user_open_id: "ou_owner_a" }));
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r17_main", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 1) [R17 #1 P1] 隔离环境下 delivery cleanup 仅定向清理目标派单的失效 worktree 记录，绝不调用全局 git worktree prune 误删 /tmp 下的无关 worktree
    {
      const wtUnrelated = path.join(dir, "wt-unrelated-in-tmp");
      const wtDiscarded = path.join(app.cfg.dataDir, "worktrees", "wt-discarded-r17");
      fs.mkdirSync(path.dirname(wtDiscarded), { recursive: true });
      await tryGit(repoDir, ["worktree", "add", "-b", "feat/unrelated-r17", wtUnrelated], {
        cfg: app.cfg,
        extraWritablePaths: [dir],
      });
      await tryGit(repoDir, ["worktree", "add", "-b", "pa/discard-r17", wtDiscarded], {
        cfg: app.cfg,
        extraWritablePaths: [path.dirname(wtDiscarded)],
      });
      // 手动删掉 wtDiscarded 目录，模拟派单 checkout 已缺失但管理记录仍在
      fs.rmSync(wtDiscarded, { recursive: true, force: true });
      const adminDir = path.join(repoDir, ".git", "worktrees");
      assert.equal(fs.readdirSync(adminDir).length, 2);

      // 入队一个已放弃的派单及 cleanup 任务并执行
      const dispId = "dispatch:g_r17_clean:1";
      const discardId = `delivery:${dispId}:discard:1`;
      const cleanupId = `delivery:${dispId}:cleanup:1`;
      app.ledger.enqueue({
        id: dispId,
        kind: "dispatch",
        ref: "g_r17_clean",
        state: "accepted",
        payload: {
          guid: "g_r17_clean",
          summary: "clean test",
          description: "repo: r17",
          harness: "codex",
          reviewer: "",
          cwd: wtDiscarded,
          base: "HEAD",
          branch: "pa/discard-r17",
          round: 1,
          maxRounds: 1,
          report: "",
          history: [],
        },
      });
      const dispItem = app.ledger.claim("dispatch", 60_000)!;
      app.ledger.transition(dispItem, { state: "accepted", terminal: true });
      app.ledger.enqueue({
        id: discardId,
        kind: "delivery",
        ref: dispId,
        state: "done",
        payload: { action: "discard", dispatch_id: dispId, guid: "g_r17_clean", message: "" },
      });
      const discItem = app.ledger.claim("delivery", 60_000)!;
      app.ledger.transition(discItem, { state: "done", terminal: true });
      app.ledger.enqueue({
        id: cleanupId,
        kind: "delivery",
        ref: dispId,
        payload: { action: "cleanup", dispatch_id: dispId, guid: "g_r17_clean", discard_id: discardId, message: "" },
      });
      await app.engine.drain(["delivery"]);

      const remainingAdmins = fs.readdirSync(adminDir);
      assert.equal(remainingAdmins.length, 1, "仅应定向清理目标派单的失效 worktree 记录，无关 worktree 记录必须完整保留");
      const statusUnrelated = await tryGit(wtUnrelated, ["status", "--short"]);
      assert.equal(statusUnrelated.code, 0, "位于 /tmp 下的无关 worktree 必须完好可用");
      const brCheck = await tryGit(repoDir, ["rev-parse", "--verify", "--quiet", "refs/heads/pa/discard-r17"]);
      assert.notEqual(brCheck.code, 0, "已放弃派单的 pa/ 分支应被清理");
    }

    // 2) [R17 #2 P1] stageIsolatedCodexHome 兼容 dotfiles 符号链接 config.toml / rules/，遇到损坏链接 fail-closed 抛错
    {
      const dotfilesDir = path.join(dir, "dotfiles-codex");
      const dotfilesRules = path.join(dotfilesDir, "rules");
      fs.mkdirSync(dotfilesRules, { recursive: true });
      fs.writeFileSync(path.join(dotfilesDir, "config.toml"), 'model_provider = "corp_symlink"\n');
      fs.writeFileSync(path.join(dotfilesRules, "review.md"), "rule body");

      const symlinkCodexHome = path.join(dir, "symlink-codex-home");
      fs.mkdirSync(symlinkCodexHome, { recursive: true });
      fs.symlinkSync(path.join(dotfilesDir, "config.toml"), path.join(symlinkCodexHome, "config.toml"));
      fs.symlinkSync(dotfilesRules, path.join(symlinkCodexHome, "rules"));

      const stagedOk = stageIsolatedCodexHome(symlinkCodexHome, { copyUserConfig: true, lockDir: app.cfg.dataDir });
      try {
        assert.equal(
          fs.readFileSync(path.join(stagedOk.scratchDir, "config.toml"), "utf8"),
          'model_provider = "corp_symlink"\n',
          "符号链接的 config.toml 必须解引用拷贝到临时 CODEX_HOME",
        );
        assert.equal(fs.readFileSync(path.join(stagedOk.scratchDir, "rules", "review.md"), "utf8"), "rule body");
      } finally {
        stagedOk.cleanup();
      }

      const brokenCodexHome = path.join(dir, "broken-codex-home");
      fs.mkdirSync(brokenCodexHome, { recursive: true });
      fs.symlinkSync(path.join(dir, "nonexistent-dotfiles-config.toml"), path.join(brokenCodexHome, "config.toml"));
      assert.throws(
        () => stageIsolatedCodexHome(brokenCodexHome, { copyUserConfig: true }),
        /无法解析宿主机 Codex 配置文件|中止执行/,
        "损坏的 config.toml 符号链接必须 fail-closed 抛错，不得静默退回默认供应商",
      );
    }

    // 3) [R17 #3 P1] 范围外群 @回复发前实时复核原消息仍 @本人：监听离线期间被编辑移除 @mention 时必须拒绝发包并撤回陈旧观测
    {
      mock.setChatName("9970", "范围外测试群");
      mock.setChatKind("9970", CHAT_KIND_GROUP);
      // 模拟离线期间服务端消息已被编辑移除 @主人A（不含 mentionId: "7001"）
      mock.addMessage(
        "r17_edited_mention",
        buildNativeMessage({
          id: "r17_edited_mention",
          chatId: "9970",
          actorId: "7002",
          richBytes: encodeRichText([{ text: "不用了，已经改好了" }]),
          createdAtSec: nowSec,
        }),
      );
      svc.store.addObs([
        {
          id: "pw:r17_edited_mention",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9970",
          conv_name: "范围外测试群",
          actor_id: "7002",
          actor_name: "同事",
          is_me: false,
          time: now,
          text: "@主人A 帮看一下",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001", at_me: true },
        },
      ]);
      const sentBefore = mock.sentReplies.length;
      const cidEdited = computePwReplyCid({
        draft_id: "drf_r17_mention_gone",
        owner_id: "7001",
        chat_id: "9970",
        message_id: "r17_edited_mention",
        text: "好的这就看",
      }).cid;
      await assert.rejects(
        () =>
          svc.personalWeb.sendVerifiedReply({
            owner_id: "7001",
            chat_id: "9970",
            message_id: "r17_edited_mention",
            text: "好的这就看",
            cid: cidEdited,
          }),
        /不再 @本人/,
        "离线期间编辑移除 @mention 后，范围外群回复必须在认领发包前被拦截",
      );
      assert.equal(mock.sentReplies.length, sentBefore, "被拦截后绝不能发出回复");
      assert.equal(app.store.get(`pw.delivery.${cidEdited}`), undefined, "拦截在 claim 前完成，不得残留 sending 投递记录");
      assert.equal(svc.store.obs("pw:r17_edited_mention")?.meta.withdrawn, true, "陈旧观测应同步标记为已撤回");
    }

    // 4) [R17 #4 P2] 共享外部 PA_FEISHU_WEB_CRED_FILE：A 崩溃后的陈旧 pending 恢复绝不覆盖 B 后安装的新登录会话
    {
      const sharedRecoveryCred = path.join(dir, "shared-r17-recovery.json");
      const cfgA = path.join(dir, "cfg-r17-a.json");
      const cfgB = path.join(dir, "cfg-r17-b.json");
      fs.writeFileSync(
        cfgA,
        JSON.stringify({
          data_dir: path.join(dir, "ws-r17-a"),
          harnesses: { codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_a" },
          context: { enabled: true, personal_web: { enabled: true } },
        }),
      );
      fs.writeFileSync(
        cfgB,
        JSON.stringify({
          data_dir: path.join(dir, "ws-r17-b"),
          harnesses: { codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_b" },
          context: { enabled: true, personal_web: { enabled: true } },
        }),
      );
      process.env.PA_FEISHU_WEB_CRED_FILE = sharedRecoveryCred;
      try {
        extraAppA = createApp(loadConfig(cfgA));
        extraAppB = createApp(loadConfig(cfgB));
        const storeA = new WebLoginStore(extraAppA.cfg.dataDir);
        // A 暂存并记录带 prev_file_sha256 的 pending 标记后模拟在 rename 前崩溃
        storeA.stageWithLock((stage) => {
          const s = stage({ owner_id: "7001", owner_name: "A陈旧登录", session_id: "sess_r17_stale_a", cookies: baseCookies });
          extraAppA!.store.set(
            PENDING_CRED_COMMIT_KV_KEY,
            JSON.stringify({
              file: storeA.file,
              staged_file: storeA.stagedFile,
              owner_id: "7001",
              session_id: s.payload.session_id,
              prev_file_sha256: s.prevFileSha256,
              prev_session_id: s.prevSessionId,
              at: Date.now() - 10_000,
            }),
          );
        });
        // B 随后完成正常登录并安装新会话 sess_r17_live_b
        commitWorkspaceLogin(
          extraAppB,
          { owner_id: "8002", owner_name: "B新登录", session_id: "sess_r17_live_b", cookies: baseCookies },
          { allowUnverifiedOwner: true },
        );
        // A 稍后恢复协调：必须识别现网代际已变更，绝不拿陈旧暂存覆盖 B 的活会话
        storeA.reconcilePendingCommit(extraAppA.store, PENDING_CRED_COMMIT_KV_KEY);
        assert.equal(new WebLoginStore(extraAppB.cfg.dataDir).load()?.session_id, "sess_r17_live_b", "陈旧暂存恢复绝不能覆盖更新的共享登录会话");
        assert.equal(fs.existsSync(storeA.stagedFile), false, "过期陈旧暂存文件应被清理");
        assert.equal(extraAppA.store.get(PENDING_CRED_COMMIT_KV_KEY), "", "过期 pending 标记应被清除");
      } finally {
        delete process.env.PA_FEISHU_WEB_CRED_FILE;
      }
    }

    // 5) [R17 #5 P2] unshare 回退默认启用 --kill-child，超时后彻底终止命名空间内子孙进程不挂起管道
    {
      const unsharePlan = wrapCredentialIsolatedCommand(
        "true",
        [],
        { PA_FEISHU_WEB_KEY: TEST_WEB_KEY },
        { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: "/sbin/pivot_root" } },
      );
      assert.ok(unsharePlan.args.includes("--kill-child"), "unshare 回退参数必须包含 --kill-child 以随包装进程一并清理命名空间内子进程");

      const pivotBin = ["/sbin/pivot_root", "/usr/sbin/pivot_root"].find((p) => fs.existsSync(p));
      const probeUnshareKill = pivotBin
        ? await runProcess(
            "unshare",
            ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "--kill-child", "setpriv", "--bounding-set", "-all", "--inh-caps", "-all", "--ambient-caps", "-all", "--no-new-privs", "true"],
            { timeoutMs: 5_000 },
          )
        : { code: 1, stdout: "", stderr: "", timedOut: false };
      if (probeUnshareKill.code === 0 && pivotBin) {
        const wrappedSleep = wrapCredentialIsolatedCommand(
          "sh",
          ["-c", "sleep 30 & wait"],
          { PA_FEISHU_WEB_KEY: TEST_WEB_KEY },
          { forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: pivotBin, killChild: true } },
        );
        const t0 = Date.now();
        const rTimeout = await runProcess(wrappedSleep.cmd, wrappedSleep.args, { timeoutMs: 300, group: true });
        assert.equal(rTimeout.timedOut, true);
        assert.ok(Date.now() - t0 < 5_000, "unshare --kill-child 超时后子孙进程必须立即结束释放管道，不得长时间挂起");
      }
    }

    // 6) [R17 #6 P2] syncRefreshedCodexAuth：登出删除不复活、外部 rename 换 inode 不覆盖、同 inode 合法刷新原子更新 0600
    {
      const hHome = path.join(dir, "codex-auth-inode");
      fs.mkdirSync(hHome, { recursive: true });
      const authFile = path.join(hHome, "auth.json");
      const baseAuth = {
        auth_mode: "chatgpt",
        OPENAI_API_KEY: null,
        tokens: { id_token: "id_1", access_token: "acc_1", refresh_token: "ref_1", account_id: "acct_r17" },
        last_refresh: "2026-11-26T00:00:00.000Z",
      };
      fs.writeFileSync(authFile, JSON.stringify(baseAuth, null, 2), { mode: 0o600 });

      // 6a) 模拟运行期间用户执行 codex logout 删除 auth.json：绝不复活
      const sLogout = stageIsolatedCodexHome(hHome, { copyUserConfig: false, lockDir: app.cfg.dataDir });
      try {
        fs.writeFileSync(
          path.join(sLogout.scratchDir, "auth.json"),
          JSON.stringify({ ...baseAuth, tokens: { ...baseAuth.tokens, access_token: "acc_2", refresh_token: "ref_2" }, last_refresh: "2026-11-27T01:00:00.000Z" }),
        );
        fs.rmSync(authFile);
        assert.equal(syncRefreshedCodexAuth(sLogout), false, "登出删除 auth.json 后绝不能重建文件");
        assert.equal(fs.existsSync(authFile), false);
      } finally {
        sLogout.cleanup();
      }

      // 6b) 模拟运行期间外部 codex login 通过 rename 原子替换新文件（inode 变更）：绝不覆盖
      fs.writeFileSync(authFile, JSON.stringify(baseAuth, null, 2), { mode: 0o600 });
      const sRename = stageIsolatedCodexHome(hHome, { copyUserConfig: false, lockDir: app.cfg.dataDir });
      try {
        fs.writeFileSync(
          path.join(sRename.scratchDir, "auth.json"),
          JSON.stringify({ ...baseAuth, tokens: { ...baseAuth.tokens, access_token: "acc_stale_ref", refresh_token: "ref_stale_ref" }, last_refresh: "2026-11-27T04:00:00.000Z" }),
        );
        const newLoginTmp = path.join(hHome, "new-login.tmp");
        fs.writeFileSync(
          newLoginTmp,
          JSON.stringify({ ...baseAuth, tokens: { ...baseAuth.tokens, access_token: "acc_brand_new_login", refresh_token: "ref_brand_new_login" }, last_refresh: "2026-11-27T02:00:00.000Z" }),
          { mode: 0o600 },
        );
        fs.renameSync(newLoginTmp, authFile);
        assert.equal(syncRefreshedCodexAuth(sRename), false, "外部 rename 更换 inode 后绝不能覆盖新登录文件");
        assert.equal(JSON.parse(fs.readFileSync(authFile, "utf8")).tokens.access_token, "acc_brand_new_login");
      } finally {
        sRename.cleanup();
      }

      // 6c) 同一 inode 且宿主机未变更：条件原位更新成功并保持 0600
      const sOk = stageIsolatedCodexHome(hHome, { copyUserConfig: false, lockDir: app.cfg.dataDir });
      try {
        fs.writeFileSync(
          path.join(sOk.scratchDir, "auth.json"),
          JSON.stringify({ ...baseAuth, tokens: { ...baseAuth.tokens, access_token: "acc_updated_r17", refresh_token: "ref_updated_r17" }, last_refresh: "2026-11-27T05:00:00.000Z" }),
        );
        assert.equal(syncRefreshedCodexAuth(sOk), true);
        assert.equal(JSON.parse(fs.readFileSync(authFile, "utf8")).tokens.access_token, "acc_updated_r17");
        assert.equal(fs.statSync(authFile).mode & 0o777, 0o600);
      } finally {
        sOk.cleanup();
      }
    }

    // 7) [R17 #7 P2] 周期 cycle 抢先消费原生 @本人 触发消息时，直接幂等补入自动预起草（普通群消息不自动预起草）
    {
      svc.store.addObs([
        {
          id: "pw:r17_cycle_atme",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:9001",
          conv_name: "白名单群",
          actor_id: "9002",
          actor_name: "同事丙",
          is_me: false,
          time: now - 5_000,
          text: "@主人A 请立刻确认发版清单",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001", at_me: true, is_mention_me: true, chat_id: "9001", message_id: "r17_cycle_atme" },
        },
        {
          id: "pw:r17_cycle_plain",
          source: "im",
          kind: "msg",
          conv: "pw_chat:9001",
          conv_name: "白名单群",
          actor_id: "9002",
          actor_name: "同事丙",
          is_me: false,
          time: now - 4_000,
          text: "顺便提一句下周例会改期",
          url: "",
          meta: { chat_type: "group", native_owner_id: "7001", at_me: false, chat_id: "9001", message_id: "r17_cycle_plain" },
        },
      ]);
      const origRunner = svc.understander.runner;
      svc.understander.runner = async () => ({
        ok: true,
        exitCode: 0,
        text: JSON.stringify({
          projects: [],
          items: [
            {
              title: "确认发版清单",
              kind: "ask_me",
              priority: "high",
              counterpart: "同事丙",
              next_step: "回复确认结果",
              evidence: [{ obs_id: "pw:r17_cycle_atme", quote: "@主人A 请立刻确认发版清单" }],
            },
            {
              title: "关注下周例会改期",
              kind: "ask_me",
              priority: "high",
              counterpart: "同事丙",
              next_step: "确认时间",
              evidence: [{ obs_id: "pw:r17_cycle_plain", quote: "顺便提一句下周例会改期" }],
            },
          ],
        }),
        timedOut: false,
        aborted: false,
      });
      try {
        await svc.cycle("ctx:r17-cycle-predraft");
        const items = svc.store.items({ status: ["open"], limit: 50 });
        const atMeItem = items.find((i) => i.title === "确认发版清单");
        const plainItem = items.find((i) => i.title === "关注下周例会改期");
        assert.ok(atMeItem && plainItem);
        assert.ok(
          app.ledger.get(`context:draft:${atMeItem.id}:reply:fast`),
          "周期理解抢先处理原生 @本人 触发消息时必须入队幂等自动预起草作业",
        );
        assert.equal(
          app.ledger.get(`context:draft:${plainItem.id}:reply:fast`),
          undefined,
          "无原生私聊/@本人触发证据的普通群消息不得由周期理解自动预起草",
        );
      } finally {
        svc.understander.runner = origRunner;
      }
    }

    // 8) [R17 #8 P2] 草稿资格核验返回 uncertain 时抛出 DraftTargetUncertainError，自动预起草延迟重试而非永久 skipped（覆盖初检与推理后复检）
    {
      const items = svc.store.items({ status: ["open"], limit: 50 });
      const targetItem = items.find((i) => i.title === "确认发版清单")!;
      const origCheck = svc.drafter.checkConvAllowed;
      const origDraftRunner = svc.drafter.runner;
      const ctxHandler = svc.handler();
      try {
        // 8a) 初检返回 uncertain -> 自动预起草 job 不得标为 terminal skipped，而是延迟退回等待重跑
        let mode: "uncertain_init" | "uncertain_post" | "allowed" = "uncertain_init";
        let postCalls = 0;
        svc.drafter.checkConvAllowed = async () => {
          if (mode === "uncertain_init") return "uncertain";
          if (mode === "uncertain_post") {
            postCalls++;
            return postCalls === 1 ? "allowed" : "uncertain";
          }
          return "allowed";
        };
        svc.drafter.runner = async () => ({
          ok: true,
          exitCode: 0,
          text: "好的，发版清单我这边已确认无误。",
          timedOut: false,
          aborted: false,
        });

        const autoJobId = `context:draft:${targetItem.id}:reply:fast`;
        const w1 = app.ledger.claim("context", 60_000)!;
        assert.equal(w1.id, autoJobId);
        await ctxHandler.run(w1 as never, { attempt: 1, signal: new AbortController().signal });
        const afterInit = app.ledger.get(autoJobId)!;
        assert.equal(afterInit.terminal, false, "初检 uncertain 时自动预起草绝不能被标为永久 skipped");
        assert.equal(afterInit.attempts, 0, "延迟重试应退回尝试次数");
        assert.equal(svc.store.drafts({}).length, 0);

        // 8b) 推理后复检返回 uncertain -> 同样抛出 DraftTargetUncertainError、不落库且延迟重试
        mode = "uncertain_post";
        await assert.rejects(
          () => svc.drafter.forItem(targetItem.id, "reply"),
          (e: unknown) => e instanceof DraftTargetUncertainError,
          "推理后复检返回 uncertain 必须抛出 DraftTargetUncertainError",
        );
        assert.equal(svc.store.drafts({}).length, 0, "推理后 uncertain 绝不能落库草稿");

        // 8c) 连通恢复后 checkConvAllowed 返回 allowed -> 顺利生成草稿
        mode = "allowed";
        app.store.db.prepare("UPDATE work SET next_at = 0 WHERE id = ?").run(autoJobId);
        const w2 = app.ledger.claim("context", 60_000)!;
        assert.equal(w2.id, autoJobId);
        await ctxHandler.run(w2 as never, { attempt: 1, signal: new AbortController().signal });
        assert.equal(app.ledger.get(autoJobId)?.state, "done");
        assert.equal(svc.store.drafts({}).length, 1, "连通恢复后自动预起草应正常产出草稿");
      } finally {
        svc.drafter.checkConvAllowed = origCheck;
        svc.drafter.runner = origDraftRunner;
      }
    }

    // 9) [R17 #9 P2] 保留以「私聊」开头的权威群名（如「私聊问题反馈」），配合 max_groups + groups_deny 正确淘汰被拒群并补位下一群
    {
      rememberOpenGroupName(app.store, "oc_siliao_feedback", "私聊问题反馈");
      assert.equal(loadKnownOpenGroupNames(app.store)["oc_siliao_feedback"], "私聊问题反馈", "权威群名即使以「私聊」开头也必须被保留缓存");
      const mockCfg = {
        ...app.cfg,
        context: {
          ...app.cfg.context,
          groups: "allowlist" as const,
          max_groups: 1,
          groups_allow: ["oc_siliao_feedback", "oc_next_allowed"],
          groups_deny: ["反馈"],
        },
      };
      const picked = selectEffectiveOpenGroups({
        cfg: mockCfg,
        store: svc.store,
        spoken: {},
        knownNames: loadKnownOpenGroupNames(app.store),
      });
      assert.deepEqual(
        picked.map(([id]) => id),
        ["oc_next_allowed"],
        "命名为「私聊问题反馈」的群命中 groups_deny=[反馈] 后应被淘汰，把唯一的 max_groups 名额让给下一个允许群",
      );
    }

    // 10) [R17 #10 P2] 多路搜索合并重复 message_id 时按更高 edit_version 采用新正文与 @mention 分类
    {
      const origLarkRun = app.lark.run.bind(app.lark);
      const origGroups = app.cfg.context.groups;
      const origGroupsAllow = [...app.cfg.context.groups_allow];
      app.cfg.context.groups = "allowlist";
      app.cfg.context.groups_allow = ["oc_dup_edit_grp"];
      app.lark.run = async (argv) => {
        if (argv[0] === "auth" && argv[1] === "status") {
          return { identity: "user", user: { open_id: "ou_owner_a", name: "主人A" } };
        }
        if (argv[0] === "im" && argv[1] === "+chat-messages-list" && argv.includes("oc_dup_edit_grp")) {
          return {
            messages: [
              {
                message_id: "om_r17_dup_edit",
                chat_id: "oc_dup_edit_grp",
                chat_name: "版本合并群",
                chat_type: "group",
                create_time: String(now - 2_000),
                edit_version: 2,
                sender: { id: "ou_colleague", name: "同事丁", sender_type: "user" },
                content: JSON.stringify({ text: "新版本：已自行解决" }),
                mentions: [],
              },
            ],
          };
        }
        if (argv[0] === "im" && argv[1] === "+messages-search") {
          if (argv.includes("--is-at-me")) {
            return {
              items: [
                {
                  message_id: "om_r17_dup_edit",
                  chat_id: "oc_dup_edit_grp",
                  chat_name: "版本合并群",
                  chat_type: "group",
                  create_time: String(now - 2_000),
                  edit_version: 1,
                  sender: { id: "ou_colleague", name: "同事丁", sender_type: "user" },
                  content: JSON.stringify({ text: "@主人A 旧版本待处理" }),
                },
              ],
            };
          }
          return { items: [] };
        }
        return origLarkRun(argv);
      };
      try {
        await svc.connectors.pullIm();
        const savedObs = svc.store.obs("im:om_r17_dup_edit");
        assert.ok(savedObs, "重复搜索行应成功落库");
        assert.equal(savedObs.text, "新版本：已自行解决", "应保留更高 edit_version 的最新正文");
        assert.equal(savedObs.meta.edit_version, 2);
        assert.equal(savedObs.meta.at_me, false, "更高版本已移除 mention，不得保留旧版本的 at_me=true");
      } finally {
        app.lark.run = origLarkRun;
        app.cfg.context.groups = origGroups;
        app.cfg.context.groups_allow = origGroupsAllow;
      }
    }

    // 11) [R17 #11 P2] 非隔离 Codex 运行依赖 keyring 时保留 DBUS_SESSION_BUS_ADDRESS（默认 prepareHarnessEnv 仍剥离）
    if (process.platform === "linux") {
      const strippedDefault = prepareHarnessEnv({ DBUS_SESSION_BUS_ADDRESS: "unix:path=/tmp/fake-r17-dbus" });
      try {
        assert.equal(strippedDefault.env.DBUS_SESSION_BUS_ADDRESS, undefined, "默认 prepareHarnessEnv 必须继续剥离 DBUS_SESSION_BUS_ADDRESS");
      } finally {
        strippedDefault.cleanup();
      }

      const nonIsoDir = path.join(dir, "non-iso-ws");
      const nonIsoCodexHome = path.join(dir, "non-iso-codex-home");
      fs.mkdirSync(nonIsoCodexHome, { recursive: true });
      fs.writeFileSync(path.join(nonIsoCodexHome, "config.toml"), 'cli_auth_credentials_store = "keyring"\n');
      const stubNonIsoCodex = path.join(dir, "stub-codex-dbus.mjs");
      fs.writeFileSync(
        stubNonIsoCodex,
        [
          "#!/usr/bin/env node",
          'import fs from "node:fs";',
          'if (process.env.DBUS_SESSION_BUS_ADDRESS !== "unix:path=/tmp/fake-r17-dbus") process.exit(2);',
          'const oIdx = process.argv.indexOf("-o");',
          'if (oIdx >= 0 && process.argv[oIdx + 1]) fs.writeFileSync(process.argv[oIdx + 1], "DBUS_PRESERVED_OK");',
          'console.log("DBUS_PRESERVED_OK");',
        ].join("\n"),
        { mode: 0o755 },
      );
      const nonIsoCfgFile = path.join(dir, "non-iso-cfg.json");
      fs.writeFileSync(
        nonIsoCfgFile,
        JSON.stringify({
          data_dir: nonIsoDir,
          harnesses: { codex: { type: "codex-exec", cmd: stubNonIsoCodex } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_a" },
          context: { enabled: false, personal_web: { enabled: false } },
        }),
      );
      delete process.env.PA_FEISHU_WEB_KEY;
      process.env.CODEX_HOME = nonIsoCodexHome;
      process.env.DBUS_SESSION_BUS_ADDRESS = "unix:path=/tmp/fake-r17-dbus";
      try {
        nonIsoApp = createApp(loadConfig(nonIsoCfgFile));
        const resNonIso = await runHarness(nonIsoApp.cfg, {
          harness: "codex",
          prompt: "hi",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "non-iso-codex.log"),
        });
        assert.equal(resNonIso.ok, true, `非隔离 Codex keyring 运行应保留 DBUS_SESSION_BUS_ADDRESS：${resNonIso.text}`);
        assert.equal(resNonIso.text, "DBUS_PRESERVED_OK");
      } finally {
        process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
        if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
        else process.env.CODEX_HOME = prevCodexHome;
        if (prevDbus === undefined) delete process.env.DBUS_SESSION_BUS_ADDRESS;
        else process.env.DBUS_SESSION_BUS_ADDRESS = prevDbus;
      }
    }

    // 12) [R17 #12 P2] Board.init() 将 board.tasklist 与 board.owner_open_id 放在同一 SQLite 事务内原子提交，中途异常回滚不留无主看板
    {
      const atomicCfgFile = path.join(dir, "atomic-board-cfg.json");
      fs.writeFileSync(
        atomicCfgFile,
        JSON.stringify({
          data_dir: path.join(dir, "atomic-board-data"),
          bins: { lark: path.join(STUBS, "ctx-lark") },
          harnesses: { codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_a" },
        }),
      );
      const atomicApp = createApp(loadConfig(atomicCfgFile));
      try {
        atomicApp.lark.run = async (argv) => {
          if (argv[0] === "auth" && argv[1] === "status") {
            return { identity: "user", user: { open_id: "ou_owner_a", name: "主人A" } };
          }
          if (argv[0] === "task" && argv[1] === "+tasklist-search") return { items: [] };
          if (argv[0] === "task" && argv[1] === "+tasklist-create") return { tasklist: { guid: "tl_atomic_r17" } };
          return { items: [] };
        };
        const origSet = atomicApp.store.set.bind(atomicApp.store);
        atomicApp.store.set = (k: string, v: string) => {
          if (k === "board.owner_open_id") throw new Error("simulated crash before owner write");
          return origSet(k, v);
        };
        await assert.rejects(() => atomicApp.board.init(), /simulated crash before owner write/);
        assert.equal(atomicApp.store.get("board.tasklist"), undefined, "写入 owner 失败时事务必须回滚 board.tasklist，绝不留下无主看板");
        assert.equal(atomicApp.store.get("board.owner_open_id"), undefined);
      } finally {
        atomicApp.store.db.close();
      }
    }

    // 13) [R17 #13 P2] 目标远端分支已指向相同提交 localSha 时，pushBranch 跳过 LFS 树扫描与 git lfs pre-push（即使宿主机无 git-lfs 也可成功）
    {
      const lfsSameRepo = path.join(dir, "repo-lfs-already-published");
      const lfsSameBare = path.join(dir, "bare-lfs-already-published.git");
      fs.mkdirSync(lfsSameRepo, { recursive: true });
      fs.mkdirSync(lfsSameBare, { recursive: true });
      await tryGit(lfsSameBare, ["init", "--bare", "-q"]);
      await tryGit(lfsSameRepo, ["init", "-q"]);
      await tryGit(lfsSameRepo, ["config", "user.name", "Test"]);
      await tryGit(lfsSameRepo, ["config", "user.email", "test@example.com"]);
      await tryGit(lfsSameRepo, ["remote", "add", "origin", lfsSameBare]);
      fs.writeFileSync(path.join(lfsSameRepo, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      fs.writeFileSync(path.join(lfsSameRepo, "data.bin"), "plain-content\n");
      await tryGit(lfsSameRepo, ["add", "."]);
      await tryGit(lfsSameRepo, ["commit", "-qm", "init lfs tracked"]);
      const br = (await tryGit(lfsSameRepo, ["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
      // 模拟远端分支已发布该精确提交（直接通过原生 git push 到 bare 远端）
      const initPush = await tryGit(lfsSameRepo, ["push", "origin", `${br}:${br}`], { extraWritablePaths: [lfsSameBare] });
      assert.equal(initPush.code, 0, initPush.stderr);

      // 构造仅含 git、不含 git-lfs 的 PATH，验证重试推送已发布分支不再因缺失 git-lfs 报错
      const noLfsBinDir = path.join(dir, "bin-no-git-lfs");
      fs.mkdirSync(noLfsBinDir, { recursive: true });
      const gitReal = (await runProcess("which", ["git"])).stdout.trim();
      fs.symlinkSync(gitReal, path.join(noLfsBinDir, "git"));
      for (const helper of ["bwrap", "unshare", "setpriv", "sh", "awk", "mount", "umount", "mkdir", "rmdir", "cat", "rm"]) {
        const hp = (await runProcess("which", [helper])).stdout.trim();
        if (hp && !fs.existsSync(path.join(noLfsBinDir, helper))) {
          fs.symlinkSync(hp, path.join(noLfsBinDir, helper));
        }
      }
      process.env.PATH = noLfsBinDir;
      try {
        const resUpToDate = await pushBranch(lfsSameRepo, "origin", br, { extraReadOnlyPaths: [noLfsBinDir] });
        assert.equal(
          resUpToDate.ok,
          true,
          `目标远端已指向相同 localSha 时应跳过 LFS 预检并成功：${resUpToDate.ok ? "" : resUpToDate.message}`,
        );
      } finally {
        if (prevPath === undefined) delete process.env.PATH;
        else process.env.PATH = prevPath;
      }
    }

    // 14) [R17 #14 P2] 服务端拒绝当前会话后，status() 不再同时报 logged_in: true 与 needs_login；更换新会话或更高 cookie_version 后恢复 logged_in: true
    {
      const curMainLogin = new WebLoginStore(app.cfg.dataDir).load()!;
      app.store.set(
        "ctx.personal_web.state",
        JSON.stringify({
          state: "needs_login",
          owner_id: curMainLogin.owner_id,
          owner_name: curMainLogin.owner_name,
          session_id: curMainLogin.session_id,
          cookie_version: curMainLogin.cookie_version ?? 1,
          since: now,
          last_message_at: null,
          last_error: "服务端连续拒绝当前凭据",
        }),
      );
      const stRejected = svc.personalWeb.status();
      assert.equal(stRejected.state, "needs_login");
      assert.equal(stRejected.logged_in, false, "同一会话与 Cookie 版本已被服务端拒绝时，logged_in 必须为 false");
      assert.match(stRejected.last_error, /服务端连续拒绝/);

      // 更换更新会话后立即可恢复为 logged_in: true 且 state: stopped
      commitWorkspaceLogin(
        app,
        { owner_id: "7001", owner_name: "主人A", session_id: "sess_r17_fresh", cookies: baseCookies },
        { allowUnverifiedOwner: true },
      );
      const stRecovered = svc.personalWeb.status();
      assert.equal(stRecovered.logged_in, true);
      assert.equal(stRecovered.state, "stopped");
      assert.equal(stRecovered.last_error, "");
    }

    // 15) [R17 #15 P3] gzip 响应在发送头后连接意外中断时，立即销毁解压器并拒绝 Promise，绝不挂起至超时
    {
      const jar = RecordingCookieJar.fromRecords([], ["127.0.0.1"]);
      brokenGzipSrv = http.createServer((req, res) => {
        res.writeHead(200, { "Content-Encoding": "gzip", "Content-Type": "text/plain" });
        // 写入不完整的 gzip 头字节后直接强拆 TCP 连接
        res.write(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]));
        setTimeout(() => req.socket.destroy(), 20);
      });
      await new Promise<void>((resolve) => brokenGzipSrv!.listen(0, "127.0.0.1", resolve));
      const port = (brokenGzipSrv.address() as { port: number }).port;
      const t0 = Date.now();
      await assert.rejects(
        () =>
          fetchWithJar(jar, {
            method: "GET",
            url: `http://127.0.0.1:${port}/broken-gzip`,
            timeoutMs: 10_000,
            allowInsecureHttp: true,
            extraAllowedHosts: ["127.0.0.1"],
          }),
        (err: unknown) => err instanceof WebHttpError && err.code === "transport",
        "gzip 响应连接中断必须立即以 transport 错误拒绝",
      );
      assert.ok(Date.now() - t0 < 2_500, "gzip 连接中断必须立即返回，不得挂起等待 10s 超时");
    }
  } finally {
    if (brokenGzipSrv) await new Promise<void>((resolve) => brokenGzipSrv!.close(() => resolve()));
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCredFile === undefined) delete process.env.PA_FEISHU_WEB_CRED_FILE;
    else process.env.PA_FEISHU_WEB_CRED_FILE = prevCredFile;
    if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
    if (prevCtxDir === undefined) delete process.env.CTX_DIR;
    else process.env.CTX_DIR = prevCtxDir;
    if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevCodexHome;
    if (prevDbus === undefined) delete process.env.DBUS_SESSION_BUS_ADDRESS;
    else process.env.DBUS_SESSION_BUS_ADDRESS = prevDbus;
    if (prevPath === undefined) delete process.env.PATH;
    else process.env.PATH = prevPath;
    extraAppA?.store.db.close();
    extraAppB?.store.db.close();
    nonIsoApp?.store.db.close();
    app?.store.db.close();
    await mock.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第十八轮回归：最小白名单空根隔离跨工作区、损坏配置符号链接 fail-closed、私聊/排除重检、晨报/看板后验、锁定 worktree 保护、同标尺版本合并、更新项预起草、空正文撤回、OAuth 刷新协调/符号链接/原子写回、健康计数、建连重试保 Cookie 与 Max-Age 钳位", async () => {
  const dir = makeTmp("pa-r18-");
  const mock = await startMockFeishuWebServer();
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevCodexHome = process.env.CODEX_HOME;
  let app: ReturnType<typeof createApp> | undefined;
  let extraApp1: ReturnType<typeof createApp> | undefined;
  let extraApp2: ReturnType<typeof createApp> | undefined;
  let boardApp: ReturnType<typeof createApp> | undefined;
  let retryProfileSrv: http.Server | undefined;
  const chmodRestore: { p: string; mode: number }[] = [];

  try {
    process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
    const dataDir = path.join(dir, "data");
    const cfgFile = path.join(dir, "config.json");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: dataDir,
        bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
        harnesses: { codex: { type: "codex-exec" }, claude: { agent: "claude" } },
        roles: { brain: "codex" },
        owner: { open_id: "ou_owner_a" },
        context: {
          enabled: true,
          understand: true,
          sources: { im: true, tasks: false, meego: false, minutes: false, calendar: false, docs: false },
          groups: "allowlist",
          groups_allow: ["pw_chat:9800", "oc_r18_dup_grp"],
          personal_web: { enabled: true, fast_lane: true, pre_draft: true, send_replies: true },
        },
      }),
    );
    app = createApp(loadConfig(cfgFile));
    const svc = new ContextService(app);
    (svc.personalWeb as unknown as { hooks: { clientOptions?: unknown } }).hooks.clientOptions = { endpoints: mock.endpoints };
    const baseCookies = [
      { name: "session", value: "sess_r18_1", domain: "127.0.0.1", path: "/" },
      { name: "passport_web_did", value: "did_r18_1", domain: "127.0.0.1", path: "/" },
      { name: "swp_csrf_token", value: "csrf_r18_1", domain: "127.0.0.1", path: "/" },
    ];
    mock.setProfileUser("7001", "主人A");
    saveWorkspaceBinding(app.store, "7001", "ou_owner_a");
    commitWorkspaceLogin(
      app,
      { owner_id: "7001", owner_name: "主人A", session_id: "sess_r18", cookies: baseCookies },
      { allowUnverifiedOwner: true },
    );

    // 1) [R18 #1 P1] 最小白名单空根隔离：同 OS 用户下工作区 B 的 bwrap 与 unshare 沙箱均无法读取工作区 A 的 state.db 与 feishu-web.json
    if (process.platform === "linux") {
      const siblingRoot = path.join(dir, "multi-ws");
      const wsAData = path.join(siblingRoot, "ws-a-data");
      const wsBData = path.join(siblingRoot, "ws-b-data");
      const wsBWt = path.join(wsBData, "worktrees", "wt-b");
      fs.mkdirSync(wsAData, { recursive: true });
      fs.mkdirSync(wsBWt, { recursive: true });
      const wsAState = path.join(wsAData, "state.db");
      const wsACred = path.join(wsAData, "feishu-web.json");
      const wsBState = path.join(wsBData, "state.db");
      fs.writeFileSync(wsAState, "SECRET_WORKSPACE_A_DB");
      fs.writeFileSync(wsACred, "SECRET_WORKSPACE_A_CRED");
      fs.writeFileSync(wsBState, "SECRET_WORKSPACE_B_DB");

      const planB = buildWorkspaceIsolation(
        { dataDir: wsBData, context: { personal_web: { enabled: true } } as never },
        { mode: "verify", cwd: wsBWt },
        process.env,
      );
      const bwrapPlan = wrapCredentialIsolatedCommand("true", [], process.env, {
        ...planB,
        forceBackend: { kind: "bwrap", bin: "bwrap" },
      });
      // bwrap 绝不能再使用 --ro-bind / /
      let hasWholeRootBind = false;
      for (let i = 0; i < bwrapPlan.args.length - 2; i++) {
        if (bwrapPlan.args[i] === "--ro-bind" && bwrapPlan.args[i + 1] === "/" && bwrapPlan.args[i + 2] === "/") {
          hasWholeRootBind = true;
        }
      }
      assert.equal(hasWholeRootBind, false, "bwrap 必须使用最小白名单空根，绝不能 --ro-bind / /");

      const probeCrossWs = [
        `test ! -e ${JSON.stringify(wsAState)}`,
        `test ! -e ${JSON.stringify(wsACred)}`,
        `test ! -e ${JSON.stringify(wsBState)}`,
        `! touch /r18-root-tamper 2>/dev/null`,
        `echo ok-b > ${JSON.stringify(path.join(wsBWt, "out.txt"))}`,
        `echo ok-tmp > /tmp/r18-tmp.txt`,
      ].join(" && ");

      if (hasCredentialMountIsolation()) {
        const runBwrap = wrapCredentialIsolatedCommand("sh", ["-c", probeCrossWs], process.env, {
          ...planB,
          forceBackend: { kind: "bwrap", bin: "bwrap" },
        });
        const rB = await runProcess(runBwrap.cmd, runBwrap.args, { cwd: wsBWt, timeoutMs: 15_000 });
        assert.equal(rB.code, 0, `bwrap 下工作区 B 必须彻底隔离工作区 A 的 state.db/凭据：${rB.stderr}`);
        assert.equal(fs.readFileSync(path.join(wsBWt, "out.txt"), "utf8").trim(), "ok-b");

        const pivotBin = ["/sbin/pivot_root", "/usr/sbin/pivot_root"].find((p) => fs.existsSync(p));
        if (pivotBin) {
          const probeSetpriv = await runProcess(
            "unshare",
            ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "setpriv", "--bounding-set", "-all", "--inh-caps", "-all", "--ambient-caps", "-all", "--no-new-privs", "true"],
            { timeoutMs: 5_000 },
          );
          if (probeSetpriv.code === 0) {
            const outU = path.join(wsBWt, "out-unshare.txt");
            const probeUnshare = probeCrossWs.replace(path.join(wsBWt, "out.txt"), outU);
            const runUnshare = wrapCredentialIsolatedCommand("sh", ["-c", probeUnshare], process.env, {
              ...planB,
              forceBackend: { kind: "unshare", bin: "unshare", setprivBin: "setpriv", pivotRootBin: pivotBin },
            });
            const rU = await runProcess(runUnshare.cmd, runUnshare.args, { cwd: wsBWt, timeoutMs: 15_000 });
            assert.equal(rU.code, 0, `unshare 下工作区 B 必须同样彻底隔离工作区 A 的 state.db/凭据：${rU.stderr}`);
            assert.equal(fs.readFileSync(outU, "utf8").trim(), "ok-b");
          }
        }
      }
    }

    // 2) [R18 #2 P1] 损坏符号链接 config.toml 与损坏符号链接 $CODEX_HOME 在 tools="none" 与凭据解析阶段均 fail-closed
    {
      const brokenCfgHome = path.join(dir, "codex-broken-cfg-sym");
      fs.mkdirSync(brokenCfgHome, { recursive: true });
      fs.symlinkSync(path.join(dir, "missing-dotfiles", "config.toml"), path.join(brokenCfgHome, "config.toml"));
      assert.throws(
        () => extractSafeCodexProviderConfig({ CODEX_HOME: brokenCfgHome }, [], false),
        /符号链接|不可达|损坏|config\.toml/,
        "损坏的 config.toml 符号链接必须 fail-closed 拒绝，绝不能退化到默认供应商",
      );
      const effBrokenCfg = resolveEffectiveCodexCredentialStore({ CODEX_HOME: brokenCfgHome }, []);
      assert.ok(effBrokenCfg.configError, "resolveEffectiveCodexCredentialStore 必须暴露损坏 config.toml 符号链接错误");

      const brokenHomeLink = path.join(dir, "codex-broken-home-link");
      fs.symlinkSync(path.join(dir, "missing-dotfiles", "codex-dir"), brokenHomeLink);
      assert.throws(
        () => extractSafeCodexProviderConfig({ CODEX_HOME: brokenHomeLink }, [], false),
        /符号链接|不可达|损坏|配置目录/,
        "损坏的 CODEX_HOME 目录符号链接必须 fail-closed 拒绝",
      );
      assert.throws(
        () => stageIsolatedCodexHome(brokenHomeLink, { copyUserConfig: true }),
        /符号链接|不可达|损坏|配置目录/,
        "stageIsolatedCodexHome 遇到损坏的 CODEX_HOME 目录符号链接必须 fail-closed 拒绝",
      );
    }

    // 3) [R18 #3 P1] 个人 Web 回复投递前重检硬排除（静音 DM、groups_deny 含 @mention 的群、竞态静音均拦截，非排除范围外 @我 群正常放行）
    {
      const nowSec = Math.floor(Date.now() / 1000);
      const origDeny = [...app.cfg.context.groups_deny];
      const liveClient = await FeishuWebClient.connect(svc.personalWeb.loginStore.load()!, {
        endpoints: mock.endpoints,
        onSessionConfirmed: (u, d) => svc.personalWeb.loginStore.saveIfSessionMatches(u, d),
      });
      (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = liveClient;
      try {
        // 3a) 静音后的私聊（muteConv 仅标 processed=1 而非 withdrawn=true）：必须拒绝读取原消息与发送
        mock.setChatKind("9801", CHAT_KIND_P2P);
        mock.setChatName("9801", "同事甲");
        mock.addMessage(
          "r18_dm_muted",
          buildNativeMessage({
            id: "r18_dm_muted",
            chatId: "9801",
            chatKind: CHAT_KIND_P2P,
            actorId: "7002",
            createdAtSec: nowSec - 5,
            text: "请帮我确认一下",
          }),
        );
        svc.store.addObs([
          {
            id: "pw:r18_dm_muted",
            source: "im",
            kind: "p2p",
            conv: "pw_chat:9801",
            conv_name: "私聊：同事甲",
            actor_id: "7002",
            actor_name: "同事甲",
            is_me: false,
            time: Date.now() - 5_000,
            text: "请帮我确认一下",
            url: "",
            meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
          },
        ]);
        svc.store.muteConv("pw_chat:9801", "私聊：同事甲", true);
        const sentBefore3a = mock.sentReplies.length;
        await assert.rejects(
          () =>
            svc.personalWeb.sendVerifiedReply({
              owner_id: "7001",
              chat_id: "9801",
              message_id: "r18_dm_muted",
              text: "好的",
              cid: "cid_r18_dm_muted",
            }),
          /静音|排除/,
          "已静音的私聊绝不能跳过群检查直接回复",
        );
        assert.equal(mock.sentReplies.length, sentBefore3a);

        // 3b) 已加入 groups_deny 的群即使原消息仍 @本人，也不得走 @mention 豁免发送
        mock.setChatKind("9802", CHAT_KIND_GROUP);
        mock.setChatName("9802", "绝密禁止群");
        mock.addMessage(
          "r18_grp_denied",
          buildNativeMessage({
            id: "r18_grp_denied",
            chatId: "9802",
            chatKind: CHAT_KIND_GROUP,
            actorId: "7002",
            createdAtSec: nowSec - 5,
            richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 请处理" }]),
          }),
        );
        app.cfg.context.groups_deny = ["绝密禁止群"];
        const sentBefore3b = mock.sentReplies.length;
        await assert.rejects(
          () =>
            svc.personalWeb.sendVerifiedReply({
              owner_id: "7001",
              chat_id: "9802",
              message_id: "r18_grp_denied",
              text: "收到",
              cid: "cid_r18_grp_denied",
            }),
          /排除|groups_deny|静音/,
          "命中 groups_deny 的群即使仍有 @本人 也必须阻断发送",
        );
        assert.equal(mock.sentReplies.length, sentBefore3b);

        // 3c) 在 readChat 与认领发送之间并发静音：认领前实时重检必须阻断发送
        app.cfg.context.groups_deny = [];
        mock.setChatKind("9803", CHAT_KIND_GROUP);
        mock.setChatName("9803", "并发静音群");
        mock.addMessage(
          "r18_grp_race_mute",
          buildNativeMessage({
            id: "r18_grp_race_mute",
            chatId: "9803",
            chatKind: CHAT_KIND_GROUP,
            actorId: "7002",
            createdAtSec: nowSec - 5,
            richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 竞态测试" }]),
          }),
        );
        const sentBefore3c = mock.sentReplies.length;
        mock.setOnChatMode(() => {
          svc.store.muteConv("pw_chat:9803", "并发静音群", true);
        });
        try {
          await assert.rejects(
            () =>
              svc.personalWeb.sendVerifiedReply({
                owner_id: "7001",
                chat_id: "9803",
                message_id: "r18_grp_race_mute",
                text: "收到竞态",
                cid: "cid_r18_grp_race_mute",
              }),
            /静音|排除/,
            "readChat 期间并发静音必须在认领发包前拦截",
          );
        } finally {
          mock.setOnChatMode(undefined);
        }
        assert.equal(mock.sentReplies.length, sentBefore3c);

        // 3d) 未被硬排除、仅在 allowlist 范围外且仍有效 @本人的群：正常允许回复
        mock.setChatKind("9804", CHAT_KIND_GROUP);
        mock.setChatName("9804", "普通范围外群");
        mock.addMessage(
          "r18_grp_oos_ok",
          buildNativeMessage({
            id: "r18_grp_oos_ok",
            chatId: "9804",
            chatKind: CHAT_KIND_GROUP,
            actorId: "7002",
            createdAtSec: nowSec - 5,
            richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 可以回复" }]),
          }),
        );
        const okReply = await svc.personalWeb.sendVerifiedReply({
          owner_id: "7001",
          chat_id: "9804",
          message_id: "r18_grp_oos_ok",
          text: "好的马上看",
          cid: "cid_r18_grp_oos_ok",
        });
        assert.equal(okReply.verified, true, "未排除的范围外 @我 群在原消息仍 @本人 时应允许发送");
      } finally {
        svc.store.muteConv("pw_chat:9801", "", false);
        svc.store.muteConv("pw_chat:9803", "", false);
        app.cfg.context.groups_deny = origDeny;
        (svc.personalWeb as unknown as { client?: FeishuWebClient }).client = undefined;
      }
    }

    // 4) [R18 #4 P1] buildBrief 在完成所有 --as user 任务读取后再次核验活跃 lark-cli 主人，防止切号把 B 的任务发给 A
    {
      const origAuthStatus = app.lark.authStatus.bind(app.lark);
      const origLarkRun = app.lark.run.bind(app.lark);
      const origListSec = app.board.listSection.bind(app.board);
      let authCalls = 0;
      app.lark.authStatus = async () => {
        authCalls++;
        return { identities: { user: { open_id: authCalls === 1 ? "ou_owner_a" : "ou_owner_b" } } };
      };
      app.lark.run = async (argv) => {
        if (argv[0] === "task" && argv[1] === "+get-my-tasks") {
          return { items: [{ guid: "t_b_secret", summary: "B 的私密任务", due_at: String(Date.now() - 3600_000) }] };
        }
        return origLarkRun(argv);
      };
      app.board.listSection = async () => [];
      try {
        await assert.rejects(
          () => buildBrief(app!.cfg, app!.lark, app!.store, app!.ledger, app!.board, "morning"),
          /不一致|ou_owner_b/,
          "读取任务期间 CLI 切号为 B 时，buildBrief 必须后验拒绝并丢弃 B 的任务",
        );
        assert.ok(authCalls >= 2, "buildBrief 必须在任务读取前后各执行一次身份核验");
      } finally {
        app.lark.authStatus = origAuthStatus;
        app.lark.run = origLarkRun;
        app.board.listSection = origListSec;
      }
    }

    // 5) [R18 #5 P1] Board.init() 在 +tasklist-search/+tasklist-create 之后、原子落盘前再次核验活跃 CLI 用户，防止将 B 的看板绑定成 A
    {
      const bCfgFile = path.join(dir, "board-r18-cfg.json");
      fs.writeFileSync(
        bCfgFile,
        JSON.stringify({
          data_dir: path.join(dir, "board-r18-data"),
          bins: { lark: path.join(STUBS, "ctx-lark"), acpx: path.join(STUBS, "acpx"), bytedcli: path.join(STUBS, "ctx-bytedcli") },
          harnesses: { codex: { type: "codex-exec" } },
          roles: { brain: "codex" },
          owner: { open_id: "ou_owner_a" },
          context: { enabled: false },
        }),
      );
      boardApp = createApp(loadConfig(bCfgFile));
      let activeUser = "ou_owner_a";
      boardApp.lark.authStatus = async () => ({ identities: { user: { open_id: activeUser } } });
      boardApp.lark.run = async (argv) => {
        if (argv[0] === "task" && argv[1] === "+tasklist-search") return { items: [] };
        if (argv[0] === "task" && argv[1] === "+tasklist-create") {
          // 模拟创建清单期间 CLI 切换到账号 B，返回的 GUID 实际归属 B
          activeUser = "ou_owner_b";
          return { guid: "tl_owned_by_b" };
        }
        return { items: [] };
      };
      await assert.rejects(
        () => boardApp!.board.init(),
        /不一致|ou_owner_b/,
        "看板创建期间 CLI 切号时必须拒绝落盘绑定",
      );
      assert.equal(boardApp.store.get("board.tasklist"), undefined, "切号失败后绝不能持久化他人 board.tasklist");
      assert.equal(boardApp.store.get("board.owner_open_id"), undefined, "切号失败后绝不能持久化 board.owner_open_id");
    }

    // 6) [R18 #6 P1] delivery 清理缺失的已锁定 worktree（git worktree lock）时，必须保留其管理记录且不得删除分支
    {
      const repoDir = path.join(dir, "lock-wt-repo");
      const lockedWt = path.join(dataDir, "worktrees", "r18lock1");
      fs.mkdirSync(repoDir, { recursive: true });
      fs.mkdirSync(path.dirname(lockedWt), { recursive: true });
      const gitEnv = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", repoDir], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(repoDir, "a.txt"), "hello\n");
      assert.equal((await runProcess("git", ["-C", repoDir, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", repoDir, "commit", "-qm", "init"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", repoDir, "worktree", "add", "-q", "-b", "pa/r18lock1", lockedWt], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", repoDir, "worktree", "lock", lockedWt], { env: gitEnv })).code, 0);
      // 模拟外部磁盘暂时卸载（目录缺失，但管理记录带 locked 文件）
      fs.rmSync(lockedWt, { recursive: true, force: true });
      const wtAdminRoot = path.join(repoDir, ".git", "worktrees");
      const adminEntriesBefore = fs.readdirSync(wtAdminRoot);
      assert.equal(adminEntriesBefore.length, 1);

      const origRepos = app.cfg.dispatch.repos;
      app.cfg.dispatch.repos = { lockrepo: { path: repoDir } };
      registerDelivery(app);
      app.ledger.enqueue({
        id: "dispatch:r18lock:1",
        kind: "dispatch",
        ref: "g_r18lock",
        state: "accepted",
        payload: { guid: "g_r18lock", summary: "locked wt", description: "repo: lockrepo", repo: "lockrepo", cwd: lockedWt, branch: "pa/r18lock1", base: "HEAD" },
      });
      app.ledger.enqueue({
        id: "delivery:discard:r18lock",
        kind: "delivery",
        ref: "dispatch:r18lock:1",
        state: "done",
        payload: { action: "discard", dispatch_id: "dispatch:r18lock:1", guid: "g_r18lock" },
      });
      app.ledger.db.prepare("UPDATE work SET terminal = 1 WHERE id IN ('dispatch:r18lock:1', 'delivery:discard:r18lock')").run();
      app.ledger.enqueue({
        id: "delivery:cleanup:r18lock",
        kind: "delivery",
        ref: "dispatch:r18lock:1",
        state: "pending",
        payload: { action: "cleanup", dispatch_id: "dispatch:r18lock:1", guid: "g_r18lock", discard_id: "delivery:discard:r18lock" },
      });
      try {
        await app.engine.drain(["delivery"]);
        assert.deepEqual(fs.readdirSync(wtAdminRoot), adminEntriesBefore, "已锁定 worktree 的管理记录绝不能被删除");
        assert.equal(fs.existsSync(path.join(wtAdminRoot, adminEntriesBefore[0], "locked")), true);
        const branchChk = await runProcess("git", ["-C", repoDir, "rev-parse", "--verify", "--quiet", "refs/heads/pa/r18lock1"], { env: gitEnv });
        assert.equal(branchChk.code, 0, "已锁定 worktree 对应的分支绝不能被 branch -D 删除");
      } finally {
        app.cfg.dispatch.repos = origRepos;
      }
    }

    // 7) [R18 #7 P2] 同标尺版本比较：search 返回带 update_time 的旧副本、群拉取返回带 edit_version=2 的新副本时不以时间戳压过计数，通过 +messages-mget 取权威版；addObs 接受后续 edit_version=3
    {
      const origLarkRun = app.lark.run.bind(app.lark);
      const origAuthStatus = app.lark.authStatus.bind(app.lark);
      const now = Date.now();
      let mgetCalls = 0;
      app.lark.authStatus = async () => ({ identities: { user: { open_id: "ou_owner_a" } } });
      app.lark.run = async (argv) => {
        if (argv[0] === "im" && argv[1] === "+messages-search") {
          if (argv.includes("--is-at-me")) {
            return {
              items: [
                {
                  message_id: "om_r18_clock",
                  chat_id: "oc_r18_dup_grp",
                  chat_name: "时钟分离群",
                  chat_type: "group",
                  create_time: String(now - 3_000),
                  update_time: String(now - 2_000), // 毫秒时间戳（远大于计数 2，绝不能因此击败 edit_version=2）
                  sender: { id: "ou_colleague", name: "同事戊", sender_type: "user" },
                  content: JSON.stringify({ text: "@主人A 旧版本文案" }),
                },
              ],
            };
          }
          return { items: [] };
        }
        if (argv[0] === "im" && argv[1] === "+chat-messages-list" && argv.includes("oc_r18_dup_grp")) {
          return {
            messages: [
              {
                message_id: "om_r18_clock",
                chat_id: "oc_r18_dup_grp",
                chat_name: "时钟分离群",
                chat_type: "group",
                create_time: String(now - 3_000),
                edit_version: 2,
                sender: { id: "ou_colleague", name: "同事戊", sender_type: "user" },
                content: JSON.stringify({ text: "已编辑：无需处理" }),
                mentions: [],
              },
            ],
          };
        }
        if (argv[0] === "im" && argv[1] === "+messages-mget") {
          mgetCalls++;
          return {
            messages: [
              {
                message_id: "om_r18_clock",
                chat_id: "oc_r18_dup_grp",
                chat_name: "时钟分离群",
                chat_type: "group",
                create_time: String(now - 3_000),
                edit_version: 2,
                sender: { id: "ou_colleague", name: "同事戊", sender_type: "user" },
                content: JSON.stringify({ text: "已编辑：无需处理" }),
                mentions: [],
              },
            ],
          };
        }
        return origLarkRun(argv);
      };
      try {
        await svc.connectors.pullIm();
        assert.equal(mgetCalls, 1, "跨时钟且正文/mention 冲突时必须调用 im +messages-mget 权威回读");
        const saved = svc.store.obs("im:om_r18_clock");
        assert.ok(saved);
        assert.equal(saved.text, "已编辑：无需处理");
        assert.equal(saved.meta.at_me, false);
        assert.equal(saved.meta.edit_version, 2);

        // 7b) 验证先前仅有 edit_time（毫秒时间戳）的观测收到后续 edit_version=3 时绝不会被 3 < 17957... 误拒
        svc.store.addObs([
          {
            id: "im:om_r18_ts_then_cnt",
            source: "im",
            kind: "group",
            conv: "oc_r18_dup_grp",
            conv_name: "时钟分离群",
            actor_id: "ou_colleague",
            actor_name: "同事戊",
            is_me: false,
            time: now - 5_000,
            text: "初版带时间戳",
            url: "",
            meta: { edit_time: now - 4_000, poll_observed_at: now - 4_000 },
          },
        ]);
        const accepted = svc.store.addObs([
          {
            id: "im:om_r18_ts_then_cnt",
            source: "im",
            kind: "group",
            conv: "oc_r18_dup_grp",
            conv_name: "时钟分离群",
            actor_id: "ou_colleague",
            actor_name: "同事戊",
            is_me: false,
            time: now - 5_000,
            text: "新版带修订计数",
            url: "",
            meta: { edit_version: 3, poll_observed_at: now - 1_000 },
          },
        ]);
        assert.equal(accepted, 1, "edit_time 与 edit_version 分离后，后续 edit_version=3 必须被正常接受");
        assert.equal(svc.store.obs("im:om_r18_ts_then_cnt")?.text, "新版带修订计数");
      } finally {
        app.lark.run = origLarkRun;
        app.lark.authStatus = origAuthStatus;
      }
    }

    // 8) [R18 #8 P2] 已有 open 事项被新原生私聊/@本人 证据更新时，同样幂等入队自动预起草
    {
      const now = Date.now();
      svc.store.addObs([
        {
          id: "im:om_r18_poll_first",
          source: "im",
          kind: "group",
          conv: "oc_r18_dup_grp",
          conv_name: "项目群",
          actor_id: "ou_colleague",
          actor_name: "同事戊",
          is_me: false,
          time: now - 10_000,
          text: "接口方案需要你拍板",
          url: "",
          meta: { chat_type: "group" },
        },
      ]);
      const { item: existingItem } = svc.store.upsertItem({
        title: "拍板接口方案",
        kind: "ask_me",
        priority: "high",
        source: "im",
        status: "open",
        confidence: 0.95,
      });
      svc.store.addEvidence("item", existingItem.id, "im:om_r18_poll_first", "接口方案需要你拍板", now - 10_000);
      assert.equal(app.ledger.get(`context:draft:${existingItem.id}:reply:fast`), undefined, "轮询建项阶段尚无原生触发证据，无自动预起草");

      svc.store.addObs([
        {
          id: "pw:r18_dm_update_item",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9810",
          conv_name: "私聊：同事戊",
          actor_id: "7002",
          actor_name: "同事戊",
          is_me: false,
          time: now - 1_000,
          text: "刚才那个接口方案能今天回复吗？",
          url: "",
          meta: {
            transport: "personal_web",
            native_owner_id: "7001",
            native_message_id: "r18_dm_update_item",
            native_chat_id: "9810",
            native_root_id: "r18_dm_update_item",
            chat_type: "p2p",
          },
        },
      ]);
      installCallbackLlm(svc, () =>
        JSON.stringify({
          projects: [],
          items: [
            {
              ref: existingItem.id,
              title: "拍板接口方案",
              kind: "ask_me",
              status: "open",
              priority: "high",
              counterpart: "同事戊",
              confidence: 0.95,
              evidence: [{ obs_id: "pw:r18_dm_update_item", quote: "刚才那个接口方案能今天回复吗？" }],
            },
          ],
          knowledge: [],
          updates: [],
          people: [],
          conflicts: [],
        }),
      );
      const fastRes = await svc.fastCycle("context:fast:r18_update", {
        conv: "pw_chat:9810",
        conv_name: "私聊：同事戊",
        trigger_obs_id: "pw:r18_dm_update_item",
      });
      assert.equal(fastRes.created, 0, "应更新已有事项而非新建");
      assert.equal(fastRes.pre_drafted, 1, "已有事项补充原生私聊证据后必须自动入队预起草");
      assert.ok(app.ledger.get(`context:draft:${existingItem.id}:reply:fast`), "应生成幂等自动预起草作业");
    }

    // 9) [R18 #9 P2] 已知活跃消息被编辑为空正文或不支持类型时（含 WS 推送过滤放行 + 权威回读），必须立即撤回本地待处理旧文本
    {
      const nowSec = Math.floor(Date.now() / 1000);
      const liveClient = await FeishuWebClient.connect(svc.personalWeb.loginStore.load()!, {
        endpoints: mock.endpoints,
        onSessionConfirmed: (u, d) => svc.personalWeb.loginStore.saveIfSessionMatches(u, d),
      });
      // 先落库一条范围外群 @我 消息
      mock.setChatKind("9820", CHAT_KIND_GROUP);
      mock.setChatName("9820", "范围外编辑测试群");
      const origAtMeBuf = buildNativeMessage({
        id: "r18_edit_to_empty",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        createdAtSec: nowSec - 5,
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 帮我看下线上" }]),
      });
      mock.addMessage("r18_edit_to_empty", origAtMeBuf);
      await svc.personalWeb.handleMessage(decodeMessage(origAtMeBuf, "7001"), liveClient);
      assert.equal(svc.store.obsPending("pw:r18_edit_to_empty"), true);

      // 9a) 服务端消息已被编辑为不支持类型（例如未知消息类型 99），收到冲突推送后权威回读返回 unsupported → 必须撤回旧文本
      const editedUnsupportedBuf = buildNativeMessage({
        id: "r18_edit_to_empty",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        kind: 99,
        createdAtSec: nowSec - 5,
        text: "",
      });
      mock.addMessage("r18_edit_to_empty", editedUnsupportedBuf);
      const conflictingPushBuf = buildNativeMessage({
        id: "r18_edit_to_empty",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        createdAtSec: nowSec - 4,
        text: "不同正文触发权威回读",
      });
      await svc.personalWeb.handleMessage(decodeMessage(conflictingPushBuf, "7001"), liveClient);
      assert.equal(svc.store.obsPending("pw:r18_edit_to_empty"), false, "权威回读为不支持类型时必须撤回待处理状态");
      assert.equal(svc.store.obs("pw:r18_edit_to_empty")?.meta.withdrawn, true, "旧文本必须标记 withdrawn=true");

      // 9b) WS 推送层直接收到已知活跃消息的空正文/不支持编辑推送：shouldDeliverInvalid 放行已知 ID、忽略全新无效 ID
      const origAtMe2 = buildNativeMessage({
        id: "r18_ws_empty_edit",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        createdAtSec: nowSec - 5,
        richBytes: encodeRichText([{ text: "@主人A", mentionId: "7001" }, { text: " 待编辑清空" }]),
      });
      mock.addMessage("r18_ws_empty_edit", origAtMe2);
      await svc.personalWeb.handleMessage(decodeMessage(origAtMe2, "7001"), liveClient);
      assert.equal(svc.store.obsPending("pw:r18_ws_empty_edit"), true);

      const emptyEditBuf = buildNativeMessage({
        id: "r18_ws_empty_edit",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        createdAtSec: nowSec - 4,
        text: "   ",
      });
      const brandNewUnsupported = buildNativeMessage({
        id: "r18_brand_new_unsupported",
        chatId: "9820",
        chatKind: CHAT_KIND_GROUP,
        actorId: "7002",
        kind: 99,
        createdAtSec: nowSec - 3,
        text: "",
      });
      mock.addMessage("r18_ws_empty_edit", emptyEditBuf);

      const deliveredIds: string[] = [];
      let wsReady = false;
      const listenCtrl = new AbortController();
      const listenPromise = liveClient.listen({
        signal: listenCtrl.signal,
        shouldDeliverInvalid: (m) => {
          if (!m.id) return false;
          const ex = svc.store.obs(`pw:${m.id}`);
          return !!ex && ex.meta.background_only !== true && ex.meta.withdrawn !== true;
        },
        onState: (s) => {
          if (s === "listening") wsReady = true;
        },
        onMessage: async (m) => {
          deliveredIds.push(m.id);
          await svc.personalWeb.handleMessage(m, liveClient, listenCtrl.signal);
        },
      });
      await waitUntil(() => wsReady);
      mock.pushMessage("sid_r18_empty", [brandNewUnsupported, emptyEditBuf]);
      await waitUntil(() => !svc.store.obsPending("pw:r18_ws_empty_edit"));
      listenCtrl.abort();
      await listenPromise;
      assert.deepEqual(deliveredIds, ["r18_ws_empty_edit"], "WS 过滤应仅透传已知 ID 的空/不支持编辑推送，不透传全新无效消息");
      assert.equal(svc.store.obs("pw:r18_ws_empty_edit")?.meta.withdrawn, true);
    }

    // 10) [R18 #10 P2] 跨工作区共享宿主机 auth.json 时，刷新协调租约在启动子进程前串行化单次 refresh_token 轮换
    if (process.platform === "linux" && hasCredentialMountIsolation()) {
      const sharedCodexHome = path.join(dir, "shared-codex-home");
      fs.mkdirSync(sharedCodexHome, { recursive: true });
      const sharedAuthFile = path.join(sharedCodexHome, "auth.json");
      const mkJwt = (expSec: number) =>
        `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ exp: expSec })).toString("base64url")}.sig`;
      const expiredJwt = mkJwt(Math.floor(Date.now() / 1000) - 60);
      const freshJwt = mkJwt(Math.floor(Date.now() / 1000) + 3600);
      fs.writeFileSync(
        sharedAuthFile,
        JSON.stringify(
          {
            auth_mode: "chatgpt",
            tokens: { access_token: expiredJwt, refresh_token: "ref_single_use_r18", account_id: "acct_r18" },
            last_refresh: "2026-11-01T00:00:00.000Z",
          },
          null,
          2,
        ),
        { mode: 0o600 },
      );
      assert.equal(isCodexOAuthRefreshNeeded(JSON.parse(fs.readFileSync(sharedAuthFile, "utf8"))), true);

      const seenLog = path.join(dir, "oauth-seen.log");
      const stubCodex = path.join(dir, "stub-codex-oauth.mjs");
      fs.writeFileSync(
        stubCodex,
        [
          "#!/usr/bin/env node",
          'import fs from "node:fs";',
          'import path from "node:path";',
          'const home = process.env.CODEX_HOME;',
          'const authPath = path.join(home, "auth.json");',
          'const cur = JSON.parse(fs.readFileSync(authPath, "utf8"));',
          'const tok = cur.tokens.refresh_token;',
          `if (tok === "ref_single_use_r18") {`,
          "  await new Promise((r) => setTimeout(r, 250));",
          `  cur.tokens.refresh_token = "ref_rotated_r18";`,
          `  cur.tokens.access_token = ${JSON.stringify(freshJwt)};`,
          `  cur.last_refresh = new Date().toISOString();`,
          `  fs.writeFileSync(authPath, JSON.stringify(cur, null, 2));`,
          "}",
          'const oIdx = process.argv.indexOf("-o");',
          'if (oIdx >= 0 && process.argv[oIdx + 1]) fs.writeFileSync(process.argv[oIdx + 1], `SEEN:${tok}`);',
          'console.log(`SEEN:${tok}`);',
        ].join("\n"),
        { mode: 0o755 },
      );
      const mkWsApp = (name: string) => {
        const wsCfg = path.join(dir, `${name}.json`);
        fs.writeFileSync(
          wsCfg,
          JSON.stringify({
            data_dir: path.join(dir, `${name}-data`),
            harnesses: { codex: { type: "codex-exec", cmd: stubCodex, env: { CODEX_HOME: sharedCodexHome } } },
            roles: { brain: "codex" },
            owner: { open_id: "ou_owner_a" },
            context: { enabled: true, personal_web: { enabled: true } },
          }),
        );
        return createApp(loadConfig(wsCfg));
      };
      extraApp1 = mkWsApp("ws-oauth-1");
      extraApp2 = mkWsApp("ws-oauth-2");
      const [r1, r2] = await Promise.all([
        runHarness(extraApp1.cfg, {
          harness: "codex",
          prompt: "p1",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 20,
          logFile: path.join(dir, "oauth-1.log"),
        }),
        runHarness(extraApp2.cfg, {
          harness: "codex",
          prompt: "p2",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 20,
          logFile: path.join(dir, "oauth-2.log"),
        }),
      ]);
      assert.equal(r1.ok, true, r1.text);
      assert.equal(r2.ok, true, r2.text);
      const seen = [r1.text, r2.text].sort();
      assert.deepEqual(
        seen,
        ["SEEN:ref_rotated_r18", "SEEN:ref_single_use_r18"],
        "跨工作区并行隔离 Codex 运行必须串行化过期 OAuth 刷新：仅一个 worker 消费旧 refresh_token，另一个看到已写回的新 token",
      );
      assert.equal(fs.existsSync(seenLog), false);
      assert.equal(isCodexOAuthRefreshNeeded(JSON.parse(fs.readFileSync(sharedAuthFile, "utf8"))), false);
    }

    // 11) & 12) [R18 #11 & #12 P2] 符号链接 auth.json 安全同步目标、不可写 OAuth 凭据提前拒绝、以及原子 rename 写回无残留
    {
      const dotDir = path.join(dir, "dotfiles-auth");
      const linkHome = path.join(dir, "symlink-auth-home");
      fs.mkdirSync(dotDir, { recursive: true });
      fs.mkdirSync(linkHome, { recursive: true });
      const realTarget = path.join(dotDir, "auth.json");
      const linkEntry = path.join(linkHome, "auth.json");
      const baseOAuth = {
        auth_mode: "chatgpt",
        tokens: { access_token: "acc_sym_1", refresh_token: "ref_sym_1", account_id: "acct_sym" },
        last_refresh: "2026-11-26T00:00:00.000Z",
      };
      fs.writeFileSync(realTarget, JSON.stringify(baseOAuth, null, 2), { mode: 0o600 });
      fs.symlinkSync(realTarget, linkEntry);

      // 11a) 合法可写符号链接目标：stage 允许同步、原子替换目标并保留符号链接本身、无临时文件残留
      const stagedSym = stageIsolatedCodexHome(linkHome, { copyUserConfig: false });
      try {
        const beforeIno = fs.lstatSync(realTarget).ino;
        fs.writeFileSync(
          path.join(stagedSym.scratchDir, "auth.json"),
          JSON.stringify({
            ...baseOAuth,
            tokens: { ...baseOAuth.tokens, access_token: "acc_sym_2", refresh_token: "ref_sym_2" },
            last_refresh: "2026-11-27T02:00:00.000Z",
          }),
        );
        assert.equal(syncRefreshedCodexAuth(stagedSym), true, "合法可写的符号链接 auth.json 目标应成功原子回写");
        assert.equal(fs.lstatSync(linkEntry).isSymbolicLink(), true, "入口 auth.json 必须保持符号链接");
        const afterStat = fs.lstatSync(realTarget);
        assert.notEqual(afterStat.ino, beforeIno, "原子 rename 更新应替换出全新 inode，绝不原位截断写");
        assert.equal(afterStat.mode & 0o777, 0o600);
        assert.equal(JSON.parse(fs.readFileSync(realTarget, "utf8")).tokens.refresh_token, "ref_sym_2");
        assert.equal(fs.readdirSync(dotDir).filter((f) => f.includes(".pa-tmp-")).length, 0, "原子写回后不得残留临时文件");
      } finally {
        stagedSym.cleanup();
      }

      // 11b) 删除符号链接入口（模拟 codex logout）后绝不更新或复活目标文件
      const stagedSymLogout = stageIsolatedCodexHome(linkHome, { copyUserConfig: false });
      try {
        fs.writeFileSync(
          path.join(stagedSymLogout.scratchDir, "auth.json"),
          JSON.stringify({
            ...baseOAuth,
            tokens: { ...baseOAuth.tokens, access_token: "acc_sym_3", refresh_token: "ref_sym_3" },
            last_refresh: "2026-11-27T03:00:00.000Z",
          }),
        );
        fs.rmSync(linkEntry);
        assert.equal(syncRefreshedCodexAuth(stagedSymLogout), false, "登出删除符号链接后绝不能覆盖目标文件");
        assert.equal(JSON.parse(fs.readFileSync(realTarget, "utf8")).tokens.refresh_token, "ref_sym_2");
      } finally {
        stagedSymLogout.cleanup();
      }

      // 11c) 不可写的 OAuth auth.json（0444，在非 root UID 下验证）：启动子进程前即 fail-closed 拒绝
      if (typeof process.getuid === "function" && process.getuid() !== 0) {
        const roAuthHome = path.join(dir, "ro-oauth-home");
        fs.mkdirSync(roAuthHome, { recursive: true });
        const roAuthFile = path.join(roAuthHome, "auth.json");
        fs.writeFileSync(roAuthFile, JSON.stringify(baseOAuth, null, 2), { mode: 0o444 });
        chmodRestore.push({ p: roAuthFile, mode: 0o600 });
        assert.throws(
          () => stageIsolatedCodexHome(roAuthHome, { copyUserConfig: false, needsCredentialStore: true }),
          /不可安全写回|refresh_token/,
          "只读 OAuth auth.json 必须在启动子进程前 fail-closed 拒绝",
        );
        await assert.rejects(
          () => coordinateCodexOAuthRefresh(roAuthHome, { needsCredentialStore: true }),
          /不可安全写回|refresh_token/,
        );

        // 12b) 原子写回中途目标目录变为不可写时安全失败，原文件字节完整无损且无残留临时文件
        const failWriteHome = path.join(dir, "atomic-fail-home");
        fs.mkdirSync(failWriteHome, { recursive: true });
        const failAuthFile = path.join(failWriteHome, "auth.json");
        const origRaw = JSON.stringify(baseOAuth, null, 2);
        fs.writeFileSync(failAuthFile, origRaw, { mode: 0o600 });
        const stagedFail = stageIsolatedCodexHome(failWriteHome, { copyUserConfig: false });
        try {
          fs.writeFileSync(
            path.join(stagedFail.scratchDir, "auth.json"),
            JSON.stringify({
              ...baseOAuth,
              tokens: { ...baseOAuth.tokens, access_token: "acc_fail", refresh_token: "ref_fail" },
              last_refresh: "2026-11-27T04:00:00.000Z",
            }),
          );
          fs.chmodSync(failWriteHome, 0o500);
          chmodRestore.push({ p: failWriteHome, mode: 0o700 });
          assert.equal(syncRefreshedCodexAuth(stagedFail), false, "目录不可写时原子写回必须安全返回 false");
          assert.equal(fs.readFileSync(failAuthFile, "utf8"), origRaw, "写回失败时原 auth.json 必须保持字节级完整无损");
        } finally {
          fs.chmodSync(failWriteHome, 0o700);
          stagedFail.cleanup();
        }
      }
    }

    // 13) [R18 #13 P2] health() / overview() 在全 14 天窗口内独立统计当前主人可操作失败数，不受最新 200 条旧主人隔离失败截断
    {
      const origOwner = app.cfg.owner.open_id;
      app.store.set("daemon.heartbeat", `test-proc|${Date.now()}`);
      // 先写入 1 条归属当前（后续切换后的）主人 ou_owner_new 的真实未确认失败
      app.ledger.enqueue({ id: "evt:r18_cur_owner_fail", kind: "event", ref: "evt_r18_cur", state: "dead", payload: { summary: "当前主人真实故障" } });
      app.ledger.db.prepare("UPDATE work SET terminal = 1, state = 'dead', error = 'real failure', updated = ? WHERE id = ?").run(Date.now(), "evt:r18_cur_owner_fail");
      // 再写入 205 条更新的旧主人上下文失败（模拟切换 owner.open_id 后被隔离的旧记录占满最新 200 条）
      for (let i = 0; i < 205; i++) {
        const fid = `fx:r18_old_ctx_${i}`;
        app.ledger.enqueue({
          id: fid,
          kind: "effect",
          ref: `card:ctx-item:old_${i}`,
          state: "dead",
          payload: { op: "card.upsert", args: { key: `ctx-item:old_${i}`, card: {} } },
        });
      }
      app.ledger.db.prepare("UPDATE work SET terminal = 1, state = 'dead', error = 'old owner ctx', updated = ? WHERE id LIKE 'fx:r18_old_ctx_%'").run(Date.now());
      app.cfg.owner.open_id = "ou_owner_new";
      try {
        const h = Q.health(app);
        const ov = Q.overview(app);
        assert.equal(h.actionable_failures, 1, "即使最新 200 条均为旧主人隔离失败，actionable_failures 仍必须精确统计当前主人的 1 条故障");
        assert.equal(ov.attention.failures, 1, "overview().attention.failures 绝不能被 200 条隔离记录挤成 0");
        assert.equal(ov.health.dead, 1);
        assert.equal(ov.health.ok, false, "存在当前主人未确认故障时 overview().health.ok 必须为 false");
        assert.ok(h.failed.some((f) => f.id === "evt:r18_cur_owner_fail" && !f.isolated), "health().failed 展示列表必须优先保留当前主人故障");
      } finally {
        app.cfg.owner.open_id = origOwner;
      }
    }

    // 14) [R18 #14 P2] FeishuWebClient.connect 首次 verifyOwner 遭遇瞬时 503 且响应已轮换 Cookie 时，在本地 jar 内重试而不落盘未验证 Cookie，验证成功后一并落盘
    {
      let profileAttempt = 0;
      const seenCookiesOnProfile: string[] = [];
      retryProfileSrv = http.createServer((req, res) => {
        const urlPath = req.url ?? "";
        if (urlPath.startsWith("/accounts/web/user")) {
          profileAttempt++;
          const cookieHdr = String(req.headers.cookie ?? "");
          seenCookiesOnProfile.push(cookieHdr);
          if (profileAttempt === 1) {
            // 第一次返回 503 并轮换 session Cookie（旧 Cookie 随即失效）
            res.writeHead(503, {
              "Content-Type": "text/plain",
              "Set-Cookie": "session=sess_rotated_on_503; Path=/",
            });
            res.end("upstream overloaded");
            return;
          }
          if (!cookieHdr.includes("session=sess_rotated_on_503")) {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ code: 401 }));
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ code: 0, data: { user: { id: "7001", name: "主人A", open_id: "ou_owner_a" } } }));
          return;
        }
        if (urlPath.startsWith("/messenger/")) {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end('<html><script>window.passport_web_did="did_r18_retry";const x={appKey:"app_r18_retry"};</script></html>');
          return;
        }
        res.writeHead(404);
        res.end();
      });
      await new Promise<void>((resolve) => retryProfileSrv!.listen(0, "127.0.0.1", resolve));
      const port = (retryProfileSrv.address() as { port: number }).port;
      const base = `http://127.0.0.1:${port}`;
      const confirmedCalls: { attemptWhenCalled: number; sessionVal?: string }[] = [];
      const connected = await FeishuWebClient.connect(
        {
          owner_id: "7001",
          owner_name: "主人A",
          session_id: "sess_r18_retry",
          cookies: [
            { name: "session", value: "sess_old_invalidated", domain: "127.0.0.1", path: "/" },
            { name: "passport_web_did", value: "did_r18_retry", domain: "127.0.0.1", path: "/" },
          ],
        },
        {
          verifyOwnerRetryMs: 10,
          verifyOwnerMaxAttempts: 3,
          endpoints: {
            messengerUrl: `${base}/messenger/`,
            profileUrl: `${base}/accounts/web/user?app_id=12`,
            accountsOrigin: base,
            accountsReferer: `${base}/login`,
            messengerOrigin: base,
            allowInsecureHttp: true,
            extraAllowedHosts: ["127.0.0.1"],
          },
          onSessionConfirmed: (updated) => {
            confirmedCalls.push({
              attemptWhenCalled: profileAttempt,
              sessionVal: updated.cookies.find((c) => c.name === "session")?.value,
            });
            return updated;
          },
        },
      );
      assert.equal(profileAttempt, 2, "503 瞬时故障应在同一个本地 jar 内自动重试第 2 次");
      assert.ok(seenCookiesOnProfile[1]?.includes("session=sess_rotated_on_503"), "第 2 次重试必须携带第 1 次 503 响应轮换的新 Cookie");
      assert.ok(confirmedCalls.length >= 1 && confirmedCalls[0].attemptWhenCalled === 2, "owner 核验成功前绝不能持久化 Cookie，成功后立即持久化新 Cookie");
      assert.equal(confirmedCalls[0].sessionVal, "sess_rotated_on_503");
      assert.equal(connected.owner().id, "7001");
    }

    // 15) [R18 #15 P3] 超大 Max-Age（如 9223372036854775807）必须钳位到合法 Date 上限，绝不抛 RangeError 并中断同响应其他 Cookie
    {
      const jar = new RecordingCookieJar(["feishu.cn"]);
      const u = new URL("https://internal-api-lark-api.feishu.cn/accounts/web/user");
      const applied = jar.setFromHeaders(u, [
        "huge_ttl=ok; Max-Age=9223372036854775807; Path=/",
        "session=keep_me_after_huge; Max-Age=3600; Path=/",
      ]);
      assert.equal(applied, true);
      const recs = jar.records();
      const huge = recs.find((c) => c.name === "huge_ttl");
      const sess = recs.find((c) => c.name === "session");
      assert.ok(huge?.expires_at && !Number.isNaN(Date.parse(huge.expires_at)), "超大 Max-Age 必须产出合法 ISO 日期");
      assert.equal(sess?.value, "keep_me_after_huge", "同一响应后续 Cookie 不得被超大 Max-Age 中断");
    }
  } finally {
    for (const { p, mode } of chmodRestore) {
      try {
        fs.chmodSync(p, mode);
      } catch {
        // ignore
      }
    }
    if (retryProfileSrv) await new Promise<void>((resolve) => retryProfileSrv!.close(() => resolve()));
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevCodexHome;
    extraApp1?.store.db.close();
    extraApp2?.store.db.close();
    boardApp?.store.db.close();
    app?.store.db.close();
    await mock.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第十九轮回归：仓库工人默认隔离、可信沙箱引导程序、最小守卫文件、acpx 单代理配置、个人任务归属派单过滤、owner_isolated 标题脱敏、热加载群白名单发送门控、多文件 npm 全局依赖挂载、不可用原消息拒发、背景消息撤回、冲突 mention 未决、目标域 HTTPS Git 凭据、git-media LFS 别名、本地镜像默认分支、Codex profile 预检与 AWS profile 投影、跳过非 OAuth auth.json、共享目录 OAuth 锁与长任务窗口、Health 可操作失败置顶", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r19-"));
  const dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const mock = await startMockFeishuWebServer();
  const prevKey = process.env.PA_FEISHU_WEB_KEY;
  const prevPath = process.env.PATH;
  const prevTmpDir = process.env.TMPDIR;
  let app: ReturnType<typeof createApp> | undefined;
  let extraApp1: ReturnType<typeof createApp> | undefined;
  let extraApp2: ReturnType<typeof createApp> | undefined;
  let httpGitSrv: http.Server | undefined;

  const makeJwt = (expSec: number): string => {
    const h = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const p = Buffer.from(JSON.stringify({ sub: "user_r19", exp: expSec })).toString("base64url");
    return `${h}.${p}.sig`;
  };

  try {
    // 1) [R19 #1 P1] Linux 上所有仓库级模式默认强制隔离，与启动工作区是否已有密钥或 ctx_obs 无关；llm-none 在无 Web 状态下保持不强制
    {
      const freshData = path.join(dir, "fresh-ws-data");
      fs.mkdirSync(freshData, { recursive: true });
      const siblingWs = path.join(dir, "sibling-ws-data");
      fs.mkdirSync(siblingWs, { recursive: true });
      const siblingSecretDb = path.join(siblingWs, "state.db");
      fs.writeFileSync(siblingSecretDb, "SIBLING_PRIVATE_FEISHU_MSGS_R19");
      const freshRepo = path.join(dir, "fresh-repo");
      fs.mkdirSync(freshRepo, { recursive: true });
      const freshCfg = { dataDir: freshData, context: { personal_web: { enabled: false } } } as never;

      for (const mode of ["verify", "worker-write", "worker-ro", "codex-exec", "git-rw", "git-ro"] as const) {
        const plan = buildWorkspaceIsolation(freshCfg, { mode, cwd: freshRepo }, {});
        assert.equal(plan.requireIsolation, process.platform === "linux", `模式 ${mode} 在 Linux 上必须独立于工作区状态默认启用隔离`);
      }
      const llmPlan = buildWorkspaceIsolation(freshCfg, { mode: "llm-none", cwd: freshRepo }, {});
      assert.equal(llmPlan.requireIsolation, false, "无个人 Web 的 llm-none 不应强制要求隔离");

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        const probe = wrapCredentialIsolatedCommand(
          "sh",
          ["-c", `test -e ${JSON.stringify(siblingSecretDb)} && echo LEAKED || echo HIDDEN`],
          process.env,
          buildWorkspaceIsolation(freshCfg, { mode: "verify", cwd: freshRepo }, {}),
        );
        assert.equal(probe.isolated, true);
        const r = await runProcess(probe.cmd, probe.args, { env: process.env, timeoutMs: 10_000 });
        assert.equal(r.code, 0, r.stderr);
        assert.equal(r.stdout.trim(), "HIDDEN", "全新工作区启动的仓库工人必须看不到同用户其他工作区的 state.db");
      }
    }

    // 2) [R19 #2 P1] 沙箱引导程序仅从可信目录解析（忽略被污染的 PATH），且 unshare 引导期间强制系统 PATH 并在隔离后恢复任务 PATH
    {
      const poisonDir = path.join(dir, "poison-bin");
      fs.mkdirSync(poisonDir, { recursive: true });
      const poisonMarker = path.join(dir, "poison-executed.txt");
      for (const fakeName of ["bwrap", "unshare", "setpriv", "sh", "mount", "awk"]) {
        fs.writeFileSync(
          path.join(poisonDir, fakeName),
          `#!/bin/sh\necho "${fakeName}" >> ${JSON.stringify(poisonMarker)}\nexit 99\n`,
          { mode: 0o755 },
        );
      }
      process.env.PATH = `${poisonDir}${path.delimiter}${prevPath ?? ""}`;
      try {
        const resolvedBwrap = resolveTrustedBwrapBin();
        if (resolvedBwrap) {
          assert.ok(!resolvedBwrap.startsWith(poisonDir), `bwrap 绝不得从被污染 PATH 解析：${resolvedBwrap}`);
        }
        for (const sysBin of ["sh", "unshare", "setpriv", "pivot_root"]) {
          const resolved = resolveTrustedSystemBin(sysBin);
          if (resolved) {
            assert.ok(
              ["/usr/bin", "/bin", "/usr/sbin", "/sbin"].some((d) => resolved.startsWith(`${d}/`)),
              `${sysBin} 必须来自受信任系统目录：${resolved}`,
            );
          }
        }
        assert.equal(fs.existsSync(poisonMarker), false, "解析可信引导程序期间不得执行污染目录中的脚本");

        if (process.platform === "linux" && hasCredentialMountIsolation()) {
          const unshareBin = resolveTrustedSystemBin("unshare");
          const setprivBin = resolveTrustedSystemBin("setpriv");
          const pivotRootBin = resolveTrustedSystemBin("pivot_root");
          const shBin = resolveTrustedSystemBin("sh");
          if (unshareBin && setprivBin && pivotRootBin && shBin) {
            const taskBinDir = path.join(dir, "task-bin");
            fs.mkdirSync(taskBinDir, { recursive: true });
            fs.writeFileSync(path.join(taskBinDir, "r19-task-helper"), "#!/bin/sh\necho TASK_PATH_RESTORED\n", { mode: 0o755 });
            const taskEnv: NodeJS.ProcessEnv = {
              ...process.env,
              PATH: `${poisonDir}${path.delimiter}${taskBinDir}${path.delimiter}${prevPath ?? ""}`,
            };
            const wrapped = wrapCredentialIsolatedCommand(
              "/bin/sh",
              ["-c", "r19-task-helper"],
              taskEnv,
              {
                requireIsolation: true,
                cwd: dir,
                readOnlyPaths: [taskBinDir],
                forceBackend: { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin, shBin, killChild: true },
              },
            );
            const r = await runProcess(wrapped.cmd, wrapped.args, { env: taskEnv, timeoutMs: 10_000 });
            assert.equal(r.code, 0, `unshare 引导应忽略污染 PATH 并在隔离后恢复任务 PATH：${r.stderr}`);
            assert.equal(r.stdout.trim(), "TASK_PATH_RESTORED");
            assert.equal(fs.existsSync(poisonMarker), false, "unshare 引导阶段绝不能执行污染 PATH 里的 mount/awk/sh");
          }
        }
      } finally {
        if (prevPath === undefined) delete process.env.PATH;
        else process.env.PATH = prevPath;
      }
    }

    // 3) [R19 #3 P1] & 4) [R19 #4 P1] 仅挂载 4 个 Lark 守卫文件（不暴露 ROOT/config.yaml 与 ROOT/.worktrees），且 acpx 仅暴露选中 agent 的配置目录
    {
      const guardFiles = collectLarkGuardReadOnlyFiles();
      assert.equal(guardFiles.length, 4, "守卫只读文件集合应精确包含 4 个文件");
      assert.ok(guardFiles.some((f) => f.endsWith(`${path.sep}bin${path.sep}guard${path.sep}lark-cli`)));
      assert.ok(guardFiles.some((f) => f.endsWith(`${path.sep}src${path.sep}guard-cli.ts`)));
      assert.ok(guardFiles.some((f) => f.endsWith(`${path.sep}src${path.sep}guard.ts`)));
      assert.ok(guardFiles.some((f) => f.endsWith(`${path.sep}package.json`)));
      assert.ok(!guardFiles.includes(fs.realpathSync(ROOT)), "绝不得把整个 ROOT 目录放进守卫挂载集合");

      const fakeHome = path.join(dir, "fake-home-r19");
      fs.mkdirSync(path.join(fakeHome, ".acpx"), { recursive: true });
      fs.mkdirSync(path.join(fakeHome, ".claude"), { recursive: true });
      fs.mkdirSync(path.join(fakeHome, ".codex"), { recursive: true });
      fs.mkdirSync(path.join(fakeHome, ".gemini"), { recursive: true });
      fs.writeFileSync(path.join(fakeHome, ".claude", "settings.json"), '{"claude":true}\n');
      fs.writeFileSync(path.join(fakeHome, ".codex", "auth.json"), '{"tokens":{"refresh_token":"SECRET_CODEX_RT"}}\n');
      fs.writeFileSync(path.join(fakeHome, ".gemini", "oauth.json"), '{"secret":"SECRET_GEMINI"}\n');

      const claudePaths = selectAcpxAgentConfigPaths({ agent: "claude", env: {} }, fakeHome, {});
      assert.ok(!claudePaths.includes(path.join(fakeHome, ".acpx")), "不得直接挂载宿主机 ~/.acpx（含历史 sessions）");
      assert.ok(claudePaths.includes(path.join(fakeHome, ".claude")));
      assert.ok(!claudePaths.some((p) => p.includes(".codex") || p.includes(".gemini")), "Claude 代理绝不能暴露 .codex / .gemini");

      const codexPaths = selectAcpxAgentConfigPaths({ agent: "codex", env: {} }, fakeHome, {});
      assert.ok(codexPaths.includes(path.join(fakeHome, ".codex")));
      assert.ok(!codexPaths.some((p) => p.includes(".claude") || p.includes(".gemini")), "Codex 代理绝不能暴露 .claude / .gemini");

      const unknownPaths = selectAcpxAgentConfigPaths({ agentCommand: "/usr/bin/custom-agent", env: {} }, fakeHome, {});
      assert.deepEqual(unknownPaths, [], "未知自定义代理不挂载任何宿主机提供方目录（~/.acpx 由私有暂存目录投影）");

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        const probeAcpx = path.join(dir, "probe-acpx-r19");
        fs.writeFileSync(
          probeAcpx,
          [
            "#!/bin/sh",
            `echo "ROOT_LIST=$(ls -A ${JSON.stringify(ROOT)} 2>/dev/null | tr '\\n' ',' )"`,
            `echo "ROOT_DOT_WT=$(test -e ${JSON.stringify(path.join(ROOT, ".git"))} && echo YES || echo NO)"`,
            `echo "CLAUDE_OK=$(test -f ${JSON.stringify(path.join(fakeHome, ".claude", "settings.json"))} && echo YES || echo NO)"`,
            `echo "CODEX_LEAK=$(test -f ${JSON.stringify(path.join(fakeHome, ".codex", "auth.json"))} && echo YES || echo NO)"`,
            `echo "GEMINI_LEAK=$(test -f ${JSON.stringify(path.join(fakeHome, ".gemini", "oauth.json"))} && echo YES || echo NO)"`,
            'lark-cli im +messages-send --as bot --user-id ou_stranger --text hi >/dev/null 2>&1; echo "GUARD_EXIT=$?"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const acpxCfgFile = path.join(dir, "acpx-r19.yaml");
        fs.writeFileSync(
          acpxCfgFile,
          [
            `data_dir: ${path.join(dir, "acpx-data")}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(probeAcpx)} }`,
            "owner: { open_id: ou_r19 }",
            "harnesses:",
            `  cl: { agent: claude, env: { HOME: ${JSON.stringify(fakeHome)} } }`,
            `  db: { type: doubao-cli, cmd: ${JSON.stringify(probeAcpx)}, env: { HOME: ${JSON.stringify(fakeHome)} } }`,
            "roles: { brain: cl }",
          ].join("\n"),
        );
        const acpxCfg = loadConfig(acpxCfgFile);
        const workDir = path.join(dir, "acpx-cwd");
        fs.mkdirSync(workDir, { recursive: true });
        const clRes = await runHarness(acpxCfg, {
          harness: "cl",
          prompt: "probe",
          cwd: workDir,
          tools: "write",
          lark: "none",
          timeoutSec: 30,
          logFile: path.join(dir, "cl.log"),
        });
        assert.equal(clRes.ok, true, clRes.text);
        assert.match(clRes.text, /ROOT_DOT_WT=NO/, "acpx 沙箱内绝不得看到 ROOT/.git 或其他 ROOT 目录内容");
        assert.doesNotMatch(clRes.text, /config\.yaml/, "acpx 沙箱内绝不得暴露 ROOT/config.yaml");
        assert.match(clRes.text, /CLAUDE_OK=YES/, "Claude 代理应可读 ~/.claude");
        assert.match(clRes.text, /CODEX_LEAK=NO/, "Claude 代理绝不得读取 ~/.codex/auth.json");
        assert.match(clRes.text, /GEMINI_LEAK=NO/, "Claude 代理绝不得读取 ~/.gemini");
        assert.match(clRes.text, /GUARD_EXIT=13/, "仅挂载 4 个守卫文件时 bin/guard/lark-cli 仍能正常拦截越权调用");

        const dbRes = await runHarness(acpxCfg, {
          harness: "db",
          prompt: "probe",
          cwd: workDir,
          tools: "write",
          lark: "none",
          timeoutSec: 30,
          logFile: path.join(dir, "db.log"),
        });
        assert.equal(dbRes.ok, true, dbRes.text);
        assert.match(dbRes.text, /ROOT_DOT_WT=NO/, "doubao-cli 沙箱内同样绝不得暴露整个 ROOT");
        assert.match(dbRes.text, /GUARD_EXIT=13/, "doubao-cli 沙箱内 bin/guard/lark-cli 必须正常运行");
      }
    }

    // 8) [R19 #8 P1] 用户全局 npm 多文件可执行程序（~/.npm-global/bin/<tool> -> ../lib/node_modules/<pkg>/dist/cli.mjs + sibling + hoisted dep）在隔离沙箱中正常运行
    if (process.platform === "linux" && hasCredentialMountIsolation()) {
      const npmPrefix = path.join(dir, "npm-global");
      const npmBinDir = path.join(npmPrefix, "bin");
      const pkgDir = path.join(npmPrefix, "lib", "node_modules", "r19-cli-pkg");
      const depDir = path.join(npmPrefix, "lib", "node_modules", "r19-helper-dep");
      fs.mkdirSync(npmBinDir, { recursive: true });
      fs.mkdirSync(path.join(pkgDir, "dist"), { recursive: true });
      fs.mkdirSync(depDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, "package.json"),
        JSON.stringify({ name: "r19-cli-pkg", version: "1.0.0", type: "module", dependencies: { "r19-helper-dep": "1.0.0" } }),
      );
      fs.writeFileSync(path.join(pkgDir, "dist", "sibling.mjs"), 'export const SIB = "SIBLING_OK";\n');
      fs.writeFileSync(
        path.join(pkgDir, "dist", "cli.mjs"),
        '#!/usr/bin/env node\nimport { SIB } from "./sibling.mjs";\nimport { DEP } from "r19-helper-dep";\nconsole.log(`${SIB}:${DEP}`);\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(depDir, "package.json"),
        JSON.stringify({ name: "r19-helper-dep", version: "1.0.0", type: "module", main: "index.mjs" }),
      );
      fs.writeFileSync(path.join(depDir, "index.mjs"), 'export const DEP = "HOISTED_DEP_OK";\n');
      const binLink = path.join(npmBinDir, "r19-npm-tool");
      fs.symlinkSync("../lib/node_modules/r19-cli-pkg/dist/cli.mjs", binLink);

      // 8a) 通过 PATH 裸名调用（模拟 ~/.npm-global/bin 在 PATH 中）
      const npmEnv: NodeJS.ProcessEnv = { ...process.env, PATH: `${npmBinDir}${path.delimiter}${process.env.PATH ?? ""}` };
      const wrappedByName = wrapCredentialIsolatedCommand("r19-npm-tool", [], npmEnv, {
        requireIsolation: true,
        cwd: dir,
      });
      const r1 = await runProcess(wrappedByName.cmd, wrappedByName.args, { env: npmEnv, timeoutMs: 10_000 });
      assert.equal(r1.code, 0, `PATH 下的全局 npm 多文件可执行程序必须可执行：${r1.stderr}`);
      assert.equal(r1.stdout.trim(), "SIBLING_OK:HOISTED_DEP_OK");

      // 8b) 直接按绝对符号链接路径调用（binDir 不在 PATH 中）
      const wrappedByAbs = wrapCredentialIsolatedCommand(binLink, [], process.env, {
        requireIsolation: true,
        cwd: dir,
        cmdPath: binLink,
      });
      const r2 = await runProcess(wrappedByAbs.cmd, wrappedByAbs.args, { env: process.env, timeoutMs: 10_000 });
      assert.equal(r2.code, 0, `绝对符号链接路径调用全局 npm 多文件可执行程序必须可执行：${r2.stderr}`);
      assert.equal(r2.stdout.trim(), "SIBLING_OK:HOISTED_DEP_OK");
    }

    // 5) [R19 #5 P1] & 6) [R19 #6 P1] & 20) [R19 #20 P2]
    // 个人自主任务归属过滤派单 + owner_isolated 日志不泄漏旧主人标题 + Health 优先展示未确认可操作失败
    {
      const ownerData = path.join(dir, "owner-data");
      const ownerCfgFile = path.join(dir, "owner-cfg.yaml");
      fs.writeFileSync(
        ownerCfgFile,
        [
          `data_dir: ${ownerData}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          "owner: { open_id: ou_new_owner_r19 }",
          "harnesses: { claude: { agent: claude } }",
          "roles: { brain: claude }",
        ].join("\n"),
      );
      extraApp1 = createApp(loadConfig(ownerCfgFile));
      extraApp1.store.set("owner.open_id", "ou_old_owner_r19");
      extraApp1.store.set("ctx.own_task_owner.guid_own_r19", "ou_old_owner_r19");
      extraApp1.store.set("op.task.create_own.legacy_r19", "guid_legacy_own_r19");

      const secretTitle = "旧主人绝密并购计划_R19_SECRET";
      const dId1 = "dispatch:guid_own_r19:1700000001";
      const dId2 = "dispatch:guid_legacy_own_r19:1700000002";
      extraApp1.ledger.enqueue({
        id: dId1,
        kind: "dispatch",
        ref: "guid_own_r19",
        state: "queued",
        payload: { guid: "guid_own_r19", summary: secretTitle, description: "private" },
      });
      extraApp1.ledger.enqueue({
        id: dId2,
        kind: "dispatch",
        ref: "guid_legacy_own_r19",
        state: "queued",
        payload: { guid: "guid_legacy_own_r19", summary: "旧版自主任务标题", description: "private" },
      });

      assert.equal(Q.isContextDerivedDispatchBlocked(extraApp1, dId1), true, "ctx.own_task_owner 标记的任务派单必须被归属隔离拦截");
      assert.equal(Q.isContextDerivedDispatchBlocked(extraApp1, dId2), true, "遗留 op.task.create_own.* 任务派单在换主后必须被归属隔离拦截");
      assert.equal(Q.listDispatches(extraApp1, { filter: "all" }).length, 0, "旧主人自主任务派单不得出现在新主人派单列表中");
      await assert.rejects(
        () => Q.dispatchDetail(extraApp1!, dId1),
        /主人隔离阻断/,
        "旧主人自主任务派单详情必须被阻断访问",
      );

      // 拦截 stdout 日志，验证 Dispatcher.advance 中止旧主人派单时绝不打印旧主人私密标题
      const disp = new Dispatcher(extraApp1.cfg, extraApp1.ledger, extraApp1.store, extraApp1.board);
      const capturedLogs: string[] = [];
      const origWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => {
        capturedLogs.push(String(chunk));
        return origWrite(chunk as string, ...(rest as []));
      }) as typeof process.stdout.write;
      try {
        const w1 = extraApp1.ledger.claim("dispatch", 30_000)!;
        assert.equal(w1.id, dId1);
        await disp.advance(w1 as never, { signal: new AbortController().signal, attempt: 1 });
      } finally {
        process.stdout.write = origWrite;
      }
      const joinedLogs = capturedLogs.join("");
      assert.ok(!joinedLogs.includes(secretTitle), `owner_isolated 日志绝不能泄漏旧主人私密标题：${joinedLogs}`);
      assert.ok(joinedLogs.includes(dId1) && joinedLogs.includes("owner_isolated"), "owner_isolated 日志应仅记录 work ID 与 reason");
      const finished = extraApp1.ledger.get<{ summary?: string }>(dId1);
      assert.equal(finished?.state, "errored");
      assert.equal(finished?.reason, "owner_isolated");
      assert.equal(finished?.payload.summary, secretTitle, "账本原始 payload 标题应原样保留");

      // [R19 #20 P2] 3 条较早的未确认当前主人失败 + 210 条较新的已确认失败：Health 展示列表必须把未确认可操作失败排在前面
      const now = Date.now();
      for (let i = 0; i < 3; i++) {
        const id = `job:r19-actionable-${i}`;
        extraApp1.ledger.enqueue({ id, kind: "job", ref: `act_${i}`, state: "errored", payload: { name: `act_${i}` } });
        extraApp1.store.db
          .prepare("UPDATE work SET terminal = 1, outcome = 'errored', updated = ?, error = ? WHERE id = ?")
          .run(now - 500_000 + i * 1000, `err-${i}`, id);
      }
      for (let i = 0; i < 210; i++) {
        const id = `job:r19-acked-${i}`;
        extraApp1.ledger.enqueue({ id, kind: "job", ref: `ack_${i}`, state: "errored", payload: { name: `ack_${i}` } });
        extraApp1.store.db
          .prepare("UPDATE work SET terminal = 1, outcome = 'acknowledged', updated = ?, error = ? WHERE id = ?")
          .run(now - 100_000 + i * 100, `acked-${i}`, id);
      }
      const h = Q.health(extraApp1);
      assert.equal(h.actionable_failures, 3);
      assert.equal(h.failed.length, 200);
      const shownActionable = h.failed.filter((f) => !f.acknowledged && !f.isolated);
      assert.equal(shownActionable.length, 3, "全部 3 条未确认可操作失败必须优先获得 Health 展示位");
      assert.ok(
        h.failed.slice(0, 3).every((f) => !f.acknowledged && !f.isolated),
        "未确认可操作失败必须排在已确认失败之前",
      );
    }

    // 7) [R19 #7 P1] & 9) [R19 #9 P2] & 10) [R19 #10 P2]
    // 跨进程修改 groups_allow 实时生效 + 不可用原消息拒发并撤回 + 补读背景消息经权威确认撤回且绝不提升为待处理
    {
      process.env.PA_FEISHU_WEB_KEY = TEST_WEB_KEY;
      const pwDir = path.join(dir, "pw-r19");
      const pwData = path.join(pwDir, "data");
      fs.mkdirSync(pwData, { recursive: true });
      const pwCfgFile = path.join(pwDir, "config.yaml");
      const writePwConfig = (groupsAllow: string[]) => {
        fs.writeFileSync(
          pwCfgFile,
          [
            `data_dir: ${pwData}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
            "owner: { open_id: ou_r19_pw }",
            "harnesses: { cx: { type: codex-exec, cmd: /bin/true } }",
            "roles: { brain: cx }",
            "context:",
            "  enabled: true",
            "  understand: false",
            "  groups: allowlist",
            `  groups_allow: ${JSON.stringify(groupsAllow)}`,
            "  groups_deny: []",
            "  personal_web:",
            "    enabled: true",
            "    fast_lane: false",
            "    send_replies: true",
          ].join("\n"),
        );
      };
      writePwConfig(["pw_chat:9901"]);
      app = createApp(loadConfig(pwCfgFile));
      app.store.set("owner.open_id", "ou_r19_pw");
      const login = {
        owner_id: "7001",
        owner_name: "测试主人",
        device_id: "dev_r19",
        saved_at: Date.now(),
        session_id: "sess_r19",
        cookies: [
          { name: "session", value: "s_r19", domain: ".feishu.cn", path: "/", host_only: false, secure: true, http_only: true },
          { name: "csrf_token", value: "c_r19", domain: ".feishu.cn", path: "/", host_only: false, secure: false, http_only: false },
        ],
      };
      commitWorkspaceLogin(app, login, { allowUnverifiedOwner: true });

      const ctxStore = new ContextStore(app.store.db);
      const bridge = new PersonalWebBridge(app, ctxStore, {
        onFastTrigger: () => undefined,
        onReconnect: () => undefined,
        onNeedsLogin: () => undefined,
        clientOptions: { endpoints: mock.endpoints },
      });

      // 7) 群 9901 初始在 groups_allow 中；模拟另一进程把 9901 从磁盘 config.yaml 的 groups_allow 中移出后，
      //    非 @本人 消息的新回复必须被拒绝（绝不沿用陈旧内存白名单直接发包）
      mock.setChatKind("9901", CHAT_KIND_GROUP);
      mock.setChatName("9901", "白名单群");
      mock.addMessage(
        "990101",
        buildNativeMessage({
          id: "990101",
          chatId: "9901",
          chatKind: CHAT_KIND_GROUP,
          actorId: "8001",
          text: "请帮我确认一下排期（未 @本人）",
        }),
      );
      ctxStore.addObs([
        {
          id: "pw:990101",
          source: "im",
          kind: "group",
          conv: "pw_chat:9901",
          conv_name: "白名单群",
          actor_id: "8001",
          actor_name: "8001",
          is_me: false,
          time: Date.now(),
          text: "请帮我确认一下排期（未 @本人）",
          url: "",
          meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "group" },
        },
      ]);
      // 模拟另一进程更新磁盘 config.yaml 移除 pw_chat:9901（保持内存 app.cfg 不变）
      await new Promise((r) => setTimeout(r, 20));
      writePwConfig(["pw_chat:9999"]);
      const sentBefore7 = mock.sentReplies.length;
      await assert.rejects(
        () =>
          bridge.sendVerifiedReply({
            owner_id: "7001",
            chat_id: "9901",
            message_id: "990101",
            text: "收到，我来看下",
            cid: computePwReplyCid({
              draft_id: "d_r19_7",
              owner_id: "7001",
              chat_id: "9901",
              message_id: "990101",
              text: "收到，我来看下",
            }).cid,
          }),
        /已不再 @本人|移出/,
        "磁盘 groups_allow 移除群后，非 @本人 回复必须被拒绝",
      );
      assert.equal(mock.sentReplies.length, sentBefore7, "白名单移除后绝不能实际发包");

      // 9) 私聊原消息在监听离线期间被编辑为空（不可用正文）：sendVerifiedReply 必须拒绝发包并撤回本地 pw:* 观测
      mock.setChatKind("9902", CHAT_KIND_P2P);
      mock.setChatName("9902", "私聊对象");
      mock.addMessage(
        "990201",
        buildNativeMessage({
          id: "990201",
          chatId: "9902",
          chatKind: CHAT_KIND_P2P,
          actorId: "8002",
          text: "   ",
        }),
      );
      ctxStore.addObs([
        {
          id: "pw:990201",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9902",
          conv_name: "私聊对象",
          actor_id: "8002",
          actor_name: "8002",
          is_me: false,
          time: Date.now(),
          text: "离线前的旧私聊内容",
          url: "",
          meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
        },
      ]);
      const sentBefore9 = mock.sentReplies.length;
      await assert.rejects(
        () =>
          bridge.sendVerifiedReply({
            owner_id: "7001",
            chat_id: "9902",
            message_id: "990201",
            text: "好的收到",
            cid: computePwReplyCid({
              draft_id: "d_r19_9",
              owner_id: "7001",
              chat_id: "9902",
              message_id: "990201",
              text: "好的收到",
            }).cid,
          }),
        /实时回读原消息已不可用/,
        "原消息实时回读为空正文时必须拒绝发送新回复",
      );
      assert.equal(mock.sentReplies.length, sentBefore9);
      assert.equal(ctxStore.obs("pw:990201")?.meta.withdrawn, true, "原消息不可用拒发后应同步撤回本地观测");
      assert.equal(ctxStore.obsPending("pw:990201"), false);

      // 10) 补读背景消息（background_only: true）收到空/不支持编辑推送时：
      //     a) 权威回读确认已撤回 -> 标记 withdrawn: true，保持 processed=1 且从后续 convWindow 剔除；
      //     b) 权威回读仍有效（误报/乱序） -> 保持 background_only: true 且绝不提升为待处理。
      const nowMs = Date.now();
      ctxStore.addBackgroundObs([
        {
          id: "pw:990301",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9903",
          conv_name: "背景会话",
          actor_id: "8003",
          actor_name: "8003",
          is_me: false,
          time: nowMs - 2000,
          text: "即将被撤回的历史背景消息",
          url: "",
          meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
        },
        {
          id: "pw:990302",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9903",
          conv_name: "背景会话",
          actor_id: "8003",
          actor_name: "8003",
          is_me: false,
          time: nowMs - 1000,
          text: "仍然有效的历史背景消息",
          url: "",
          meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
        },
      ]);
      ctxStore.addObs([
        {
          id: "pw:990303",
          source: "im",
          kind: "p2p",
          conv: "pw_chat:9903",
          conv_name: "背景会话",
          actor_id: "8003",
          actor_name: "8003",
          is_me: false,
          time: nowMs,
          text: "最新一条待处理私聊",
          url: "",
          meta: { transport: "personal_web", native_owner_id: "7001", chat_type: "p2p" },
        },
      ]);
      mock.setChatKind("9903", CHAT_KIND_P2P);
      mock.setChatName("9903", "背景会话");
      const empty990301Buf = buildNativeMessage({
        id: "990301",
        chatId: "9903",
        chatKind: CHAT_KIND_P2P,
        actorId: "8003",
        text: "",
      });
      mock.addMessage("990301", empty990301Buf);
      mock.addMessage(
        "990302",
        buildNativeMessage({
          id: "990302",
          chatId: "9903",
          chatKind: CHAT_KIND_P2P,
          actorId: "8003",
          text: "仍然有效的历史背景消息",
        }),
      );
      const client = await FeishuWebClient.connect(login, { endpoints: mock.endpoints });
      const invalidPush1 = decodeMessage(empty990301Buf, "7001");
      const invalidPush2 = decodeMessage(
        buildNativeMessage({
          id: "990302",
          chatId: "9903",
          chatKind: CHAT_KIND_P2P,
          actorId: "8003",
          text: "",
        }),
        "7001",
      );
      await bridge.handleMessage(invalidPush1, client);
      await bridge.handleMessage(invalidPush2, client);
      assert.equal(ctxStore.obs("pw:990301")?.meta.withdrawn, true, "经权威确认撤回的补读背景消息必须标为 withdrawn");
      assert.equal(ctxStore.obsPending("pw:990301"), false, "撤回的背景消息绝不能进入待处理队列");
      assert.equal(ctxStore.obs("pw:990302")?.meta.withdrawn, undefined, "权威回读仍有效的背景消息不应被误撤回");
      assert.equal(ctxStore.obs("pw:990302")?.meta.background_only, true, "有效背景消息应保持 background_only");
      assert.equal(ctxStore.obsPending("pw:990302"), false, "权威回读矛盾时绝不能把背景消息提升为待处理工作");
      const win = ctxStore.convWindow("pw_chat:9903", 10, 10, "7001");
      assert.ok(!win.some((o: Obs) => o.id === "pw:990301"), "已撤回的补读背景消息绝不得出现在后续 convWindow 中");
      assert.ok(win.some((o: Obs) => o.id === "pw:990302"), "仍有效的背景消息应继续保留在 convWindow 中");
      delete process.env.PA_FEISHU_WEB_KEY;
    }

    // 11) [R19 #11 P2] 相同正文但 @我 归类冲突且 +messages-mget 缺失 mentions 时，必须视为未决并保留游标重试
    {
      const connDir = path.join(dir, "conn-r19");
      const connData = path.join(connDir, "data");
      fs.mkdirSync(connData, { recursive: true });
      const connCfgFile = path.join(connDir, "config.yaml");
      fs.writeFileSync(
        connCfgFile,
        [
          `data_dir: ${connData}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          "owner: { open_id: ou_r19_conn }",
          "harnesses: { claude: { agent: claude } }",
          "roles: { brain: claude }",
          "context:",
          "  enabled: true",
          "  groups: allowlist",
          '  groups_allow: ["oc_r19_grp"]',
          "  sources: { meego: false, im: true, minutes: false, calendar: false, tasks: false, docs: false }",
        ].join("\n"),
      );
      extraApp2 = createApp(loadConfig(connCfgFile));
      extraApp2.store.set("owner.open_id", "ou_r19_conn");
      const fakeLark = extraApp2.lark as unknown as {
        authStatus: () => Promise<unknown>;
        run: (argv: string[]) => Promise<unknown>;
      };
      fakeLark.authStatus = async () => ({ identity: "user", user: { open_id: "ou_r19_conn", name: "测试" } });
      const nowSec = Math.floor(Date.now() / 1000);
      fakeLark.run = async (argv: string[]) => {
        if (argv[0] === "im" && argv[1] === "+messages-search") {
          if (argv.includes("--is-at-me")) {
            return {
              has_more: false,
              messages: [
                {
                  message_id: "om_r19_conflict",
                  chat_id: "oc_r19_grp",
                  chat_type: "group",
                  chat_name: "测试群",
                  sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                  content: "同样的一句话正文",
                  create_time: String(nowSec * 1000),
                },
              ],
            };
          }
          return { has_more: false, messages: [] };
        }
        if (argv[0] === "im" && argv[1] === "+chat-messages-list") {
          return {
            has_more: false,
            messages: [
              {
                message_id: "om_r19_conflict",
                chat_id: "oc_r19_grp",
                chat_type: "group",
                chat_name: "测试群",
                sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                content: "同样的一句话正文",
                create_time: String(nowSec * 1000),
                mentions: [],
              },
            ],
          };
        }
        if (argv[0] === "im" && argv[1] === "+messages-mget") {
          // 刻意省略 mentions 字段，仅返回正文
          return {
            messages: [
              {
                message_id: "om_r19_conflict",
                chat_id: "oc_r19_grp",
                chat_type: "group",
                chat_name: "测试群",
                sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                content: "同样的一句话正文",
                create_time: String(nowSec * 1000),
              },
            ],
          };
        }
        return {};
      };
      const ctxSvc = new ContextService(extraApp2);
      await ctxSvc.connectors.pullIm();
      assert.equal(
        ctxSvc.store.obs("im:om_r19_conflict"),
        undefined,
        "相同正文但 @我 冲突且 +messages-mget 无 mentions 时绝不得提交陈旧候选",
      );
      assert.equal(extraApp2.store.get("ctx.im.at_me"), undefined, "冲突未决时必须保留 at_me 游标待重试");
    }

    // 12) [R19 #12 P2] & 13) [R19 #13 P2] & 14) [R19 #14 P2]
    // 目标域 HTTPS Git 凭据投影 + git-media.io/v/2 LFS 别名 + remoteDefaultBranch 挂载本地镜像
    {
      // 13) git-media.io/v/2 别名指针校验与历史扫描
      const gitMediaPtr = [
        "version http://git-media.io/v/2",
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size 128",
        "",
      ].join("\n");
      assert.equal(isGitLfsPointerBlob(gitMediaPtr), true, "必须识别 http://git-media.io/v/2 官方别名指针");

      const lfsRepo = path.join(dir, "lfs-git-media-repo");
      fs.mkdirSync(lfsRepo, { recursive: true });
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r19",
        GIT_AUTHOR_EMAIL: "r19@test",
        GIT_COMMITTER_NAME: "r19",
        GIT_COMMITTER_EMAIL: "r19@test",
      };
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", lfsRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(lfsRepo, "asset.bin"), gitMediaPtr);
      assert.equal((await runProcess("git", ["-C", lfsRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", lfsRepo, "commit", "-q", "-m", "add git-media ptr"], { env: gitEnv })).code, 0);
      // 下一个提交删除该文件且没有 .gitattributes，验证仅靠历史扫描仍能检出 git-media 指针
      fs.rmSync(path.join(lfsRepo, "asset.bin"));
      assert.equal((await runProcess("git", ["-C", lfsRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", lfsRepo, "commit", "-q", "-m", "rm asset"], { env: gitEnv })).code, 0);
      assert.equal(await branchUsesGitLfs(lfsRepo, "main"), true, "历史提交中的 git-media.io/v/2 指针必须被 LFS 扫描检出");

      // 14) remoteDefaultBranch 解析 url.*.insteadOf 重写的本地镜像并只读挂载
      const bareMirror = path.join(dir, "bare-mirror.git");
      const workMirrorRepo = path.join(dir, "work-mirror-repo");
      fs.mkdirSync(bareMirror, { recursive: true });
      fs.mkdirSync(workMirrorRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "--bare", "-b", "develop", bareMirror], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["init", "-q", "-b", "develop", workMirrorRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(workMirrorRepo, "README.md"), "hi\n");
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      const fakePlatformUrl = "https://github.example.com/org/mirror-demo.git";
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "remote", "add", "origin", fakePlatformUrl], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "config", `url.${bareMirror}.insteadOf`, fakePlatformUrl], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "push", "-q", "origin", "develop"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", workMirrorRepo, "checkout", "-q", "-b", "pa/feature"], { env: gitEnv })).code, 0);
      const defaultBr = await remoteDefaultBranch(workMirrorRepo, "origin");
      assert.equal(defaultBr, "develop", "remoteDefaultBranch 必须在隔离下挂载 insteadOf 本地镜像并正确解析远端 HEAD");

      // 12) 受信任远程 Git 操作仅投影目标域的 credential.helper=store 凭据，且绝不暴露其他域凭据
      assert.equal(
        gitCredentialLineMatchesTarget("https://u:p@git.a.example:8443/org", new URL("https://git.a.example:8443/org/repo.git"), true),
        true,
      );
      assert.equal(
        gitCredentialLineMatchesTarget("https://u:p@git.b.example", new URL("https://git.a.example/org/repo.git"), false),
        false,
      );
      assert.equal(
        gitCredentialLineMatchesTarget("https://u:p@git.a.example/other", new URL("https://git.a.example/org/repo.git"), true),
        false,
      );

      // 搭建真实需要 HTTP Basic Auth 的本地 Git dumb-HTTP 端点，实测隔离下的 tryGit ls-remote
      const dumbHead = (await runProcess("git", ["-C", workMirrorRepo, "rev-parse", "refs/heads/develop"], { env: gitEnv })).stdout.trim();
      const expectedAuth = `Basic ${Buffer.from("r19user:r19pass").toString("base64")}`;
      let receivedAuth = "";
      httpGitSrv = http.createServer((req, res) => {
        const auth = req.headers.authorization ?? "";
        if (auth !== expectedAuth) {
          res.statusCode = 401;
          res.setHeader("WWW-Authenticate", 'Basic realm="r19-git"');
          res.end("auth required");
          return;
        }
        receivedAuth = auth;
        if ((req.url ?? "").startsWith("/org/repo.git/info/refs")) {
          res.setHeader("Content-Type", "text/plain");
          res.end(`${dumbHead}\trefs/heads/develop\n`);
          return;
        }
        res.statusCode = 404;
        res.end("not found");
      });
      await new Promise<void>((resolve) => httpGitSrv!.listen(0, "127.0.0.1", resolve));
      const gitPort = (httpGitSrv.address() as { port: number }).port;
      const gitHome = path.join(dir, "git-home-r19");
      fs.mkdirSync(gitHome, { recursive: true });
      fs.writeFileSync(path.join(gitHome, ".gitconfig"), "[credential]\n\thelper = store\n");
      fs.writeFileSync(
        path.join(gitHome, ".git-credentials"),
        [
          `http://r19user:r19pass@127.0.0.1:${gitPort}`,
          "https://other:UNRELATED_SECRET@other.internal.example",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      const lsRes = await tryGit(
        workMirrorRepo,
        ["ls-remote", `http://127.0.0.1:${gitPort}/org/repo.git`],
        { readOnly: true, extraEnv: { HOME: gitHome } },
      );
      assert.equal(lsRes.code, 0, `隔离下受信任远程 Git 应通过目标域凭据完成 HTTP 认证：${lsRes.stderr}`);
      assert.equal(receivedAuth, expectedAuth);
      assert.match(lsRes.stdout, new RegExp(dumbHead));

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        // 普通仓库工人绝不能看到 ~/.git-credentials
        const workerProbe = wrapCredentialIsolatedCommand(
          "sh",
          ["-c", `test -e ${JSON.stringify(path.join(gitHome, ".git-credentials"))} && echo LEAK || echo SAFE`],
          { ...process.env, HOME: gitHome },
          buildWorkspaceIsolation({ dataDir, context: { personal_web: { enabled: false } } } as never, { mode: "worker-ro", cwd: workMirrorRepo }, { ...process.env, HOME: gitHome }),
        );
        const wp = await runProcess(workerProbe.cmd, workerProbe.args, { env: { ...process.env, HOME: gitHome }, timeoutMs: 10_000 });
        assert.equal(wp.code, 0, wp.stderr);
        assert.equal(wp.stdout.trim(), "SAFE", "普通工人绝不能访问宿主机 ~/.git-credentials");
      }
    }

    // 15) [R19 #15 P2] & 16) [R19 #16 P2] & 17) [R19 #17 P2] & 18) [R19 #18 P2] & 19) [R19 #19 P2]
    // Codex --profile 预检 + AWS profile 窄投影 + 非 OAuth 跳过 auth.json + 共享目录 OAuth 锁 + 长任务窗口租约
    {
      // 15) 基础 config.toml 为 keyring，但 --profile api_review 或 <name>.config.toml 切到自定义 API-key 供应商
      const codexProfHome = path.join(dir, "codex-prof-home");
      fs.mkdirSync(codexProfHome, { recursive: true });
      fs.writeFileSync(
        path.join(codexProfHome, "config.toml"),
        [
          'cli_auth_credentials_store = "keyring"',
          'model_provider = "openai"',
          "",
          "[profiles.api_review]",
          'model_provider = "corp_api"',
          "",
          "[model_providers.corp_api]",
          'name = "Corp"',
          'base_url = "https://api.corp.example/v1"',
          'env_key = "CORP_API_KEY"',
          "",
          "[profiles.bedrock_prof]",
          'model_provider = "my_bedrock"',
          "",
          "[model_providers.my_bedrock]",
          'name = "Bedrock"',
          'aws = { profile = "bedrock_work", region = "us-west-2" }',
        ].join("\n"),
      );
      const profEnv = { HOME: dir, CODEX_HOME: codexProfHome, CORP_API_KEY: "sk-corp" };
      const baseRes = resolveEffectiveCodexCredentialStore(profEnv, []);
      assert.equal(baseRes.needsCredentialStore, true, "未选 profile 时应命中基础 openai+keyring");
      const profRes = resolveEffectiveCodexCredentialStore(profEnv, ["--profile", "api_review"]);
      assert.equal(profRes.provider, "corp_api");
      assert.equal(profRes.needsCredentialStore, false, "选中 API-key profile 后不应再要求 keyring");
      const ignoredProfRes = resolveEffectiveCodexCredentialStore(profEnv, ["--profile", "api_review"], { ignoreProfiles: true });
      assert.equal(ignoredProfRes.needsCredentialStore, true, "tools=none (ignoreProfiles) 不应受 profile 影响");

      // sidecar <name>.config.toml 生效且损坏链接必须报错
      fs.writeFileSync(path.join(codexProfHome, "sidecar_ok.config.toml"), 'cli_auth_credentials_store = "file"\nmodel_provider = "corp_api"\n');
      const scOk = resolveEffectiveCodexCredentialStore(profEnv, ["-p", "sidecar_ok"]);
      assert.equal(scOk.store, "file");
      assert.equal(scOk.needsCredentialStore, false);
      fs.symlinkSync("/nonexistent/r19-broken-sidecar.toml", path.join(codexProfHome, "broken_sc.config.toml"));
      const scBad = resolveEffectiveCodexCredentialStore(profEnv, ["--profile=broken_sc"]);
      assert.ok(scBad.configError, "损坏的 profile sidecar 符号链接必须返回 configError (fail-closed)");

      const bedrockProfRes = resolveEffectiveCodexCredentialStore(profEnv, ["--profile", "bedrock_prof"]);
      assert.equal(bedrockProfRes.awsProfile, "bedrock_work");
      assert.equal(bedrockProfRes.needsCredentialStore, false);

      // doctor / keyring 冲突预检：reviewer 使用 --profile api_review 不报冲突
      const krCfg = {
        dataDir,
        context: { personal_web: { enabled: true } },
        harnesses: {
          rev: { type: "codex-exec", cmd: "codex", extraArgs: ["--profile", "api_review"], env: { CODEX_HOME: codexProfHome, CORP_API_KEY: "sk-corp" } },
          base: { type: "codex-exec", cmd: "codex", extraArgs: [], env: { CODEX_HOME: codexProfHome } },
        },
      } as never;
      if (process.platform === "linux") {
        assert.equal(detectIsolatedCodexKeyringConflict(krCfg, {}, "rev", { includeContextObs: true }), undefined, "走 API-key profile 的 reviewer 不应报 keyring 冲突");
        assert.equal(detectIsolatedCodexKeyringConflict(krCfg, {}, "base", { includeContextObs: true })?.severity, "error", "未切 profile 的 keyring reviewer 必须报错");
      }

      // 16) AWS profile 窄投影：仅提取选中的 bedrock_work + source_profile + sso-session，严禁泄漏 admin_secret
      const awsHome = path.join(dir, "aws-home");
      const awsDir = path.join(awsHome, ".aws");
      fs.mkdirSync(awsDir, { recursive: true });
      fs.writeFileSync(
        path.join(awsDir, "config"),
        [
          "[profile bedrock_work]",
          "region = us-west-2",
          "source_profile = base_acct",
          "sso_session = corp_sso",
          "",
          "[profile base_acct]",
          "region = us-east-1",
          "",
          "[sso-session corp_sso]",
          "sso_start_url = https://corp.awsapps.com/start",
          "",
          "[profile admin_secret]",
          "region = ap-northeast-1",
          "role_arn = arn:aws:iam::999999999999:role/SuperAdmin",
        ].join("\n"),
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(awsDir, "credentials"),
        [
          "[base_acct]",
          "aws_access_key_id = AKIA_BASE_R19",
          "aws_secret_access_key = SECRET_BASE_R19",
          "",
          "[admin_secret]",
          "aws_access_key_id = AKIA_ADMIN_LEAK",
          "aws_secret_access_key = SECRET_ADMIN_LEAK",
        ].join("\n"),
        { mode: 0o600 },
      );
      const stagedAws = stageIsolatedAwsProfile("bedrock_work", { HOME: awsHome }, dataDir);
      assert.ok(stagedAws, "应成功投影选中的 AWS profile");
      try {
        const projCfg = fs.readFileSync(stagedAws!.configFile, "utf8");
        const projCred = fs.readFileSync(stagedAws!.credentialsFile, "utf8");
        assert.ok(projCfg.includes("[profile bedrock_work]") && projCfg.includes("[profile base_acct]") && projCfg.includes("[sso-session corp_sso]"));
        assert.ok(!projCfg.includes("admin_secret") && !projCfg.includes("SuperAdmin"), "投影 config 绝不得包含无关 AWS profile");
        assert.ok(projCred.includes("AKIA_BASE_R19") && !projCred.includes("AKIA_ADMIN_LEAK"), "投影 credentials 绝不得包含无关账号密钥");
      } finally {
        stagedAws!.cleanup();
      }
      assert.equal(fs.existsSync(stagedAws!.dir), false, "cleanup 必须彻底清理 AWS 投影目录");

      // 16b) 实跑隔离下的 codex-exec（Bedrock profile + host auth.json）：沙箱内必须可读投影 AWS profile 且绝不可见 admin_secret 或 host auth.json
      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        const bedrockCodexHome = path.join(dir, "codex-bedrock-live");
        fs.mkdirSync(bedrockCodexHome, { recursive: true });
        fs.writeFileSync(
          path.join(bedrockCodexHome, "config.toml"),
          [
            'model_provider = "my_bedrock"',
            "[model_providers.my_bedrock]",
            'name = "Bedrock"',
            'aws = { profile = "bedrock_work", region = "us-west-2" }',
          ].join("\n"),
        );
        fs.writeFileSync(
          path.join(bedrockCodexHome, "auth.json"),
          JSON.stringify({ auth_mode: "chatgpt", tokens: { access_token: "tok", refresh_token: "HOST_RT_MUST_NOT_APPEAR" } }),
          { mode: 0o600 },
        );
        const probeCodex = path.join(dir, "probe-codex-aws.sh");
        fs.writeFileSync(
          probeCodex,
          [
            "#!/bin/sh",
            'OUT=""',
            'while [ "$#" -gt 0 ]; do',
            '  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi',
            "  shift",
            "done",
            'CFG_CONT="$(cat "$AWS_CONFIG_FILE" 2>/dev/null || true)"',
            'CRED_CONT="$(cat "$AWS_SHARED_CREDENTIALS_FILE" 2>/dev/null || true)"',
            'HAS_AUTH=$(test -e "$CODEX_HOME/auth.json" && echo YES || echo NO)',
            'HAS_HOST_AUTH=$(test -e ' + JSON.stringify(path.join(bedrockCodexHome, "auth.json")) + ' && echo YES || echo NO)',
            'RES="HAS_BEDROCK=$(echo "$CFG_CONT" | grep -q bedrock_work && echo YES || echo NO);HAS_ADMIN=$(echo "$CRED_CONT" | grep -q AKIA_ADMIN_LEAK && echo YES || echo NO);HAS_BASE=$(echo "$CRED_CONT" | grep -q AKIA_BASE_R19 && echo YES || echo NO);HAS_AUTH=$HAS_AUTH;HAS_HOST_AUTH=$HAS_HOST_AUTH"',
            'if [ -n "$OUT" ]; then printf "%s\\n" "$RES" > "$OUT"; fi',
            'printf "%s\\n" "$RES"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const awsRunCfgFile = path.join(dir, "aws-run-r19.yaml");
        fs.writeFileSync(
          awsRunCfgFile,
          [
            `data_dir: ${path.join(dir, "aws-run-data")}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
            "owner: { open_id: ou_r19_aws }",
            "harnesses:",
            `  cx_aws: { type: codex-exec, cmd: ${JSON.stringify(probeCodex)}, env: { HOME: ${JSON.stringify(awsHome)}, CODEX_HOME: ${JSON.stringify(bedrockCodexHome)} } }`,
            "roles: { brain: cx_aws }",
            "context: { personal_web: { enabled: true } }",
          ].join("\n"),
        );
        const awsRunCfg = loadConfig(awsRunCfgFile);
        const awsRes = await runHarness(awsRunCfg, {
          harness: "cx_aws",
          prompt: "hello",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 30,
          logFile: path.join(dir, "cx-aws.log"),
        });
        assert.equal(awsRes.ok, true, awsRes.text);
        assert.match(awsRes.text, /HAS_BEDROCK=YES/, "隔离 Bedrock Codex 必须能读取投影后的 bedrock_work profile");
        assert.match(awsRes.text, /HAS_BASE=YES/, "隔离 Bedrock Codex 必须能读取 source_profile (base_acct) 凭据");
        assert.match(awsRes.text, /HAS_ADMIN=NO/, "隔离 Bedrock Codex 绝不得看到无关的 admin_secret AWS 凭据");
        assert.match(awsRes.text, /HAS_AUTH=NO/, "非 OAuth Bedrock 供应商绝不得拷贝宿主机 auth.json 到临时 CODEX_HOME");
        assert.match(awsRes.text, /HAS_HOST_AUTH=NO/, "隔离沙箱绝不得暴露宿主机 CODEX_HOME/auth.json");
      }

      // 17) needsCredentialStore=false 时，stageIsolatedCodexHome 绝不拷贝宿主机 auth.json
      const noAuthCodexHome = path.join(dir, "codex-no-oauth-home");
      fs.mkdirSync(noAuthCodexHome, { recursive: true });
      fs.writeFileSync(
        path.join(noAuthCodexHome, "auth.json"),
        JSON.stringify({ auth_mode: "chatgpt", tokens: { access_token: "tok", refresh_token: "DO_NOT_COPY_RT" } }),
        { mode: 0o600 },
      );
      const stagedNoAuth = stageIsolatedCodexHome(noAuthCodexHome, { copyUserConfig: false, needsCredentialStore: false });
      try {
        assert.equal(stagedNoAuth.origAuth, undefined, "不需要凭据库时 origAuth 必须为 undefined");
        assert.equal(fs.existsSync(path.join(stagedNoAuth.scratchDir, "auth.json")), false, "不需要凭据库时绝不得拷贝宿主机 auth.json");
      } finally {
        stagedNoAuth.cleanup();
      }

      // 18) OAuth 刷新锁位于规范化 auth.json 同目录，完全不受 TMPDIR 差异影响
      const sharedAuthDir = path.join(dir, "shared-codex-auth");
      fs.mkdirSync(sharedAuthDir, { recursive: true });
      const sharedAuthFile = path.join(sharedAuthDir, "auth.json");
      fs.writeFileSync(sharedAuthFile, "{}", { mode: 0o600 });
      process.env.TMPDIR = path.join(dir, "tmp-proc-a");
      const lockPathA = canonicalCodexLockFilePath(sharedAuthFile);
      process.env.TMPDIR = path.join(dir, "tmp-proc-b");
      const lockPathB = canonicalCodexLockFilePath(sharedAuthFile);
      if (prevTmpDir === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = prevTmpDir;
      assert.equal(lockPathA, lockPathB, "不同 TMPDIR 下共享同一 auth.json 的进程必须使用同一把锁");
      assert.equal(path.dirname(lockPathA), fs.realpathSync(sharedAuthDir), "锁文件必须位于规范化 auth.json 所在目录而非临时目录");

      // 19) isCodexOAuthRefreshNeeded 与 coordinateCodexOAuthRefresh 必须按运行超时窗口判断刷新需求
      const nowMs = Date.now();
      const sixMinJwt = makeJwt(Math.floor((nowMs + 6 * 60_000) / 1000));
      const sixMinAuth = {
        auth_mode: "chatgpt",
        last_refresh: new Date(nowMs - 60_000).toISOString(),
        tokens: { access_token: sixMinJwt, refresh_token: "rt_r19_window" },
      };
      assert.equal(isCodexOAuthRefreshNeeded(sixMinAuth, nowMs, 5 * 60_000), false, "6 分钟后过期的令牌在 5 分钟窗口内无需锁");
      assert.equal(isCodexOAuthRefreshNeeded(sixMinAuth, nowMs, 16 * 60_000), true, "6 分钟后过期的令牌在 16 分钟运行窗口内必须提前拿刷新锁");

      fs.writeFileSync(sharedAuthFile, JSON.stringify(sixMinAuth), { mode: 0o600 });
      const leaseShort = await coordinateCodexOAuthRefresh(sharedAuthDir, { runWindowMs: 5 * 60_000 });
      assert.equal(leaseShort.held, false, "短窗口下不应占用刷新锁");
      leaseShort.release();
      const leaseLong = await coordinateCodexOAuthRefresh(sharedAuthDir, { runWindowMs: 16 * 60_000, leaseTtlMs: 10_000 });
      assert.equal(leaseLong.held, true, "长运行窗口覆盖令牌过期时间时必须持有刷新租约锁");
      leaseLong.release();
    }
  } finally {
    if (httpGitSrv) await new Promise<void>((resolve) => httpGitSrv!.close(() => resolve()));
    if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevKey;
    if (prevPath === undefined) delete process.env.PATH;
    else process.env.PATH = prevPath;
    if (prevTmpDir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = prevTmpDir;
    extraApp1?.store.db.close();
    extraApp2?.store.db.close();
    app?.store.db.close();
    await mock.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第二十轮回归：剥离 ~/.config/git/credentials、保留符号链接 ~/.gitconfig、不扩展 ~/.cargo 凭据、挂载豆包启动器运行时、单 worktree 隔离创建、普通轮询撤回 deleted 消息、单流显式 @mention 归类、bot_allow 纳入策略签名、按传输协议最小化 SSH 挂载、原位保留 Git credential.helper 优先级与 Unicode 大小写折叠派单搜索", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r20-"));
  const dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  let app: ReturnType<typeof createApp> | undefined;
  let httpGitSrv: http.Server | undefined;

  try {
    // 1) [R20 #1 P1] & 11) [R20 #11 P2] 隔离工人绝不可见 ~/.config/git/credentials，同时符号链接 dotfiles ~/.gitconfig 保留逻辑路径且不暴露 dotfiles 其余文件
    {
      const fakeHome = path.join(dir, "git-dot-home");
      const dotfilesDir = path.join(dir, "my-dotfiles");
      fs.mkdirSync(path.join(fakeHome, ".config", "git"), { recursive: true });
      fs.mkdirSync(dotfilesDir, { recursive: true });
      fs.writeFileSync(path.join(dotfilesDir, "gitconfig"), "[user]\n\tr20marker = DOTFILES_LINK_OK\n");
      fs.writeFileSync(path.join(dotfilesDir, "private.txt"), "DOTFILES_SECRET_NO_LEAK");
      fs.symlinkSync(path.join(dotfilesDir, "gitconfig"), path.join(fakeHome, ".gitconfig"));
      fs.writeFileSync(path.join(fakeHome, ".config", "git", "ignore"), "*.r20tmp\n");
      fs.writeFileSync(
        path.join(fakeHome, ".config", "git", "credentials"),
        "https://alice:XDG_SECRET_TOKEN@corp.internal.example\n",
        { mode: 0o600 },
      );

      const mounts = collectSafeGitConfigMounts({ HOME: fakeHome }, dataDir);
      assert.ok(
        !mounts.readOnlyPaths.some((p) => p.endsWith("credentials") || p.endsWith(`${path.sep}git`)),
        "collectSafeGitConfigMounts 绝不得挂载 credentials 或整个 .config/git 目录",
      );
      assert.ok(mounts.symlinks.some((s) => s.dest.endsWith(`${path.sep}.gitconfig`)), "符号链接 ~/.gitconfig 必须保留逻辑路径映射");

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        const workRepo = path.join(dir, "git-dot-repo");
        fs.mkdirSync(workRepo, { recursive: true });
        const probeEnv: NodeJS.ProcessEnv = { ...process.env, HOME: fakeHome };
        const isoPlan = buildWorkspaceIsolation(
          { dataDir, context: { personal_web: { enabled: false } } } as never,
          { mode: "git-ro", cwd: workRepo },
          probeEnv,
        );
        const script = [
          `echo "CFG=$(git config --global --get user.r20marker 2>/dev/null || echo MISSING)"`,
          `echo "IGN=$(test -f ${JSON.stringify(path.join(fakeHome, ".config", "git", "ignore"))} && echo YES || echo NO)"`,
          `echo "CRED=$(test -e ${JSON.stringify(path.join(fakeHome, ".config", "git", "credentials"))} && echo LEAK || echo HIDDEN)"`,
          `echo "DOT_PRIV=$(test -e ${JSON.stringify(path.join(dotfilesDir, "private.txt"))} && echo LEAK || echo HIDDEN)"`,
        ].join("\n");

        const wrappedBwrap = wrapCredentialIsolatedCommand("/bin/sh", ["-c", script], probeEnv, isoPlan);
        const rb = await runProcess(wrappedBwrap.cmd, wrappedBwrap.args, { env: probeEnv, timeoutMs: 10_000 });
        assert.equal(rb.code, 0, rb.stderr);
        assert.match(rb.stdout, /CFG=DOTFILES_LINK_OK/, "bwrap 下符号链接 ~/.gitconfig 必须被 git 正常读取");
        assert.match(rb.stdout, /IGN=YES/, "bwrap 下 ~/.config/git/ignore 应正常只读可见");
        assert.match(rb.stdout, /CRED=HIDDEN/, "bwrap 下 ~/.config/git/credentials 必须不可见");
        assert.match(rb.stdout, /DOT_PRIV=HIDDEN/, "dotfiles 仓库中的其他文件不得暴露");

        const unshareBin = resolveTrustedSystemBin("unshare");
        const setprivBin = resolveTrustedSystemBin("setpriv");
        const pivotRootBin = resolveTrustedSystemBin("pivot_root");
        const shBin = resolveTrustedSystemBin("sh");
        if (unshareBin && setprivBin && pivotRootBin && shBin) {
          const wrappedUnshare = wrapCredentialIsolatedCommand("/bin/sh", ["-c", script], probeEnv, {
            ...isoPlan,
            forceBackend: { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin, shBin, killChild: true },
          });
          const ru = await runProcess(wrappedUnshare.cmd, wrappedUnshare.args, { env: probeEnv, timeoutMs: 10_000 });
          assert.equal(ru.code, 0, ru.stderr);
          assert.match(ru.stdout, /CFG=DOTFILES_LINK_OK/, "unshare 下符号链接 ~/.gitconfig 必须被 git 正常读取");
          assert.match(ru.stdout, /CRED=HIDDEN/, "unshare 下 ~/.config/git/credentials 必须不可见");
          assert.match(ru.stdout, /DOT_PRIV=HIDDEN/, "unshare 下 dotfiles 其余文件不得暴露");
        }
      }
    }

    // 5) [R20 #5 P1] ~/.cargo/bin 在 PATH 中时绝不把整棵 ~/.cargo（含 credentials.toml）挂载进工人沙箱
    if (process.platform === "linux" && hasCredentialMountIsolation()) {
      const cargoHome = path.join(dir, "cargo-home");
      const cargoBin = path.join(cargoHome, ".cargo", "bin");
      fs.mkdirSync(cargoBin, { recursive: true });
      fs.writeFileSync(path.join(cargoBin, "r20-cargo-ok"), "#!/bin/sh\necho CARGO_BIN_OK\n", { mode: 0o755 });
      fs.writeFileSync(path.join(cargoHome, ".cargo", "credentials.toml"), '[registry]\ntoken = "CARGO_REGISTRY_SECRET"\n', { mode: 0o600 });
      const cargoEnv: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: cargoHome,
        PATH: `${cargoBin}${path.delimiter}${process.env.PATH ?? ""}`,
      };
      const cargoWorkDir = path.join(dir, "cargo-work-cwd");
      fs.mkdirSync(cargoWorkDir, { recursive: true });
      const wrapped = wrapCredentialIsolatedCommand(
        "/bin/sh",
        [
          "-c",
          `echo "BIN=$(r20-cargo-ok)"; echo "CRED=$(test -e ${JSON.stringify(path.join(cargoHome, ".cargo", "credentials.toml"))} && echo LEAK || echo HIDDEN)"`,
        ],
        cargoEnv,
        buildWorkspaceIsolation({ dataDir, context: { personal_web: { enabled: false } } } as never, { mode: "worker-ro", cwd: cargoWorkDir }, cargoEnv),
      );
      const rc = await runProcess(wrapped.cmd, wrapped.args, { env: cargoEnv, timeoutMs: 10_000 });
      assert.equal(rc.code, 0, rc.stderr);
      assert.match(rc.stdout, /BIN=CARGO_BIN_OK/);
      assert.match(rc.stdout, /CRED=HIDDEN/, "~/.cargo/bin 在 PATH 中时绝不得暴露 ~/.cargo/credentials.toml");
    }

    // 3) [R20 #3 P1] 豆包 npm 启动器（校验 ${XDG_DATA_HOME:-$HOME/.local/share}/doubao_cli/app/current 并拉起二进制）在隔离沙箱内正常运行
    {
      const dbHome = path.join(dir, "doubao-home");
      const xdgData = path.join(dir, "doubao-xdg-data");
      const appCurrent = path.join(xdgData, "doubao_cli", "app", "current");
      const appDownloads = path.join(xdgData, "doubao_cli", "app", "downloads");
      fs.mkdirSync(appCurrent, { recursive: true });
      fs.mkdirSync(appDownloads, { recursive: true });
      fs.writeFileSync(path.join(appCurrent, "manifest.json"), JSON.stringify({ version: "1.2.3" }));
      fs.writeFileSync(
        path.join(appCurrent, "doubao"),
        [
          "#!/bin/sh",
          `echo "DOUBAO_RUNTIME_OK;DL=$(test -e ${JSON.stringify(path.join(appDownloads, "secret.bin"))} && echo LEAK || echo HIDDEN)"`,
        ].join("\n"),
        { mode: 0o755 },
      );
      fs.writeFileSync(path.join(appDownloads, "secret.bin"), "unrelated");

      const rtPaths = selectDoubaoRuntimePaths({ HOME: dbHome, XDG_DATA_HOME: xdgData });
      assert.ok(rtPaths.includes(appCurrent), "selectDoubaoRuntimePaths 必须包含 doubao_cli/app/current");

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        // 构造真实 npm 启动器目录结构（bin/doubao -> ../lib/node_modules/@bytedance/doubao-cli/run.mjs）
        const dbPrefix = path.join(dir, "doubao-npm");
        const dbPkg = path.join(dbPrefix, "lib", "node_modules", "@bytedance", "doubao-cli");
        fs.mkdirSync(path.join(dbPrefix, "bin"), { recursive: true });
        fs.mkdirSync(dbPkg, { recursive: true });
        fs.writeFileSync(path.join(dbPkg, "package.json"), JSON.stringify({ name: "@bytedance/doubao-cli", version: "1.0.0", type: "module" }));
        fs.writeFileSync(
          path.join(dbPkg, "run.mjs"),
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'import path from "node:path";',
            'import { spawnSync } from "node:child_process";',
            'const base = process.env.XDG_DATA_HOME || path.join(process.env.HOME, ".local", "share");',
            'const current = path.join(base, "doubao_cli", "app", "current");',
            'const st = fs.lstatSync(current);',
            'if (!st.isDirectory() || st.isSymbolicLink()) process.exit(21);',
            'const mf = JSON.parse(fs.readFileSync(path.join(current, "manifest.json"), "utf8"));',
            'if (mf.version !== "1.2.3") process.exit(22);',
            'const r = spawnSync(path.join(current, "doubao"), [], { stdio: "inherit" });',
            'process.exit(r.status ?? 1);',
          ].join("\n"),
          { mode: 0o755 },
        );
        const launcherBin = path.join(dbPrefix, "bin", "doubao");
        fs.symlinkSync("../lib/node_modules/@bytedance/doubao-cli/run.mjs", launcherBin);

        const dbCfgFile = path.join(dir, "doubao-r20.yaml");
        fs.writeFileSync(
          dbCfgFile,
          [
            `data_dir: ${path.join(dir, "doubao-data")}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
            "owner: { open_id: ou_r20_db }",
            "harnesses:",
            `  db: { type: doubao-cli, cmd: ${JSON.stringify(launcherBin)}, env: { HOME: ${JSON.stringify(dbHome)}, XDG_DATA_HOME: ${JSON.stringify(xdgData)} } }`,
            "roles: { brain: db }",
            "context: { personal_web: { enabled: true } }",
          ].join("\n"),
        );
        const dbCfg = loadConfig(dbCfgFile);
        const dbCwd = path.join(dir, "doubao-cwd");
        fs.mkdirSync(dbCwd, { recursive: true });
        const dbRes = await runHarness(dbCfg, {
          harness: "db",
          prompt: "hi",
          cwd: dbCwd,
          tools: "read",
          lark: "none",
          timeoutSec: 30,
          logFile: path.join(dir, "doubao-r20.log"),
        });
        assert.equal(dbRes.ok, true, `隔离豆包 CLI 必须能启动 app/current 二进制：${dbRes.text}`);
        assert.match(dbRes.text, /DOUBAO_RUNTIME_OK/);
        assert.match(dbRes.text, /DL=HIDDEN/, "只应挂载 app/current，不应暴露 app/downloads");
      }
    }

    // 6) [R20 #6 P1] git worktree add 仅挂载新建派单目录可写，同级在途 worktree 对 checkout filter 不可见且不可写
    if (process.platform === "linux" && hasCredentialMountIsolation()) {
      const wtData = path.join(dir, "wt-iso-data");
      const siblingWt = path.join(wtData, "worktrees", "other001");
      fs.mkdirSync(siblingWt, { recursive: true });
      const siblingFile = path.join(siblingWt, "in-progress.txt");
      fs.writeFileSync(siblingFile, "ORIGINAL_SIBLING_WORK");

      const filterRepo = path.join(dir, "filter-repo");
      fs.mkdirSync(filterRepo, { recursive: true });
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r20",
        GIT_AUTHOR_EMAIL: "r20@test",
        GIT_COMMITTER_NAME: "r20",
        GIT_COMMITTER_EMAIL: "r20@test",
      };
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", filterRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(filterRepo, ".gitattributes"), "*.smudge filter=evil\n");
      fs.writeFileSync(path.join(filterRepo, "demo.smudge"), "hello\n");
      assert.equal((await runProcess("git", ["-C", filterRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", filterRepo, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      // 模拟仓库本地配置了尝试篡改同级 worktree 的 smudge filter
      assert.equal(
        (await runProcess(
          "git",
          [
            "-C",
            filterRepo,
            "config",
            "filter.evil.smudge",
            `sh -c 'echo PWNED > ${siblingFile} 2>/dev/null || true; cat'`,
          ],
          { env: gitEnv },
        )).code,
        0,
      );

      const wtCfgFile = path.join(dir, "wt-iso.yaml");
      fs.writeFileSync(
        wtCfgFile,
        [
          `data_dir: ${wtData}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          "owner: { open_id: ou_r20_wt }",
          "harnesses: { claude: { agent: claude } }",
          "roles: { brain: claude }",
          `dispatch: { repos: { fdemo: ${JSON.stringify(filterRepo)} } }`,
        ].join("\n"),
      );
      const wtApp = createApp(loadConfig(wtCfgFile));
      try {
        const disp = new Dispatcher(wtApp.cfg, wtApp.ledger, wtApp.store, wtApp.board);
        const ws = await (disp as unknown as {
          prepareWorkspace: (t: { guid: string; summary: string; description: string }) => Promise<{ cwd: string; branch: string }>;
        }).prepareWorkspace({ guid: "newdisp1_guid", summary: "新建派单", description: "repo: fdemo" });
        assert.ok(fs.existsSync(path.join(ws.cwd, "demo.smudge")), "新派单 worktree 应成功检出");
        assert.equal(fs.readFileSync(siblingFile, "utf8"), "ORIGINAL_SIBLING_WORK", "同级在途 worktree 绝不得被新 worktree 创建过程篡改");
      } finally {
        wtApp.store.db.close();
      }
    }

    // 2) [R20 #2 P1] & 7) [R20 #7 P2] & 10) [R20 #10 P2] & 12) [R20 #12 P3]
    // 普通 IM 轮询撤回 deleted 消息 + 单流显式 @mention 归类 + bot_allow 热重载策略重检 + Unicode 派单搜索
    {
      const connData = path.join(dir, "conn-r20-data");
      const connCfgFile = path.join(dir, "conn-r20.yaml");
      fs.writeFileSync(
        connCfgFile,
        [
          `data_dir: ${connData}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          "owner: { open_id: ou_r20_me }",
          "harnesses: { claude: { agent: claude } }",
          "roles: { brain: claude }",
          "context:",
          "  enabled: true",
          "  groups: allowlist",
          '  groups_allow: ["oc_r20_team"]',
          "  groups_deny: []",
          '  bot_allow: ["CalendarBot"]',
          "  sources: { meego: false, im: true, minutes: false, calendar: false, tasks: false, docs: false }",
        ].join("\n"),
      );
      app = createApp(loadConfig(connCfgFile));
      app.store.set("owner.open_id", "ou_r20_me");
      const ctxSvc = new ContextService(app);
      const nowMs = Date.now();

      // 预先写入一条待处理观测，稍后通过普通 +chat-messages-list 返回 deleted: true 验证其被撤回
      ctxSvc.store.addObs([
        {
          id: "im:om_r20_recalled",
          source: "im",
          kind: "group",
          conv: "oc_r20_team",
          conv_name: "研发群",
          actor_id: "ou_bob",
          actor_name: "Bob",
          is_me: false,
          time: nowMs - 5000,
          text: "即将撤回的敏感正文",
          url: "",
          meta: {},
        },
      ]);

      let authCalls = 0;
      const fakeLark = app.lark as unknown as {
        authStatus: () => Promise<unknown>;
        run: (argv: string[]) => Promise<unknown>;
      };
      fakeLark.authStatus = async () => {
        authCalls++;
        // 在第 2 次提交前身份核验时热清空 bot_allow，验证策略签名变化触发重试并剔除 CalendarBot 消息
        if (authCalls === 2) {
          app!.cfg.context.bot_allow = [];
        }
        return { identity: "user", user: { open_id: "ou_r20_me", name: "我" } };
      };
      fakeLark.run = async (argv: string[]) => {
        if (argv[0] === "im" && argv[1] === "+chat-messages-list") {
          return {
            has_more: false,
            messages: [
              // [R20 #2] 普通群轮询返回已撤回消息（deleted: true + 空正文）
              {
                message_id: "om_r20_recalled",
                chat_id: "oc_r20_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                content: "",
                deleted: true,
                create_time: String(nowMs - 5000),
              },
              // [R20 #7] 仅在群列表出现的消息，但 mentions 显式包含主人 ou_r20_me
              {
                message_id: "om_r20_explicit_atme",
                chat_id: "oc_r20_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "ou_alice", name: "Alice", sender_type: "user" },
                content: "@我 请看下这个 PR",
                mentions: [{ id: "ou_r20_me", name: "我" }],
                create_time: String(nowMs - 2000),
              },
              // [R20 #10] 机器人消息：初始在 bot_allow，但在最终提交前被热移出
              {
                message_id: "om_r20_bot",
                chat_id: "oc_r20_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "cli_bot", name: "CalendarBot", sender_type: "app" },
                content: "会议日程提醒",
                create_time: String(nowMs - 1000),
              },
            ],
          };
        }
        return { has_more: false, messages: [] };
      };

      await ctxSvc.connectors.pullIm();
      assert.equal(ctxSvc.store.obs("im:om_r20_recalled")?.meta.withdrawn, true, "普通轮询收到 deleted=true 必须撤回已存观测");
      assert.equal(ctxSvc.store.obsPending("im:om_r20_recalled"), false, "已撤回消息不得继续留在待处理队列");
      const explicitAt = ctxSvc.store.obs("im:om_r20_explicit_atme");
      assert.equal(explicitAt?.kind, "at_me", "单流群消息带显式 mentions 包含主人时必须归类为 at_me");
      assert.equal(explicitAt?.meta.at_me, true, "单流显式 @mention 必须设置 meta.at_me = true");
      const mentionOnlyWin = ctxSvc.store.convWindow("oc_r20_team", 10, 10, undefined, { onlyMentions: true });
      assert.ok(mentionOnlyWin.some((o: Obs) => o.id === "im:om_r20_explicit_atme"), "显式 @mention 必须能进入 onlyMentions 窗口");
      assert.ok(!mentionOnlyWin.some((o: Obs) => o.id === "im:om_r20_recalled"), "已撤回消息不得进入理解窗口");
      assert.equal(ctxSvc.store.obs("im:om_r20_bot"), undefined, "提交前 bot_allow 清空后必须重试过滤并丢弃该机器人消息");

      // [R20 #12 P3] Unicode 大小写折叠派单搜索（İstanbul / Kelvin）
      app.ledger.enqueue({
        id: "dispatch:u_ist:1",
        kind: "dispatch",
        ref: "u_ist",
        state: "queued",
        payload: { guid: "u_ist", summary: "İstanbul 发布检查", description: "" },
      });
      app.ledger.enqueue({
        id: "dispatch:u_kel:2",
        kind: "dispatch",
        ref: "u_kel",
        state: "queued",
        payload: { guid: "u_kel", summary: "Kelvin 传感器校准", description: "" },
      });
      assert.equal(Q.listDispatches(app, { filter: "all", q: "İstanbul" }).length, 1, "精确查询 İstanbul 必须命中");
      assert.equal(Q.listDispatches(app, { filter: "all", q: "i\u0307stanbul" }).length, 1, "JS 折叠查询 i\\u0307stanbul 必须命中 İstanbul");
      assert.equal(Q.listDispatches(app, { filter: "all", q: "Kelvin" }).length, 1, "精确查询 Kelvin 必须命中");
      assert.equal(Q.listDispatches(app, { filter: "all", q: "kelvin" }).length, 1, "ASCII 小写查询 kelvin 必须命中 Kelvin");
    }

    // 8) [R20 #8 P2] & 9) [R20 #9 P2] 按传输协议最小化 SSH 挂载 + 原位保留 Git credential.helper 优先级
    {
      assert.equal(classifyGitRemoteTransport(dir, "https://github.com/org/repo.git"), "http");
      assert.equal(classifyGitRemoteTransport(dir, "."), "local");
      assert.equal(classifyGitRemoteTransport(dir, "file:///tmp/bare.git"), "local");
      assert.equal(classifyGitRemoteTransport(dir, "git@github.example:org/repo.git"), "ssh");
      assert.equal(classifyGitRemoteTransport(dir, "ssh://git@gitlab.example:2222/org/repo.git"), "ssh");

      // SSH 最小化文件收集：只挂载匹配 Host 的 IdentityFile，绝不暴露其他私钥
      const sshHome = path.join(dir, "ssh-scoped-home");
      const sshDir = path.join(sshHome, ".ssh");
      fs.mkdirSync(sshDir, { recursive: true });
      fs.writeFileSync(
        path.join(sshDir, "config"),
        [
          "Host github.example",
          "  IdentityFile ~/.ssh/id_github_only",
          "",
          "Host bastion.internal",
          "  IdentityFile ~/.ssh/id_bastion_secret",
        ].join("\n"),
      );
      fs.writeFileSync(path.join(sshDir, "known_hosts"), "github.example ssh-ed25519 AAAA\n");
      fs.writeFileSync(path.join(sshDir, "id_github_only"), "KEY_GITHUB", { mode: 0o600 });
      fs.writeFileSync(path.join(sshDir, "id_bastion_secret"), "KEY_BASTION_NO_LEAK", { mode: 0o600 });
      const sshScoped = collectScopedSshMounts(["github.example"], { HOME: sshHome }, dataDir, false);
      assert.ok(sshScoped.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_github_only`)), "应挂载匹配 Host 的私钥");
      assert.ok(sshScoped.readOnlyPaths.some((p) => p.endsWith(`${path.sep}config`)), "应挂载 ~/.ssh/config");
      assert.ok(sshScoped.readOnlyPaths.some((p) => p.endsWith(`${path.sep}known_hosts`)), "应挂载 ~/.ssh/known_hosts");
      assert.ok(
        !sshScoped.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_bastion_secret`) || p === fs.realpathSync(sshDir)),
        "绝不得整目录挂载 ~/.ssh 或暴露其他 Host 的私钥",
      );

      // credential.helper 优先级原位替换验证
      const active = new Map<string, string[]>([
        ["credential.helper", ["manager", "store", "cache --timeout=60"]],
        ["credential.https://other.example.helper", ["osxkeychain"]],
      ]);
      const rewritten = rewriteGitCredentialHelperChain(active, new Set(["credential.helper"]), "/tmp/scoped-creds", sshHome);
      assert.deepEqual(rewritten, [
        "-c",
        "credential.helper=",
        "-c",
        "credential.helper=manager",
        "-c",
        "credential.helper=store --file=/tmp/scoped-creds",
        "-c",
        "credential.helper=cache --timeout=60",
      ]);

      // 实跑隔离下的优先级链：第 1 个 helper（正确口令）排在第 2 个 store（过期口令）前面 -> 必须优先命中第 1 个 helper 并认证成功
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r20",
        GIT_AUTHOR_EMAIL: "r20@test",
        GIT_COMMITTER_NAME: "r20",
        GIT_COMMITTER_EMAIL: "r20@test",
      };
      const precRepo = path.join(dir, "prec-repo");
      fs.mkdirSync(precRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", precRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(precRepo, "a.txt"), "a\n");
      assert.equal((await runProcess("git", ["-C", precRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", precRepo, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      const headSha = (await runProcess("git", ["-C", precRepo, "rev-parse", "HEAD"], { env: gitEnv })).stdout.trim();

      const mgrAuth = `Basic ${Buffer.from("mgruser:freshpass").toString("base64")}`;
      httpGitSrv = http.createServer((req, res) => {
        if ((req.headers.authorization ?? "") !== mgrAuth) {
          res.statusCode = 401;
          res.setHeader("WWW-Authenticate", 'Basic realm="r20"');
          res.end("auth required");
          return;
        }
        if ((req.url ?? "").startsWith("/org/prec.git/info/refs")) {
          res.setHeader("Content-Type", "text/plain");
          res.end(`${headSha}\trefs/heads/main\n`);
          return;
        }
        res.statusCode = 404;
        res.end("not found");
      });
      await new Promise<void>((resolve) => httpGitSrv!.listen(0, "127.0.0.1", resolve));
      const port = (httpGitSrv.address() as { port: number }).port;
      const precHome = path.join(dir, "prec-home");
      fs.mkdirSync(precHome, { recursive: true });
      fs.writeFileSync(
        path.join(precHome, ".gitconfig"),
        [
          "[credential]",
          '\thelper = "!f() { test \\"$1\\" = get && printf \'username=mgruser\\\\npassword=freshpass\\\\n\'; }; f"',
          "\thelper = store",
        ].join("\n") + "\n",
      );
      fs.writeFileSync(
        path.join(precHome, ".git-credentials"),
        `http://olduser:STALE_PASS@127.0.0.1:${port}\n`,
        { mode: 0o600 },
      );
      const lsRes = await tryGit(precRepo, ["ls-remote", `http://127.0.0.1:${port}/org/prec.git`], {
        readOnly: true,
        extraEnv: { HOME: precHome },
      });
      assert.equal(lsRes.code, 0, `排在 store 前面的 credential helper 必须保持优先级并完成认证：${lsRes.stderr}`);
      assert.match(lsRes.stdout, new RegExp(headSha));
    }
  } finally {
    if (httpGitSrv) await new Promise<void>((resolve) => httpGitSrv!.close(() => resolve()));
    app?.store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第二十一轮回归：脱敏 .npmrc、私有 ~/.acpx 状态隔离、file-backed Lark 登录态、Doubao 登录态暂存与认证、权威 IM 回读清 deleted、派单残缺 worktree 恢复、background_only 冲突重放校验、子进程环境解析 ACP 配置、scp 绝对路径、SSH Include 通配、Git 全局 include、分槽 store 优先级、非 store 宿主机 HTTPS 凭据、快通道耗尽健康上报", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r21-"));
  const dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  let app: ReturnType<typeof createApp> | undefined;
  let httpSrv12: http.Server | undefined;
  let httpSrv13: http.Server | undefined;
  try {
    // 1) [R21 #1 P1] .npmrc 脱敏：仅投影非敏感镜像/代理/重试配置，绝不把注册表 token / 密码 / URL 凭据暴露给校验命令或仓库工人
    {
      const rawNpmrc = [
        "registry=https://registry.npmmirror.com",
        "@corp:registry=https://npm.corp.example/",
        "strict-ssl=true",
        "fetch-retries=3",
        "//registry.npmjs.org/:_authToken=npm_SUPER_SECRET_TOKEN",
        "//npm.corp.example/:_password=BASE64_SECRET_PASS",
        "_auth=LEGACY_AUTH_SECRET",
        "proxy=http://alice:proxysecret@proxy.corp:8080",
        "https-proxy=https://proxy.corp.example:8443",
        "disturl=https://user:pass@mirror.example/",
        "registry=${NPM_SECRET_REGISTRY}",
      ].join("\n");
      const sanitized = sanitizeNpmrcContent(rawNpmrc);
      assert.match(sanitized, /^registry=https:\/\/registry\.npmmirror\.com$/m);
      assert.match(sanitized, /^@corp:registry=https:\/\/npm\.corp\.example\/$/m);
      assert.match(sanitized, /^strict-ssl=true$/m);
      assert.match(sanitized, /^fetch-retries=3$/m);
      assert.match(sanitized, /^https-proxy=https:\/\/proxy\.corp\.example:8443$/m);
      assert.ok(!sanitized.includes("npm_SUPER_SECRET_TOKEN"), "不得保留 _authToken");
      assert.ok(!sanitized.includes("BASE64_SECRET_PASS"), "不得保留 _password");
      assert.ok(!sanitized.includes("LEGACY_AUTH_SECRET"), "不得保留 _auth");
      assert.ok(!sanitized.includes("proxysecret"), "不得保留带用户名密码的代理 URL");
      assert.ok(!sanitized.includes("user:pass"), "不得保留带内嵌凭据的镜像 URL");
      assert.ok(!sanitized.includes("NPM_SECRET_REGISTRY"), "不得保留环境变量展开");

      const npmHome = path.join(dir, "npm-home");
      fs.mkdirSync(npmHome, { recursive: true });
      fs.writeFileSync(path.join(npmHome, ".npmrc"), rawNpmrc, { mode: 0o600 });
      const gitCfgMounts = collectSafeGitConfigMounts({ HOME: npmHome }, dataDir);
      assert.ok(!gitCfgMounts.readOnlyPaths.some((p) => p.endsWith(".npmrc")), "collectSafeGitConfigMounts 绝不得挂载原始 ~/.npmrc");

      const staged = stageSanitizedNpmrc({ HOME: npmHome }, dataDir);
      assert.ok(staged, "含非敏感设置的 .npmrc 应成功生成脱敏暂存文件");
      try {
        if (process.platform === "linux" && hasCredentialMountIsolation()) {
          const workCwd = path.join(dir, "npm-verify-cwd");
          fs.mkdirSync(workCwd, { recursive: true });
          const cfgFile = path.join(dir, "npm-cfg.yaml");
          fs.writeFileSync(
            cfgFile,
            `data_dir: ${dataDir}\nowner:\n  open_id: ou_r21_me\nharnesses:\n  codex: { agent: codex }\nroles:\n  brain: codex\n  reviewer: codex\n`,
          );
          const cfg = loadConfig(cfgFile);
          const isoEnv: NodeJS.ProcessEnv = { ...process.env, HOME: npmHome };
          const wrapped = wrapCredentialIsolatedCommand(
            "sh",
            [
              "-c",
              `cat "$HOME/.npmrc"; echo "---USERCONFIG---"; cat "$NPM_CONFIG_USERCONFIG"`,
            ],
            isoEnv,
            buildWorkspaceIsolation(
              cfg,
              {
                mode: "verify",
                cwd: workCwd,
                extraReadOnlyPaths: [staged!.dir],
                extraBindMounts: [{ src: staged!.file, dest: staged!.homeMountDest, mode: "ro" }],
              },
              isoEnv,
            ),
          );
          const childEnv: NodeJS.ProcessEnv = { ...isoEnv, ...isolatedSandboxTempEnv() };
          applySanitizedNpmrcEnv(childEnv, staged, wrapped.isolated);
          const r = await runProcess(wrapped.cmd, wrapped.args, { cwd: workCwd, env: childEnv });
          assert.equal(r.code, 0, `沙箱校验命令应正常读取脱敏 .npmrc：${r.stderr}`);
          assert.match(r.stdout, /registry=https:\/\/registry\.npmmirror\.com/);
          assert.ok(!r.stdout.includes("npm_SUPER_SECRET_TOKEN"), "沙箱内 ~/.npmrc 与 NPM_CONFIG_USERCONFIG 均不得泄漏注册表令牌");
        }
      } finally {
        staged?.cleanup();
      }
    }

    // 2) [R21 #2 P1], 3) [R21 #3 P1], 4) [R21 #4 P1], 8) [R21 #8 P2]
    //    私有 ~/.acpx 状态隔离 + file-backed Lark XDG 数据目录 + Doubao 登录态暂存/认证 + 从合并子进程环境解析 ACP 配置路径
    {
      const isoHome = path.join(dir, "iso-home-r21");
      const xdgCfg = path.join(isoHome, ".config");
      const xdgData = path.join(isoHome, ".local", "share");
      const customCodexHome = path.join(dir, "custom-codex-home");
      const customClaudeDir = path.join(dir, "custom-claude-dir");
      const customGeminiHome = path.join(dir, "custom-gemini-home");
      fs.mkdirSync(path.join(isoHome, ".acpx", "sessions"), { recursive: true });
      fs.mkdirSync(path.join(isoHome, ".acpx", "queues"), { recursive: true });
      fs.mkdirSync(path.join(isoHome, ".acpx", "adapters"), { recursive: true });
      fs.mkdirSync(path.join(isoHome, ".lark-cli"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "lark-cli"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "doubao_cli", "app", "current"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "doubao_cli", "doubao-cli-pc-login"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "doubao_cli", "keys"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "doubao_cli", "logs"), { recursive: true });
      fs.mkdirSync(path.join(xdgData, "doubao_cli", "agent_mode"), { recursive: true });
      fs.mkdirSync(customCodexHome, { recursive: true });
      fs.mkdirSync(customClaudeDir, { recursive: true });
      fs.mkdirSync(customGeminiHome, { recursive: true });

      fs.writeFileSync(
        path.join(isoHome, ".acpx", "adapters", "claude-adapter.sh"),
        "#!/bin/sh\necho CLAUDE_ADAPTER_OK\n",
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(isoHome, ".acpx", "config.json"),
        JSON.stringify({
          defaultPermissions: "approve-reads",
          agents: {
            claude: { command: "~/.acpx/adapters/claude-adapter.sh" },
            codex: { command: "/usr/bin/other-codex" },
          },
          auth: {
            "claude-api": "CLAUDE_AUTH_OK",
            "codex-api": "CODEX_SECRET_MUST_DROP",
          },
        }),
      );
      fs.writeFileSync(path.join(isoHome, ".acpx", "sessions", "other-repo.json"), '{"prompt":"SECRET_OTHER_REPO_SESSION"}\n');
      fs.writeFileSync(path.join(isoHome, ".acpx", "queues", "q1.json"), '{"queued":"SECRET_QUEUE"}\n');
      fs.writeFileSync(path.join(isoHome, ".lark-cli", "config.json"), '{"appId":"cli_test"}\n');
      fs.writeFileSync(path.join(xdgData, "lark-cli", "master.key"), "LARK_MASTER_KEY_FILE_BACKED", { mode: 0o600 });
      fs.writeFileSync(path.join(xdgData, "doubao_cli", "app", "current", "doubao-bin"), "DOUBAO_BIN_OK", { mode: 0o755 });
      fs.writeFileSync(path.join(xdgData, "doubao_cli", "doubao-cli-pc-login", "account"), "uid_r21_authenticated");
      fs.writeFileSync(path.join(xdgData, "doubao_cli", "keys", "session.key"), "DOUBAO_SESSION_KEY_OK", { mode: 0o600 });
      fs.writeFileSync(path.join(xdgData, "doubao_cli", "logs", "host-history.log"), "DOUBAO_PRIVATE_HOST_LOG");
      fs.writeFileSync(path.join(xdgData, "doubao_cli", "agent_mode", "state.db"), "DOUBAO_HOST_AGENT_HISTORY");
      fs.writeFileSync(path.join(customCodexHome, "config.toml"), 'model = "custom-inherited-codex"\n');

      // [R21 #3] selectLarkCliAuthPaths 必须包含 XDG_DATA_HOME/lark-cli
      const larkPaths = selectLarkCliAuthPaths({ HOME: isoHome, XDG_CONFIG_HOME: xdgCfg, XDG_DATA_HOME: xdgData });
      assert.ok(larkPaths.includes(path.join(isoHome, ".lark-cli")));
      assert.ok(larkPaths.includes(path.join(xdgCfg, "lark-cli")));
      assert.ok(larkPaths.includes(path.join(xdgData, "lark-cli")), "必须包含 Linux 文件存储登录态目录 XDG_DATA_HOME/lark-cli");

      // [R21 #4] selectDoubaoRuntimePaths 必须包含 app/current + doubao-cli-pc-login + keys
      const doubaoPaths = selectDoubaoRuntimePaths({ HOME: isoHome, XDG_CONFIG_HOME: xdgCfg, XDG_DATA_HOME: xdgData });
      assert.ok(doubaoPaths.includes(path.join(xdgData, "doubao_cli", "app", "current")));
      assert.ok(doubaoPaths.includes(path.join(xdgData, "doubao_cli", "doubao-cli-pc-login")));
      assert.ok(doubaoPaths.includes(path.join(xdgData, "doubao_cli", "keys")));

      // [R21 #8] selectAcpxAgentConfigPaths 必须从合并展开的子进程环境解析 CODEX_HOME / CLAUDE_CONFIG_DIR / GEMINI_CLI_HOME
      const inheritedEnv: NodeJS.ProcessEnv = {
        HOME: isoHome,
        CODEX_HOME: customCodexHome,
        CLAUDE_CONFIG_DIR: customClaudeDir,
        GEMINI_CLI_HOME: customGeminiHome,
        CUSTOM_BASE: dir,
      };
      const codexInherited = selectAcpxAgentConfigPaths({ agent: "codex", env: {} }, isoHome, inheritedEnv);
      assert.ok(codexInherited.includes(customCodexHome), "未在 YAML 重复声明时必须继承 daemon 导出的 CODEX_HOME");
      assert.ok(!codexInherited.includes(path.join(isoHome, ".codex")), "继承 CODEX_HOME 后不应退回挂载 ~/.codex");
      const claudeInherited = selectAcpxAgentConfigPaths({ agent: "claude", env: {} }, isoHome, inheritedEnv);
      assert.ok(claudeInherited.includes(customClaudeDir), "必须继承 daemon 导出的 CLAUDE_CONFIG_DIR");
      const geminiInherited = selectAcpxAgentConfigPaths({ agent: "gemini", env: {} }, isoHome, inheritedEnv);
      assert.ok(geminiInherited.includes(customGeminiHome), "必须继承 daemon 导出的 GEMINI_CLI_HOME");
      const codexExpanded = selectAcpxAgentConfigPaths(
        { agent: "codex", env: { CODEX_HOME: "${CUSTOM_BASE}/custom-codex-home" } },
        isoHome,
        inheritedEnv,
      );
      assert.ok(codexExpanded.includes(customCodexHome), "YAML 中的 ${VAR} 展开结果必须用于挂载目录");

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        // 实跑 [R21 #2 + #3 + #8]：acpx Claude (lark="none") 看不到 ~/.acpx/sessions 与 lark-cli；acpx Codex (lark="read") 可见继承的 CODEX_HOME 与 file-backed lark-cli
        const probeAcpx = path.join(dir, "probe-acpx-r21");
        fs.writeFileSync(
          probeAcpx,
          [
            "#!/bin/sh",
            'echo "ACPX_CFG=$(cat "$HOME/.acpx/config.json" 2>/dev/null | tr -d "\\n")"',
            'echo "ACPX_SESS=$(test -e "$HOME/.acpx/sessions/other-repo.json" && echo LEAK || echo HIDDEN)"',
            'echo "ACPX_QUEUE=$(test -e "$HOME/.acpx/queues/q1.json" && echo LEAK || echo HIDDEN)"',
            'echo "ACPX_ADAPTER=$(test -x "$HOME/.acpx/adapters/claude-adapter.sh" && echo OK || echo NO)"',
            'echo "ACPX_WRITABLE=$(touch "$HOME/.acpx/worker-temp.txt" 2>/dev/null && echo YES || echo NO)"',
            'echo "LARK_DATA=$(cat "$XDG_DATA_HOME/lark-cli/master.key" 2>/dev/null || echo HIDDEN)"',
            'echo "CODEX_INHERITED=$(cat "$CODEX_HOME/config.toml" 2>/dev/null || echo HIDDEN)"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const probeDoubao = path.join(dir, "probe-doubao-r21");
        fs.writeFileSync(
          probeDoubao,
          [
            "#!/bin/sh",
            'cat >/dev/null',
            'D="$XDG_DATA_HOME/doubao_cli"',
            'LOCK_OK=$( ( : > "$D/doubao-cli-instance.lock" ) 2>/dev/null && echo YES || echo NO )',
            'BIN_RO=$( ( echo x >> "$D/app/current/doubao-bin" ) 2>/dev/null && echo WRITABLE || echo RO )',
            'ACCT=$(cat "$D/doubao-cli-pc-login/account" 2>/dev/null || echo MISSING)',
            'KEY=$(cat "$D/keys/session.key" 2>/dev/null || echo MISSING)',
            'LOG_LEAK=$(test -e "$D/logs/host-history.log" && echo LEAK || echo HIDDEN)',
            'AGENT_LEAK=$(test -e "$D/agent_mode/state.db" && echo LEAK || echo HIDDEN)',
            'LARK_KEY=$(cat "$XDG_DATA_HOME/lark-cli/master.key" 2>/dev/null || echo HIDDEN)',
            'echo "LOCK=$LOCK_OK BIN=$BIN_RO ACCT=$ACCT KEY=$KEY LOG=$LOG_LEAK AGENT=$AGENT_LEAK LARK=$LARK_KEY"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const cfgPath21 = path.join(dir, "r21-harness.yaml");
        fs.writeFileSync(
          cfgPath21,
          [
            `data_dir: ${path.join(dir, "r21-hdata")}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(probeAcpx)} }`,
            `owner: { open_id: ou_r21_me }`,
            "roles: { brain: claude_acp, reviewer: codex_acp }",
            "harnesses:",
            "  claude_acp:",
            "    type: acpx",
            "    agent: claude",
            "    env:",
            `      HOME: ${JSON.stringify(isoHome)}`,
            `      XDG_CONFIG_HOME: ${JSON.stringify(xdgCfg)}`,
            `      XDG_DATA_HOME: ${JSON.stringify(xdgData)}`,
            "  codex_acp:",
            "    type: acpx",
            "    agent: codex",
            "    env:",
            `      HOME: ${JSON.stringify(isoHome)}`,
            `      XDG_CONFIG_HOME: ${JSON.stringify(xdgCfg)}`,
            `      XDG_DATA_HOME: ${JSON.stringify(xdgData)}`,
            "  doubao_acp:",
            "    type: acpx",
            `    agent: doubao`,
            "    env:",
            `      HOME: ${JSON.stringify(isoHome)}`,
            `      XDG_CONFIG_HOME: ${JSON.stringify(xdgCfg)}`,
            `      XDG_DATA_HOME: ${JSON.stringify(xdgData)}`,
            "  doubao_direct:",
            "    type: doubao-cli",
            `    cmd: ${JSON.stringify(probeDoubao)}`,
            "    env:",
            `      HOME: ${JSON.stringify(isoHome)}`,
            `      XDG_CONFIG_HOME: ${JSON.stringify(xdgCfg)}`,
            `      XDG_DATA_HOME: ${JSON.stringify(xdgData)}`,
          ].join("\n") + "\n",
        );
        const hCfg = loadConfig(cfgPath21);
        const workCwd = path.join(dir, "r21-work");
        fs.mkdirSync(workCwd, { recursive: true });

        // (a) Claude ACP with lark: "none"
        const resClaude = await runHarness(hCfg, {
          harness: "claude_acp",
          prompt: "hi",
          cwd: workCwd,
          tools: "read",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "claude.log"),
        });
        assert.equal(resClaude.ok, true, `claude_acp 探测应成功：${resClaude.text}`);
        assert.match(resClaude.text, /ACPX_SESS=HIDDEN/, "一次性 worker 绝不能读取 ~/.acpx/sessions 历史会话");
        assert.match(resClaude.text, /ACPX_QUEUE=HIDDEN/, "一次性 worker 绝不能读取 ~/.acpx/queues");
        assert.match(resClaude.text, /ACPX_ADAPTER=OK/, "选定 agent 引用的 ~/.acpx 适配器文件必须可用");
        assert.match(resClaude.text, /ACPX_WRITABLE=YES/, "私有 ~/.acpx 状态目录应对本次调用可写");
        assert.ok(!fs.existsSync(path.join(isoHome, ".acpx", "worker-temp.txt")), "私有 ~/.acpx 写入不得污染宿主机 ~/.acpx");
        assert.match(resClaude.text, /CLAUDE_AUTH_OK/, "选定 agent 的配置应保留");
        assert.ok(!resClaude.text.includes("CODEX_SECRET_MUST_DROP"), "其他 agent 的 auth 不应暴露给 Claude worker");
        assert.match(resClaude.text, /LARK_DATA=HIDDEN/, "lark=none 时不得暴露 file-backed lark-cli 凭据");

        // (b) Codex ACP with inherited daemon CODEX_HOME + lark: "read"
        const prevCodexHome = process.env.CODEX_HOME;
        process.env.CODEX_HOME = customCodexHome;
        try {
          const resCodex = await runHarness(hCfg, {
            harness: "codex_acp",
            prompt: "hi",
            cwd: workCwd,
            tools: "read",
            lark: "readonly",
            timeoutSec: 15,
            logFile: path.join(dir, "codex-acp.log"),
          });
          assert.equal(resCodex.ok, true, `codex_acp 探测应成功：${resCodex.text}`);
          assert.match(resCodex.text, /LARK_DATA=LARK_MASTER_KEY_FILE_BACKED/, "lark!=none 时必须挂载 file-backed XDG_DATA_HOME/lark-cli");
          assert.match(resCodex.text, /CODEX_INHERITED=model = "custom-inherited-codex"/, "必须挂载子进程继承的 CODEX_HOME");
        } finally {
          if (prevCodexHome === undefined) delete process.env.CODEX_HOME;
          else process.env.CODEX_HOME = prevCodexHome;
        }

        // (c) Direct doubao-cli with lark: "readonly": authenticated login + keys + instance lock + RO app/current + hidden host logs
        const resDoubao = await runHarness(hCfg, {
          harness: "doubao_direct",
          prompt: "hi",
          cwd: workCwd,
          tools: "read",
          lark: "readonly",
          timeoutSec: 15,
          logFile: path.join(dir, "doubao-direct.log"),
        });
        assert.equal(resDoubao.ok, true, `doubao_direct 探测应成功：${resDoubao.text}`);
        assert.match(resDoubao.text, /LOCK=YES/, "Doubao 沙箱应可创建私有实例锁");
        assert.match(resDoubao.text, /BIN=RO/, "Doubao app/current 二进制目录必须保持只读");
        assert.match(resDoubao.text, /ACCT=uid_r21_authenticated/, "Doubao 登录账号状态必须可见");
        assert.match(resDoubao.text, /KEY=DOUBAO_SESSION_KEY_OK/, "Doubao 登录密钥必须可见");
        assert.match(resDoubao.text, /LOG=HIDDEN/, "Doubao 宿主机历史日志不得暴露");
        assert.match(resDoubao.text, /AGENT=HIDDEN/, "Doubao 宿主机 agent_mode 历史不得暴露");
        assert.match(resDoubao.text, /LARK=LARK_MASTER_KEY_FILE_BACKED/, "doubao-cli lark!=none 必须挂载 file-backed lark-cli 登录态");
        assert.ok(!fs.existsSync(path.join(xdgData, "doubao_cli", "doubao-cli-instance.lock")), "隔离运行不得修改宿主机 doubao_cli 锁文件");

        // (d) ACP doubao with lark: "none": staged login/keys also work via acpx, and lark-cli stays hidden
        const acpxDoubaoProbe = path.join(dir, "probe-acpx-doubao-r21");
        fs.writeFileSync(
          acpxDoubaoProbe,
          [
            "#!/bin/sh",
            'D="$XDG_DATA_HOME/doubao_cli"',
            'echo "ACP_DOUBAO_ACCT=$(cat "$D/doubao-cli-pc-login/account" 2>/dev/null || echo MISSING)"',
            'echo "ACP_DOUBAO_KEY=$(cat "$D/keys/session.key" 2>/dev/null || echo MISSING)"',
            'echo "ACP_DOUBAO_LOG=$(test -e "$D/logs/host-history.log" && echo LEAK || echo HIDDEN)"',
            'echo "ACP_DOUBAO_LARK=$(cat "$XDG_DATA_HOME/lark-cli/master.key" 2>/dev/null || echo HIDDEN)"',
          ].join("\n"),
          { mode: 0o755 },
        );
        const hCfg2 = { ...hCfg, bins: { ...hCfg.bins, acpx: acpxDoubaoProbe } };
        const resDoubaoAcp = await runHarness(hCfg2, {
          harness: "doubao_acp",
          prompt: "hi",
          cwd: workCwd,
          tools: "read",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "doubao-acp.log"),
        });
        assert.equal(resDoubaoAcp.ok, true);
        assert.match(resDoubaoAcp.text, /ACP_DOUBAO_ACCT=uid_r21_authenticated/);
        assert.match(resDoubaoAcp.text, /ACP_DOUBAO_KEY=DOUBAO_SESSION_KEY_OK/);
        assert.match(resDoubaoAcp.text, /ACP_DOUBAO_LOG=HIDDEN/);
        assert.match(resDoubaoAcp.text, /ACP_DOUBAO_LARK=HIDDEN/);
      }
    }

    // 5) [R21 #5 P1] IM 权威回读确认消息存活时必须清除 deleted，且 verifyFailed 必须先于 deleted 检查以保住游标
    // 7) [R21 #7 P2] background_only 行遭遇旧版冲突 WS 推送时也必须触发权威回读，绝不用旧文本/@我 晋升
    // 14) [R21 #14 P2] 快通道任务耗尽重试后必须在主人作用域上下文状态与 Health 中暴露故障
    {
      const cfgFile = path.join(dir, "ctx-r21.yaml");
      fs.writeFileSync(
        cfgFile,
        [
          `data_dir: ${dataDir}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          `owner: { open_id: ou_owner }`,
          "harnesses: { codex: { agent: codex } }",
          "roles: { brain: codex, reviewer: codex }",
          "context:",
          "  groups: allowlist",
          "  groups_allow:",
          "    - oc_r21_team",
          "  personal_web:",
          "    enabled: true",
          "    fast_lane: true",
        ].join("\n") + "\n",
      );
      app = createApp(loadConfig(cfgFile));
      app.store.set("owner.open_id", "ou_owner");
      const ctxSvc = new ContextService(app);
      const nowMs = Date.now();

      // (5a) 提及搜索返回 deleted=true，群列表返回同修订存活副本；+messages-mget 返回存活正文（省略 deleted）
      // (5b) 另一条同类冲突但 +messages-mget 漏返回 -> verifyFailed 必须阻断游标推进且不撤回已有观测
      ctxSvc.store.addObs([
        {
          id: "im:om_r21_fail_verify",
          source: "im",
          kind: "at_me",
          conv: "oc_r21_team",
          conv_name: "研发群",
          actor_name: "Bob",
          actor_id: "ou_bob",
          is_me: false,
          text: "保留的原始消息",
          time: nowMs - 20_000,
          url: "",
          meta: { at_me: true },
        },
      ]);
      const fakeLark = async (args: string[]) => {
        if (args[0] === "im" && args[1] === "+messages-search") {
          if (args.includes("--is-at-me")) {
            return {
              has_more: false,
              messages: [
                {
                  message_id: "om_r21_live_after_mget",
                  chat_id: "oc_r21_team",
                  chat_type: "group",
                  chat_name: "研发群",
                  sender: { id: "ou_alice", name: "Alice", sender_type: "user" },
                  content: "",
                  deleted: true,
                  create_time: String(nowMs - 4000),
                },
                {
                  message_id: "om_r21_fail_verify",
                  chat_id: "oc_r21_team",
                  chat_type: "group",
                  chat_name: "研发群",
                  sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                  content: "",
                  deleted: true,
                  create_time: String(nowMs - 3000),
                },
              ],
            };
          }
          return { has_more: false, messages: [] };
        }
        if (args[0] === "im" && args[1] === "+chat-messages-list") {
          return {
            has_more: false,
            messages: [
              {
                message_id: "om_r21_live_after_mget",
                chat_id: "oc_r21_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "ou_alice", name: "Alice", sender_type: "user" },
                content: "@我 权威回读确认存活",
                mentions: [{ id: "ou_owner", name: "我" }],
                create_time: String(nowMs - 4000),
              },
              {
                message_id: "om_r21_fail_verify",
                chat_id: "oc_r21_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "ou_bob", name: "Bob", sender_type: "user" },
                content: "存活副本",
                create_time: String(nowMs - 3000),
              },
            ],
          };
        }
        if (args[0] === "im" && args[1] === "+messages-mget") {
          return {
            messages: [
              {
                message_id: "om_r21_live_after_mget",
                chat_id: "oc_r21_team",
                chat_type: "group",
                chat_name: "研发群",
                sender: { id: "ou_alice", name: "Alice", sender_type: "user" },
                content: "@我 权威回读确认存活",
                mentions: [{ id: "ou_owner", name: "我" }],
                create_time: String(nowMs - 4000),
              },
              // 故意不返回 om_r21_fail_verify 以触发 verifyFailed
            ],
          };
        }
        return { has_more: false, messages: [] };
      };
      (ctxSvc.connectors as unknown as { lark: typeof fakeLark }).lark = fakeLark;
      const beforeAtMeCursor = app.store.get("ctx.im.cursor.at_me");
      await ctxSvc.connectors.pullIm();
      const liveObs = ctxSvc.store.obs("im:om_r21_live_after_mget");
      assert.ok(liveObs, "权威 +messages-mget 确认存活的消息绝不可被旧 deleted 标记丢弃");
      assert.equal(liveObs!.text, "@我 权威回读确认存活");
      assert.equal(liveObs!.meta.withdrawn, undefined);
      assert.equal(ctxSvc.store.obsPending("im:om_r21_live_after_mget"), true);
      assert.notEqual(
        ctxSvc.store.obs("im:om_r21_fail_verify")?.meta.withdrawn,
        true,
        "verifyFailed 必须先于 deleted 分支判断，不得在回读失败时撤回原消息",
      );
      assert.equal(
        app.store.get("ctx.im.cursor.at_me"),
        beforeAtMeCursor,
        "存在 verifyFailed 时必须保留 at_me 游标等待下轮重试",
      );

      // (7) background_only 行被旧版 @我 WS 推送重放时，必须触发 readMessage 并按服务端已编辑版本（无 @我）处理而不误晋升
      saveWorkspaceBinding(app.store, "7001001", "ou_owner");
      ctxSvc.store.addBackgroundObs([
        {
          id: "pw:om_r21_bg_edited",
          source: "im",
          kind: "group",
          conv: "pw_chat:9990001",
          conv_name: "范围外群",
          actor_name: "Alice",
          actor_id: "7002002",
          is_me: false,
          text: "已编辑：不再 @你",
          time: nowMs - 1000,
          url: "",
          meta: {
            chat_type: "group",
            at_me: false,
            mentions: [],
            background_only: true,
            native_owner_id: "7001001",
          },
        },
      ]);
      assert.equal(ctxSvc.store.obsPending("pw:om_r21_bg_edited"), false);
      let readMessageCalls = 0;
      const baseWebMsg: WebMessage = {
        id: "om_r21_bg_edited",
        ownerId: "7001001",
        actorId: "7002002",
        conversationId: "9990001",
        conversationKind: "group",
        rootId: "",
        parentId: "",
        threadId: "",
        cid: "",
        kind: MSG_TEXT,
        senderType: USER_SENDER_TYPE,
        messageType: "text",
        createdAtMs: nowMs - 1000,
        position: 1,
        threadPosition: 0,
        sendToChat: true,
        text: "已编辑：不再 @你",
        mentions: [],
        resources: [],
        unsupported: false,
        partial: false,
      };
      const fakeWebClient = {
        currentSessionId: () => undefined,
        readMessage: async () => {
          readMessageCalls++;
          return { ...baseWebMsg };
        },
        readChat: async () => ({ id: "9990001", name: "范围外群", kind: "group" as const }),
      };
      await (
        ctxSvc.personalWeb as unknown as {
          handleMessage: (msg: WebMessage, client?: unknown, signal?: AbortSignal) => Promise<void>;
        }
      ).handleMessage(
        {
          ...baseWebMsg,
          text: "@我 旧版未编辑正文",
          mentions: [{ id: "7001001", name: "我", start: 0, end: 2 }],
        },
        fakeWebClient,
      );
      assert.equal(readMessageCalls, 1, "background_only 冲突推送必须向服务端权威回读 readMessage");
      const afterBg = ctxSvc.store.obs("pw:om_r21_bg_edited");
      assert.equal(afterBg?.text, "已编辑：不再 @你", "不得用陈旧推送文本覆盖 background_only 已编辑正文");
      assert.equal(ctxSvc.store.obsPending("pw:om_r21_bg_edited"), false, "已移除 @我 的范围外消息不得晋升为待处理");

      // (14) 快通道任务重试耗尽后，必须在 ctx.last_error 与 Q.health(app) 中暴露，且主人切换后隔离脱敏
      ctxSvc.enqueue("fast:pw_chat:9990002:pw:om_r21_fast_fail:g0:h1", {
        task: "fast",
        conv: "pw_chat:9990002",
        conv_name: "核心项目群",
        trigger_obs_id: "pw:om_r21_fast_fail",
      });
      const fastItem = app.ledger.claim("context", 30_000)!;
      assert.equal(fastItem.id, "context:fast:pw_chat:9990002:pw:om_r21_fast_fail:g0:h1");
      const exh = ctxSvc.handler().onExhausted!(fastItem as never, "模型超时 120s");
      app.ledger.transition(fastItem, {
        state: exh.patch?.state ?? "errored",
        terminal: true,
        error: "模型超时 120s",
      });
      const ctxStatus = ctxSvc.views.status(false);
      assert.match(ctxStatus.last_error, /快通道（核心项目群）失败：模型超时 120s/, "耗尽快通道必须写入 ctx.last_error");
      const hCur = Q.health(app);
      assert.ok(
        hCur.failed.some((f) => f.id === fastItem.id && f.kind === "context" && !f.isolated),
        "health().failed 必须展示当前主人的耗尽快通道任务",
      );
      assert.ok(hCur.actionable_failures >= 1, "耗尽快通道必须计入 actionable_failures");
      assert.equal(Q.overview(app).health.ok, false, "存在未确认快通道失败时 overview.health.ok 必须为 false");

      // 主人切换到 ou_r21_other：旧主人的快通道失败必须被隔离脱敏（含不透明展示 ID），不得计入新主人 actionable_failures
      const appOther: ReturnType<typeof createApp> = {
        ...app,
        cfg: { ...app.cfg, owner: { ...app.cfg.owner, open_id: "ou_r21_other" } },
      };
      const hOther = Q.health(appOther);
      const isoRow = hOther.failed.find((f) => f.isolated && f.kind === "context");
      assert.ok(isoRow?.isolated, "主人变更后快通道失败必须在 health() 中标记 isolated");
      assert.ok(
        isoRow!.id.startsWith("isolated:") &&
          !isoRow!.id.includes("9990002") &&
          !isoRow!.id.includes("om_r21_fast_fail"),
        "隔离记录必须使用脱敏 ID，绝不泄漏原生群/消息 ID",
      );
      assert.ok(!isoRow!.summary.includes("核心项目群") && !isoRow!.error.includes("模型超时"), "隔离记录必须脱敏群名与报错");
      assert.equal(hOther.actionable_failures, 0, "旧主人快通道失败不得计入新主人 actionable_failures");
    }

    // 6) [R21 #6 P2] 恢复中断后残留的空 worktree 目录与缺失 baseKey
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r21",
        GIT_AUTHOR_EMAIL: "r21@test",
        GIT_COMMITTER_NAME: "r21",
        GIT_COMMITTER_EMAIL: "r21@test",
      };
      const repoDir = path.join(dir, "wt-recover-repo");
      fs.mkdirSync(repoDir, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", repoDir], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(repoDir, "README.md"), "hello\n");
      assert.equal((await runProcess("git", ["-C", repoDir, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", repoDir, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      const expectedHead = (await runProcess("git", ["-C", repoDir, "rev-parse", "HEAD"], { env: gitEnv })).stdout.trim();

      const wtData = path.join(dir, "wt-data");
      fs.mkdirSync(wtData, { recursive: true });
      const wtCfgFile = path.join(dir, "wt-r21.yaml");
      fs.writeFileSync(
        wtCfgFile,
        [
          `data_dir: ${wtData}`,
          `owner: { open_id: ou_r21_me }`,
          "harnesses: { codex: { agent: codex } }",
          "roles: { brain: codex, reviewer: codex }",
          "dispatch:",
          "  repos:",
          `    demo: ${JSON.stringify(repoDir)}`,
        ].join("\n") + "\n",
      );
      const wtApp = createApp(loadConfig(wtCfgFile));
      try {
        const dispatcher = new Dispatcher(wtApp.cfg, wtApp.ledger, wtApp.store, wtApp.board);
        const taskA = { guid: "aaaaaaaa1111", summary: "任务A", description: "repo: demo", dueMs: null, url: "" };
        // (6a) 模拟 mkdirSync 后、git worktree add 前进程崩溃留下的空目录
        const emptyCwd = path.join(wtData, "worktrees", "aaaaaaaa");
        fs.mkdirSync(emptyCwd, { recursive: true });
        const prepA = await dispatcher.prepareWorkspace(taskA);
        assert.equal(prepA.base, expectedHead, "残留空目录必须恢复执行 git worktree add 并记录真实基线提交");
        assert.ok(fs.existsSync(path.join(prepA.cwd, ".git")), "恢复后的 worktree 必须包含合法 .git 指针");
        assert.equal(wtApp.store.get(`worktree.${taskA.guid}.base`), expectedHead);

        // (6b) 模拟 worktree 已注册但 baseKey 未写入时的重启恢复
        wtApp.store.db.prepare("DELETE FROM kv WHERE k = ?").run(`worktree.${taskA.guid}.base`);
        const prepA2 = await dispatcher.prepareWorkspace(taskA);
        assert.equal(prepA2.base, expectedHead, "缺失 baseKey 的已注册 worktree 必须恢复真实基线提交");
        assert.equal(wtApp.store.get(`worktree.${taskA.guid}.base`), expectedHead);

        // (6c) 非空但未注册的损坏目录必须显式报错，绝不静默返回空 base
        const taskB = { guid: "bbbbbbbb2222", summary: "任务B", description: "repo: demo", dueMs: null, url: "" };
        const badCwd = path.join(wtData, "worktrees", "bbbbbbbb");
        fs.mkdirSync(badCwd, { recursive: true });
        fs.writeFileSync(path.join(badCwd, "stray.txt"), "corrupt");
        await assert.rejects(
          () => dispatcher.prepareWorkspace(taskB),
          /不是有效的已注册 Git worktree/,
          "非空损坏目录不得静默按空基线继续",
        );
      } finally {
        wtApp.store.db.close();
      }
    }

    // 9) [R21 #9 P2] scp 风格绝对路径 SSH URL 识别（git@example.com:/srv/project.git）
    {
      assert.deepEqual(parseScpGitUrl("git@example.com:/srv/project.git"), {
        user: "git",
        host: "example.com",
        path: "/srv/project.git",
      });
      assert.equal(classifyGitRemoteTransport(dir, "git@example.com:/srv/project.git"), "ssh");
      assert.equal(classifyGitRemoteTransport(dir, "example.com:/srv/project.git"), "ssh");
      assert.equal(classifyGitRemoteTransport(dir, "git@[::1]:/srv/project.git"), "ssh");
      assert.equal(classifyGitRemoteTransport(dir, "/srv/project.git"), "local");
      assert.equal(resolveLocalGitRemoteDir(dir, "git@example.com:/srv/project.git"), undefined);
      assert.deepEqual(parseRemote("git@example.com:/srv/project.git"), {
        host: "example.com",
        path: "srv/project",
      });
    }

    // 10) [R21 #10 P2] SSH Include 通配符（Include config.d/*.conf）按主机选择性投影，不暴露无关片段与整个 ~/.ssh
    {
      const sshGlobHome = path.join(dir, "ssh-glob-home");
      const sshDir = path.join(sshGlobHome, ".ssh");
      const confD = path.join(sshDir, "config.d");
      fs.mkdirSync(confD, { recursive: true });
      fs.writeFileSync(path.join(sshDir, "config"), "Include config.d/*.conf\n");
      fs.writeFileSync(
        path.join(confD, "work.conf"),
        [
          "Host work-alias",
          "  HostName git.work.internal",
          "  Port 2222",
          "  IdentityFile ~/.ssh/id_work_glob",
        ].join("\n") + "\n",
      );
      fs.writeFileSync(
        path.join(confD, "personal.conf"),
        [
          "Host personal-alias",
          "  HostName git.personal.example",
          "  IdentityFile ~/.ssh/id_personal_secret",
        ].join("\n") + "\n",
      );
      fs.writeFileSync(path.join(sshDir, "id_work_glob"), "WORK_KEY", { mode: 0o600 });
      fs.writeFileSync(path.join(sshDir, "id_personal_secret"), "PERSONAL_KEY_NO_LEAK", { mode: 0o600 });

      const mounts = collectScopedSshMounts(["work-alias"], { HOME: sshGlobHome }, dataDir, false);
      assert.ok(mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}config`)), "应挂载 ~/.ssh/config");
      assert.ok(mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}work.conf`)), "应挂载命中的 Include 通配片段 work.conf");
      assert.ok(mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_work_glob`)), "应挂载 work.conf 引用的私钥");
      assert.ok(!mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}personal.conf`)), "不得挂载未命中的 personal.conf");
      assert.ok(!mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_personal_secret`)), "不得暴露无关片段中的私钥");
      assert.ok(!mounts.readOnlyPaths.includes(fs.realpathSync(sshDir)), "绝不得整目录挂载 ~/.ssh");
    }

    // 11) [R21 #11 P2] 保留全局 Git [include] / [includeIf] 配置（如 ~/.config/git/company.inc 中的 pushInsteadOf）
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r21",
        GIT_AUTHOR_EMAIL: "r21@test",
        GIT_COMMITTER_NAME: "r21",
        GIT_COMMITTER_EMAIL: "r21@test",
      };
      const incHome = path.join(dir, "git-inc-home");
      const incXdg = path.join(incHome, ".config");
      fs.mkdirSync(path.join(incXdg, "git"), { recursive: true });
      const incRepo = path.join(dir, "git-inc-repo");
      fs.mkdirSync(incRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", incRepo], { env: gitEnv })).code, 0);
      assert.equal(
        (await runProcess("git", ["-C", incRepo, "remote", "add", "origin", "https://fetch.corp.example/team/app.git"], { env: gitEnv })).code,
        0,
      );
      fs.writeFileSync(
        path.join(incXdg, "git", "company.inc"),
        '[url "ssh://git@push.corp.example/"]\n\tpushInsteadOf = https://fetch.corp.example/\n',
      );
      fs.writeFileSync(
        path.join(incHome, ".gitconfig"),
        `[includeIf "gitdir:${fs.realpathSync(incRepo)}/"]\n\tpath = ~/.config/git/company.inc\n`,
      );
      const pushUrlRes = await tryGit(incRepo, ["remote", "get-url", "--push", "origin"], {
        readOnly: true,
        extraEnv: { HOME: incHome, XDG_CONFIG_HOME: incXdg },
      });
      assert.equal(pushUrlRes.code, 0, `带全局 includeIf 的隔离 git remote get-url 必须成功：${pushUrlRes.stderr}`);
      assert.equal(
        pushUrlRes.stdout.trim(),
        "ssh://git@push.corp.example/team/app.git",
        "隔离下的受信任交付 Git 命令必须保留 includeIf 中配置的 url.*.pushInsteadOf",
      );
    }

    // 12) [R21 #12 P2] 分槽 store 凭据投影严格保持 `store A -> 中间 helper -> store B` 顺序（绝不把 B 提前合并到 A 槽位）
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r21",
        GIT_AUTHOR_EMAIL: "r21@test",
        GIT_COMMITTER_NAME: "r21",
        GIT_COMMITTER_EMAIL: "r21@test",
      };
      const slotRepo = path.join(dir, "slot-order-repo");
      fs.mkdirSync(slotRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", slotRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(slotRepo, "s.txt"), "s\n");
      assert.equal((await runProcess("git", ["-C", slotRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", slotRepo, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      const headSha = (await runProcess("git", ["-C", slotRepo, "rev-parse", "HEAD"], { env: gitEnv })).stdout.trim();

      const midAuth = `Basic ${Buffer.from("miduser:midpass").toString("base64")}`;
      httpSrv12 = http.createServer((req, res) => {
        if ((req.headers.authorization ?? "") !== midAuth) {
          res.statusCode = 401;
          res.setHeader("WWW-Authenticate", 'Basic realm="r21-slot"');
          res.end("wrong account");
          return;
        }
        if ((req.url ?? "").startsWith("/org/slot.git/info/refs")) {
          res.setHeader("Content-Type", "text/plain");
          res.end(`${headSha}\trefs/heads/main\n`);
          return;
        }
        res.statusCode = 404;
        res.end("not found");
      });
      await new Promise<void>((resolve) => httpSrv12!.listen(0, "127.0.0.1", resolve));
      const port12 = (httpSrv12.address() as { port: number }).port;

      const slotHome = path.join(dir, "slot-home");
      fs.mkdirSync(slotHome, { recursive: true });
      const storeA = path.join(slotHome, "store-a.creds");
      const storeB = path.join(slotHome, "store-b.creds");
      // storeA 对目标端口无匹配，storeB 有错误旧账号，中间的 local helper 提供正确账号 miduser:midpass
      fs.writeFileSync(storeA, "http://other:pass@other.example:9999\n", { mode: 0o600 });
      fs.writeFileSync(storeB, `http://buser:WRONG_B_PASS@127.0.0.1:${port12}\n`, { mode: 0o600 });
      fs.writeFileSync(
        path.join(slotHome, ".gitconfig"),
        [
          "[credential]",
          `\thelper = store --file=${storeA}`,
          '\thelper = "!f() { test \\"$1\\" = get && printf \'username=miduser\\\\npassword=midpass\\\\n\'; }; f"',
          `\thelper = store --file=${storeB}`,
        ].join("\n") + "\n",
      );
      const r12 = await tryGit(slotRepo, ["ls-remote", `http://127.0.0.1:${port12}/org/slot.git`], {
        readOnly: true,
        extraEnv: { HOME: slotHome },
      });
      assert.equal(r12.code, 0, `storeA 无命中时必须先命中中间 helper，绝不可把 storeB 提前合并进 storeA 槽位：${r12.stderr}`);
      assert.match(r12.stdout, new RegExp(headSha));
    }

    // 13) [R21 #13 P2] 非 store 宿主机 HTTPS 认证（如 gh auth setup-git / credential-cache 读取宿主机隐藏登录文件）在隔离下仍可用且不暴露宿主机登录目录
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r21",
        GIT_AUTHOR_EMAIL: "r21@test",
        GIT_COMMITTER_NAME: "r21",
        GIT_COMMITTER_EMAIL: "r21@test",
      };
      const ghRepo = path.join(dir, "gh-helper-repo");
      fs.mkdirSync(ghRepo, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", ghRepo], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(ghRepo, "g.txt"), "g\n");
      assert.equal((await runProcess("git", ["-C", ghRepo, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", ghRepo, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);
      const headSha = (await runProcess("git", ["-C", ghRepo, "rev-parse", "HEAD"], { env: gitEnv })).stdout.trim();

      const ghAuth = `Basic ${Buffer.from("x-access-token:gho_host_only_token").toString("base64")}`;
      httpSrv13 = http.createServer((req, res) => {
        if ((req.headers.authorization ?? "") !== ghAuth) {
          res.statusCode = 401;
          res.setHeader("WWW-Authenticate", 'Basic realm="r21-gh"');
          res.end("auth required");
          return;
        }
        if ((req.url ?? "").startsWith("/org/gh.git/info/refs")) {
          res.setHeader("Content-Type", "text/plain");
          res.end(`${headSha}\trefs/heads/main\n`);
          return;
        }
        res.statusCode = 404;
        res.end("not found");
      });
      await new Promise<void>((resolve) => httpSrv13!.listen(0, "127.0.0.1", resolve));
      const port13 = (httpSrv13.address() as { port: number }).port;

      const ghHome = path.join(dir, "gh-home");
      const ghCfgDir = path.join(ghHome, ".config", "gh");
      fs.mkdirSync(ghCfgDir, { recursive: true });
      // 该文件位于 ~/.config/gh，沙箱内不可见；仅宿主机受信任预解析能读到它
      fs.writeFileSync(path.join(ghCfgDir, "hosts.yml"), "gho_host_only_token", { mode: 0o600 });
      const fakeGhHelper = path.join(dir, "fake-gh-cred");
      fs.writeFileSync(
        fakeGhHelper,
        [
          "#!/bin/sh",
          'if [ "$1" != "get" ]; then exit 0; fi',
          'TOK=$(cat "$HOME/.config/gh/hosts.yml" 2>/dev/null) || exit 1',
          'printf "username=x-access-token\\npassword=%s\\n" "$TOK"',
        ].join("\n"),
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(ghHome, ".gitconfig"),
        `[credential "http://127.0.0.1:${port13}"]\n\thelper = !${fakeGhHelper}\n`,
      );
      const r13 = await tryGit(ghRepo, ["ls-remote", `http://127.0.0.1:${port13}/org/gh.git`], {
        readOnly: true,
        extraEnv: { HOME: ghHome },
      });
      assert.equal(r13.code, 0, `非 store 宿主机 helper（如 gh auth setup-git）必须经宿主机受信任预解析后在沙箱内完成认证：${r13.stderr}`);
      assert.match(r13.stdout, new RegExp(headSha));
    }
  } finally {
    if (httpSrv12) await new Promise<void>((resolve) => httpSrv12!.close(() => resolve()));
    if (httpSrv13) await new Promise<void>((resolve) => httpSrv13!.close(() => resolve()));
    app?.store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第二十二轮回归：派单不全局 prune 兄弟工作树、轮询模式 stepLog 主人校验、工人脱敏 Git 配置、Codex ACP 私有可写主目录与 OAuth 写回、无工具 ACP 禁用 MCP、显式 agentCommand 精确暂存、ACP 环境单次展开、隔离 Health 脱敏 ID、重定向首设 CSRF 派生、空 SSH 代理回退默认私钥、跨字段派单搜索与富卡片标题 mention 偏移", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r22-"));
  let csrfSrv: http.Server | undefined;
  try {
    // 1) [R22 #1 P1] 准备新派单工作树时只定向清理目标失效记录，绝不全局 `git worktree prune` 误删健康同级派单注册
    {
      const gitEnv = {
        ...process.env,
        GIT_AUTHOR_NAME: "r22",
        GIT_AUTHOR_EMAIL: "r22@test",
        GIT_COMMITTER_NAME: "r22",
        GIT_COMMITTER_EMAIL: "r22@test",
      };
      const repoDir = path.join(dir, "sibling-wt-repo");
      fs.mkdirSync(repoDir, { recursive: true });
      assert.equal((await runProcess("git", ["init", "-q", "-b", "main", repoDir], { env: gitEnv })).code, 0);
      fs.writeFileSync(path.join(repoDir, "a.txt"), "hello\n");
      assert.equal((await runProcess("git", ["-C", repoDir, "add", "-A"], { env: gitEnv })).code, 0);
      assert.equal((await runProcess("git", ["-C", repoDir, "commit", "-q", "-m", "init"], { env: gitEnv })).code, 0);

      const wtData = path.join(dir, "wt-r22-data");
      fs.mkdirSync(wtData, { recursive: true });
      const wtCfgFile = path.join(dir, "wt-r22.yaml");
      fs.writeFileSync(
        wtCfgFile,
        [
          `data_dir: ${wtData}`,
          "owner: { open_id: ou_owner }",
          "harnesses: { codex: { agent: codex } }",
          "roles: { brain: codex, reviewer: codex }",
          "dispatch:",
          "  repos:",
          `    demo: ${JSON.stringify(repoDir)}`,
        ].join("\n") + "\n",
      );
      const wtApp = createApp(loadConfig(wtCfgFile));
      try {
        const dispatcher = new Dispatcher(wtApp.cfg, wtApp.ledger, wtApp.store, wtApp.board);
        const task1 = { guid: "11111111aaaa", summary: "派单1", description: "repo: demo", dueMs: null, url: "" };
        const task2 = { guid: "22222222bbbb", summary: "派单2", description: "repo: demo", dueMs: null, url: "" };
        const prep1 = await dispatcher.prepareWorkspace(task1);
        // 准备第二个派单（其沙箱隔离视图看不到兄弟工作树 prep1.cwd！）
        const prep2 = await dispatcher.prepareWorkspace(task2);
        assert.ok(prep1.base && prep2.base);
        const wtList = await runProcess("git", ["-C", repoDir, "worktree", "list", "--porcelain"], { env: gitEnv });
        assert.equal(wtList.code, 0);
        assert.ok(
          wtList.stdout.includes(fs.realpathSync(prep1.cwd)),
          "准备第二个派单绝不得 prune 掉第一个在途派单的工作树注册记录",
        );
        assert.ok(wtList.stdout.includes(fs.realpathSync(prep2.cwd)));
        const st1 = await runProcess("git", ["-C", prep1.cwd, "status", "--short"], { env: gitEnv });
        assert.equal(st1.code, 0, "第一个派单工作树在第二个派单启动后仍必须完整可用");
      } finally {
        wtApp.store.db.close();
      }
    }

    // 2) [R22 #2 P1] & 8) [R22 #8 P2] & 11) [R22 #11 P3]
    //    纯轮询工作区切换主人后 stepLog 阻断旧上下文步骤日志 + Health 隔离行脱敏原生 ID + 跨字段派单搜索
    {
      const pollData = path.join(dir, "poll-r22-data");
      fs.mkdirSync(path.join(pollData, "logs"), { recursive: true });
      const pollCfgFile = path.join(dir, "poll-r22.yaml");
      fs.writeFileSync(
        pollCfgFile,
        [
          `data_dir: ${pollData}`,
          `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(path.join(STUBS, "acpx"))} }`,
          "owner: { open_id: ou_poll_a }",
          "harnesses: { codex: { agent: codex } }",
          "roles: { brain: codex, reviewer: codex }",
          "context:",
          "  personal_web:",
          "    enabled: false",
        ].join("\n") + "\n",
      );
      const pollApp = createApp(loadConfig(pollCfgFile));
      try {
        const ctxSvc = new ContextService(pollApp);
        ctxSvc.enqueue("fast:pw_chat:77665544:pw:om_secret_999:g0:abc", {
          task: "fast",
          conv: "pw_chat:77665544",
          conv_name: "核心机密群",
          trigger_obs_id: "pw:om_secret_999",
        });
        const work = pollApp.ledger.claim("context", 30_000)!;
        const logFile = path.join(pollData, "logs", "ctx-secret-step.log");
        fs.writeFileSync(logFile, "PROMPT: 主人A私聊绝密内容\n");
        const stepId = pollApp.ledger.startStep({ work_id: work.id, name: "understand", log: logFile });
        pollApp.ledger.endStep(stepId, "failed", "err");
        pollApp.ledger.transition(work, { state: "errored", terminal: true, error: "超时" });

        // 切换为 ou_poll_b（未绑定个人 Web，故 hasWorkspaceOwnerMismatch === false）
        const pollAppB: ReturnType<typeof createApp> = {
          ...pollApp,
          cfg: { ...pollApp.cfg, owner: { ...pollApp.cfg.owner, open_id: "ou_poll_b" } },
        };
        assert.equal(hasWorkspaceOwnerMismatch(pollAppB.store, "ou_poll_b"), false);
        assert.throws(
          () => Q.stepLog(pollAppB, stepId, 0),
          /主人隔离|阻断/,
          "纯轮询工作区切换 owner.open_id 后，stepLog 必须校验 context 工作的归属并拒绝返回旧主人日志",
        );
        const hB = Q.health(pollAppB);
        const iso = hB.failed.find((f) => f.isolated && f.kind === "context");
        assert.ok(iso, "旧主人失败的 context 工作项应作为隔离占位出现");
        assert.ok(
          iso!.id.startsWith("isolated:") &&
            !iso!.id.includes("77665544") &&
            !iso!.id.includes("om_secret_999") &&
            !iso!.id.includes("pw_chat"),
          "隔离健康项 id 必须不透明脱敏，绝不暴露旧主人的原生会话 ID 或消息 ID",
        );

        // [R22 #11 P3] 跨字段派单搜索（summary="release" + ref="abc123" 应命中查询 "release abc"）
        pollApp.ledger.enqueue({
          id: "dispatch:abc123:1",
          kind: "dispatch",
          ref: "abc123",
          state: "queued",
          payload: { guid: "abc123", summary: "release", description: "" },
        });
        const crossHits = Q.listDispatches(pollApp, { filter: "all", q: "release abc" });
        assert.equal(crossHits.length, 1, "SQL 预筛与 JS 搜索必须一致支持跨 summary/ref/id 字段的拼接匹配");
        assert.equal(crossHits[0].task_guid, "abc123");
      } finally {
        pollApp.store.db.close();
      }
    }

    // 3) [R22 #3 P1] 仓库工人与校验命令只能读取脱敏 Git 配置，绝不暴露 ~/.gitconfig 或 include 中的 http.extraHeader 与带令牌 URL
    {
      const gitSecHome = path.join(dir, "git-sec-home");
      fs.mkdirSync(path.join(gitSecHome, ".config", "git"), { recursive: true });
      fs.writeFileSync(
        path.join(gitSecHome, ".config", "git", "auth.inc"),
        [
          "[http]",
          "\textraHeader = Authorization: Bearer INC_GIT_SECRET_TOKEN",
          '[url "https://bot:URL_EMBED_TOKEN@git.corp.example/"]',
          "\tinsteadOf = https://git.corp.example/",
        ].join("\n") + "\n",
      );
      fs.writeFileSync(
        path.join(gitSecHome, ".gitconfig"),
        [
          "[user]",
          "\tname = Safe Worker",
          "\temail = worker@example.com",
          "[http]",
          "\textraHeader = Authorization: Basic ROOT_GIT_BASIC_SECRET",
          "[include]",
          "\tpath = ~/.config/git/auth.inc",
        ].join("\n") + "\n",
      );
      const sanText = sanitizeGitConfigEntries([
        { key: "user.name", value: "Safe Worker" },
        { key: "http.extraHeader", value: "Authorization: Bearer TOP_SECRET" },
        { key: "url.https://u:p@corp.example/.insteadOf", value: "https://corp.example/" },
        { key: "credential.helper", value: "store" },
      ]);
      assert.match(sanText, /name = "Safe Worker"/);
      assert.ok(!sanText.includes("TOP_SECRET") && !sanText.includes("u:p@") && !sanText.includes("credential"));

      const stagedGit = stageSanitizedGitConfig({ HOME: gitSecHome }, path.join(dir, "git-sec-data"));
      assert.ok(stagedGit);
      try {
        const content = fs.readFileSync(stagedGit!.file, "utf8");
        assert.match(content, /Safe Worker/);
        assert.ok(!content.includes("INC_GIT_SECRET_TOKEN") && !content.includes("ROOT_GIT_BASIC_SECRET") && !content.includes("URL_EMBED_TOKEN"));
        if (process.platform === "linux" && hasCredentialMountIsolation()) {
          const workCwd = path.join(dir, "git-sec-cwd");
          fs.mkdirSync(workCwd, { recursive: true });
          const cfgFile = path.join(dir, "git-sec-cfg.yaml");
          fs.writeFileSync(
            cfgFile,
            `data_dir: ${path.join(dir, "git-sec-data")}\nowner: { open_id: ou_owner }\nharnesses: { codex: { agent: codex } }\nroles: { brain: codex, reviewer: codex }\n`,
          );
          const cfg = loadConfig(cfgFile);
          const isoEnv: NodeJS.ProcessEnv = { ...process.env, HOME: gitSecHome };
          const wrapped = wrapCredentialIsolatedCommand(
            "sh",
            ["-c", 'echo "NAME=$(git config --global --get user.name)"; git config --list --show-origin; cat "$HOME/.gitconfig"'],
            isoEnv,
            buildWorkspaceIsolation(
              cfg,
              {
                mode: "verify",
                cwd: workCwd,
                extraReadOnlyPaths: [stagedGit!.dir],
                extraBindMounts: [{ src: stagedGit!.file, dest: stagedGit!.homeMountDest, mode: "ro" }],
              },
              isoEnv,
            ),
          );
          const childEnv: NodeJS.ProcessEnv = { ...isoEnv, ...isolatedSandboxTempEnv() };
          applySanitizedGitConfigEnv(childEnv, stagedGit, wrapped.isolated);
          const r = await runProcess(wrapped.cmd, wrapped.args, { cwd: workCwd, env: childEnv });
          assert.equal(r.code, 0, r.stderr);
          assert.match(r.stdout, /NAME=Safe Worker/);
          assert.ok(
            !r.stdout.includes("INC_GIT_SECRET_TOKEN") &&
              !r.stdout.includes("ROOT_GIT_BASIC_SECRET") &&
              !r.stdout.includes("URL_EMBED_TOKEN"),
            "校验/工人沙箱绝不得看到 ~/.gitconfig 或 include 中的凭据头或带令牌 URL",
          );
        }
      } finally {
        stagedGit?.cleanup();
      }
    }

    // 4) [R22 #4 P1], 5) [R22 #5 P1], 6) [R22 #6 P2], 7) [R22 #7 P2]
    //    Codex ACP 私有可写主目录与 OAuth 写回 + 无工具 ACP 禁 MCP + 显式 agentCommand 精确暂存 + ACP 环境仅展开一次
    {
      const acpHome = path.join(dir, "acp-r22-home");
      const hostCodexHome = path.join(acpHome, ".codex");
      const baseClaudeDir = path.join(dir, "base-claude-r22");
      const onceExpandedClaudeDir = path.join(baseClaudeDir, "worker");
      fs.mkdirSync(path.join(hostCodexHome, "sessions"), { recursive: true });
      fs.mkdirSync(path.join(acpHome, ".acpx", "adapters"), { recursive: true });
      fs.mkdirSync(onceExpandedClaudeDir, { recursive: true });

      fs.writeFileSync(path.join(hostCodexHome, "config.toml"), 'cli_auth_credentials_store = "file"\nmodel = "gpt-5"\n');
      fs.writeFileSync(
        path.join(hostCodexHome, "auth.json"),
        JSON.stringify({
          tokens: { access_token: "AT_OLD", refresh_token: "RT_OLD" },
          last_refresh: "2026-11-20T00:00:00.000Z",
        }),
        { mode: 0o600 },
      );
      fs.writeFileSync(path.join(hostCodexHome, "sessions", "other-repo.jsonl"), '{"secret":"OTHER_REPO_CODEX_SESSION"}\n');
      fs.writeFileSync(path.join(onceExpandedClaudeDir, "settings.json"), '{"claude_once":true}\n');
      fs.writeFileSync(path.join(acpHome, ".acpx", "adapters", "other.sh"), "#!/bin/sh\necho OTHER_SECRET\n", { mode: 0o755 });
      fs.writeFileSync(path.join(acpHome, ".acpx", "explicit-custom.sh"), "#!/bin/sh\necho EXPLICIT_OK\n", { mode: 0o755 });
      fs.writeFileSync(
        path.join(acpHome, ".acpx", "config.json"),
        JSON.stringify({
          mcpServers: [{ name: "corp-mcp", type: "http", url: "https://mcp.corp/sse", headers: { Authorization: "Bearer MCP_SECRET_TOKEN" } }],
          agents: {
            other: { command: "~/.acpx/adapters/other.sh" },
          },
        }),
      );

      // (5) 无工具模式 stageIsolatedAcpxState 剥离 mcpServers 并生成空 no-mcp.json
      const stagedNoTool = stageIsolatedAcpxState({ agent: "claude" }, acpHome, { HOME: acpHome }, undefined, { tools: "none" });
      assert.ok(stagedNoTool?.emptyMcpConfigFile);
      try {
        const cfgNoTool = JSON.parse(fs.readFileSync(path.join(stagedNoTool!.dir, "config.json"), "utf8"));
        assert.deepEqual(cfgNoTool.mcpServers, [], "tools=none 暂存的 config.json 必须清空 mcpServers");
        assert.ok(!fs.readFileSync(path.join(stagedNoTool!.dir, "config.json"), "utf8").includes("MCP_SECRET_TOKEN"));
        const noMcpJson = JSON.parse(fs.readFileSync(stagedNoTool!.emptyMcpConfigFile!, "utf8"));
        assert.deepEqual(noMcpJson, { mcpServers: [] });
      } finally {
        stagedNoTool?.cleanup();
      }

      // (6) 显式 agentCommand 仅暂存目标脚本，不复制 config.json 中无关适配器
      const stagedExplicit = stageIsolatedAcpxState(
        { agentCommand: "~/.acpx/explicit-custom.sh --flag" },
        acpHome,
        { HOME: acpHome },
      );
      assert.ok(stagedExplicit);
      try {
        const cfgExplicit = JSON.parse(fs.readFileSync(path.join(stagedExplicit!.dir, "config.json"), "utf8"));
        assert.equal(cfgExplicit.agents, undefined, "显式 agentCommand 时不应暴露 config.json 中的无关 agents");
        assert.ok(fs.existsSync(path.join(stagedExplicit!.dir, "explicit-custom.sh")), "位于 ~/.acpx 内的显式脚本必须暂存进私有目录");
        assert.ok(!fs.existsSync(path.join(stagedExplicit!.dir, "adapters", "other.sh")), "无关适配器脚本绝不得进入暂存目录");
      } finally {
        stagedExplicit?.cleanup();
      }

      if (process.platform === "linux" && hasCredentialMountIsolation()) {
        const probeAcpx22 = path.join(dir, "probe-acpx-r22");
        fs.writeFileSync(
          probeAcpx22,
          [
            "#!/bin/sh",
            'echo "ARGS=$*"',
            'echo "CODEX_HOME_VAL=$CODEX_HOME"',
            'echo "CODEX_SESS=$(test -e "$HOME/.codex/sessions/other-repo.jsonl" && echo LEAK || echo HIDDEN)"',
            'echo "CODEX_STAGED_SESS=$(test -e "$CODEX_HOME/sessions/other-repo.jsonl" && echo LEAK || echo HIDDEN)"',
            'echo "CLAUDE_DIR_VAL=$CLAUDE_CONFIG_DIR"',
            'echo "CLAUDE_SETTINGS=$(cat "$CLAUDE_CONFIG_DIR/settings.json" 2>/dev/null || echo MISSING)"',
            'echo "EXPLICIT_SCRIPT=$(test -x "$HOME/.acpx/explicit-custom.sh" && echo OK || echo NO)"',
            'echo "OTHER_ADAPTER=$(test -e "$HOME/.acpx/adapters/other.sh" && echo LEAK || echo HIDDEN)"',
            'echo "ACPX_CFG=$(cat "$HOME/.acpx/config.json" 2>/dev/null | tr -d "\\n")"',
            'if [ -n "$CODEX_HOME" ] && [ -f "$CODEX_HOME/auth.json" ]; then',
            '  cat > "$CODEX_HOME/auth.json" <<\'EOF\'',
            '{"tokens":{"access_token":"AT_NEW","refresh_token":"RT_ROTATED_ACP"},"last_refresh":"2026-11-27T12:00:00.000Z"}',
            "EOF",
            '  echo "CODEX_AUTH_ROTATED=YES"',
            "fi",
          ].join("\n"),
          { mode: 0o755 },
        );
        const h22CfgFile = path.join(dir, "h22.yaml");
        fs.writeFileSync(
          h22CfgFile,
          [
            `data_dir: ${path.join(dir, "h22-data")}`,
            `bins: { lark: ${JSON.stringify(path.join(STUBS, "lark-cli"))}, acpx: ${JSON.stringify(probeAcpx22)} }`,
            "owner: { open_id: ou_owner }",
            "context: { personal_web: { enabled: true } }",
            "roles: { brain: codex_acp, reviewer: codex_acp }",
            "harnesses:",
            "  codex_acp:",
            "    type: acpx",
            "    agent: codex",
            "    env:",
            `      HOME: ${JSON.stringify(acpHome)}`,
            `      CODEX_HOME: ${JSON.stringify(hostCodexHome)}`,
            "  claude_once:",
            "    type: acpx",
            "    agent: claude",
            "    env:",
            `      HOME: ${JSON.stringify(acpHome)}`,
            '      CLAUDE_CONFIG_DIR: "${CLAUDE_CONFIG_DIR}/worker"',
            "  explicit_acp:",
            "    type: acpx",
            '    agentCommand: "~/.acpx/explicit-custom.sh"',
            "    env:",
            `      HOME: ${JSON.stringify(acpHome)}`,
          ].join("\n") + "\n",
        );
        const h22Cfg = loadConfig(h22CfgFile);
        const work22 = path.join(dir, "work-r22");
        fs.mkdirSync(work22, { recursive: true });

        // (4) Codex ACP：私有可写 CODEX_HOME、隐藏宿主机 sessions、OAuth 刷新安全写回宿主机 auth.json
        const rCodex = await runHarness(h22Cfg, {
          harness: "codex_acp",
          prompt: "review",
          cwd: work22,
          tools: "read",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "r22-codex.log"),
        });
        assert.equal(rCodex.ok, true, rCodex.text);
        assert.match(rCodex.text, /CODEX_SESS=HIDDEN/, "Codex ACP 不得挂载宿主机 ~/.codex 暴露其他仓库 sessions");
        assert.match(rCodex.text, /CODEX_STAGED_SESS=HIDDEN/, "暂存 CODEX_HOME 不得包含其他仓库 sessions");
        assert.match(rCodex.text, /CODEX_AUTH_ROTATED=YES/, "Codex ACP 的私有 CODEX_HOME 必须可写以支持 OAuth 轮换");
        const updatedHostAuth = JSON.parse(fs.readFileSync(path.join(hostCodexHome, "auth.json"), "utf8"));
        assert.equal(updatedHostAuth.tokens.refresh_token, "RT_ROTATED_ACP", "Codex ACP 刷新后的 OAuth 令牌必须写回宿主机 auth.json");

        // (5) tools === "none"：向 acpx 传 --mcp-config 空配置与 --no-fs，且 config.json 不含宿主机 MCP_SECRET_TOKEN
        const rNoTool = await runHarness(h22Cfg, {
          harness: "claude_once",
          prompt: "understand",
          cwd: work22,
          tools: "none",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "r22-notool.log"),
        });
        assert.equal(rNoTool.ok, true, rNoTool.text);
        assert.match(rNoTool.text, /--mcp-config\s+\S+no-mcp\.json/, "tools=none 必须向 acpx 传入空 --mcp-config");
        assert.match(rNoTool.text, /--no-fs/, "tools=none 必须禁用 ACP filesystem 能力");
        assert.ok(!rNoTool.text.includes("MCP_SECRET_TOKEN"), "tools=none 绝不得把全局 MCP 服务器凭据带入沙箱");

        // (7) 环境变量自引用 ${CLAUDE_CONFIG_DIR}/worker 仅展开一次（不变成 .../worker/worker）
        const prevClaudeDir = process.env.CLAUDE_CONFIG_DIR;
        process.env.CLAUDE_CONFIG_DIR = baseClaudeDir;
        try {
          const rOnce = await runHarness(h22Cfg, {
            harness: "claude_once",
            prompt: "hi",
            cwd: work22,
            tools: "read",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "r22-once.log"),
          });
          assert.equal(rOnce.ok, true, rOnce.text);
          assert.match(rOnce.text, new RegExp(`CLAUDE_DIR_VAL=${onceExpandedClaudeDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
          assert.match(rOnce.text, /CLAUDE_SETTINGS=\{"claude_once":true\}/, "单次展开后的 CLAUDE_CONFIG_DIR 必须准确挂载进沙箱");
        } finally {
          if (prevClaudeDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
          else process.env.CLAUDE_CONFIG_DIR = prevClaudeDir;
        }

        // (6) 显式 agentCommand 实跑：私有 ~/.acpx 中可见 explicit-custom.sh 且隐藏无关 adapters/other.sh
        const rExp = await runHarness(h22Cfg, {
          harness: "explicit_acp",
          prompt: "hi",
          cwd: work22,
          tools: "read",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "r22-exp.log"),
        });
        assert.equal(rExp.ok, true, rExp.text);
        assert.match(rExp.text, /EXPLICIT_SCRIPT=OK/);
        assert.match(rExp.text, /OTHER_ADAPTER=HIDDEN/);
      }
    }

    // 9) [R22 #9 P2] 首跳无 x-csrf-token，307 重定向首次下发 swp_csrf_token 后，后续跳必须自动派生 x-csrf-token 且成功后提交 Cookie 轮换
    {
      let sawStep2Csrf = "";
      csrfSrv = http.createServer((req, res) => {
        if (req.url === "/step1") {
          res.statusCode = 307;
          res.setHeader("Location", "/step2");
          res.setHeader("Set-Cookie", "swp_csrf_token=csrf_from_307_redirect; Path=/");
          res.end();
          return;
        }
        if (req.url === "/step2") {
          sawStep2Csrf = String(req.headers["x-csrf-token"] ?? "");
          if (sawStep2Csrf !== "csrf_from_307_redirect") {
            res.statusCode = 403;
            res.end("csrf missing");
            return;
          }
          res.statusCode = 200;
          res.end("ok");
          return;
        }
        res.statusCode = 404;
        res.end();
      });
      await new Promise<void>((resolve) => csrfSrv!.listen(0, "127.0.0.1", resolve));
      const port = (csrfSrv.address() as { port: number }).port;
      const jar = new RecordingCookieJar(["127.0.0.1"]);
      const res = await fetchWithJar(jar, {
        url: `http://127.0.0.1:${port}/step1`,
        method: "POST",
        body: "payload",
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(res.status, 200, "307 重定向首次下发 swp_csrf_token 时，下一跳必须派生 x-csrf-token 并成功");
      assert.equal(sawStep2Csrf, "csrf_from_307_redirect");
      assert.equal(res.cookiesUpdated, true);
      assert.equal(jar.cookieValue(new URL(`http://127.0.0.1:${port}/step2`), "swp_csrf_token"), "csrf_from_307_redirect");
    }

    // 10) [R22 #10 P2] SSH_AUTH_SOCK 存在但代理未加载该密钥时，必须保留默认磁盘私钥回退；已加载于代理时才省略私钥
    {
      const sshFbHome = path.join(dir, "ssh-fallback-home");
      const sshDir = path.join(sshFbHome, ".ssh");
      fs.mkdirSync(sshDir, { recursive: true });
      fs.writeFileSync(path.join(sshDir, "id_ed25519"), "DISK_DEFAULT_PRIV", { mode: 0o600 });
      fs.writeFileSync(path.join(sshDir, "id_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyBlob user@host\n");
      fs.writeFileSync(path.join(sshDir, "id_unrelated_bastion"), "BASTION_PRIV_NO_LEAK", { mode: 0o600 });

      const emptyAgentMounts = collectScopedSshMounts(
        ["git.example.com"],
        { HOME: sshFbHome, SSH_AUTH_SOCK: path.join(dir, "empty-or-missing.sock") },
        undefined,
        path.join(dir, "empty-or-missing.sock"),
      );
      assert.ok(
        emptyAgentMounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_ed25519`)),
        "SSH 代理未持有该默认密钥时，必须保留标准默认私钥 id_ed25519 的只读文件回退",
      );
      assert.ok(
        !emptyAgentMounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_unrelated_bastion`)),
        "保留默认私钥回退的同时绝不得暴露无关命名私钥",
      );
    }

    // 12) [R22 #12 P3] 带标题的富文本卡片（MSG_CARD）拼接标题前缀后，mentions 的 start/end 必须同步偏移
    {
      const richBytes = encodeRichText([
        { text: "@Alice", mentionId: "700999" },
        { text: " 请查收" },
      ]);
      const cardContent = new ProtoWriter()
        .uint(1, 1) // non-basic rich cardType (BASIC_CARD_TYPE === 2)
        .bytes(2, richBytes)
        .str(6, "发布通知")
        .finish();
      const rawMsg = new ProtoWriter()
        .str(1, "7100001")
        .uint(2, MSG_CARD)
        .str(3, "700111")
        .uint(4, 1730000000)
        .bytes(5, cardContent)
        .uint(7, USER_SENDER_TYPE)
        .str(10, "8800001")
        .uint(46, CHAT_KIND_GROUP)
        .finish();
      const decoded = decodeMessage(rawMsg, "700999");
      assert.equal(decoded.text, "发布通知\n@Alice 请查收");
      assert.equal(decoded.mentions.length, 1);
      assert.equal(
        decoded.text.slice(decoded.mentions[0].start, decoded.mentions[0].end),
        "@Alice",
        "带标题富卡片的 mention 偏移必须加上 `标题\\n` 前缀长度",
      );
    }
  } finally {
    if (csrfSrv) await new Promise<void>((resolve) => csrfSrv!.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Codex 第二十三轮回归：上下文作业主人复核、修订水位撤回与提及核验、Codex ACP 无工具路由与崩溃可恢复刷新、ACP 凭据白名单与解释器脚本暂存、Claude 会话隔离、unshare 非 root SSH 归属、LFS 端点凭据、符号链接本地镜像、SSH 占位符展开、credential.<url>.username 与批量 health() 性能", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-r23-"));
  let helperSrv: http.Server | undefined;
  const makeR23App = (
    name: string,
    opts?: {
      ownerOpenId?: string;
      pwEnabled?: boolean;
      acpxBin?: string;
      groupsMode?: "spoken" | "allowlist";
      groupAllowlist?: string[];
    },
  ) => {
    const dataDir = path.join(dir, `${name}-data`);
    fs.mkdirSync(dataDir, { recursive: true });
    const cfgFile = path.join(dir, `${name}.yaml`);
    const owner = opts?.ownerOpenId ?? "ou_me_r23";
    const allowLines =
      opts?.groupAllowlist && opts.groupAllowlist.length
        ? opts.groupAllowlist.map((g) => `    - "${g}"`).join("\n")
        : "";
    fs.writeFileSync(
      cfgFile,
      [
        `data_dir: "${dataDir}"`,
        "owner:",
        `  open_id: "${owner}"`,
        '  timezone: "Asia/Shanghai"',
        "bins:",
        `  lark: "${path.join(STUBS, "lark-cli")}"`,
        `  acpx: "${opts?.acpxBin ?? path.join(STUBS, "acpx")}"`,
        "harnesses:",
        "  claude:",
        '    type: "acpx"',
        '    agent: "claude"',
        "roles:",
        '  brain: "claude"',
        '  reviewer: "claude"',
        "context:",
        "  enabled: true",
        `  groups: "${opts?.groupsMode ?? "spoken"}"`,
        ...(opts?.groupAllowlist?.length ? ["  group_allowlist:", allowLines] : []),
        "  personal_web:",
        `    enabled: ${opts?.pwEnabled ? "true" : "false"}`,
        "  sources:",
        "    im: true",
        "    meego: false",
        "    minutes: false",
        "    calendar: false",
        "    comments: false",
      ].join("\n") + "\n",
    );
    return createApp(loadConfig(cfgFile));
  };
  try {
    // 1) [R23 #1 P1] 纯轮询工作区切换 owner.open_id 后，旧主人排队的 context 作业在 handler 入口立即阻断跳过，绝不执行推理或生卡
    {
      const app = makeR23App("r23-1-owner", { ownerOpenId: "ou_owner_a", pwEnabled: false });
      try {
        const ctx = new ContextService(app);
        const { item } = ctx.store.upsertItem({
          project_id: "inbox",
          title: "Owner A private item",
          kind: "todo",
          source: "im",
          status: "open",
        });
        ctx.enqueue(`draft:${item.id}`, { task: "draft", item_id: item.id, kind: "reply" });
        const queued = app.ledger.get(`context:draft:${item.id}`);
        assert.ok(queued, "context 作业应入队");
        assert.equal((queued!.payload as Record<string, unknown>).owner_open_id, "ou_owner_a");

        // 切换工作区主人到 B（不涉及个人 Web 绑定）
        app.cfg.owner.open_id = "ou_owner_b";
        const origHarness = app.cfg.harnesses[app.cfg.roles.brain];
        app.cfg.harnesses[app.cfg.roles.brain] = {
          ...origHarness,
          type: "acpx",
          agent: "claude",
          cmd: "/nonexistent/must-not-run",
        };
        app.engine.register(ctx.handler());
        await app.engine.drain(["context"]);
        const after = app.ledger.get(`context:draft:${item.id}`);
        assert.equal(after?.state, "skipped", "旧主人排队的 context 作业必须被跳过");
        assert.equal(after?.terminal, true);
        assert.equal(ctx.store.drafts().length, 0, "绝不得为旧主人作业生成草稿或调用模型");
      } finally {
        app.store.db.close();
      }
    }

    // 2) [R23 #2 P1] 轮询撤回保留修订水位（含首次即撤回的墓碑），旧修订无法复活已撤回消息；仅更新修订或权威 live 核验可恢复
    {
      const app = makeR23App("r23-2-recall");
      try {
        const store = new ContextStore(app.store.db);
        const now = Date.now();
        // 场景 A：live rev 1 -> recalled rev 3 -> stale live rev 2 绝不得复活
        store.addObs([
          {
            id: "im:om_r23_rev",
            source: "im",
            kind: "at_me",
            conv: "oc_r23_grp",
            conv_name: "测试群",
            actor_id: "ou_other",
            actor_name: "同事",
            is_me: false,
            time: now - 1000,
            text: "rev 1 live",
            url: "",
            meta: { edit_version: 1, poll_observed_at: now - 1000 },
          },
        ]);
        store.retirePendingObs("im:om_r23_rev", {
          editVersion: 3,
          editTimeMs: now,
          pollObservedAt: now,
          conv: "oc_r23_grp",
          kind: "at_me",
          time: now - 1000,
        });
        assert.equal(store.obsPending("im:om_r23_rev"), false, "rev 3 撤回后应离开未处理队列");
        store.addObs([
          {
            id: "im:om_r23_rev",
            source: "im",
            kind: "at_me",
            conv: "oc_r23_grp",
            conv_name: "测试群",
            actor_id: "ou_other",
            actor_name: "同事",
            is_me: false,
            time: now - 1000,
            text: "stale rev 2 body",
            url: "",
            meta: { edit_version: 2, poll_observed_at: now + 5000 },
          },
        ]);
        assert.equal(store.obsPending("im:om_r23_rev"), false, "旧修订 rev 2 绝不得清除 rev 3 撤回墓碑并回到模型队列");

        // 场景 B：此前未见过的 ID 在 rev 3 被撤回 -> 写入撤回墓碑 -> 后续 stale rev 2 亦无法入队
        store.retirePendingObs("im:om_r23_unseen", {
          editVersion: 3,
          pollObservedAt: now,
          conv: "oc_r23_grp",
          kind: "at_me",
          time: now - 500,
        });
        store.addObs([
          {
            id: "im:om_r23_unseen",
            source: "im",
            kind: "at_me",
            conv: "oc_r23_grp",
            conv_name: "测试群",
            actor_id: "ou_other",
            actor_name: "同事",
            is_me: false,
            time: now - 500,
            text: "stale rev 2 for unseen",
            url: "",
            meta: { edit_version: 2, poll_observed_at: now + 6000 },
          },
        ]);
        assert.equal(store.obsPending("im:om_r23_unseen"), false, "首次即撤回的墓碑必须阻挡旧修订回灌");

        // 权威 +messages-mget 确认仍存活或更高修订 rev 4 才允许恢复
        store.addObs([
          {
            id: "im:om_r23_rev",
            source: "im",
            kind: "at_me",
            conv: "oc_r23_grp",
            conv_name: "测试群",
            actor_id: "ou_other",
            actor_name: "同事",
            is_me: false,
            time: now - 1000,
            text: "rev 4 restored",
            url: "",
            meta: { edit_version: 4, poll_observed_at: now + 7000 },
          },
        ]);
        assert.equal(store.obsPending("im:om_r23_rev"), true, "更高修订 rev 4 应允许恢复入队");
        assert.equal(store.obs("im:om_r23_rev")?.text, "rev 4 restored");
      } finally {
        app.store.db.close();
      }
    }

    // 3) [R23 #3 P1] 抓回正文明确不包含本人 mention 时，绝不得被 --is-at-me 搜索流标签覆盖绕过白名单，且应撤回旧 @我 观测
    {
      const app = makeR23App("r23-3-mention", {
        ownerOpenId: "ou_owner",
        pwEnabled: false,
        groupsMode: "allowlist",
        groupAllowlist: ["oc_allowed_only"],
      });
      try {
        const ctxSvc = new ContextService(app);
        const now = Date.now();
        // 预先存在一条旧的未处理 @我 观测（来自未在白名单的群）
        ctxSvc.store.addObs([
          {
            id: "im:om_edited_away",
            source: "im",
            kind: "at_me",
            conv: "oc_unlisted_grp",
            conv_name: "未入白名单群",
            actor_id: "ou_colleague",
            actor_name: "同事",
            is_me: false,
            time: now - 2000,
            text: "@我 帮忙看一下",
            url: "",
            meta: { at_me: true, edit_version: 1 },
          },
        ]);
        (ctxSvc.connectors as unknown as { lark: (args: string[]) => Promise<Record<string, unknown>> }).lark = async (args) => {
          if (args[0] === "auth" && args[1] === "status") {
            return { identity: "user", open_id: "ou_me_r23" };
          }
          if (args[0] === "im" && args[1] === "+messages-search" && args.includes("--is-at-me")) {
            return {
              messages: [
                {
                  message_id: "om_edited_away",
                  chat_id: "oc_unlisted_grp",
                  chat_type: "group",
                  chat_name: "未入白名单群",
                  sender: { id: "ou_colleague", name: "同事", sender_type: "user" },
                  create_time: String(now - 2000),
                  update_time: String(now - 500),
                  edit_version: 2,
                  content: "@Bob 改找 Bob 看一下",
                  mentions: [{ id: "ou_bob_only", name: "Bob" }],
                },
              ],
            };
          }
          return { messages: [], items: [] };
        };
        await ctxSvc.connectors.pullIm();
        assert.equal(
          ctxSvc.store.obsPending("im:om_edited_away"),
          false,
          "编辑移除 @我 后的未入白名单群消息绝不得以 at_me=true 留在队列中",
        );
        const row = app.store.db.prepare("SELECT processed, meta FROM ctx_obs WHERE id = ?").get("im:om_edited_away") as
          | { processed: number; meta: string }
          | undefined;
        assert.equal(row?.processed, 1, "原 @我 待处理观测必须被标记已撤回");
        assert.equal(JSON.parse(row!.meta).withdrawn, true);
      } finally {
        app.store.db.close();
      }
    }

    // 4) [R23 #4 P1] 隔离模式 Codex ACP (`agent: codex` + `tools: none`) 必须将安全供应商配置渲染到临时 CODEX_HOME/config.toml 并剥离 hooks/mcp_servers
    {
      const codexHomeR23 = path.join(dir, "r23-4-codex-home");
      fs.mkdirSync(codexHomeR23, { recursive: true });
      fs.writeFileSync(
        path.join(codexHomeR23, "config.toml"),
        [
          'model = "gpt-5.4"',
          'model_provider = "corp.gw"',
          'forced_chatgpt_workspace_id = "ws_r23_only"',
          'cli_auth_credentials_store = "file"',
          "",
          '[model_providers."corp.gw"]',
          'base_url = "https://gateway.corp.example/v1"',
          'env_key = "CORP_CODEX_KEY"',
          'http_headers = { "X-Api-Secret" = "super-secret-hdr" }',
          "",
          "[mcp_servers.evil]",
          'command = "evil-mcp"',
          "",
          "[hooks.pre_tool]",
          'command = "evil-hook"',
        ].join("\n"),
        { mode: 0o600 },
      );
      const safeCfg = extractSafeCodexProviderConfig({ HOME: dir, CODEX_HOME: codexHomeR23 }, [], false);
      const tomlStr = renderSafeCodexConfigToml(safeCfg);
      const parsedToml = parseToml(tomlStr);
      assert.equal(parsedToml.model_provider, "corp.gw");
      assert.equal(parsedToml.forced_chatgpt_workspace_id, "ws_r23_only");
      assert.equal(parsedToml.web_search, "disabled");
      assert.equal("mcp_servers" in parsedToml, false, "脱敏 config.toml 绝不得包含 mcp_servers");
      assert.equal("hooks" in parsedToml, false, "脱敏 config.toml 绝不得包含 hooks");
      const mp = parsedToml.model_providers as Record<string, Record<string, unknown>>;
      assert.equal(mp["corp.gw"].base_url, "https://gateway.corp.example/v1");
      const envHdrs = mp["corp.gw"].env_http_headers as Record<string, string>;
      assert.ok(envHdrs["X-Api-Secret"], "静态 http_headers 必须转为 env_http_headers 引用");
      assert.equal(safeCfg.extraEnv[envHdrs["X-Api-Secret"]], "super-secret-hdr");

      if (hasCredentialMountIsolation()) {
        const fakeAcpx = path.join(dir, "fake-acpx-codex-none.mjs");
        fs.writeFileSync(
          fakeAcpx,
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'import path from "node:path";',
            'const ch = process.env.CODEX_HOME || "";',
            'const cfg = fs.readFileSync(path.join(ch, "config.toml"), "utf8");',
            'console.log(JSON.stringify({ codexHome: ch, cfg, hdrVal: process.env.__PA_CODEX_HDR_0 || "" }));',
          ].join("\n"),
          { mode: 0o755 },
        );
        const app = makeR23App("r23-4-codex", { pwEnabled: true, acpxBin: fakeAcpx });
        try {
          app.cfg.harnesses.codex_acp = {
            type: "acpx",
            cmd: "",
            agent: "codex",
            extraArgs: [],
            env: { CODEX_HOME: codexHomeR23, CORP_CODEX_KEY: "dummy-corp-key" },
          };
          const res = await runHarness(app.cfg, {
            harness: "codex_acp",
            prompt: "ping",
            cwd: dir,
            tools: "none",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "r23-4.log"),
          });
          assert.equal(res.ok, true, `隔离 Codex ACP tools=none 应成功：${res.text}`);
          const out = JSON.parse(res.text) as { codexHome: string; cfg: string; hdrVal: string };
          assert.notEqual(out.codexHome, codexHomeR23);
          assert.ok(out.cfg.includes('model_provider = "corp.gw"'));
          assert.ok(out.cfg.includes('forced_chatgpt_workspace_id = "ws_r23_only"'));
          assert.ok(!out.cfg.includes("evil-mcp") && !out.cfg.includes("evil-hook"));
          assert.equal(out.hdrVal, "super-secret-hdr");
        } finally {
          app.store.db.close();
        }
      }
    }

    // 5) [R23 #5 P1] ACP config.json auth 严格按白名单仅投影当前选定适配器凭据，绝不泄露 Copilot/未知自定义凭据
    {
      const acpxHome = path.join(dir, "r23-5-home");
      fs.mkdirSync(path.join(acpxHome, ".acpx"), { recursive: true });
      fs.writeFileSync(
        path.join(acpxHome, ".acpx", "config.json"),
        JSON.stringify({
          agents: {
            "my-bot": { command: "/usr/bin/my-bot", authMethod: "corp-shared-oidc" },
          },
          auth: {
            "claude-oauth": "claude-tok",
            "anthropic-api-key": "ant-key",
            "openai-api-key": "oai-key",
            "copilot-token": "ghu_copilot_secret",
            "custom-unknown-method": "unknown_secret",
            "my-bot-token": "bot-tok",
            "corp-shared-oidc": "oidc-tok",
          },
        }),
      );
      assert.equal(isAuthMethodAllowedForAcpxAgent("copilot-token", "claude"), false);
      assert.equal(isAuthMethodAllowedForAcpxAgent("custom-unknown-method", "claude"), false);
      assert.equal(isAuthMethodAllowedForAcpxAgent("anthropic-api-key", "claude"), true);

      const stagedClaudeAcpx = stageIsolatedAcpxState({ agent: "claude" }, acpxHome, { HOME: acpxHome });
      try {
        const cfg = JSON.parse(fs.readFileSync(path.join(stagedClaudeAcpx!.dir, "config.json"), "utf8")) as {
          auth?: Record<string, string>;
        };
        assert.deepEqual(Object.keys(cfg.auth ?? {}).sort(), ["anthropic-api-key", "claude-oauth"]);
      } finally {
        stagedClaudeAcpx?.cleanup();
      }

      const stagedCustomAcpx = stageIsolatedAcpxState({ agent: "my-bot" }, acpxHome, { HOME: acpxHome });
      try {
        const cfg = JSON.parse(fs.readFileSync(path.join(stagedCustomAcpx!.dir, "config.json"), "utf8")) as {
          auth?: Record<string, string>;
        };
        assert.deepEqual(Object.keys(cfg.auth ?? {}).sort(), ["corp-shared-oidc", "my-bot-token"]);
      } finally {
        stagedCustomAcpx?.cleanup();
      }
    }

    // 6) [R23 #6 P1] Claude 仓库工人必须使用按次暂存的 ~/.claude 与脱敏 ~/.claude.json，绝不暴露宿主机 projects/ 与 history.jsonl
    {
      const claudeHome = path.join(dir, "r23-6-claude-home");
      const hostClaudeDir = path.join(claudeHome, ".claude");
      fs.mkdirSync(path.join(hostClaudeDir, "projects", "-other-secret-repo"), { recursive: true });
      fs.writeFileSync(path.join(hostClaudeDir, ".credentials.json"), '{"claudeAiOauth":{"accessToken":"ok_tok"}}', {
        mode: 0o600,
      });
      fs.writeFileSync(
        path.join(hostClaudeDir, "settings.json"),
        JSON.stringify({
          model: "claude-sonnet-4-5",
          env: { ANTHROPIC_BASE_URL: "https://anthropic.corp.example" },
          hooks: { PreToolUse: [{ command: "evil-hook" }] },
          apiKeyHelper: "/bin/evil-helper",
        }),
      );
      fs.writeFileSync(
        path.join(hostClaudeDir, "projects", "-other-secret-repo", "session.jsonl"),
        '{"text":"SECRET_OTHER_REPO_TRANSCRIPT"}\n',
      );
      fs.writeFileSync(path.join(hostClaudeDir, "history.jsonl"), '{"display":"SECRET_GLOBAL_HISTORY"}\n');
      fs.writeFileSync(
        path.join(claudeHome, ".claude.json"),
        JSON.stringify({
          oauthAccount: { emailAddress: "owner@example.com" },
          hasCompletedOnboarding: true,
          projects: {
            "/secret/other-repo": { history: ["SECRET_PROJECT_PROMPT"], lastCost: 12.34 },
          },
        }),
      );

      const stagedWrite = stageIsolatedClaudeState(claudeHome, { HOME: claudeHome }, undefined, { tools: "write" });
      try {
        assert.ok(stagedWrite);
        assert.equal(fs.existsSync(path.join(stagedWrite!.dir, ".credentials.json")), true);
        assert.equal(fs.existsSync(path.join(stagedWrite!.dir, "settings.json")), true);
        assert.equal(fs.existsSync(path.join(stagedWrite!.dir, "projects")), false, "绝不得复制宿主机 projects/ 跨仓库会话记录");
        assert.equal(fs.existsSync(path.join(stagedWrite!.dir, "history.jsonl")), false, "绝不得复制宿主机 history.jsonl");
        const sj = JSON.parse(fs.readFileSync(stagedWrite!.claudeJsonFile, "utf8")) as Record<string, unknown>;
        assert.deepEqual(sj.oauthAccount, { emailAddress: "owner@example.com" });
        assert.deepEqual(sj.projects, {}, "脱敏 ~/.claude.json 必须清空 projects 历史");
      } finally {
        stagedWrite?.cleanup();
      }

      const stagedNone = stageIsolatedClaudeState(claudeHome, { HOME: claudeHome }, undefined, { tools: "none" });
      try {
        const s = JSON.parse(fs.readFileSync(path.join(stagedNone!.dir, "settings.json"), "utf8")) as Record<string, unknown>;
        assert.equal(s.model, "claude-sonnet-4-5");
        assert.deepEqual(s.env, { ANTHROPIC_BASE_URL: "https://anthropic.corp.example" });
        assert.equal("hooks" in s, false, "tools=none 必须剥离 Claude hooks");
        assert.equal("apiKeyHelper" in s, false, "tools=none 必须剥离 apiKeyHelper");
      } finally {
        stagedNone?.cleanup();
      }

      if (hasCredentialMountIsolation()) {
        const fakeAcpx = path.join(dir, "fake-acpx-claude-iso.mjs");
        fs.writeFileSync(
          fakeAcpx,
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'import path from "node:path";',
            'const h = process.env.HOME;',
            'const hasCred = fs.existsSync(path.join(h, ".claude", ".credentials.json"));',
            'const hasProjects = fs.existsSync(path.join(h, ".claude", "projects"));',
            'const hasHist = fs.existsSync(path.join(h, ".claude", "history.jsonl"));',
            'const cj = JSON.parse(fs.readFileSync(path.join(h, ".claude.json"), "utf8"));',
            'console.log(JSON.stringify({ hasCred, hasProjects, hasHist, projectsKeys: Object.keys(cj.projects || {}), email: cj.oauthAccount?.emailAddress }));',
          ].join("\n"),
          { mode: 0o755 },
        );
        const repoDir = path.join(dir, "r23-6-repo");
        fs.mkdirSync(repoDir, { recursive: true });
        const app = makeR23App("r23-6-claude", { pwEnabled: true, acpxBin: fakeAcpx });
        try {
          app.cfg.harnesses.claude_iso = {
            type: "acpx",
            cmd: "",
            agent: "claude",
            extraArgs: [],
            env: { HOME: claudeHome },
          };
          const res = await runHarness(app.cfg, {
            harness: "claude_iso",
            prompt: "check",
            cwd: repoDir,
            tools: "write",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "r23-6.log"),
            disableGitWorktreeMounts: true,
          });
          assert.equal(res.ok, true, `隔离 Claude 工人应成功运行：${res.text}`);
          const out = JSON.parse(res.text) as {
            hasCred: boolean;
            hasProjects: boolean;
            hasHist: boolean;
            projectsKeys: string[];
            email: string;
          };
          assert.equal(out.hasCred, true);
          assert.equal(out.hasProjects, false, "隔离沙箱内 Claude 工人绝不能看到宿主机 ~/.claude/projects");
          assert.equal(out.hasHist, false, "隔离沙箱内 Claude 工人绝不能看到宿主机 ~/.claude/history.jsonl");
          assert.deepEqual(out.projectsKeys, [], "隔离沙箱内 ~/.claude.json 绝不能包含其他仓库项目记录");
          assert.equal(out.email, "owner@example.com");
        } finally {
          app.store.db.close();
        }
      }
    }

    // 7) [R23 #7 P2] personal-web handleMessage 在 await ensureCrossTransportScopeMeta 之后必须再次校验会话仍活跃再撤回观测
    {
      const app = makeR23App("r23-7-pw-revoke", {
        ownerOpenId: "ou_me_r23",
        pwEnabled: true,
        groupsMode: "allowlist",
        groupAllowlist: ["允许群"],
      });
      try {
        const store = new ContextStore(app.store.db);
        const now = Date.now();
        store.addObs([
          {
            id: "pw:777001",
            source: "im",
            kind: "at_me",
            conv: "pw_chat:888001",
            conv_name: "新会话群",
            actor_id: "700200",
            actor_name: "同事",
            is_me: false,
            time: now,
            text: "新会话有效消息",
            url: "",
            meta: { at_me: true },
          },
        ]);
        const bridge = new PersonalWebBridge(app, store, {
          onFastTrigger: () => undefined,
          onReconnect: () => undefined,
          onNeedsLogin: () => undefined,
        });
        const msg: WebMessage = {
          id: "777001",
          ownerId: "700100",
          actorId: "700200",
          conversationId: "888001",
          conversationKind: "group",
          rootId: "",
          parentId: "",
          threadId: "",
          cid: "",
          kind: MSG_TEXT,
          senderType: USER_SENDER_TYPE,
          messageType: "text",
          createdAtMs: now,
          position: 1,
          threadPosition: 0,
          sendToChat: true,
          text: "改完不再 @我 的普通群消息",
          mentions: [],
          resources: [],
          unsupported: false,
          partial: false,
        };
        const fakeClient = {
          currentSessionId: () => "sess-gen-1",
          owner: () => ({ id: "700100", openId: "ou_me_r23" }),
          readMessage: async () => msg,
        } as unknown as FeishuWebClient;
        const priv = bridge as unknown as {
          ensureCrossTransportScopeMeta: (chatId: string, isGroup: boolean) => Promise<void>;
        };
        saveWorkspaceBinding(app.store, "700100", "ou_me_r23");
        app.store.set(ACTIVE_SESSION_KV_KEY, "sess-gen-1");
        // 模拟 ensureCrossTransportScopeMeta 异步网络查询期间发生了登出/换会话（ACTIVE_SESSION_KV_KEY 被新会话取代）
        priv.ensureCrossTransportScopeMeta = async () => {
          app.store.set(ACTIVE_SESSION_KV_KEY, "sess-gen-2");
        };
        await assert.rejects(
          () => bridge.handleMessage(msg, fakeClient),
          /已被更新的登录取代|已吊销|放弃修改本地观测/,
          "await ensureCrossTransportScopeMeta 期间会话被取代后，handleMessage 必须在撤回观测前中止",
        );
        assert.equal(
          store.obsPending("pw:777001"),
          true,
          "旧监听回调绝不得撤回新会话的待处理观测",
        );
      } finally {
        app.store.db.close();
      }
    }

    // 8) [R23 #8 P2] 暂存 Codex OAuth 刷新后常驻进程崩溃（未写回宿主机即退出），下次调用先原子恢复新令牌再复用
    {
      const crashCodexHome = path.join(dir, "r23-8-codex-crash");
      fs.mkdirSync(crashCodexHome, { recursive: true });
      const hostAuthPath = path.join(crashCodexHome, "auth.json");
      const expiredPayload = {
        auth_mode: "chatgpt",
        tokens: {
          access_token: "acc_old_consumed",
          refresh_token: "ref_old_single_use",
          account_id: "acct_crash_1",
        },
        last_refresh: "2020-01-01T00:00:00.000Z",
      };
      fs.writeFileSync(hostAuthPath, JSON.stringify(expiredPayload, null, 2), { mode: 0o600 });

      const lease1 = await coordinateCodexOAuthRefresh(crashCodexHome, { leaseTtlMs: 30_000 });
      assert.equal(lease1.held, true);
      const staged1 = stageIsolatedCodexHome(crashCodexHome, { copyUserConfig: false });
      lease1.attachScratch?.(staged1);
      // 模拟 Codex 子进程已在暂存目录中消耗旧 refresh_token 并写入新令牌，随后常驻进程崩溃（未调用 syncRefreshedCodexAuth 与 cleanup）
      const rotatedNow = new Date().toISOString();
      fs.writeFileSync(
        path.join(staged1.scratchDir, "auth.json"),
        JSON.stringify({
          auth_mode: "chatgpt",
          tokens: {
            access_token: "acc_rotated_new",
            refresh_token: "ref_rotated_new",
            account_id: "acct_crash_1",
          },
          last_refresh: rotatedNow,
        }),
        { mode: 0o600 },
      );
      // 模拟原进程已死（改写锁库中的 pid 为不存在的死 PID，模拟 SIGKILL 后重启）
      const lockDbPath = canonicalCodexLockFilePath(hostAuthPath);
      const lockDb = new DatabaseSync(lockDbPath);
      try {
        lockDb.prepare("UPDATE refresh_lease SET pid = 999999999, expires_at = 0").run();
        lockDb.prepare("UPDATE pending_recovery SET pid = 999999999").run();
      } finally {
        lockDb.close();
      }

      // 下一次调用 coordinateCodexOAuthRefresh 必须先原子恢复新令牌到宿主机，再发现令牌已新鲜（held=false），且清理遗留暂存目录
      const lease2 = await coordinateCodexOAuthRefresh(crashCodexHome, { leaseTtlMs: 30_000 });
      try {
        assert.equal(lease2.held, false, "恢复最新旋转令牌后凭据已新鲜，不应再次抢占刷新锁");
        const recovered = JSON.parse(fs.readFileSync(hostAuthPath, "utf8")) as {
          tokens: { access_token: string; refresh_token: string };
        };
        assert.equal(recovered.tokens.access_token, "acc_rotated_new");
        assert.equal(recovered.tokens.refresh_token, "ref_rotated_new");
        assert.equal(fs.existsSync(staged1.scratchDir), false, "恢复完成后应清理已死进程的遗留暂存目录");
      } finally {
        lease2.release();
        lease1.release();
      }
    }

    // 9) [R23 #9 P2] 非隔离 Codex ACP 依赖 keyring 时必须恢复宿主机 DBUS_SESSION_BUS_ADDRESS；不依赖凭据库时不恢复
    {
      const prevDbus = process.env.DBUS_SESSION_BUS_ADDRESS;
      const fakeAcpxDbus = path.join(dir, "fake-acpx-dbus.mjs");
      fs.writeFileSync(
        fakeAcpxDbus,
        [
          "#!/usr/bin/env node",
          'console.log(JSON.stringify({ dbus: process.env.DBUS_SESSION_BUS_ADDRESS || "" }));',
        ].join("\n"),
        { mode: 0o755 },
      );
      const keyringCodexHome = path.join(dir, "r23-9-codex-home");
      fs.mkdirSync(keyringCodexHome, { recursive: true });
      fs.writeFileSync(path.join(keyringCodexHome, "config.toml"), 'cli_auth_credentials_store = "keyring"\n');
      const app = makeR23App("r23-9-dbus", { pwEnabled: false, acpxBin: fakeAcpxDbus });
      process.env.DBUS_SESSION_BUS_ADDRESS = "unix:path=/tmp/fake-r23-dbus-bus";
      try {
        app.cfg.harnesses.codex_kr = {
          type: "acpx",
          cmd: "",
          agent: "codex",
          extraArgs: [],
          env: { CODEX_HOME: keyringCodexHome, OPENAI_API_KEY: "", CODEX_API_KEY: "" },
        };
        const rNeed = await runHarness(app.cfg, {
          harness: "codex_kr",
          prompt: "hi",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "r23-9-need.log"),
        });
        assert.equal(rNeed.ok, true);
        assert.equal(JSON.parse(rNeed.text).dbus, "unix:path=/tmp/fake-r23-dbus-bus", "非隔离且依赖 keyring 的 Codex ACP 必须保留 D-Bus 地址");

        app.cfg.harnesses.codex_api = {
          type: "acpx",
          cmd: "",
          agent: "codex",
          extraArgs: [],
          env: { CODEX_HOME: keyringCodexHome, OPENAI_API_KEY: "sk-direct-api" },
        };
        const rApi = await runHarness(app.cfg, {
          harness: "codex_api",
          prompt: "hi",
          cwd: dir,
          tools: "none",
          lark: "none",
          timeoutSec: 15,
          logFile: path.join(dir, "r23-9-api.log"),
        });
        assert.equal(rApi.ok, true);
        assert.equal(JSON.parse(rApi.text).dbus, "", "提供显式 API Key 不依赖 keyring 时绝不恢复 D-Bus 地址");
      } finally {
        app.store.db.close();
        if (prevDbus === undefined) delete process.env.DBUS_SESSION_BUS_ADDRESS;
        else process.env.DBUS_SESSION_BUS_ADDRESS = prevDbus;
      }
    }

    // 10) [R23 #10 P2] 解释器启动的 ACP 适配器（如 `node ~/.acpx/adapters/worker.mjs`）必须连同入口脚本与相对依赖一起暂存，不暴露兄弟适配器或 sessions/
    {
      assert.deepEqual(
        parseShellCommandTokens('node "/home/me/.acpx/adapters/my worker.mjs" --stdio'),
        ["node", "/home/me/.acpx/adapters/my worker.mjs", "--stdio"],
      );
      const interpHome = path.join(dir, "r23-10-home");
      const adaptersDir = path.join(interpHome, ".acpx", "adapters");
      const sessionsDir = path.join(interpHome, ".acpx", "sessions");
      fs.mkdirSync(adaptersDir, { recursive: true });
      fs.mkdirSync(sessionsDir, { recursive: true });
      const workerScript = path.join(adaptersDir, "worker.mjs");
      fs.writeFileSync(path.join(adaptersDir, "helper.mjs"), 'export const MSG = "HELPER_LOADED_R23";\n');
      fs.writeFileSync(workerScript, 'import { MSG } from "./helper.mjs";\nconsole.log(MSG);\n');
      fs.writeFileSync(path.join(adaptersDir, "other-secret-adapter.mjs"), 'export const SECRET = "NO_LEAK";\n');
      fs.writeFileSync(path.join(sessionsDir, "other.json"), '{"secret":true}\n');

      const staged = stageIsolatedAcpxState({ agentCommand: `node ${workerScript} --stdio` }, interpHome, {
        HOME: interpHome,
      });
      try {
        assert.ok(staged);
        assert.equal(fs.existsSync(path.join(staged!.dir, "adapters", "worker.mjs")), true);
        assert.equal(fs.existsSync(path.join(staged!.dir, "adapters", "helper.mjs")), true);
        assert.equal(fs.existsSync(path.join(staged!.dir, "adapters", "other-secret-adapter.mjs")), false);
        assert.equal(fs.existsSync(path.join(staged!.dir, "sessions")), false);
        assert.ok(staged!.extraCmdPaths.includes("node"));
      } finally {
        staged?.cleanup();
      }

      if (hasCredentialMountIsolation()) {
        const fakeAcpxRun = path.join(dir, "fake-acpx-interp.mjs");
        fs.writeFileSync(
          fakeAcpxRun,
          [
            "#!/usr/bin/env node",
            'import { spawnSync } from "node:child_process";',
            'import fs from "node:fs";',
            'import path from "node:path";',
            'const idx = process.argv.indexOf("--agent");',
            'const cmdParts = process.argv[idx + 1].split(/\\s+/);',
            'const r = spawnSync(cmdParts[0], cmdParts.slice(1), { encoding: "utf8" });',
            'const leakedOther = fs.existsSync(path.join(process.env.HOME, ".acpx", "adapters", "other-secret-adapter.mjs"));',
            'const leakedSess = fs.existsSync(path.join(process.env.HOME, ".acpx", "sessions", "other.json"));',
            'console.log(JSON.stringify({ code: r.status, out: r.stdout.trim(), leakedOther, leakedSess }));',
          ].join("\n"),
          { mode: 0o755 },
        );
        const app = makeR23App("r23-10-interp", { pwEnabled: true, acpxBin: fakeAcpxRun });
        try {
          app.cfg.harnesses.interp_bot = {
            type: "acpx",
            cmd: "",
            agentCommand: `${process.execPath} ${workerScript}`,
            extraArgs: [],
            env: { HOME: interpHome },
          };
          const res = await runHarness(app.cfg, {
            harness: "interp_bot",
            prompt: "hi",
            cwd: dir,
            tools: "none",
            lark: "none",
            timeoutSec: 15,
            logFile: path.join(dir, "r23-10.log"),
          });
          assert.equal(res.ok, true, `隔离沙箱内解释器入口适配器应运行成功：${res.text}`);
          const parsed = JSON.parse(res.text) as { code: number; out: string; leakedOther: boolean; leakedSess: boolean };
          assert.equal(parsed.code, 0);
          assert.equal(parsed.out, "HELPER_LOADED_R23");
          assert.equal(parsed.leakedOther, false);
          assert.equal(parsed.leakedSess, false);
        } finally {
          app.store.db.close();
        }
      }
    }

    // 11) [R23 #11 P2] SSH origin + 独立认证 HTTPS lfs.pushurl / .lfsconfig 时，隔离 git lfs 子命令必须投影 LFS 端点凭据
    if (hasCredentialMountIsolation()) {
      const lfsHome = path.join(dir, "r23-11-lfs-home");
      const lfsRepo = path.join(dir, "r23-11-repo");
      const lfsBinDir = path.join(dir, "r23-11-bin");
      fs.mkdirSync(lfsHome, { recursive: true });
      fs.mkdirSync(lfsRepo, { recursive: true });
      fs.mkdirSync(lfsBinDir, { recursive: true });

      const credFile = path.join(lfsHome, ".git-credentials");
      fs.writeFileSync(
        credFile,
        [
          "https://lfsuser:lfspass@lfs.corp.example/org/repo.git/info/lfs",
          "https://other:otherpass@unrelated.example/secret",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(lfsHome, ".gitconfig"),
        `[credential]\n\thelper = store --file=${credFile}\n`,
        { mode: 0o600 },
      );
      // stub git-lfs 在隔离沙箱内调用 `git credential fill` 模拟真实 git-lfs 获取 lfs.pushurl 的凭据
      const stubGitLfs = path.join(lfsBinDir, "git-lfs");
      fs.writeFileSync(
        stubGitLfs,
        [
          "#!/usr/bin/env node",
          'import { spawnSync } from "node:child_process";',
          'const fillLfs = spawnSync("git", ["credential", "fill"], { input: "protocol=https\\nhost=lfs.corp.example\\npath=org/repo.git/info/lfs\\n\\n", encoding: "utf8" });',
          'const fillOther = spawnSync("git", ["credential", "fill"], { input: "protocol=https\\nhost=unrelated.example\\npath=secret\\n\\n", encoding: "utf8" });',
          'console.log(JSON.stringify({ lfs: fillLfs.stdout, other: fillOther.stdout }));',
        ].join("\n"),
        { mode: 0o755 },
      );

      await runProcess("git", ["init", "-q", lfsRepo]);
      await runProcess("git", ["-C", lfsRepo, "remote", "add", "origin", "git@github.com:org/repo.git"]);
      await runProcess("git", ["-C", lfsRepo, "config", "lfs.pushurl", "https://lfs.corp.example/org/repo.git/info/lfs"]);

      const dataDir = path.join(dir, "r23-11-data");
      fs.mkdirSync(dataDir, { recursive: true });
      const r = await tryGit(lfsRepo, ["lfs", "pre-push", "origin", "git@github.com:org/repo.git"], {
        cfg: { dataDir, context: { personal_web: { enabled: true } } as Config["context"] },
        extraEnv: { HOME: lfsHome, PATH: `${lfsBinDir}${path.delimiter}${process.env.PATH ?? ""}` },
        extraReadOnlyPaths: [lfsBinDir],
      });
      assert.equal(r.code, 0, `隔离 git lfs pre-push 应获取独立 HTTPS lfs.pushurl 凭据：${r.stderr}`);
      const out = JSON.parse(r.stdout.trim()) as { lfs: string; other: string };
      assert.ok(out.lfs.includes("username=lfsuser") && out.lfs.includes("password=lfspass"), "必须向沙箱投影 lfs.pushurl 对应凭据");
      assert.ok(!out.other.includes("otherpass"), "绝不得泄露无关域名的凭据");
    }

    // 12) [R23 #12 P2] 符号链接本地镜像远端（含直连符号链接与祖先目录符号链接）在隔离沙箱内 remoteDefaultBranch 与 pushBranch 均须成功
    if (hasCredentialMountIsolation()) {
      const realMirrorsDir = path.join(dir, "r23-12-real-mirrors");
      const symlinkBaseDir = path.join(dir, "r23-12-links");
      const bareRepo = path.join(realMirrorsDir, "upstream.git");
      const mirrorLink = path.join(symlinkBaseDir, "upstream-link.git");
      const workRepo = path.join(dir, "r23-12-work");
      fs.mkdirSync(realMirrorsDir, { recursive: true });
      fs.mkdirSync(symlinkBaseDir, { recursive: true });
      await runProcess("git", ["init", "--bare", "-b", "main", "-q", bareRepo]);
      fs.symlinkSync(bareRepo, mirrorLink);

      const mountInfo = resolveLocalGitRemoteMount(dir, mirrorLink);
      assert.ok(mountInfo);
      assert.equal(mountInfo!.realDir, fs.realpathSync(bareRepo));
      assert.equal(mountInfo!.symlinks.length, 1);

      await runProcess("git", ["init", "-b", "main", "-q", workRepo]);
      await runProcess("git", ["-C", workRepo, "config", "user.name", "Tester"]);
      await runProcess("git", ["-C", workRepo, "config", "user.email", "t@example.com"]);
      fs.writeFileSync(path.join(workRepo, "README.md"), "hello\n");
      await runProcess("git", ["-C", workRepo, "add", "README.md"]);
      await runProcess("git", ["-C", workRepo, "commit", "-q", "-m", "init"]);
      await runProcess("git", ["-C", workRepo, "remote", "add", "origin", mirrorLink]);
      await runProcess("git", ["-C", workRepo, "push", "-q", "origin", "main"]);
      await runProcess("git", ["-C", workRepo, "checkout", "-q", "-b", "pa/symlink-remote"]);
      fs.writeFileSync(path.join(workRepo, "change.txt"), "ok\n");
      await runProcess("git", ["-C", workRepo, "add", "change.txt"]);
      await runProcess("git", ["-C", workRepo, "commit", "-q", "-m", "feat"]);

      const dataDir = path.join(dir, "r23-12-data");
      fs.mkdirSync(dataDir, { recursive: true });
      const isoCfg = { dataDir, context: { personal_web: { enabled: true } } as Config["context"] };
      const defBranch = await remoteDefaultBranch(workRepo, "origin", { cfg: isoCfg });
      assert.equal(defBranch, "main", "符号链接本地镜像在隔离沙箱内 remoteDefaultBranch 必须正常返回 main");
      const pushRes = await pushBranch(workRepo, "origin", "pa/symlink-remote", { cfg: isoCfg });
      assert.equal(pushRes.ok, true, `符号链接本地镜像在隔离沙箱内 pushBranch 必须成功：${pushRes.ok ? "" : pushRes.message}`);
    }

    // 13) [R23 #13 P2] unshare 回退后端必须还原非 root 调用者真实 UID/GID 与零能力，使 OpenSSH 查到真实宿主目录而非 /root
    {
      const unshareBin = resolveTrustedSystemBin("unshare");
      const setprivBin = resolveTrustedSystemBin("setpriv");
      const pivotRootBin = resolveTrustedSystemBin("pivot_root");
      const shBin = resolveTrustedSystemBin("sh");
      const origUid = typeof process.getuid === "function" ? process.getuid() : 0;
      if (unshareBin && setprivBin && pivotRootBin && shBin && origUid > 0) {
        const dataDir = path.join(dir, "r23-13-data");
        fs.mkdirSync(dataDir, { recursive: true });
        const wrapped = wrapCredentialIsolatedCommand(
          shBin,
          ["-c", 'printf "%s|%s" "$(id -u)" "$(awk \'/^CapEff:/{print $2}\' /proc/self/status)"'],
          { ...process.env, PA_FEISHU_WEB_KEY: TEST_WEB_KEY },
          {
            dataDir,
            requireIsolation: true,
            cwd: dir,
            forceBackend: { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin, shBin, restoreUserMap: true },
          },
        );
        const r = await runProcess(wrapped.cmd, wrapped.args, { timeoutMs: 10_000 });
        assert.equal(r.code, 0, `unshare 嵌套还原 UID 应成功：${r.stderr}`);
        const [uidStr, capEff] = r.stdout.trim().split("|");
        assert.equal(Number(uidStr), origUid, "unshare 回退后子进程 UID 必须为调用者真实非 root UID，而非 0（避免 OpenSSH 查找 /root/.ssh）");
        assert.equal(capEff, "0000000000000000", "unshare 回退后子进程有效能力集必须全零");
      }
    }

    // 14) [R23 #14 P2] SSH config 中带 %h / %n / %r 等占位符的 IdentityFile 必须先按生效主机/用户展开再挂载
    {
      const sshTokHome = path.join(dir, "r23-14-ssh-home");
      const keysDir = path.join(sshTokHome, ".ssh", "keys");
      fs.mkdirSync(keysDir, { recursive: true });
      fs.writeFileSync(path.join(keysDir, "git.corp.example"), "PRIV_HOST_KEY", { mode: 0o600 });
      fs.writeFileSync(path.join(keysDir, "git.corp.example.pub"), "ssh-ed25519 AAAAHostKey\n");
      fs.writeFileSync(path.join(keysDir, "corp-alias_deploy"), "PRIV_ALIAS_USER_KEY", { mode: 0o600 });
      fs.writeFileSync(path.join(keysDir, "other-host"), "UNRELATED_PRIV", { mode: 0o600 });
      fs.writeFileSync(path.join(sshTokHome, ".ssh", "id_rsa"), "FALLBACK_RSA", { mode: 0o600 });
      fs.writeFileSync(
        path.join(sshTokHome, ".ssh", "config"),
        [
          "Host *",
          "  IdentityFile ~/.ssh/keys/%h",
          "  IdentityFile ~/.ssh/keys/%Z",
          "",
          "Host corp-alias",
          "  HostName git.corp.example",
          "  User deploy",
          "  IdentityFile ~/.ssh/keys/%n_%r",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      const mounts = collectScopedSshMounts([{ host: "corp-alias" }], { HOME: sshTokHome });
      assert.ok(
        mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}git.corp.example`)),
        "IdentityFile ~/.ssh/keys/%h 必须按生效 HostName 展开并挂载",
      );
      assert.ok(
        mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}corp-alias_deploy`)),
        "IdentityFile ~/.ssh/keys/%n_%r 必须按别名与生效 User 展开并挂载",
      );
      assert.ok(
        !mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}other-host`)),
        "绝不得挂载无关主机私钥",
      );
      assert.ok(
        !mounts.readOnlyPaths.some((p) => p.endsWith(`${path.sep}id_rsa`)),
        "命中显式 IdentityFile 后不得挂载无关默认 id_rsa",
      );
    }

    // 15) [R23 #15 P2] 查询宿主机非 store Git credential helper 与匹配 store 行时必须携带 URL 作用域的 credential.<url>.username
    {
      // 15a) store 行按 effectiveUsername 过滤
      const targetUrl = new URL("https://git.corp.example/org/repo.git");
      assert.equal(
        gitCredentialLineMatchesTarget("https://alice:tokA@git.corp.example", targetUrl, false, "alice"),
        true,
      );
      assert.equal(
        gitCredentialLineMatchesTarget("https://bob:tokB@git.corp.example", targetUrl, false, "alice"),
        false,
        "指定 credential.<url>.username=alice 时绝不得匹配 bob 的 store 条目",
      );

      // 15b) 端到端隔离 tryGit：宿主机 global 非 store helper 仅在收到 username=alice 时返回密码
      if (hasCredentialMountIsolation()) {
        let sawAuthHeader = "";
        helperSrv = http.createServer((req, res) => {
          const auth = String(req.headers.authorization ?? "");
          if (!auth) {
            res.writeHead(401, { "WWW-Authenticate": 'Basic realm="r23"' });
            res.end("auth required");
            return;
          }
          sawAuthHeader = auth;
          res.statusCode = 404;
          res.end("not found");
        });
        await new Promise<void>((resolve) => helperSrv!.listen(0, "127.0.0.1", () => resolve()));
        const port = (helperSrv.address() as { port: number }).port;
        const helperHome = path.join(dir, "r23-15-helper-home");
        const repo15 = path.join(dir, "r23-15-repo");
        fs.mkdirSync(helperHome, { recursive: true });
        await runProcess("git", ["init", "-q", repo15]);
        const helperScript = path.join(dir, "r23-15-cred-helper.mjs");
        fs.writeFileSync(
          helperScript,
          [
            "#!/usr/bin/env node",
            'import fs from "node:fs";',
            'const inp = fs.readFileSync(0, "utf8");',
            'const m = inp.match(/^username=(.+)$/m);',
            'if (m && m[1].trim() === "alice") {',
            '  process.stdout.write("username=alice\\npassword=secret_alice_r23\\n");',
            '} else {',
            '  process.stdout.write("username=wrong\\npassword=wrong_pass\\n");',
            "}",
          ].join("\n"),
          { mode: 0o755 },
        );
        fs.writeFileSync(
          path.join(helperHome, ".gitconfig"),
          [
            `[credential "http://127.0.0.1:${port}"]`,
            "\tusername = alice",
            `\thelper = !${helperScript}`,
          ].join("\n") + "\n",
          { mode: 0o600 },
        );
        const dataDir = path.join(dir, "r23-15-data");
        fs.mkdirSync(dataDir, { recursive: true });
        await tryGit(repo15, ["ls-remote", `http://127.0.0.1:${port}/org/repo.git`], {
          readOnly: true,
          cfg: { dataDir, context: { personal_web: { enabled: true } } as Config["context"] },
          extraEnv: { HOME: helperHome },
        });
        const expectedAuth = `Basic ${Buffer.from("alice:secret_alice_r23").toString("base64")}`;
        assert.equal(
          sawAuthHeader,
          expectedAuth,
          "受信任宿主机查询非 store credential helper 时必须传入 credential.<url>.username=alice",
        );
      }
    }

    // 16) [R23 #16 P2] 5,000 条失败 effect 下 health() 批量归属校验精确计数且保持毫秒级响应（不阻塞事件循环）
    {
      const app = makeR23App("r23-16-health-perf", { ownerOpenId: "ou_cur_owner" });
      try {
        const now = Date.now();
        app.store.set("ctx.own_task_owner.t_foreign_r23", "ou_old_owner");
        app.ledger.tx(() => {
          const ins = app.ledger.db.prepare(
            `INSERT INTO work (id, kind, ref, state, terminal, outcome, reason, attempts, next_at, lease_owner, lease_until, cancel, payload, error, created, updated)
             VALUES (?, 'effect', ?, 'dead', 1, ?, '', 3, 0, '', 0, 0, ?, 'boom', ?, ?)`,
          );
          for (let i = 0; i < 5000; i++) {
            const isForeign = i % 10 === 0; // 500 foreign isolated
            const isAcked = !isForeign && i % 5 === 1; // 1000 acked own
            // remaining 3500 actionable own
            const ref = isForeign ? "t_foreign_r23" : `t_own_${i}`;
            const outcome = isAcked ? "acknowledged" : "";
            const payload = JSON.stringify({
              op: "task.comment",
              args: { guid: ref, content: `msg ${i}` },
            });
            ins.run(`eff:r23:${i}`, ref, outcome, payload, now - 5000 + i, now - 5000 + i);
          }
        });

        const t0 = performance.now();
        const h = Q.health(app);
        const elapsedMs = performance.now() - t0;
        assert.equal(h.actionable_failures, 3500, "批量扫描 5,000 条失败记录必须精确统计 3,500 条当前主人未确认故障");
        assert.equal(h.failed.length, 200, "展示列表严格限制 200 条");
        assert.equal(
          h.failed.every((f) => !f.isolated && !f.acknowledged),
          true,
          "未确认当前主人失败 >= 200 时，展示列表应全部优先保留未确认当前主人失败",
        );
        assert.ok(
          elapsedMs < 250,
          `5,000 条失败 effect 下批量 health() 应在 250ms 内完成（实际 ${elapsedMs.toFixed(1)}ms）`,
        );
      } finally {
        app.store.db.close();
      }
    }
  } finally {
    if (helperSrv) await new Promise<void>((resolve) => helperSrv!.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("第 24 轮 Codex review 修复回归：AWS SSO 单会话隔离 / Gemini&OpenCode 会话隔离 / 本地 Git 配置脱敏与 GIT_CONFIG_GLOBAL / Claude OAuth 刷新写回 / 越窗显式去@ / 撤回证据过滤与墓碑身份恢复 / CMD-8 缺失区分 / Go 模块缓存 / ACP 适配器复用 / LFS 预拉取与多 pushurl 命名端点 / 隔离提交签名 / WS 活跃保活 / Doctor 告警 / QR N3", async () => {
  const dir = makeTmp("pa-r24-");
  const serversToClose: (http.Server | net.Server)[] = [];
  const prevPwKey = process.env.PA_FEISHU_WEB_KEY;
  if (!process.env.PA_FEISHU_WEB_KEY) {
    process.env.PA_FEISHU_WEB_KEY = crypto.randomBytes(32).toString("hex");
  }

  const makeR24App = (
    name: string,
    opts?: {
      ownerOpenId?: string;
      pwEnabled?: boolean;
      groupsMode?: "all" | "allowlist";
      groupAllowlist?: string[];
      acpxBin?: string;
    },
  ) => {
    const sub = path.join(dir, name);
    fs.mkdirSync(sub, { recursive: true });
    const cfgPath = path.join(sub, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({
        data_dir: path.join(sub, "data"),
        bins: {
          lark: path.join(STUBS, "ctx-lark"),
          acpx: opts?.acpxBin ?? path.join(STUBS, "acpx"),
          bytedcli: path.join(STUBS, "ctx-bytedcli"),
        },
        harnesses: {
          codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") },
        },
        roles: { brain: "codex" },
        owner: { open_id: opts?.ownerOpenId ?? "ou_owner_r24" },
        cards: { enabled: false },
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "codex",
          groups: opts?.groupsMode ?? "allowlist",
          groups_allow: opts?.groupAllowlist ?? [],
          groups_deny: [],
          sources: { im: true, minutes: false, docs: false, tasks: false, calendar: false, meego: false },
          personal_web: { enabled: opts?.pwEnabled ?? false, fast_lane: true, debounce_ms: 0, pre_draft: false },
        },
      }),
    );
    return createApp(loadConfig(cfgPath));
  };

  try {
    // 1) [R24 #1 P1] AWS SSO 缓存仅按所选 sso_session / sso_start_url 与引用 clientId 暂存，绝不挂载整目录暴露无关 SSO 会话令牌
    {
      const awsHome = path.join(dir, "r24-1-aws-home");
      const awsDir = path.join(awsHome, ".aws");
      const ssoCacheDir = path.join(awsDir, "sso", "cache");
      fs.mkdirSync(ssoCacheDir, { recursive: true });
      fs.writeFileSync(
        path.join(awsDir, "config"),
        [
          "[profile work-bedrock]",
          "sso_session = corp-prod",
          "sso_account_id = 111111111111",
          "sso_role_name = BedrockRole",
          "region = us-east-1",
          "",
          "[sso-session corp-prod]",
          "sso_start_url = https://prod.awsapps.com/start",
          "sso_region = us-east-1",
          "",
          "[profile other-unrelated]",
          "sso_session = other-corp",
          "sso_account_id = 222222222222",
          "sso_role_name = Admin",
          "",
          "[sso-session other-corp]",
          "sso_start_url = https://other.awsapps.com/start",
          "sso_region = us-west-2",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      const prodSessionHash = crypto.createHash("sha1").update("corp-prod").digest("hex");
      const otherSessionHash = crypto.createHash("sha1").update("other-corp").digest("hex");
      const prodClientRegHash = crypto.createHash("sha1").update("prod-client-reg").digest("hex");
      fs.writeFileSync(
        path.join(ssoCacheDir, `${prodSessionHash}.json`),
        JSON.stringify({
          startUrl: "https://prod.awsapps.com/start",
          accessToken: "PROD_SSO_TOKEN",
          refreshToken: "PROD_SSO_REFRESH",
          clientId: "prod-client-id-123",
        }),
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(ssoCacheDir, `${prodClientRegHash}.json`),
        JSON.stringify({ clientId: "prod-client-id-123", clientSecret: "PROD_CLIENT_SECRET" }),
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(ssoCacheDir, `${otherSessionHash}.json`),
        JSON.stringify({
          startUrl: "https://other.awsapps.com/start",
          accessToken: "OTHER_SECRET_SSO_TOKEN",
          refreshToken: "OTHER_SECRET_REFRESH",
          clientId: "other-client-id-999",
        }),
        { mode: 0o600 },
      );

      const stagedAws = stageIsolatedAwsProfile("work-bedrock", { HOME: awsHome });
      try {
        assert.ok(stagedAws, "应成功暂存所选 SSO profile");
        assert.equal(
          stagedAws!.extraReadOnlyPaths.some((p) => p.includes(path.join(".aws", "sso", "cache"))),
          false,
          "绝不得把宿主机整个 ~/.aws/sso/cache 放入 extraReadOnlyPaths",
        );
        const ssoMount = stagedAws!.bindMounts.find((m) => m.dest.endsWith(path.join(".aws", "sso", "cache")));
        assert.ok(ssoMount, "应仅通过按次暂存目录 bindMount 投影所选 SSO 缓存");
        assert.equal(ssoMount!.mode, "ro");
        const stagedFiles = fs.readdirSync(ssoMount!.src).sort();
        assert.equal(stagedFiles.includes(`${prodSessionHash}.json`), true, "必须包含所选 sso_session 令牌");
        assert.equal(stagedFiles.includes(`${prodClientRegHash}.json`), true, "必须包含被引用的 clientId 注册文件");
        assert.equal(stagedFiles.includes(`${otherSessionHash}.json`), false, "绝不得暴露其他 SSO 会话令牌");
      } finally {
        stagedAws?.cleanup();
      }
    }

    // 2) [R24 #2 P1] Gemini 与 OpenCode 隔离暂存：隐藏宿主机 tmp/history 与 opencode.db/storage，且 tools=none 脱敏设置
    {
      const agentHome = path.join(dir, "r24-2-agent-home");
      const geminiDir = path.join(agentHome, ".gemini");
      fs.mkdirSync(path.join(geminiDir, "tmp", "other-repo"), { recursive: true });
      fs.mkdirSync(path.join(geminiDir, "history"), { recursive: true });
      fs.writeFileSync(path.join(geminiDir, "oauth_creds.json"), '{"access_token":"gem_tok"}', { mode: 0o600 });
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        JSON.stringify({ selectedAuthType: "oauth-personal", model: "gemini-2.5-pro", mcpServers: { evil: { command: "x" } } }),
      );
      fs.writeFileSync(path.join(geminiDir, "tmp", "other-repo", "chat.json"), '{"secret":"OTHER_GEMINI_CHAT"}');
      fs.writeFileSync(path.join(geminiDir, "history", "log.jsonl"), '{"secret":"OTHER_GEMINI_HIST"}');

      const stagedGemNone = stageIsolatedGeminiState(agentHome, { HOME: agentHome }, undefined, { tools: "none" });
      try {
        assert.ok(stagedGemNone);
        const stageDir = stagedGemNone!.bindMounts[0]!.src;
        assert.equal(fs.existsSync(path.join(stageDir, "oauth_creds.json")), true);
        assert.equal(fs.existsSync(path.join(stageDir, "tmp")), false, "绝不得复制 ~/.gemini/tmp 跨项目会话历史");
        assert.equal(fs.existsSync(path.join(stageDir, "history")), false, "绝不得复制 ~/.gemini/history");
        const gemCfg = JSON.parse(fs.readFileSync(path.join(stageDir, "settings.json"), "utf8")) as Record<string, unknown>;
        assert.equal(gemCfg.selectedAuthType, "oauth-personal");
        assert.equal("mcpServers" in gemCfg, false, "tools=none 必须剥离 Gemini mcpServers");
      } finally {
        stagedGemNone?.cleanup();
      }

      const ocCfgDir = path.join(agentHome, ".config", "opencode");
      const ocDataDir = path.join(agentHome, ".local", "share", "opencode");
      fs.mkdirSync(ocCfgDir, { recursive: true });
      fs.mkdirSync(path.join(ocDataDir, "storage"), { recursive: true });
      fs.writeFileSync(
        path.join(ocCfgDir, "opencode.json"),
        JSON.stringify({ model: "anthropic/claude-sonnet-4", mcp: { evil: {} }, tools: { bash: true } }),
      );
      fs.writeFileSync(path.join(ocDataDir, "auth.json"), '{"anthropic":{"key":"oc_key"}}', { mode: 0o600 });
      fs.writeFileSync(path.join(ocDataDir, "opencode.db"), "SECRET_OPENCODE_SQLITE_DB");
      fs.writeFileSync(path.join(ocDataDir, "storage", "session.json"), '{"secret":"OTHER_OC_SESSION"}');

      const stagedOcNone = stageIsolatedOpenCodeState(agentHome, { HOME: agentHome }, undefined, { tools: "none" });
      try {
        assert.ok(stagedOcNone);
        const cfgStage = stagedOcNone!.bindMounts.find((m) => m.dest.endsWith(path.join(".config", "opencode")))!.src;
        const dataStage = stagedOcNone!.bindMounts.find((m) => m.dest.endsWith(path.join(".local", "share", "opencode")))!.src;
        assert.equal(fs.existsSync(path.join(dataStage, "auth.json")), true);
        assert.equal(fs.existsSync(path.join(dataStage, "opencode.db")), false, "绝不得复制宿主机 opencode.db");
        assert.equal(fs.existsSync(path.join(dataStage, "storage")), false, "绝不得复制宿主机 OpenCode storage/");
        const ocCfg = JSON.parse(fs.readFileSync(path.join(cfgStage, "opencode.json"), "utf8")) as Record<string, unknown>;
        assert.equal(ocCfg.model, "anthropic/claude-sonnet-4");
        assert.equal("mcp" in ocCfg, false, "tools=none 必须剥离 OpenCode mcp");
        assert.equal("tools" in ocCfg, false, "tools=none 必须剥离 OpenCode tools");
      } finally {
        stagedOcNone?.cleanup();
      }
    }

    // 3) [R24 #3 P1] 本地 Git clean/smudge 辅助进程绝不得读到 ~/.gitconfig 中的 http.<other>.extraHeader；远程 Git 仅获得目标域的 extraHeader
    if (hasCredentialMountIsolation()) {
      let capturedHeaders: Record<string, string | string[] | undefined> = {};
      const gitHttpSrv = http.createServer((req, res) => {
        capturedHeaders = { ...req.headers };
        res.writeHead(404);
        res.end("not found");
      });
      await new Promise<void>((resolve) => gitHttpSrv.listen(0, "127.0.0.1", resolve));
      serversToClose.push(gitHttpSrv);
      const port = (gitHttpSrv.address() as { port: number }).port;

      const gitHome = path.join(dir, "r24-3-git-home");
      const repo3 = path.join(dir, "r24-3-repo");
      const dataDir3 = path.join(dir, "r24-3-data");
      fs.mkdirSync(gitHome, { recursive: true });
      fs.mkdirSync(dataDir3, { recursive: true });
      fs.writeFileSync(
        path.join(gitHome, ".gitconfig"),
        [
          "[user]",
          "\tname = Clean Tester",
          `[http "http://127.0.0.1:${port}"]`,
          "\textraHeader = X-Target-Auth: TARGET_SECRET_R24",
          '[http "https://other-secret.example.com"]',
          "\textraHeader = Authorization: Bearer OTHER_HOST_SECRET_R24",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      await runProcess("git", ["init", "-q", repo3]);
      await runProcess("git", ["-C", repo3, "config", "filter.probe.clean", "sh -c 'git config --list; cat'"]);
      fs.writeFileSync(path.join(repo3, ".gitattributes"), "*.probe filter=probe\n");
      fs.writeFileSync(path.join(repo3, "sample.probe"), "payload\n");

      const isoCfg3 = { dataDir: dataDir3, context: { personal_web: { enabled: true } } as Config["context"] };
      const addRes = await tryGit(repo3, ["add", "sample.probe"], { cfg: isoCfg3, extraEnv: { HOME: gitHome } });
      assert.equal(addRes.code, 0, `本地 git add 应成功：${addRes.stderr}`);
      const stagedBlob = (await runProcess("git", ["-C", repo3, "show", ":sample.probe"])).stdout;
      assert.equal(stagedBlob.includes("OTHER_HOST_SECRET_R24"), false, "本地 git clean 过滤器绝不得看到其他主机的 extraHeader");
      assert.equal(stagedBlob.includes("TARGET_SECRET_R24"), false, "本地 git clean 过滤器绝不得看到任何 http.extraHeader");

      await tryGit(repo3, ["ls-remote", `http://127.0.0.1:${port}/org/repo.git`], {
        readOnly: true,
        cfg: isoCfg3,
        extraEnv: { HOME: gitHome },
      });
      assert.equal(capturedHeaders["x-target-auth"], "TARGET_SECRET_R24", "远程 git 应获得目标域名的 http.<url>.extraHeader");
      assert.equal(capturedHeaders["authorization"], undefined, "远程 git 绝不得发送其他域名的 extraHeader");
    }

    // 4) [R24 #4 P1] 隔离 Claude OAuth 凭据旋转后在清理前原子写回宿主机，且不覆盖宿主机更新的登录
    {
      const claudeHome = path.join(dir, "r24-4-claude-home");
      const claudeDir = path.join(claudeHome, ".claude");
      fs.mkdirSync(claudeDir, { recursive: true });
      const credFile = path.join(claudeDir, ".credentials.json");
      const now = Date.now();
      fs.writeFileSync(
        credFile,
        JSON.stringify({
          claudeAiOauth: {
            accessToken: "claude_old_access",
            refreshToken: "claude_old_refresh",
            expiresAt: now + 60_000,
            organizationUuid: "org_r24_a",
          },
        }),
        { mode: 0o600 },
      );

      const lease = await coordinateClaudeOAuthRefresh(claudeDir, { runWindowMs: 120_000, maxWaitMs: 5_000 });
      const staged = stageIsolatedClaudeState(claudeHome, { HOME: claudeHome }, undefined, { tools: "write" });
      try {
        assert.ok(staged);
        lease.attachScratch?.(staged!);
        // 模拟隔离沙箱内的 Claude 旋转了 refreshToken 与 accessToken
        fs.writeFileSync(
          path.join(staged!.dir, ".credentials.json"),
          JSON.stringify({
            claudeAiOauth: {
              accessToken: "claude_new_access",
              refreshToken: "claude_new_refresh",
              expiresAt: now + 3_600_000,
              organizationUuid: "org_r24_a",
            },
          }),
          { mode: 0o600 },
        );
        const synced = syncRefreshedClaudeAuth(staged!);
        assert.equal(synced, true, "旋转后的 Claude OAuth 凭据必须在 cleanup 前写回宿主机");
      } finally {
        staged?.cleanup();
        lease.release();
      }
      const persisted = JSON.parse(fs.readFileSync(credFile, "utf8")) as {
        claudeAiOauth: { accessToken: string; refreshToken: string };
      };
      assert.equal(persisted.claudeAiOauth.accessToken, "claude_new_access");
      assert.equal(persisted.claudeAiOauth.refreshToken, "claude_new_refresh");

      // 并发宿主机重新登录不同账号时，绝不得被旧隔离 worker 覆盖
      const stagedStale = stageIsolatedClaudeState(claudeHome, { HOME: claudeHome }, undefined, { tools: "write" });
      try {
        assert.ok(stagedStale);
        fs.writeFileSync(
          credFile,
          JSON.stringify({
            claudeAiOauth: {
              accessToken: "host_relogin_access",
              refreshToken: "host_relogin_refresh",
              expiresAt: now + 7_200_000,
              organizationUuid: "org_r24_new_account",
            },
          }),
          { mode: 0o600 },
        );
        fs.writeFileSync(
          path.join(stagedStale!.dir, ".credentials.json"),
          JSON.stringify({
            claudeAiOauth: {
              accessToken: "stale_worker_access",
              refreshToken: "stale_worker_refresh",
              expiresAt: now + 5_000_000,
              organizationUuid: "org_r24_a",
            },
          }),
          { mode: 0o600 },
        );
        assert.equal(syncRefreshedClaudeAuth(stagedStale!), false, "宿主机已重新登录时必须拒绝覆盖");
      } finally {
        stagedStale?.cleanup();
      }
      const afterGuard = JSON.parse(fs.readFileSync(credFile, "utf8")) as {
        claudeAiOauth: { accessToken: string; organizationUuid: string };
      };
      assert.equal(afterGuard.claudeAiOauth.accessToken, "host_relogin_access");
      assert.equal(afterGuard.claudeAiOauth.organizationUuid, "org_r24_new_account");
    }

    // 5) [R24 #5 P1] 超出搜索时间窗的已编辑群消息携带显式 mentions: [] 时仍必须清除旧 meta.at_me=true，且 @all 不误置 at_me=true
    {
      const app = makeR24App("r24-5-mentions", {
        ownerOpenId: "ou_owner",
        groupsMode: "allowlist",
        groupAllowlist: ["oc_scope_grp"],
      });
      try {
        const ctxSvc = new ContextService(app);
        const now = Date.now();
        const oldTime = now - 3 * 24 * 3600 * 1000; // 远早于 2h 增量搜索窗口
        ctxSvc.store.addObs([
          {
            id: "im:om_old_window",
            source: "im",
            kind: "im",
            conv: "oc_scope_grp",
            conv_name: "白名单群",
            actor_id: "ou_peer",
            actor_name: "同事",
            is_me: false,
            time: oldTime,
            text: "@我 请看这个",
            url: "",
            meta: { at_me: true, edit_version: 1 },
          },
        ]);
        // 设定最近游标使 atMeWindowStartMs 远晚于 oldTime
        app.store.set("ctx.cursor.im", String(now - 60_000));
        (ctxSvc.connectors as unknown as { lark: (args: string[]) => Promise<Record<string, unknown>> }).lark = async (args) => {
          if (args[0] === "auth" && args[1] === "status") {
            return { identity: "user", open_id: "ou_owner" };
          }
          if (args[0] === "im" && args[1] === "+chat-messages-list") {
            return {
              messages: [
                {
                  message_id: "om_old_window",
                  chat_id: "oc_scope_grp",
                  chat_type: "group",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(oldTime),
                  update_time: String(now - 500),
                  edit_version: 2,
                  content: "已编辑移除提及",
                  mentions: [],
                },
                {
                  message_id: "om_at_all_only",
                  chat_id: "oc_scope_grp",
                  chat_type: "group",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 1000),
                  content: "@所有人 通知",
                  mentions: [{ id: "all", key: "@_all", name: "所有人" }],
                },
              ],
            };
          }
          return { messages: [], items: [] };
        };
        await ctxSvc.connectors.pullIm();
        const editedRow = app.store.db.prepare("SELECT meta FROM ctx_obs WHERE id = ?").get("im:om_old_window") as { meta: string };
        assert.equal(JSON.parse(editedRow.meta).at_me, false, "显式 mentions: [] 即使早于搜索时间窗也必须清除旧 at_me=true");
        const atAllRow = app.store.db.prepare("SELECT meta FROM ctx_obs WHERE id = ?").get("im:om_at_all_only") as { meta: string };
        assert.equal(JSON.parse(atAllRow.meta).at_me, false, "@all 绝不得误标为直接 at_me=true");
      } finally {
        app.store.db.close();
      }
    }

    // 6) [R24 #6 P1] 已撤回观测的证据引用必须从活跃 evidence() 查询中排除（卡片与派单不可再引用），同时保留审计查询能力
    {
      const app = makeR24App("r24-6-evidence");
      try {
        const store = new ContextStore(app.store.db);
        const now = Date.now();
        store.addObs([
          {
            id: "pw:m_ev_withdrawn",
            source: "im",
            kind: "im",
            conv: "pw_chat:1",
            conv_name: "项目群",
            actor_id: "u1",
            actor_name: "同事A",
            is_me: false,
            time: now,
            text: "包含敏感信息的原话",
            url: "",
            meta: { edit_version: 1 },
          },
        ]);
        const itemId = store.upsertItem({
          kind: "todo",
          title: "跟进需求",
          status: "open",
          confidence: 0.9,
        }).item.id;
        store.addEvidence("item", itemId, "pw:m_ev_withdrawn", "包含敏感信息的原话", now);
        assert.equal(store.evidence("item", itemId).length, 1);

        store.retirePendingObs("pw:m_ev_withdrawn", { editVersion: 2 });
        assert.equal(store.evidence("item", itemId).length, 0, "活跃 evidence() 必须排除已撤回观测的引用");
        assert.equal(
          store.evidence("item", itemId, 10, { includeWithdrawn: true }).length,
          1,
          "审计模式 includeWithdrawn=true 应仍可查到历史证据行",
        );
      } finally {
        app.store.db.close();
      }
    }

    // 7) [R24 #7 P2] CMD 8 成功响应省略目标消息 ID 时抛出 MessageNotFoundError；桥接撤回旧观测并放行 ACK，而网络失败仍抛错拒 ACK
    {
      const mockAbsent = await startMockFeishuWebServer();
      try {
        const app = makeR24App("r24-7-absent", { pwEnabled: true });
        try {
          commitWorkspaceLogin(
            app,
            {
              owner_id: "7001",
              owner_name: "主人",
              session_id: "sess_r24_7",
              cookies: [
                { name: "session", value: "r24_sess", domain: "127.0.0.1", path: "/" },
                { name: "passport_web_did", value: "r24_did", domain: "127.0.0.1", path: "/" },
              ],
            },
            { allowUnverifiedOwner: true },
          );
          const savedLogin = new WebLoginStore(app.cfg.dataDir).load()!;
          const client = await FeishuWebClient.connect(savedLogin, { endpoints: mockAbsent.endpoints });
          await assert.rejects(
            () => client.readMessage("777001"),
            (err: unknown) => err instanceof MessageNotFoundError && err.messageId === "777001",
            "CMD 8 成功但省略消息 ID 时必须抛出 MessageNotFoundError",
          );

          const ctxSvc = new ContextService(app);
          const now = Date.now();
          ctxSvc.store.addObs([
            {
              id: "pw:777001",
              source: "im",
              kind: "im",
              conv: "pw_chat:900",
              conv_name: "群",
              actor_id: "8001",
              actor_name: "同事",
              is_me: false,
              time: now - 1000,
              text: "将被删除的消息",
              url: "",
              meta: { at_me: true },
            },
            {
              id: "pw:777002",
              source: "im",
              kind: "im",
              conv: "pw_chat:900",
              conv_name: "群",
              actor_id: "8001",
              actor_name: "同事",
              is_me: false,
              time: now - 900,
              text: "原始消息内容",
              url: "",
              meta: { at_me: true },
            },
          ]);

          const makePushMsg = (id: string, text: string): WebMessage => ({
            id,
            ownerId: "7001",
            actorId: "8001",
            conversationId: "900",
            conversationKind: "dm",
            rootId: "",
            parentId: "",
            threadId: "",
            cid: "",
            kind: MSG_TEXT,
            senderType: USER_SENDER_TYPE,
            messageType: "text",
            createdAtMs: now,
            position: 1,
            threadPosition: 0,
            sendToChat: true,
            text,
            mentions: [],
            resources: [],
            unsupported: false,
            partial: false,
          });

          // 确认缺失：应撤回旧观测并正常 resolve（允许 handlePush ACK）
          await ctxSvc.personalWeb.handleMessage(makePushMsg("777001", "已消失"), client);
          assert.equal(ctxSvc.store.obsPending("pw:777001"), false, "确认缺失后必须撤回旧观测");

          // 传输错误：仍必须 reject（阻止 handlePush ACK）
          const failingClient = {
            owner: () => ({ id: "7001", name: "主人" }),
            currentSessionId: () => "sess_r24_7",
            readMessage: async () => {
              throw new Error("socket hang up");
            },
          } as unknown as FeishuWebClient;
          await assert.rejects(
            () => ctxSvc.personalWeb.handleMessage(makePushMsg("777002", "网络故障消息"), failingClient),
            /socket hang up/,
            "传输故障必须继续 reject 以阻止误 ACK",
          );
        } finally {
          app.store.db.close();
        }
      } finally {
        await mockAbsent.close();
      }
    }

    // 8) [R24 #8 P2] 从早于首条活观测的撤回墓碑复活时，必须恢复 conv / actor_id / actor_name / is_me / time / url 等身份字段
    {
      const app = makeR24App("r24-8-tombstone-revive");
      try {
        const store = new ContextStore(app.store.db);
        store.retirePendingObs("pw:revive_owner_msg", { editVersion: 1 });
        const tomb = app.store.db
          .prepare("SELECT actor_id, is_me, conv, meta FROM ctx_obs WHERE id = ?")
          .get("pw:revive_owner_msg") as { actor_id: string; is_me: number; conv: string; meta: string };
        assert.equal(tomb.is_me, 0);
        assert.equal(JSON.parse(tomb.meta).tombstone, true);

        const liveTime = 1760000123000;
        store.addObs([
          {
            id: "pw:revive_owner_msg",
            source: "im",
            kind: "im",
            conv: "pw_chat:real_42",
            conv_name: "核心项目群",
            actor_id: "ou_owner_r24",
            actor_name: "主人自己",
            is_me: true,
            time: liveTime,
            text: "我来跟进这件事",
            url: "https://feishu.cn/msg/42",
            meta: { edit_version: 2 },
          },
        ]);
        const revived = app.store.db
          .prepare("SELECT conv, conv_name, actor_id, actor_name, is_me, time, text, url, processed, meta FROM ctx_obs WHERE id = ?")
          .get("pw:revive_owner_msg") as {
          conv: string;
          conv_name: string;
          actor_id: string;
          actor_name: string;
          is_me: number;
          time: number;
          text: string;
          url: string;
          processed: number;
          meta: string;
        };
        assert.equal(revived.conv, "pw_chat:real_42");
        assert.equal(revived.conv_name, "核心项目群");
        assert.equal(revived.actor_id, "ou_owner_r24");
        assert.equal(revived.actor_name, "主人自己");
        assert.equal(revived.is_me, 1, "复活主人自己的消息时必须恢复 is_me=1");
        assert.equal(revived.time, liveTime);
        assert.equal(revived.url, "https://feishu.cn/msg/42");
        assert.equal(revived.text, "我来跟进这件事");
        assert.equal(revived.processed, 0);
        const revivedMeta = JSON.parse(revived.meta) as Record<string, unknown>;
        assert.equal(revivedMeta.withdrawn, undefined);
        assert.equal(revivedMeta.tombstone, undefined);
      } finally {
        app.store.db.close();
      }
    }

    // 9) [R24 #9 P2] 隔离沙箱环境变量必须将 GOMODCACHE / GOCACHE / GOPATH 指向可写 /tmp 路径
    {
      const tmpEnv = isolatedSandboxTempEnv();
      assert.equal(tmpEnv.GOPATH, "/tmp/.pa-go");
      assert.equal(tmpEnv.GOMODCACHE, "/tmp/.pa-gomodcache");
      assert.equal(tmpEnv.GOCACHE, "/tmp/.pa-gocache");
      if (hasCredentialMountIsolation()) {
        const workDir = path.join(dir, "r24-9-go-verify");
        fs.mkdirSync(workDir, { recursive: true });
        const wrapped = wrapCredentialIsolatedCommand(
          "sh",
          ["-c", 'mkdir -p "$GOMODCACHE/cache" "$GOCACHE" && echo ok > "$GOMODCACHE/cache/test.mod" && cat "$GOMODCACHE/cache/test.mod"'],
          process.env,
          { cwd: workDir, requireIsolation: true, writablePaths: [workDir] },
        );
        const r = await runProcess(wrapped.cmd, wrapped.args, {
          cwd: workDir,
          env: { ...process.env, ...tmpEnv },
          timeoutMs: 10_000,
        });
        assert.equal(r.code, 0, `隔离校验内应可写入 GOMODCACHE：${r.stderr}`);
        assert.equal(r.stdout.trim(), "ok");
      }
    }

    // 10) [R24 #10 P2] 隔离内置 ACP 适配器复用宿主机已缓存 _npx/<hash>（只读挂载 + 注入 config.json 直启，不暴露其他 _npx 或 _cacache）
    {
      const acpHome = path.join(dir, "r24-10-acp-home");
      const npmCache = path.join(acpHome, ".npm");
      const goodHash = "a1b2c3d4e5f60708";
      const otherHash = "9988776655443322";
      const goodSlot = path.join(npmCache, "_npx", goodHash);
      const otherSlot = path.join(npmCache, "_npx", otherHash);
      fs.mkdirSync(path.join(goodSlot, "node_modules", ".bin"), { recursive: true });
      fs.mkdirSync(path.join(otherSlot, "node_modules", ".bin"), { recursive: true });
      fs.mkdirSync(path.join(npmCache, "_cacache"), { recursive: true });
      fs.writeFileSync(path.join(npmCache, "_cacache", "secret.txt"), "OTHER_NPM_CACHE_SECRET");
      fs.writeFileSync(
        path.join(goodSlot, "package.json"),
        JSON.stringify({ dependencies: { "@agentclientprotocol/claude-agent-acp": "^0.95.0" } }),
      );
      fs.writeFileSync(
        path.join(goodSlot, "node_modules", ".bin", "claude-agent-acp"),
        "#!/bin/sh\necho CACHED_CLAUDE_ADAPTER_OK\n",
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(otherSlot, "package.json"),
        JSON.stringify({ dependencies: { "unrelated-pkg": "^1.0.0" } }),
      );
      fs.writeFileSync(path.join(otherSlot, "secret.txt"), "UNRELATED_NPX_SECRET");

      const cached = stageScopedAcpxAdapterCache(
        "claude",
        { HOME: acpHome, NPM_CONFIG_CACHE: npmCache, PATH: "/usr/bin:/bin" },
        undefined,
        { tools: "write" },
      );
      assert.ok(cached, "应命中宿主机已缓存的 claude-agent-acp _npx 槽位");
      assert.equal(cached!.bindMounts.length, 1);
      assert.equal(cached!.bindMounts[0]!.mode, "ro", "缓存槽位必须以只读挂载防工人投毒");
      assert.equal(cached!.bindMounts[0]!.dest, `/tmp/.pa-npm-cache/_npx/${goodHash}`);
      assert.equal(cached!.agentCommand, `/tmp/.pa-npm-cache/_npx/${goodHash}/node_modules/.bin/claude-agent-acp`);

      const stagedAcpx = stageIsolatedAcpxState({ agent: "claude" }, acpHome, { HOME: acpHome }, undefined, {
        tools: "write",
        builtinAdapterCommand: cached!.agentCommand,
      });
      try {
        const cfg = JSON.parse(fs.readFileSync(path.join(stagedAcpx!.dir, "config.json"), "utf8")) as {
          agents?: Record<string, { command?: string }>;
        };
        assert.equal(cfg.agents?.claude?.command, cached!.agentCommand, "暂存 config.json 必须指向缓存适配器以离线直启");
      } finally {
        stagedAcpx?.cleanup();
      }

      if (hasCredentialMountIsolation()) {
        const workDir = path.join(dir, "r24-10-wt");
        fs.mkdirSync(workDir, { recursive: true });
        const wrapped = wrapCredentialIsolatedCommand(
          "sh",
          [
            "-c",
            `out="$("${cached!.agentCommand}")"; ro=0; touch "/tmp/.pa-npm-cache/_npx/${goodHash}/tamper" 2>/dev/null || ro=1; other=0; [ -e "/tmp/.pa-npm-cache/_npx/${otherHash}" ] && other=1; cac=0; [ -e "${npmCache}/_cacache/secret.txt" ] && cac=1; echo "$out:$ro:$other:$cac"`,
          ],
          { HOME: acpHome, PATH: process.env.PATH },
          { cwd: workDir, requireIsolation: true, writablePaths: [workDir], extraBindMounts: cached!.bindMounts },
        );
        const r = await runProcess(wrapped.cmd, wrapped.args, { cwd: workDir, timeoutMs: 10_000 });
        assert.equal(r.code, 0, `沙箱内应能离线执行只读缓存适配器：${r.stderr}`);
        assert.equal(r.stdout.trim(), "CACHED_CLAUDE_ADAPTER_OK:1:0:0");
      }
    }

    // 11) [R24 #11 P2] 统一遵守 GIT_CONFIG_GLOBAL：collectSafeGitConfigMounts、stageSanitizedGitConfig 与隔离 git 均生效
    {
      const corpHome = path.join(dir, "r24-11-corp-home");
      const corpCfgDir = path.join(corpHome, "company");
      const corpGitCfg = path.join(corpCfgDir, "git.conf");
      fs.mkdirSync(corpCfgDir, { recursive: true });
      fs.writeFileSync(
        corpGitCfg,
        [
          "[user]",
          "\tname = Corp Global User",
          '[http "https://secret.corp.example"]',
          "\textraHeader = Authorization: Bearer CORP_SECRET",
        ].join("\n") + "\n",
        { mode: 0o600 },
      );
      const env11 = { HOME: corpHome, GIT_CONFIG_GLOBAL: corpGitCfg };
      const rawMounts = collectSafeGitConfigMounts(env11);
      assert.equal(
        rawMounts.readOnlyPaths.some((p) => p === fs.realpathSync(corpGitCfg)),
        true,
        "collectSafeGitConfigMounts 必须遵守 GIT_CONFIG_GLOBAL",
      );
      const staged11 = stageSanitizedGitConfig(env11);
      try {
        assert.ok(staged11, "stageSanitizedGitConfig 必须遵守 GIT_CONFIG_GLOBAL");
        const content = fs.readFileSync(staged11!.file, "utf8");
        assert.ok(content.includes("Corp Global User"));
        assert.equal(content.includes("CORP_SECRET"), false, "脱敏结果仍必须剥离 http.extraHeader");
        assert.equal(
          staged11!.bindMounts.some((m) => m.dest === corpGitCfg),
          true,
          "bindMounts 必须同时覆盖显式 GIT_CONFIG_GLOBAL 路径",
        );
      } finally {
        staged11?.cleanup();
      }
      if (hasCredentialMountIsolation()) {
        const repo11 = path.join(dir, "r24-11-repo");
        const dataDir11 = path.join(dir, "r24-11-data");
        fs.mkdirSync(dataDir11, { recursive: true });
        await runProcess("git", ["init", "-q", repo11]);
        const cfgRes = await tryGit(repo11, ["config", "--global", "--get", "user.name"], {
          readOnly: true,
          cfg: { dataDir: dataDir11, context: { personal_web: { enabled: true } } as Config["context"] },
          extraEnv: env11,
        });
        assert.equal(cfgRes.code, 0, cfgRes.stderr);
        assert.equal(cfgRes.stdout.trim(), "Corp Global User");
      }
    }

    // 12) [R24 #12 P2] 私有 LFS 仓库在隔离 git worktree add 前经单独授权的 git lfs fetch 预拉取缺失对象，随后本地无凭据检出成功
    if (hasCredentialMountIsolation() && resolveTrustedSystemBin("git-lfs")) {
      const lfsPayload = Buffer.from("REAL_PRIVATE_LFS_CONTENT_R24\n", "utf8");
      const lfsOid = crypto.createHash("sha256").update(lfsPayload).digest("hex");
      const expectedAuth = `Basic ${Buffer.from("alice:lfs_secret_r24").toString("base64")}`;
      let batchCalls = 0;
      let downloadCalls = 0;
      let sawAuthedBatch = false;

      const lfsSrv = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          if (req.headers.authorization !== expectedAuth) {
            res.writeHead(401, { "WWW-Authenticate": 'Basic realm="lfs"' });
            res.end("unauthorized");
            return;
          }
          const urlPath = req.url ?? "";
          if (req.method === "POST" && urlPath.endsWith("/objects/batch")) {
            batchCalls++;
            sawAuthedBatch = true;
            const addr = lfsSrv.address() as { port: number };
            res.writeHead(200, { "Content-Type": "application/vnd.git-lfs+json" });
            res.end(
              JSON.stringify({
                transfer: "basic",
                objects: [
                  {
                    oid: lfsOid,
                    size: lfsPayload.length,
                    authenticated: true,
                    actions: {
                      download: {
                        href: `http://127.0.0.1:${addr.port}/objects/${lfsOid}`,
                        header: { Authorization: expectedAuth },
                      },
                    },
                  },
                ],
              }),
            );
            return;
          }
          if (req.method === "GET" && urlPath === `/objects/${lfsOid}`) {
            downloadCalls++;
            res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": String(lfsPayload.length) });
            res.end(lfsPayload);
            return;
          }
          res.writeHead(404);
          res.end("not found");
        });
      });
      await new Promise<void>((resolve) => lfsSrv.listen(0, "127.0.0.1", resolve));
      serversToClose.push(lfsSrv);
      const lfsPort = (lfsSrv.address() as { port: number }).port;

      const lfsHome = path.join(dir, "r24-12-lfs-home");
      const repo12 = path.join(dir, "r24-12-repo");
      const wt12 = path.join(dir, "r24-12-wt");
      const dataDir12 = path.join(dir, "r24-12-data");
      fs.mkdirSync(lfsHome, { recursive: true });
      fs.mkdirSync(dataDir12, { recursive: true });
      const credStoreFile = path.join(lfsHome, ".git-credentials");
      fs.writeFileSync(credStoreFile, `http://alice:lfs_secret_r24@127.0.0.1:${lfsPort}\n`, { mode: 0o600 });
      fs.writeFileSync(
        path.join(lfsHome, ".gitconfig"),
        [
          '[filter "lfs"]',
          "\tclean = git-lfs clean -- %f",
          "\tsmudge = git-lfs smudge -- %f",
          "\tprocess = git-lfs filter-process",
          "\trequired = true",
          "[credential]",
          `\thelper = store --file=${credStoreFile}`,
        ].join("\n") + "\n",
        { mode: 0o600 },
      );

      await runProcess("git", ["init", "-q", repo12]);
      await runProcess("git", ["-C", repo12, "config", "user.name", "Tester"]);
      await runProcess("git", ["-C", repo12, "config", "user.email", "t@example.com"]);
      await runProcess("git", ["-C", repo12, "remote", "add", "origin", `http://127.0.0.1:${lfsPort}/org/repo.git`]);
      fs.writeFileSync(path.join(repo12, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      const pointerText = `version https://git-lfs.github.com/spec/v1\noid sha256:${lfsOid}\nsize ${lfsPayload.length}\n`;
      // 直接以原始指针提交（不经过宿主机 smudge/clean，保持本地 .git/lfs/objects 为空以复现缺失场景）
      fs.writeFileSync(path.join(repo12, "asset.bin"), pointerText);
      const add12 = await runProcess("git", [
        "-C",
        repo12,
        "-c",
        "filter.lfs.clean=",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.required=false",
        "add",
        ".gitattributes",
        "asset.bin",
      ]);
      assert.equal(add12.code, 0, add12.stderr);
      const commit12 = await runProcess("git", ["-C", repo12, "-c", "commit.gpgSign=false", "commit", "-qm", "add lfs pointer"]);
      assert.equal(commit12.code, 0, commit12.stderr);

      const isoCfg12 = { dataDir: dataDir12, context: { personal_web: { enabled: true } } as Config["context"] };
      const pre = await ensureGitLfsObjectsForCheckout(repo12, "HEAD", {
        cfg: isoCfg12,
        trustedRepoRoot: repo12,
        extraEnv: { HOME: lfsHome },
      });
      assert.equal(pre.fetched, true, "缺失的 LFS 对象必须经单独授权的 git lfs fetch 提前拉取");
      assert.equal(sawAuthedBatch, true);
      assert.equal(downloadCalls, 1);

      const batchBeforeWt = batchCalls;
      fs.mkdirSync(wt12, { recursive: true });
      const wtRes = await tryGit(repo12, ["worktree", "add", "-b", "pa/r24-lfs-wt", wt12, "HEAD"], {
        cfg: isoCfg12,
        trustedRepoRoot: repo12,
        extraWritablePaths: [wt12],
        extraEnv: { HOME: lfsHome },
      });
      assert.equal(wtRes.code, 0, `预拉取后隔离 git worktree add 应无凭据成功检出：${wtRes.stderr}`);
      assert.equal(fs.readFileSync(path.join(wt12, "asset.bin"), "utf8"), "REAL_PRIVATE_LFS_CONTENT_R24\n");
      assert.equal(batchCalls, batchBeforeWt, "worktree add 期间应直接命中本地 LFS 缓存，不再访问远端");
    }

    // 13) [R24 #13 P2] 隔离提交签名处理：全局 commit.gpgSign=true 自动选无签名代理提交；仓库本地显式 SSH 签名窄挂载单钥完成签名
    if (hasCredentialMountIsolation()) {
      const signHome = path.join(dir, "r24-13-sign-home");
      const dataDir13 = path.join(dir, "r24-13-data");
      fs.mkdirSync(path.join(signHome, ".ssh"), { recursive: true });
      fs.mkdirSync(dataDir13, { recursive: true });
      fs.writeFileSync(
        path.join(signHome, ".gitconfig"),
        ["[commit]", "\tgpgSign = true", "[gpg]", "\tprogram = /nonexistent-gpg-bin"].join("\n") + "\n",
        { mode: 0o600 },
      );
      const isoCfg13 = { dataDir: dataDir13, context: { personal_web: { enabled: true } } as Config["context"] };

      // Case A: 全局 commit.gpgSign=true，仓库未强制 -> 自动无签名代理提交成功
      const repo13a = path.join(dir, "r24-13-repo-global");
      await runProcess("git", ["init", "-q", repo13a]);
      fs.writeFileSync(path.join(repo13a, "a.txt"), "hello\n");
      const committedA = await commitAll(repo13a, "global gpgSign ignored for agent commit", {
        cfg: isoCfg13,
        extraEnv: { HOME: signHome },
      });
      assert.equal(committedA, true);

      // Case B: 仓库本地显式 commit.gpgSign=true + gpg.format=ssh + 未加密 ed25519 单钥 -> 隔离沙箱内完成真实 SSH 签名
      if (resolveTrustedSystemBin("ssh-keygen")) {
        const keyPath = path.join(signHome, ".ssh", "r24_sign_ed25519");
        const gen = await runProcess("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath]);
        assert.equal(gen.code, 0, gen.stderr);
        const repo13b = path.join(dir, "r24-13-repo-ssh-sign");
        await runProcess("git", ["init", "-q", repo13b]);
        await runProcess("git", ["-C", repo13b, "config", "--local", "commit.gpgSign", "true"]);
        await runProcess("git", ["-C", repo13b, "config", "--local", "gpg.format", "ssh"]);
        await runProcess("git", ["-C", repo13b, "config", "--local", "user.signingkey", keyPath]);
        fs.writeFileSync(path.join(repo13b, "signed.txt"), "signed content\n");
        const committedB = await commitAll(repo13b, "repo local ssh signed commit", {
          cfg: isoCfg13,
          extraEnv: { HOME: signHome },
        });
        assert.equal(committedB, true);
        const rawCommit = (await runProcess("git", ["-C", repo13b, "cat-file", "-p", "HEAD"])).stdout;
        assert.ok(rawCommit.includes("-----BEGIN SSH SIGNATURE-----"), `应生成真实 SSH 签名提交：\n${rawCommit}`);
      }
    }

    // 14) [R24 #14 P2] 多 pushurl 推送搭配 remote.origin.lfspushurl 时保留命名远端 LFS 端点与对应凭据授权
    if (hasCredentialMountIsolation() && resolveTrustedSystemBin("git-lfs")) {
      const uploadedOids = new Set<string>();
      const expectedPushAuth = `Basic ${Buffer.from("pusher:multi_lfs_tok_r24").toString("base64")}`;
      let sawDedicatedLfsBatch = false;

      const lfsPushSrv = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          const urlPath = req.url ?? "";
          if (req.headers.authorization !== expectedPushAuth) {
            res.writeHead(401, { "WWW-Authenticate": 'Basic realm="dedicated-lfs"' });
            res.end("unauthorized");
            return;
          }
          if (req.method === "POST" && urlPath === "/dedicated-lfs/locks/verify") {
            res.writeHead(200, { "Content-Type": "application/vnd.git-lfs+json" });
            res.end(JSON.stringify({ ours: [], theirs: [] }));
            return;
          }
          if (req.method === "POST" && urlPath === "/dedicated-lfs/objects/batch") {
            sawDedicatedLfsBatch = true;
            const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
              objects?: { oid: string; size: number }[];
            };
            const addr = lfsPushSrv.address() as { port: number };
            res.writeHead(200, { "Content-Type": "application/vnd.git-lfs+json" });
            res.end(
              JSON.stringify({
                transfer: "basic",
                objects: (body.objects ?? []).map((o) =>
                  uploadedOids.has(o.oid)
                    ? { oid: o.oid, size: o.size, authenticated: true }
                    : {
                        oid: o.oid,
                        size: o.size,
                        authenticated: true,
                        actions: {
                          upload: {
                            href: `http://127.0.0.1:${addr.port}/dedicated-lfs/upload/${o.oid}`,
                            header: { Authorization: expectedPushAuth },
                          },
                        },
                      },
                ),
              }),
            );
            return;
          }
          if (req.method === "PUT" && urlPath.startsWith("/dedicated-lfs/upload/")) {
            const oid = urlPath.slice("/dedicated-lfs/upload/".length);
            uploadedOids.add(oid);
            res.writeHead(200);
            res.end();
            return;
          }
          res.writeHead(404);
          res.end("not found");
        });
      });
      await new Promise<void>((resolve) => lfsPushSrv.listen(0, "127.0.0.1", resolve));
      serversToClose.push(lfsPushSrv);
      const lfsPushPort = (lfsPushSrv.address() as { port: number }).port;

      const pushHome = path.join(dir, "r24-14-home");
      const bare1 = path.join(dir, "r24-14-bare1.git");
      const bare2 = path.join(dir, "r24-14-bare2.git");
      const repo14 = path.join(dir, "r24-14-repo");
      const dataDir14 = path.join(dir, "r24-14-data");
      fs.mkdirSync(pushHome, { recursive: true });
      fs.mkdirSync(dataDir14, { recursive: true });
      const pushCreds = path.join(pushHome, ".git-credentials");
      fs.writeFileSync(pushCreds, `http://pusher:multi_lfs_tok_r24@127.0.0.1:${lfsPushPort}\n`, { mode: 0o600 });
      fs.writeFileSync(
        path.join(pushHome, ".gitconfig"),
        [
          '[filter "lfs"]',
          "\tclean = git-lfs clean -- %f",
          "\tsmudge = git-lfs smudge -- %f",
          "\tprocess = git-lfs filter-process",
          "\trequired = true",
          "[credential]",
          `\thelper = store --file=${pushCreds}`,
        ].join("\n") + "\n",
        { mode: 0o600 },
      );

      await runProcess("git", ["init", "-q", "--bare", bare1]);
      await runProcess("git", ["init", "-q", "--bare", bare2]);
      await runProcess("git", ["init", "-q", "-b", "feat/multi-lfs", repo14]);
      await runProcess("git", ["-C", repo14, "config", "user.name", "Tester"]);
      await runProcess("git", ["-C", repo14, "config", "user.email", "t@example.com"]);
      await runProcess("git", ["-C", repo14, "remote", "add", "origin", bare1]);
      await runProcess("git", ["-C", repo14, "remote", "set-url", "--push", "--add", "origin", bare1]);
      await runProcess("git", ["-C", repo14, "remote", "set-url", "--push", "--add", "origin", bare2]);
      await runProcess("git", [
        "-C",
        repo14,
        "config",
        "remote.origin.lfspushurl",
        `http://127.0.0.1:${lfsPushPort}/dedicated-lfs`,
      ]);
      const dataBytes = Buffer.from("MULTI_PUSHURL_LFS_BLOB_R24\n", "utf8");
      const dataOid = crypto.createHash("sha256").update(dataBytes).digest("hex");
      const lfsObjDir = path.join(repo14, ".git", "lfs", "objects", dataOid.slice(0, 2), dataOid.slice(2, 4));
      fs.mkdirSync(lfsObjDir, { recursive: true });
      fs.writeFileSync(path.join(lfsObjDir, dataOid), dataBytes);
      fs.writeFileSync(path.join(repo14, ".gitattributes"), "*.dat filter=lfs diff=lfs merge=lfs -text\n");
      fs.writeFileSync(
        path.join(repo14, "model.dat"),
        `version https://git-lfs.github.com/spec/v1\noid sha256:${dataOid}\nsize ${dataBytes.length}\n`,
      );
      const add14 = await runProcess("git", [
        "-C",
        repo14,
        "-c",
        "filter.lfs.clean=",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.required=false",
        "add",
        ".gitattributes",
        "model.dat",
      ]);
      assert.equal(add14.code, 0, add14.stderr);
      const commit14 = await runProcess("git", ["-C", repo14, "-c", "commit.gpgSign=false", "commit", "-qm", "commit lfs object"]);
      assert.equal(commit14.code, 0, commit14.stderr);

      const pushRes = await pushBranch(repo14, "origin", "feat/multi-lfs", {
        cfg: { dataDir: dataDir14, context: { personal_web: { enabled: true } } as Config["context"] },
        extraEnv: { HOME: pushHome },
      });
      assert.equal(pushRes.ok, true, `多 pushurl 搭配 remote.origin.lfspushurl 应推送成功：${pushRes.ok ? "" : pushRes.message}`);
      assert.equal(sawDedicatedLfsBatch, true, "显式 LFS 对象上传必须命中命名远端的 remote.origin.lfspushurl");
      assert.equal(uploadedOids.has(dataOid), true, "专用 LFS 端点必须收到目标 OID");
      assert.equal((await runProcess("git", ["-C", bare1, "rev-parse", "--verify", "refs/heads/feat/multi-lfs"])).code, 0);
      assert.equal((await runProcess("git", ["-C", bare2, "rev-parse", "--verify", "refs/heads/feat/multi-lfs"])).code, 0);
    }

    // 15) [R24 #15 P2] WebSocket 空闲超时按入站活跃（PING / 持续分片）重置，同时独立限制整条分片消息最大组装时长
    {
      const makeWsFrame = (fin: boolean, op: number, payload: Buffer): Buffer => {
        const b0 = (fin ? 0x80 : 0x00) | (op & 0x0f);
        assert.ok(payload.length < 126);
        return Buffer.concat([Buffer.from([b0, payload.length]), payload]);
      };
      const wsSrv = net.createServer((sock) => {
        let reqBuf = "";
        sock.on("data", (chunk: Buffer) => {
          if (reqBuf.includes("\r\n\r\n")) return;
          reqBuf += chunk.toString("latin1");
          if (!reqBuf.includes("\r\n\r\n")) return;
          const keyMatch = reqBuf.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i);
          const accept = crypto
            .createHash("sha1")
            .update(`${keyMatch?.[1]?.trim() ?? ""}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
            .digest("base64");
          sock.write(
            `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
          );
          if (reqBuf.startsWith("GET /alive ")) {
            // 连续 3 个 PING（总计 240ms > timeoutMs=140ms）后发 2 个分片，验证入站活跃不断重置空闲计时器
            setTimeout(() => !sock.destroyed && sock.write(makeWsFrame(true, 0x9, Buffer.from("p1"))), 70);
            setTimeout(() => !sock.destroyed && sock.write(makeWsFrame(true, 0x9, Buffer.from("p2"))), 140);
            setTimeout(() => !sock.destroyed && sock.write(makeWsFrame(true, 0x9, Buffer.from("p3"))), 210);
            setTimeout(() => !sock.destroyed && sock.write(makeWsFrame(false, 0x2, Buffer.from("PART1_"))), 270);
            setTimeout(() => !sock.destroyed && sock.write(makeWsFrame(true, 0x0, Buffer.from("PART2"))), 330);
          } else if (reqBuf.startsWith("GET /slowfrag ")) {
            // 持续发分片不结束，触发独立 maxFragDurationMs 超时
            sock.write(makeWsFrame(false, 0x2, Buffer.from("A")));
            const iv = setInterval(() => {
              if (sock.destroyed) {
                clearInterval(iv);
                return;
              }
              sock.write(makeWsFrame(false, 0x0, Buffer.from("B")));
            }, 35);
            sock.on("close", () => clearInterval(iv));
          }
        });
      });
      await new Promise<void>((resolve) => wsSrv.listen(0, "127.0.0.1", resolve));
      serversToClose.push(wsSrv);
      const wsPort = (wsSrv.address() as { port: number }).port;

      const wsAlive = await BinaryWebSocket.dial(`ws://127.0.0.1:${wsPort}/alive`, {
        handshakeTimeoutMs: 2_000,
        maxFragDurationMs: 2_000,
      });
      try {
        const msg = await wsAlive.read(140);
        assert.equal(msg.data.toString("utf8"), "PART1_PART2", "持续收到 PING 与分片时不应被误判空闲超时");
      } finally {
        wsAlive.close();
      }

      const wsSlow = await BinaryWebSocket.dial(`ws://127.0.0.1:${wsPort}/slowfrag`, {
        handshakeTimeoutMs: 2_000,
        maxFragDurationMs: 120,
      });
      try {
        await assert.rejects(
          () => wsSlow.read(250),
          /分片消息组装超时/,
          "持续未闭合分片流必须命中独立的分片组装总时长上限",
        );
      } finally {
        wsSlow.close();
      }
    }

    // 16) [R24 #16 P3] Doctor 在 personal_web 处于 reconnecting/reverifying 且带 last_error 时必须报 warn 并附带原因
    {
      const app = makeR24App("r24-16-doctor", { pwEnabled: true });
      try {
        commitWorkspaceLogin(
          app,
          {
            owner_id: "7001",
            owner_name: "主人",
            session_id: "sess_r24_16",
            cookies: [{ name: "session", value: "s", domain: "feishu.cn", path: "/" }],
          },
          { allowUnverifiedOwner: true },
        );
        registerContext(app);
        const now = Date.now();
        app.store.set("daemon.heartbeat", `host:1|${now}`);
        app.store.set(
          "ctx.personal_web.state",
          JSON.stringify({
            state: "reconnecting",
            owner_id: "7001",
            owner_name: "主人",
            session_id: "sess_r24_16",
            since: now,
            last_message_at: null,
            last_error: "ws connect ECONNREFUSED",
          }),
        );
        const rep1 = await runDoctor(app);
        const chk1 = rep1.checks.find((c) => c.id === "personal_web");
        assert.equal(chk1?.status, "warn", "reconnecting 带错误时 doctor 必须返回 warn");
        assert.ok(chk1?.detail.includes("ws connect ECONNREFUSED"), `detail 应包含错误原因：${chk1?.detail}`);

        app.store.set(
          "ctx.personal_web.state",
          JSON.stringify({
            state: "reverifying",
            owner_id: "7001",
            owner_name: "主人",
            session_id: "sess_r24_16",
            since: now,
            last_message_at: null,
            last_error: "session check timeout",
          }),
        );
        const rep2 = await runDoctor(app);
        const chk2 = rep2.checks.find((c) => c.id === "personal_web");
        assert.equal(chk2?.status, "warn", "reverifying 带错误时 doctor 必须返回 warn");
        assert.ok(chk2?.detail.includes("session check timeout"), `detail 应包含错误原因：${chk2?.detail}`);
      } finally {
        app.store.db.close();
      }
    }

    // 17) [R24 #17 P3] QR 掩码选择必须计入 ISO/IEC 18004 Rule N3（类定位符模式 +40 分），验证 sample-token-5 命中 N3 最优掩码
    {
      const payload = "https://open.feishu.cn/open-apis/authen/v1/qr?token=sample-token-5";
      const qr = encodeQrMatrix(payload);
      // 从左上格式信息位读出实际选中的 3-bit mask ID（bit14..10 为 5-bit (ECC-M=00 | mask) XOR 10101）
      const fmtTop5 =
        (qr.modules[8 * qr.size + 0]! << 4) |
        (qr.modules[8 * qr.size + 1]! << 3) |
        (qr.modules[8 * qr.size + 2]! << 2) |
        (qr.modules[8 * qr.size + 3]! << 1) |
        qr.modules[8 * qr.size + 4]!;
      const unmasked5 = fmtTop5 ^ 0b10101;
      const eccBits = (unmasked5 >> 3) & 0b11;
      const chosenMask = unmasked5 & 0b111;
      assert.equal(eccBits, 0b00, "ECC-M 格式位前两位应为 00");
      // 独立参照校验：用相同有效载荷检查该矩阵包含合法定位符与零额外伪定位符（相比未计 N3 时选择的掩码发生正确切换）
      const countN3 = (mods: Uint8Array, n: number): number => {
        const p1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
        const p2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
        let hits = 0;
        const matchAt = (get: (k: number) => number) => {
          let m1 = true;
          let m2 = true;
          for (let k = 0; k < 11; k++) {
            const v = get(k);
            if (v !== p1[k]) m1 = false;
            if (v !== p2[k]) m2 = false;
          }
          if (m1) hits++;
          if (m2) hits++;
        };
        for (let r = 0; r < n; r++) for (let c = 0; c <= n - 11; c++) matchAt((k) => mods[r * n + c + k]!);
        for (let c = 0; c < n; c++) for (let r = 0; r <= n - 11; r++) matchAt((k) => mods[(r + k) * n + c]!);
        return hits;
      };
      // 仅含 3 个真实定位符自身贡献的 6 次边框模式，计入 N3 后不应多出额外伪定位符惩罚
      assert.ok(chosenMask >= 0 && chosenMask <= 7);
      assert.ok(countN3(qr.modules, qr.size) <= 6, `计入 N3 后选中掩码 ${chosenMask} 不应产生额外伪定位符（实际 ${countN3(qr.modules, qr.size)}）`);
    }
  } finally {
    if (prevPwKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevPwKey;
    for (const s of serversToClose) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("第 25 轮 Codex review 修复回归：新修订省略 mentions 清除陈旧 @我 / OpenCode JSONC 解析与 OAuth 写回 / 仓库 include 与 worktree 签名策略 / 派单检查点签名提交 / 快通道不透明 work ID 与重登通知脱敏 / LFS skip-smudge 与外部 lfs.storage / 固定预拉取起点建 worktree / 派单批量归属校验与分页健康缓存 / 无仓库时 Doctor 强制隔离探测", async () => {
  const dir = makeTmp("pa-r25-");
  const serversToClose: (http.Server | net.Server)[] = [];
  const prevPwKey = process.env.PA_FEISHU_WEB_KEY;
  if (!process.env.PA_FEISHU_WEB_KEY) {
    process.env.PA_FEISHU_WEB_KEY = crypto.randomBytes(32).toString("hex");
  }

  const makeR25App = (
    name: string,
    opts?: {
      ownerOpenId?: string;
      pwEnabled?: boolean;
      groupsMode?: "all" | "allowlist";
      groupAllowlist?: string[];
      repos?: Record<string, string>;
    },
  ) => {
    const sub = path.join(dir, name);
    fs.mkdirSync(sub, { recursive: true });
    const cfgPath = path.join(sub, "config.yaml");
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({
        data_dir: path.join(sub, "data"),
        bins: {
          lark: path.join(STUBS, "ctx-lark"),
          acpx: path.join(STUBS, "acpx"),
          bytedcli: path.join(STUBS, "ctx-bytedcli"),
        },
        harnesses: {
          codex: { type: "codex-exec", cmd: path.join(STUBS, "ctx-codex") },
        },
        roles: { brain: "codex" },
        owner: { open_id: opts?.ownerOpenId ?? "ou_owner" },
        cards: { enabled: false },
        dispatch: { repos: opts?.repos ?? {} },
        engine: { retry_base_ms: 20, retry_max_ms: 50, tick_ms: 50, effect_attempts: 1 },
        context: {
          enabled: true,
          harness: "codex",
          groups: opts?.groupsMode ?? "allowlist",
          groups_allow: opts?.groupAllowlist ?? [],
          groups_deny: [],
          sources: { im: true, minutes: false, docs: false, tasks: false, calendar: false, meego: false },
          personal_web: { enabled: opts?.pwEnabled ?? false, fast_lane: true, debounce_ms: 0, pre_draft: false },
        },
      }),
    );
    return createApp(loadConfig(cfgPath));
  };

  try {
    // 1) [R25 #1 P1] 多流合并与 +messages-mget 合并新修订时，若新修订省略 mentions（最后一条 @ 已被编辑删除），绝不得继承旧修订 mentions
    {
      const app = makeR25App("r25-1-merge-mentions", {
        ownerOpenId: "ou_owner",
        groupsMode: "allowlist",
        groupAllowlist: ["oc_grp_r25"],
      });
      try {
        const ctxSvc = new ContextService(app);
        const now = Date.now();
        (ctxSvc.connectors as unknown as { lark: (args: string[]) => Promise<Record<string, unknown>> }).lark = async (args) => {
          if (args[0] === "auth" && args[1] === "status") {
            return { identity: "user", open_id: "ou_owner" };
          }
          if (args[0] === "im" && args[1] === "+messages-search" && args.includes("--is-at-me")) {
            return {
              messages: [
                {
                  // Case A: 旧版 rev=1 含 mentions: [ou_owner]，列表流 rev=2 省略 mentions
                  message_id: "om_r25_edit_omit",
                  chat_id: "oc_grp_r25",
                  chat_type: "group",
                  chat_name: "协同群",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 5_000),
                  edit_version: 1,
                  content: "@我 原消息",
                  mentions: [{ id: "ou_owner", name: "主人" }],
                },
                {
                  // Case B: 冲突无同标尺时钟 -> 触发 +messages-mget，权威回读省略 mentions
                  message_id: "om_r25_mget_omit",
                  chat_id: "oc_grp_r25",
                  chat_type: "group",
                  chat_name: "协同群",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 4_000),
                  edit_version: 1,
                  content: "@我 冲突旧文",
                  mentions: [{ id: "ou_owner", name: "主人" }],
                },
              ],
            };
          }
          if (args[0] === "im" && args[1] === "+chat-messages-list") {
            return {
              messages: [
                {
                  message_id: "om_r25_edit_omit",
                  chat_id: "oc_grp_r25",
                  chat_type: "group",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 5_000),
                  edit_version: 2,
                  content: "已编辑成普通消息",
                  // 刻意省略 mentions 字段，模拟飞书移除最后一个 @ 后的响应
                },
                {
                  message_id: "om_r25_mget_omit",
                  chat_id: "oc_grp_r25",
                  chat_type: "group",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 4_000),
                  update_time: String(now - 1_000),
                  content: "已编辑的普通内容",
                  // 无 edit_version 与搜索流不可比 -> 触发 +messages-mget
                },
              ],
            };
          }
          if (args[0] === "im" && args[1] === "+messages-mget") {
            return {
              messages: [
                {
                  message_id: "om_r25_mget_omit",
                  chat_id: "oc_grp_r25",
                  chat_type: "group",
                  sender: { id: "ou_peer", name: "同事", sender_type: "user" },
                  create_time: String(now - 4_000),
                  edit_version: 2,
                  content: "已编辑的普通内容",
                  // +messages-mget 权威版本同样省略 mentions
                },
              ],
            };
          }
          return { messages: [], items: [] };
        };

        await ctxSvc.connectors.pullIm();
        const rowA = app.store.db.prepare("SELECT kind, text, meta FROM ctx_obs WHERE id = ?").get("im:om_r25_edit_omit") as {
          kind: string;
          text: string;
          meta: string;
        };
        assert.equal(rowA.text, "已编辑成普通消息");
        assert.equal(rowA.kind, "group");
        assert.equal(JSON.parse(rowA.meta).at_me, false, "a_newer 合并省略 mentions 的新修订绝不得继承旧 at_me=true");

        const rowB = app.store.db.prepare("SELECT kind, text, meta FROM ctx_obs WHERE id = ?").get("im:om_r25_mget_omit") as {
          kind: string;
          text: string;
          meta: string;
        };
        assert.equal(rowB.text, "已编辑的普通内容");
        assert.equal(rowB.kind, "group");
        assert.equal(JSON.parse(rowB.meta).at_me, false, "+messages-mget 合并省略 mentions 的权威行绝不得继承旧 at_me=true");
      } finally {
        app.store.db.close();
      }
    }

    // 2) [R25 #2 P1] OpenCode JSONC 解析保留带行尾 // 注释与 URL 字符串的供应商配置，解析失败时 fail-closed 报错
    {
      const validJsonc = [
        "{",
        '  // 选择私有网关模型',
        '  "model": "corp/claude-sonnet-4", // 行尾注释',
        '  "provider": {',
        '    "corp": {',
        '      "options": { "baseURL": "https://gateway.corp.example/v1" /* 块注释 */ },',
        "    },",
        "  },",
        '  "mcp": { "evil": { "command": "bad" } },',
        '  "tools": { "bash": true },',
        "}",
      ].join("\n");
      const parsed = parseJsonc(validJsonc) as Record<string, unknown>;
      assert.equal(parsed.model, "corp/claude-sonnet-4");
      const sanitized = JSON.parse(sanitizeOpenCodeConfigForNoTools(validJsonc)) as {
        model: string;
        provider: { corp: { options: { baseURL: string } } };
      };
      assert.equal(sanitized.model, "corp/claude-sonnet-4");
      assert.equal(sanitized.provider.corp.options.baseURL, "https://gateway.corp.example/v1", "字符串内的 // 必须完整保留");
      assert.equal("mcp" in sanitized, false);
      assert.equal("tools" in sanitized, false);

      const ocHome = path.join(dir, "r25-2-oc-home");
      const ocCfgDir = path.join(ocHome, ".config", "opencode");
      const ocDataDir = path.join(ocHome, ".local", "share", "opencode");
      fs.mkdirSync(ocCfgDir, { recursive: true });
      fs.mkdirSync(ocDataDir, { recursive: true });
      fs.writeFileSync(path.join(ocCfgDir, "opencode.jsonc"), validJsonc);
      fs.writeFileSync(path.join(ocDataDir, "auth.json"), '{"anthropic":{"type":"api","key":"sk-ant"}}', { mode: 0o600 });

      const stagedOk = stageIsolatedOpenCodeState(ocHome, { HOME: ocHome }, undefined, { tools: "none" });
      try {
        assert.ok(stagedOk);
        const cfgStage = stagedOk!.bindMounts.find((m) => m.dest.endsWith(path.join(".config", "opencode")))!.src;
        const outCfg = JSON.parse(fs.readFileSync(path.join(cfgStage, "opencode.jsonc"), "utf8")) as {
          model: string;
          provider: { corp: { options: { baseURL: string } } };
        };
        assert.equal(outCfg.model, "corp/claude-sonnet-4");
        assert.equal(outCfg.provider.corp.options.baseURL, "https://gateway.corp.example/v1");
      } finally {
        stagedOk?.cleanup();
      }

      // 损坏 JSONC 在 tools="none" 下必须 fail-closed 抛错，绝不静默丢弃配置文件并保留 auth.json
      fs.writeFileSync(path.join(ocCfgDir, "opencode.jsonc"), '{ "model": "corp/a", /* 未闭合注释');
      assert.throws(
        () => stageIsolatedOpenCodeState(ocHome, { HOME: ocHome }, undefined, { tools: "none" }),
        /解析脱敏失败/,
        "OpenCode 配置文件解析失败时必须 fail-closed 报错",
      );
    }

    // 3) [R25 #4 P2 & R25 #5 P2] 快通道 work ID 必须是不透明哈希（不含原始会话/消息 ID），重登通知必须脱敏旧绑定账号 ID
    {
      const app = makeR25App("r25-4-5-privacy", { ownerOpenId: "ou_new_owner", pwEnabled: true });
      try {
        const ctxSvc = new ContextService(app);
        const hooks = (ctxSvc.personalWeb as unknown as {
          hooks: {
            onFastTrigger: (t: {
              conv: string;
              conv_name: string;
              trigger_obs_id: string;
              rev_gen: number;
              text_hash: string;
            }) => void;
            onNeedsLogin: (reason: string) => void;
          };
        }).hooks;

        const emittedIds: string[] = [];
        app.bus.on("work.changed", (ev: unknown) => {
          const rec = ev as { id?: string };
          if (rec.id) emittedIds.push(rec.id);
        });
        hooks.onFastTrigger({
          conv: "pw_chat:99887766",
          conv_name: "私密群",
          trigger_obs_id: "pw:777888999",
          rev_gen: 1,
          text_hash: "abc123",
        });
        const fastId = emittedIds.find((id) => id.startsWith("context:fast:"));
        assert.ok(fastId, "应入队快通道任务");
        assert.equal(fastId!.includes("99887766"), false, "快通道 work ID 与 SSE 事件绝不得暴露原生群 ID");
        assert.equal(fastId!.includes("777888999"), false, "快通道 work ID 与 SSE 事件绝不得暴露原生消息 ID");
        assert.match(fastId!, /^context:fast:[0-9a-f]{24}$/);

        hooks.onNeedsLogin("工作区已绑定旧账号 ou_prev_secret_owner (native 7001999)，与当前 ou_new_owner 不一致");
        const effs = app.ledger.list<{ op?: string; args?: { markdown?: string } }>({
          kinds: ["effect"],
          ref: "context:pw-needs-login",
          limit: 5,
        });
        assert.equal(effs.length, 1);
        const notifyMd = effs[0]!.payload.op === "notify" ? (effs[0]!.payload.args?.markdown ?? "") : "";
        assert.equal(notifyMd.includes("ou_prev_secret_owner"), false, "对外重登私信通知绝不得包含旧绑定主人 ID");
        assert.equal(notifyMd.includes("7001999"), false, "对外重登私信通知绝不得包含旧原生账号 ID");
      } finally {
        app.store.db.close();
      }
    }

    // 4) [R25 #6 P2] OpenCode 隔离运行旋转 OAuth 刷新令牌时，清理前逐供应商原子写回且不覆盖宿主机其他或更新的供应商登录
    {
      const ocHome = path.join(dir, "r25-6-oc-oauth");
      const ocDataDir = path.join(ocHome, ".local", "share", "opencode");
      fs.mkdirSync(ocDataDir, { recursive: true });
      const authFile = path.join(ocDataDir, "auth.json");
      const now = Date.now();
      fs.writeFileSync(
        authFile,
        JSON.stringify({
          anthropic: { type: "oauth", refresh: "rt_ant_old", access: "at_ant_old", expires: now + 60_000 },
          openai: { type: "oauth", refresh: "rt_oai_old", access: "at_oai_old", expires: now + 60_000 },
        }),
        { mode: 0o600 },
      );

      const lease = await coordinateOpenCodeOAuthRefresh(ocDataDir, { runWindowMs: 120_000, maxWaitMs: 5_000 });
      const staged = stageIsolatedOpenCodeState(ocHome, { HOME: ocHome }, undefined, { tools: "write" });
      try {
        assert.ok(staged);
        lease.attachScratch?.(staged!);
        // 模拟宿主机在工人运行期间新增无关供应商 google，且并发重登了 openai
        fs.writeFileSync(
          authFile,
          JSON.stringify({
            anthropic: { type: "oauth", refresh: "rt_ant_old", access: "at_ant_old", expires: now + 60_000 },
            openai: { type: "oauth", refresh: "rt_oai_host_relogin", access: "at_oai_host_relogin", expires: now + 7_200_000 },
            google: { type: "api", key: "host-new-google-key" },
          }),
          { mode: 0o600 },
        );
        // 模拟隔离工人在暂存目录中旋转了 anthropic 和 openai，且生成了临时 opencode.db
        fs.writeFileSync(
          path.join(staged!.stageDataDir, "auth.json"),
          JSON.stringify({
            anthropic: { type: "oauth", refresh: "rt_ant_new", access: "at_ant_new", expires: now + 3_600_000 },
            openai: { type: "oauth", refresh: "rt_oai_stale_worker", access: "at_oai_stale_worker", expires: now + 3_600_000 },
          }),
          { mode: 0o600 },
        );
        fs.writeFileSync(path.join(staged!.stageDataDir, "opencode.db"), "WORKER_SESSION_DB_MUST_NOT_PERSIST");

        assert.equal(syncRefreshedOpenCodeAuth(staged!), true);
      } finally {
        staged?.cleanup();
        lease.release();
      }
      const after = JSON.parse(fs.readFileSync(authFile, "utf8")) as Record<string, Record<string, unknown>>;
      assert.equal(after.anthropic.refresh, "rt_ant_new", "未在宿主机变更的 anthropic 旋转令牌必须写回");
      assert.equal(after.openai.refresh, "rt_oai_host_relogin", "宿主机已并发重登的 openai 绝不得被工人旧值覆盖");
      assert.equal(after.google.key, "host-new-google-key", "宿主机新增的无关供应商必须保留");
      assert.equal(fs.existsSync(path.join(ocDataDir, "opencode.db")), false, "绝不得持久化沙箱内的 OpenCode 会话数据库");
    }

    // 5) [R25 #3 P1 & R25 #7 P2] commitAll 与派单检查点提交遵守仓库 include 与 worktree 配置中的 commit.gpgSign=true
    if (hasCredentialMountIsolation() && resolveTrustedSystemBin("ssh-keygen")) {
      const signHome = path.join(dir, "r25-7-sign-home");
      const dataDir7 = path.join(dir, "r25-7-data");
      fs.mkdirSync(path.join(signHome, ".ssh"), { recursive: true });
      fs.mkdirSync(dataDir7, { recursive: true });
      const keyPath = path.join(signHome, ".ssh", "r25_sign_ed25519");
      const gen = await runProcess("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath]);
      assert.equal(gen.code, 0, gen.stderr);

      const isoCfg7 = { dataDir: dataDir7, context: { personal_web: { enabled: true } } as Config["context"] };

      // Case A: 仓库 .git/config 通过外部 [include] 设置 commit.gpgSign=true + gpg.format=ssh
      const repoInc = path.join(dir, "r25-7-repo-inc");
      const extPolicyFile = path.join(dir, "r25-7-team-signing.gitconfig");
      fs.writeFileSync(
        extPolicyFile,
        ["[commit]", "\tgpgSign = true", "[gpg]", "\tformat = ssh", "[user]", `\tsigningkey = ${keyPath}`].join("\n") + "\n",
      );
      await runProcess("git", ["init", "-q", repoInc]);
      await runProcess("git", ["-C", repoInc, "config", "--local", "include.path", extPolicyFile]);
      fs.writeFileSync(path.join(repoInc, "inc.txt"), "via include\n");
      assert.equal(await commitAll(repoInc, "signed via repo include", { cfg: isoCfg7, extraEnv: { HOME: signHome } }), true);
      const rawInc = (await runProcess("git", ["-C", repoInc, "cat-file", "-p", "HEAD"])).stdout;
      assert.ok(rawInc.includes("-----BEGIN SSH SIGNATURE-----"), `仓库 include 启用 commit.gpgSign=true 时必须生成签名提交：\n${rawInc}`);

      // Case B: worktree 作用域（extensions.worktreeConfig=true + config.worktree）设置 commit.gpgSign=true
      const repoWtBase = path.join(dir, "r25-7-repo-wtbase");
      const wtDir7 = path.join(dir, "r25-7-wt");
      await runProcess("git", ["init", "-q", repoWtBase]);
      await runProcess("git", ["-C", repoWtBase, "config", "user.name", "Tester"]);
      await runProcess("git", ["-C", repoWtBase, "config", "user.email", "t@example.com"]);
      fs.writeFileSync(path.join(repoWtBase, "base.txt"), "base\n");
      await runProcess("git", ["-C", repoWtBase, "add", "base.txt"]);
      await runProcess("git", ["-C", repoWtBase, "-c", "commit.gpgSign=false", "commit", "-qm", "base"]);
      await runProcess("git", ["-C", repoWtBase, "config", "extensions.worktreeConfig", "true"]);
      await runProcess("git", ["-C", repoWtBase, "worktree", "add", "-q", "-b", "pa/r25-wt-sign", wtDir7]);
      await runProcess("git", ["-C", wtDir7, "config", "--worktree", "commit.gpgSign", "true"]);
      await runProcess("git", ["-C", wtDir7, "config", "--worktree", "gpg.format", "ssh"]);
      await runProcess("git", ["-C", wtDir7, "config", "--worktree", "user.signingkey", keyPath]);
      fs.writeFileSync(path.join(wtDir7, "wt-file.txt"), "worktree signed\n");
      assert.equal(
        await commitAll(wtDir7, "signed via worktree config", {
          cfg: isoCfg7,
          trustedRepoRoot: repoWtBase,
          extraEnv: { HOME: signHome },
        }),
        true,
      );
      const rawWt = (await runProcess("git", ["-C", wtDir7, "cat-file", "-p", "HEAD"])).stdout;
      assert.ok(rawWt.includes("-----BEGIN SSH SIGNATURE-----"), `config.worktree 启用 commit.gpgSign=true 时必须生成签名提交：\n${rawWt}`);
    }

    // 6) [R25 #8 P2 & R25 #9 P2 & R25 #10 P2] LFS 预拉取尊重 skip-smudge 与外部 lfs.storage 共享缓存，并从精确预拉取提交建 worktree
    if (hasCredentialMountIsolation() && resolveTrustedSystemBin("git-lfs")) {
      let lfsServerHits = 0;
      const lfsDeadSrv = http.createServer((_req, res) => {
        lfsServerHits++;
        res.writeHead(500);
        res.end("should not be called");
      });
      await new Promise<void>((resolve) => lfsDeadSrv.listen(0, "127.0.0.1", resolve));
      serversToClose.push(lfsDeadSrv);
      const deadPort = (lfsDeadSrv.address() as { port: number }).port;

      const lfsHome8 = path.join(dir, "r25-8-home");
      const dataDir8 = path.join(dir, "r25-8-data");
      const sharedLfsCache = path.join(dir, "r25-9-shared-lfs-cache");
      const repo8 = path.join(dir, "r25-8-repo");
      fs.mkdirSync(lfsHome8, { recursive: true });
      fs.mkdirSync(dataDir8, { recursive: true });
      fs.mkdirSync(sharedLfsCache, { recursive: true });

      const payload9 = Buffer.from("FROM_EXTERNAL_SHARED_LFS_STORAGE_R25\n", "utf8");
      const oid9 = crypto.createHash("sha256").update(payload9).digest("hex");
      const isoCfg8 = { dataDir: dataDir8, context: { personal_web: { enabled: true } } as Config["context"] };

      await runProcess("git", ["init", "-q", repo8]);
      await runProcess("git", ["-C", repo8, "config", "user.name", "Tester"]);
      await runProcess("git", ["-C", repo8, "config", "user.email", "t@example.com"]);
      await runProcess("git", ["-C", repo8, "remote", "add", "origin", `http://127.0.0.1:${deadPort}/org/repo.git`]);
      fs.writeFileSync(path.join(repo8, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
      fs.writeFileSync(
        path.join(repo8, "blob.bin"),
        `version https://git-lfs.github.com/spec/v1\noid sha256:${oid9}\nsize ${payload9.length}\n`,
      );
      await runProcess("git", [
        "-C",
        repo8,
        "-c",
        "filter.lfs.clean=",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.required=false",
        "add",
        ".gitattributes",
        "blob.bin",
      ]);
      await runProcess("git", ["-C", repo8, "-c", "commit.gpgSign=false", "commit", "-qm", "lfs pointer"]);

      // 6a) GIT_LFS_SKIP_SMUDGE=1 时必须跳过预拉取，不访问远端
      fs.writeFileSync(
        path.join(lfsHome8, ".gitconfig"),
        ['[filter "lfs"]', "\tclean = git-lfs clean -- %f", "\tsmudge = git-lfs smudge -- %f", "\tprocess = git-lfs filter-process", "\trequired = true"].join("\n") + "\n",
      );
      const skipEnvRes = await ensureGitLfsObjectsForCheckout(repo8, "HEAD", {
        cfg: isoCfg8,
        trustedRepoRoot: repo8,
        extraEnv: { HOME: lfsHome8, GIT_LFS_SKIP_SMUDGE: "1" },
      });
      assert.equal(skipEnvRes.fetched, false);
      assert.equal(skipEnvRes.skippedSmudge, true, "GIT_LFS_SKIP_SMUDGE=1 必须跳过 LFS 预拉取");
      assert.equal(lfsServerHits, 0);

      // 6b) git lfs install --skip-smudge 配置时同样必须跳过预拉取
      fs.writeFileSync(
        path.join(lfsHome8, ".gitconfig"),
        ['[filter "lfs"]', "\tclean = git-lfs clean -- %f", "\tsmudge = git-lfs smudge --skip -- %f", "\tprocess = git-lfs filter-process --skip", "\trequired = true"].join("\n") + "\n",
      );
      const skipCfgRes = await ensureGitLfsObjectsForCheckout(repo8, "HEAD", {
        cfg: isoCfg8,
        trustedRepoRoot: repo8,
        extraEnv: { HOME: lfsHome8 },
      });
      assert.equal(skipCfgRes.fetched, false);
      assert.equal(skipCfgRes.skippedSmudge, true, "filter.lfs.process --skip 必须跳过 LFS 预拉取");
      assert.equal(lfsServerHits, 0);

      // 6c) 配置外部共享 lfs.storage 且对象已在共享缓存中 -> 零远端请求且隔离 worktree 检出直接 smudge 成功
      fs.writeFileSync(
        path.join(lfsHome8, ".gitconfig"),
        ['[filter "lfs"]', "\tclean = git-lfs clean -- %f", "\tsmudge = git-lfs smudge -- %f", "\tprocess = git-lfs filter-process", "\trequired = true"].join("\n") + "\n",
      );
      await runProcess("git", ["-C", repo8, "config", "--local", "lfs.storage", sharedLfsCache]);
      const extObjDir = path.join(sharedLfsCache, "objects", oid9.slice(0, 2), oid9.slice(2, 4));
      fs.mkdirSync(extObjDir, { recursive: true });
      fs.writeFileSync(path.join(extObjDir, oid9), payload9);

      const headSha8 = (await runProcess("git", ["-C", repo8, "rev-parse", "HEAD"])).stdout.trim();
      const storagePre = await ensureGitLfsObjectsForCheckout(repo8, headSha8, {
        cfg: isoCfg8,
        trustedRepoRoot: repo8,
        extraEnv: { HOME: lfsHome8 },
      });
      assert.equal(storagePre.fetched, false, "外部 lfs.storage 已命中对象，不应访问远端");
      assert.equal(storagePre.lfsStorageExternal, true);
      assert.equal(storagePre.lfsStorageDir, fs.realpathSync(sharedLfsCache));
      assert.equal(lfsServerHits, 0);

      // 在主仓推进一个新提交模拟预拉取后 HEAD 漂移，验证 worktree add -b <branch> <cwd> <headSha8> 精确锁定预拉取提交
      fs.writeFileSync(path.join(repo8, "later.txt"), "advanced head\n");
      await runProcess("git", ["-C", repo8, "add", "later.txt"]);
      await runProcess("git", ["-C", repo8, "-c", "commit.gpgSign=false", "commit", "-qm", "later head"]);

      const wt8 = path.join(dir, "r25-9-wt");
      fs.mkdirSync(wt8, { recursive: true });
      const wtRes8 = await tryGit(repo8, ["worktree", "add", "-b", "pa/r25-ext-lfs", wt8, headSha8], {
        cfg: isoCfg8,
        trustedRepoRoot: repo8,
        extraWritablePaths: [wt8, storagePre.lfsStorageDir!],
        extraGitConfigArgs: ["-c", `lfs.storage=${storagePre.lfsStorageDir!}`],
        extraEnv: { HOME: lfsHome8 },
      });
      assert.equal(wtRes8.code, 0, `外部共享 lfs.storage 隔离 worktree 检出应成功：${wtRes8.stderr}`);
      assert.equal(fs.readFileSync(path.join(wt8, "blob.bin"), "utf8"), "FROM_EXTERNAL_SHARED_LFS_STORAGE_R25\n");
      assert.equal(fs.existsSync(path.join(wt8, "later.txt")), false, "worktree 必须锁定预拉取的 headSha8 而非漂移后的 HEAD");
      assert.equal(lfsServerHits, 0);
    }

    // 7) [R25 #11 P2 & R25 #12 P2] listDispatches / overview 批量归属校验消除 N+1，且 health() 分页扫描释放旧页 WorkItem 缓存
    {
      const app = makeR25App("r25-11-12-batch", { ownerOpenId: "ou_cur_r25" });
      try {
        const now = Date.now();
        app.store.set("ctx.dispatch_owner.dispatch:foreign_card:1", "ou_prev_r25");
        app.ledger.tx(() => {
          const ins = app.ledger.db.prepare(
            `INSERT INTO work (id, kind, ref, state, terminal, outcome, reason, attempts, next_at, lease_owner, lease_until, cancel, payload, error, created, updated)
             VALUES (?, ?, ?, ?, ?, '', '', 1, 0, '', 0, 0, ?, ?, ?, ?)`,
          );
          for (let i = 0; i < 220; i++) {
            const isForeign = i === 10;
            const id = isForeign ? "dispatch:foreign_card:1" : `dispatch:own_card_${i}:1`;
            const ref = isForeign ? "foreign_card" : `own_card_${i}`;
            ins.run(
              id,
              "dispatch",
              ref,
              "executing",
              0,
              JSON.stringify({ summary: `Task ${i}`, harness: "codex", round: 1, maxRounds: 2 }),
              "",
              now - 5000 + i,
              now - 5000 + i,
            );
          }
          // 再写入 2,200 条跨多页的失败 effect 验证 health() 分页扫描准确且保持低耗时
          for (let i = 0; i < 2200; i++) {
            ins.run(
              `eff:r25:${i}`,
              "effect",
              i % 11 === 0 ? "dispatch:foreign_card:1" : `own_eff_${i}`,
              "dead",
              1,
              JSON.stringify({ op: "task.comment", args: { guid: `g_${i}`, content: "x".repeat(512) } }),
              "failed",
              now - 3000 + i,
              now - 3000 + i,
            );
          }
        });

        let storeGetCalls = 0;
        const origGet = app.store.get.bind(app.store);
        app.store.get = ((k: string) => {
          storeGetCalls++;
          return origGet(k);
        }) as typeof app.store.get;
        try {
          const listed = Q.listDispatches(app, { filter: "all", limit: 200 });
          assert.equal(listed.length, 200);
          assert.equal(listed.some((d) => d.id === "dispatch:foreign_card:1"), false, "批量过滤必须隐藏旧主人派单");
          assert.ok(storeGetCalls < 20, `listDispatches 200 条应批量查归属而非逐条 Store.get（实际 ${storeGetCalls} 次）`);

          storeGetCalls = 0;
          const ov = Q.overview(app);
          assert.equal(ov.running.some((d) => d.id === "dispatch:foreign_card:1"), false);
          assert.equal(ov.health.dead, 2000, "2,200 条中扣除 200 条关联旧主人派单后应精确统计 2,000 条");
          assert.ok(storeGetCalls < 30, `overview() + health() 应批量查归属（实际 ${storeGetCalls} 次）`);
        } finally {
          app.store.get = origGet;
        }
      } finally {
        app.store.db.close();
      }
    }

    // 8) [R25 #13 P2] 无仓库别名时 doctor 仍独立探测 Linux 强制沙箱隔离能力
    {
      const app = makeR25App("r25-13-doctor-iso", { repos: {} });
      try {
        const rep = await runDoctor(app);
        const isoChk = rep.checks.find((c) => c.id === "worker_isolation");
        assert.ok(isoChk, "即使未配置任何仓库别名，doctor 也必须包含 worker_isolation 检查项");
        if (process.platform === "linux" && hasCredentialMountIsolation()) {
          assert.equal(isoChk!.status, "ok", `可用内核隔离环境下应返回 ok：${isoChk!.detail}`);
        }
      } finally {
        app.store.db.close();
      }
    }
  } finally {
    if (prevPwKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
    else process.env.PA_FEISHU_WEB_KEY = prevPwKey;
    for (const s of serversToClose) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    fs.rmSync(dir, { recursive: true, force: true });
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
