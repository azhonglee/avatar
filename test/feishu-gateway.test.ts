import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import YAML from "yaml";
import { WebSocketServer } from "ws";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { ContextService } from "../src/context/index.ts";
import { PersonalWebBridge } from "../src/context/personal-web.ts";
import { FeishuGatewayClient } from "../src/gateway/client.ts";
import { loadGatewayConfig } from "../src/gateway/config.ts";
import {
  CHAT_KIND_GROUP,
  CHAT_MODE_TOPIC,
  CMD_CHAT_MODE,
  CMD_HISTORY,
  CMD_READ_MESSAGE,
  CMD_SEND_MESSAGE,
  decodeRichText,
  encodePacket,
  encodeRichText,
  parseProto,
  ProtoWriter,
  USER_SENDER_TYPE,
  type WebEndpoints,
  type WebMessage,
} from "../src/gateway/feishu-web/index.ts";
import { GatewayHttpError, type GatewayEvent } from "../src/gateway/protocol.ts";
import { startGatewayServer } from "../src/gateway/server.ts";
import { FeishuGatewayService } from "../src/gateway/service.ts";
import { GatewayStore } from "../src/gateway/store.ts";

function makeTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function makeWebMsg(overrides: Partial<WebMessage> = {}): WebMessage {
  return {
    id: "80001",
    ownerId: "owner-1",
    kind: 4,
    messageType: "text",
    conversationId: "chat-alpha",
    conversationKind: "group",
    actorId: "actor-9",
    senderType: USER_SENDER_TYPE,
    text: "请确认独立网关上线窗口",
    createdAtMs: Date.now(),
    rootId: "",
    parentId: "",
    threadId: "",
    cid: "cid-in",
    position: 5,
    threadPosition: 0,
    sendToChat: false,
    mentions: [{ id: "owner-1", name: "@我", start: 0, end: 2 }],
    resources: [],
    partial: false,
    unsupported: false,
    ...overrides,
  };
}

function buildMessageBytes(opts: {
  id: string;
  chatId: string;
  actorId: string;
  text: string;
  rootId?: string;
  parentId?: string;
  threadId?: string;
  cid?: string;
  position?: number;
}): Buffer {
  const richContent = encodeRichText([{ text: opts.text }]);
  const w = new ProtoWriter()
    .str(1, opts.id)
    .uint(2, 4)
    .str(3, opts.actorId)
    .uint(4, Math.floor(Date.now() / 1000))
    .bytes(5, new ProtoWriter().bytes(3, richContent).finish())
    .uint(7, USER_SENDER_TYPE)
    .str(10, opts.chatId)
    .uint(13, opts.position ?? 10)
    .uint(46, CHAT_KIND_GROUP);
  if (opts.rootId) w.str(8, opts.rootId);
  if (opts.parentId) w.str(9, opts.parentId);
  if (opts.cid) w.str(12, opts.cid);
  if (opts.threadId) w.str(20, opts.threadId);
  return w.finish();
}

function buildChatBytes(chatId: string, name: string, kind = CHAT_KIND_GROUP, mode = CHAT_MODE_TOPIC): Buffer {
  return new ProtoWriter().str(1, chatId).uint(2, kind).str(4, name).uint(39, mode).finish();
}

function mapEntry(key: string, val: Buffer): Buffer {
  return new ProtoWriter().str(1, key).bytes(2, val).finish();
}

async function startMockFeishu() {
  const OWNER_ID = "10001";
  const chats = new Map<string, Buffer>([
    ["chat-alpha", buildChatBytes("chat-alpha", "架构评审群")],
    ["chat-secret", buildChatBytes("chat-secret", "高管私密群")],
  ]);
  const messages = new Map<string, Buffer>([
    ["orig-100", buildMessageBytes({ id: "orig-100", chatId: "chat-alpha", actorId: "actor-9", text: "请确认上线窗口", cid: "c-orig", position: 10 })],
  ]);
  let sendCount = 0;
  let seq = 200;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    const body = Buffer.concat(chunks);

    if (url.pathname === "/messenger/") {
      res.writeHead(200, {
        "Content-Type": "text/html",
        "Set-Cookie": ["passport_web_did=did-100; Path=/", "swp_csrf_token=csrf-1; Path=/"],
      });
      res.end(`<script>window.passport_web_did="did-100"; var cfg={appKey:"app-key-1"};</script>`);
      return;
    }
    if (url.pathname === "/accounts/web/user") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(`{"code":0,"data":{"user":{"id":${OWNER_ID},"name":"Owner","open_id":"ou_owner"}}}`);
      return;
    }
    if (url.pathname === "/suite/passport/frontier_ticket/") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ code: 0, ticket: "ticket-gw" }));
      return;
    }
    if (url.pathname === "/im/gateway/") {
      const pkt = parseProto(body);
      const cmd = pkt.uint(3);
      const payload = pkt.bytes(5);
      const cid = pkt.str(6);

      if (cmd === CMD_CHAT_MODE) {
        const chatId = parseProto(payload).str(1);
        const found = chats.get(chatId);
        const respPayload = found ? new ProtoWriter().bytes(1, mapEntry(chatId, found)).finish() : Buffer.alloc(0);
        res.writeHead(200, { "content-type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }
      if (cmd === CMD_READ_MESSAGE) {
        const id = parseProto(payload).str(1);
        const found = messages.get(id);
        const respPayload = found ? new ProtoWriter().bytes(1, mapEntry(id, found)).finish() : Buffer.alloc(0);
        res.writeHead(200, { "content-type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }
      if (cmd === CMD_HISTORY) {
        const reqFields = parseProto(payload);
        const wanted = new Set(reqFields.allUints(2).map(Number));
        const out = new ProtoWriter();
        for (const [id, buf] of messages) {
          const pos = parseProto(buf).int32(13);
          if (wanted.size > 0 && !wanted.has(pos)) continue;
          out.bytes(1, mapEntry(id, buf));
        }
        res.writeHead(200, { "content-type": "application/x-protobuf" });
        res.end(encodePacket(cmd, out.finish(), cid));
        return;
      }
      if (cmd === CMD_SEND_MESSAGE) {
        sendCount++;
        const reqFields = parseProto(payload);
        const chatId = reqFields.str(3);
        const rootId = reqFields.str(4);
        const parentId = reqFields.str(5);
        const msgCid = reqFields.str(6);
        const inThread = reqFields.uint(12) === 1;
        const sentText = decodeRichText(parseProto(reqFields.bytes(2)).bytes(14)).text;
        const replyId = `rep-${++seq}`;
        const replyBuf = buildMessageBytes({
          id: replyId,
          chatId,
          actorId: OWNER_ID,
          text: sentText,
          rootId,
          parentId,
          threadId: inThread || chats.has(chatId) ? `th-${rootId}` : "",
          cid: msgCid,
          position: 11,
        });
        messages.set(replyId, replyBuf);
        const respPayload = new ProtoWriter().bytes(1, replyBuf).finish();
        res.writeHead(200, { "content-type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }
    }
    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({ noServer: true });
  server.on("upgrade", (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;
  const endpoints: WebEndpoints = {
    messengerUrl: `${base}/messenger/`,
    qrInitUrl: `${base}/accounts/qrlogin/init`,
    qrPollUrl: `${base}/accounts/qrlogin/polling`,
    qrRedirectUri: `${base}/next/messenger`,
    profileUrl: `${base}/accounts/web/user?app_id=12`,
    gatewayUrl: `${base}/im/gateway/`,
    ticketUrl: `${base}/suite/passport/frontier_ticket/`,
    websocketUrl: `ws://127.0.0.1:${addr.port}/ws/v2`,
    accountsOrigin: base,
    accountsReferer: `${base}/accounts/page/login`,
    messengerOrigin: base,
    allowInsecureHttp: true,
    extraAllowedHosts: ["127.0.0.1"],
  };
  return {
    endpoints,
    getSendCount: () => sendCount,
    async close() {
      for (const c of wss.clients) c.terminate();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

describe("independent feishu-gateway daemon (Unix socket, scope isolation, SSE cursor replay, idempotent replies)", () => {
  it("enforces socket permissions, live-socket protection, loopback-only TCP, and distinct token invariants", async () => {
    const dir = makeTmp("pa-gw-sec-");
    const gwDir = path.join(dir, "gw-data");
    const sockPath = path.join(dir, "run", "gateway.sock");
    try {
      // 1) World-accessible socket_mode rejected
      const badModeCfg = path.join(dir, "bad-mode.yaml");
      fs.writeFileSync(badModeCfg, YAML.stringify({ data_dir: gwDir, listen: { socket: sockPath, socket_mode: "0666" } }));
      assert.throws(() => loadGatewayConfig(badModeCfg), /socket_mode/);

      // 2) Wildcard / non-loopback TCP host rejected
      const badHostCfg = path.join(dir, "bad-host.yaml");
      fs.writeFileSync(badHostCfg, YAML.stringify({ data_dir: gwDir, listen: { socket: "", host: "0.0.0.0", port: 7879 } }));
      assert.throws(() => loadGatewayConfig(badHostCfg), /回环地址/);

      // 3) Start live gateway on Unix socket with 0660 mode
      const okCfgPath = path.join(dir, "gateway.yaml");
      fs.writeFileSync(okCfgPath, YAML.stringify({ data_dir: gwDir, listen: { socket: sockPath, socket_mode: "0660" } }));
      const cfg = loadGatewayConfig(okCfgPath);
      const store = new GatewayStore(cfg.dataDir);
      const service = new FeishuGatewayService(cfg, store);

      // Equal read_token and reply_token rejected
      const prevR = process.env.FEISHU_GW_READ_TOKEN;
      const prevW = process.env.FEISHU_GW_REPLY_TOKEN;
      process.env.FEISHU_GW_READ_TOKEN = "same-token-1234567890";
      process.env.FEISHU_GW_REPLY_TOKEN = "same-token-1234567890";
      assert.throws(() => store.resolveTokens(), /必须严格不同/);

      // Env-provided read_token must NOT be written into tokens.json when reply_token is generated
      process.env.FEISHU_GW_READ_TOKEN = "env-read-token-1234567890";
      delete process.env.FEISHU_GW_REPLY_TOKEN;
      const mixed = store.resolveTokens();
      assert.equal(mixed.readSource, "env");
      assert.equal(mixed.replySource, "file");
      const tokenDisk = JSON.parse(fs.readFileSync(store.tokensFile, "utf8")) as Record<string, string>;
      assert.equal(tokenDisk.read_token, undefined, "环境变量提供的令牌不得落盘到 tokens.json");
      assert.equal(tokenDisk.reply_token, mixed.replyToken);

      if (prevR === undefined) delete process.env.FEISHU_GW_READ_TOKEN;
      else process.env.FEISHU_GW_READ_TOKEN = prevR;
      if (prevW === undefined) delete process.env.FEISHU_GW_REPLY_TOKEN;
      else process.env.FEISHU_GW_REPLY_TOKEN = prevW;

      const tokens = store.resolveTokens();
      const server = await startGatewayServer(cfg, service, tokens);
      try {
        const mode = fs.statSync(sockPath).mode & 0o777;
        assert.equal(mode, 0o660);

        // Starting a second server on the SAME live Unix socket must fail without unlinking the live socket
        await assert.rejects(startGatewayServer(cfg, service, tokens), /已被另一个运行中的网关实例占用/);
        const client = new FeishuGatewayClient({ socketPath: sockPath, readToken: tokens.readToken, replyToken: tokens.replyToken });
        const health = await client.health();
        assert.equal(health.ok, true);

        // Refuses to unlink a regular file disguised as socket path
        const regularFile = path.join(dir, "not-a-socket");
        fs.writeFileSync(regularFile, "keep-me");
        const badFileCfgPath = path.join(dir, "bad-file.yaml");
        fs.writeFileSync(badFileCfgPath, YAML.stringify({ data_dir: gwDir, listen: { socket: regularFile, socket_mode: "0600" } }));
        await assert.rejects(startGatewayServer(loadGatewayConfig(badFileCfgPath), service, tokens), /不是 Unix Socket/);
        assert.equal(fs.readFileSync(regularFile, "utf8"), "keep-me");

        // Strict scope separation: read_token rejected on /v1/replies; reply_token rejected on /v1/status & /v1/events
        const readOnlyClient = new FeishuGatewayClient({ socketPath: sockPath, readToken: tokens.readToken, replyToken: tokens.readToken });
        await assert.rejects(
          readOnlyClient.sendReply({ chat_id: "c1", message_id: "m1", text: "hi", cid: "cid-scope-test-01" }),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "insufficient_scope",
        );

        const replyAsReadClient = new FeishuGatewayClient({ socketPath: sockPath, readToken: tokens.replyToken });
        await assert.rejects(
          replyAsReadClient.status(),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "insufficient_scope",
        );
        await assert.rejects(
          replyAsReadClient.listEvents(0, 10),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "insufficient_scope",
        );
      } finally {
        await server.stop();
        store.close();
      }
      assert.equal(fs.existsSync(sockPath), false, "stopping server cleans up owned Unix socket");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("streams live events over Unix socket SSE, scrubs recalls, enforces gateway deny_chats, and catches up after Avatar restart with zero loss", async () => {
    const dir = makeTmp("pa-gw-e2e-");
    const gwDir = path.join(dir, "gw");
    const appDir = path.join(dir, "avatar");
    const sockPath = path.join(dir, "gateway.sock");
    const gwCfgPath = path.join(dir, "gateway.yaml");
    const appCfgPath = path.join(dir, "config.yaml");

    fs.writeFileSync(
      gwCfgPath,
      YAML.stringify({
        data_dir: gwDir,
        listen: { socket: sockPath, socket_mode: "0600" },
        allow_reply: false,
        deny_chats: ["chat-secret", "机密"],
      }),
    );
    fs.writeFileSync(
      appCfgPath,
      YAML.stringify({
        data_dir: appDir,
        owner: { open_id: "ou_owner" },
        cards: { enabled: false },
        harnesses: { brain: { type: "acpx", agent: "claude" } },
        roles: { brain: "brain", reviewer: "brain" },
        context: {
          enabled: true,
          understand: true,
          groups: "spoken",
          personal_web: {
            enabled: true,
            gateway_socket: sockPath,
            fast_lane: true,
            debounce_ms: 0,
            send_replies: false,
          },
        },
      }),
    );

    const gwCfg = loadGatewayConfig(gwCfgPath);
    const gwStore = new GatewayStore(gwCfg.dataDir);
    const gwService = new FeishuGatewayService(gwCfg, gwStore);
    const tokens = gwStore.resolveTokens();
    const gwServer = await startGatewayServer(gwCfg, gwService, tokens, { heartbeatMs: 1_000 });

    const app = createApp(loadConfig(appCfgPath));
    const svc = new ContextService(app);
    const gwClient = new FeishuGatewayClient({ socketPath: sockPath, readToken: tokens.readToken, replyToken: tokens.replyToken });
    const fastTriggers: string[] = [];
    const reconnects: number[] = [];

    const bridge = new PersonalWebBridge(app, svc.store, {
      gatewayClient: gwClient,
      watchIntervalMs: 100,
      onFastTrigger: (t) => fastTriggers.push(t.trigger_obs_id),
      onReconnect: () => reconnects.push(Date.now()),
      onNeedsLogin: () => undefined,
    });

    try {
      // 1) Gateway-side deny_chats drops denied message before SQLite ingest
      const dropped = await gwService.handleMessage(makeWebMsg({ id: "m-secret", conversationId: "chat-secret", text: "高管机密" }));
      assert.equal(dropped, null);
      assert.equal(gwStore.listEvents(0, 50).events.length, 0);

      // 2) Start Avatar bridge -> receive live message 1 over SSE
      bridge.start();
      await gwService.handleMessage(makeWebMsg({ id: "m-live-1", conversationId: "chat-alpha", text: "第一条实时消息" }));
      const waitUntil = async (cond: () => boolean, ms = 3_000) => {
        const deadline = Date.now() + ms;
        while (!cond() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
        assert.ok(cond(), "condition timed out");
      };
      await waitUntil(() => !!svc.store.obs("pw:m-live-1") && bridge.cursor() >= 1);
      assert.deepEqual(fastTriggers, ["pw:m-live-1"]);
      const cursorBeforeRestart = bridge.cursor();

      // 3) Simulate Avatar restart: stop bridge while gateway stays up and ingests m-missed-2 + recalls m-live-1
      bridge.stop();
      await gwService.handleMessage(makeWebMsg({ id: "m-missed-2", conversationId: "chat-alpha", text: "主进程重启期间到达的消息" }));
      await gwService.handleMessage(makeWebMsg({ id: "m-live-1", conversationId: "chat-alpha", text: "", unsupported: true }));

      // Verify gateway scrubbed historical payload of recalled m-live-1 from SQLite
      const rawEvents = gwStore.listEvents(0, 50).events;
      assert.equal(
        rawEvents.some((e: GatewayEvent) => e.kind === "message" && e.message_id === "m-live-1"),
        false,
        "撤回消息的历史正文必须已从网关缓存擦除",
      );
      assert.equal(
        rawEvents.some((e: GatewayEvent) => e.kind === "delete" && e.message_id === "m-live-1"),
        true,
      );

      // 4) Restart Avatar bridge -> catches up seamlessly from persisted cursor without losing m-missed-2 or recall
      const bridge2 = new PersonalWebBridge(app, svc.store, {
        gatewayClient: gwClient,
        watchIntervalMs: 100,
        onFastTrigger: (t) => fastTriggers.push(t.trigger_obs_id),
        onReconnect: () => reconnects.push(Date.now()),
        onNeedsLogin: () => undefined,
      });
      bridge2.start();
      try {
        await waitUntil(() => !!svc.store.obs("pw:m-missed-2") && !svc.store.obs("pw:m-live-1") && bridge2.cursor() > cursorBeforeRestart);
        assert.equal(svc.store.obs("pw:m-missed-2")?.text, "主进程重启期间到达的消息");
        assert.equal(svc.store.obs("pw:m-live-1"), undefined, "重启补拉期间收到的 delete 事件应删除本地观测");
        assert.deepEqual(fastTriggers, ["pw:m-live-1", "pw:m-missed-2"]);
      } finally {
        bridge2.stop();
      }

      // 5) Retention gap triggers truncated flag and onReconnect fallback
      gwStore.db.prepare("DELETE FROM gw_events").run();
      await gwService.handleMessage(makeWebMsg({ id: "m-after-gap", conversationId: "chat-alpha", text: "清理后的新消息" }));
      app.store.set("ctx.pw_gateway.cursor", "1");
      const gapPage = await gwClient.listEvents(1, 50);
      assert.equal(gapPage.truncated, true);
    } finally {
      bridge.stop();
      gwService.stop();
      await gwServer.stop();
      gwStore.close();
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enforces gateway allow_reply gate, cid idempotency, cid mismatch, ambiguous sending lock, and readback-only recovery end-to-end", async () => {
    const dir = makeTmp("pa-gw-reply-");
    const gwDir = path.join(dir, "gw");
    const sockPath = path.join(dir, "gateway.sock");
    const gwCfgPath = path.join(dir, "gateway.yaml");
    const prevKey = process.env.FEISHU_GW_KEY;
    process.env.FEISHU_GW_KEY = "reply-test-encryption-key-012345";

    const mockFeishu = await startMockFeishu();
    fs.writeFileSync(
      gwCfgPath,
      YAML.stringify({
        data_dir: gwDir,
        listen: { socket: sockPath, socket_mode: "0600" },
        allow_reply: false,
        deny_chats: ["chat-secret"],
      }),
    );

    const gwCfg = loadGatewayConfig(gwCfgPath);
    const gwStore = new GatewayStore(gwCfg.dataDir);
    const gwService = new FeishuGatewayService(gwCfg, gwStore, {
      clientOptions: { endpoints: mockFeishu.endpoints },
    });
    gwService.loginStore.save({
      owner_id: "10001",
      owner_name: "Owner",
      owner_open_id: "ou_owner",
      cookies: [{ name: "session", value: "s-live", domain: "127.0.0.1", path: "/" }],
    });
    const tokens = gwStore.resolveTokens();
    const gwServer = await startGatewayServer(gwCfg, gwService, tokens);
    const client = new FeishuGatewayClient({ socketPath: sockPath, readToken: tokens.readToken, replyToken: tokens.replyToken });

    try {
      // 1) allow_reply: false -> permanent 403 reply_disabled
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-reply-0001" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "reply_disabled" && e.permanent === true,
      );
      assert.equal(mockFeishu.getSendCount(), 0);

      // 2) Enable allow_reply -> first call sends & verifies; second call with same cid returns cached verified without re-sending
      gwCfg.allow_reply = true;
      const r1 = await client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-reply-0001" });
      assert.equal(r1.verified, true);
      assert.equal(mockFeishu.getSendCount(), 1);

      const r2 = await client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-reply-0001" });
      assert.equal(r2.replyId, r1.replyId);
      assert.equal(mockFeishu.getSendCount(), 1, "同 cid 重试绝不二次发包");

      // 3) Reusing same cid with different text -> permanent 409 cid_mismatch
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "改成周五上线", cid: "cid-reply-0001" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "cid_mismatch" && e.permanent === true,
      );

      // 4) Gateway deny_chats blocks reply with permanent 403 chat_denied
      await assert.rejects(
        client.sendReply({ chat_id: "chat-secret", message_id: "orig-100", text: "不允许发", cid: "cid-reply-denied-1" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "chat_denied" && e.permanent === true,
      );

      // 5) Ambiguous sending record -> permanent 409 ambiguous_delivery without re-sending
      gwStore.saveDelivery({
        cid: "cid-ambiguous-01",
        status: "sending",
        reply_id: "",
        chat_id: "chat-alpha",
        root_id: "orig-100",
        parent_id: "orig-100",
        threaded: false,
        thread_id: "",
        text_hash: gwStore.getDelivery("cid-reply-0001")!.text_hash,
        updated_at: Date.now(),
      });
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-ambiguous-01" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "ambiguous_delivery" && e.permanent === true,
      );
      assert.equal(mockFeishu.getSendCount(), 1);

      // 6) Created (readback-only) completes verification even after allow_reply is turned back to false
      gwStore.saveDelivery({
        cid: "cid-readback-01",
        status: "created",
        reply_id: r1.replyId,
        chat_id: "chat-alpha",
        root_id: r1.rootId,
        parent_id: r1.parentId,
        threaded: false,
        thread_id: "",
        text_hash: gwStore.getDelivery("cid-reply-0001")!.text_hash,
        updated_at: Date.now(),
      });
      // Inject matching cid on mock stored message so verifyReplyReadback matches cid
      const prevSendCount = mockFeishu.getSendCount();
      gwCfg.allow_reply = false;
      // Note: mock message r1.replyId has cid="cid-reply-0001", so reuse cid="cid-reply-0001" after resetting its status to created
      gwStore.saveDelivery({
        cid: "cid-reply-0001",
        status: "created",
        reply_id: r1.replyId,
        chat_id: "chat-alpha",
        root_id: r1.rootId,
        parent_id: r1.parentId,
        threaded: false,
        thread_id: "",
        text_hash: gwStore.getDelivery("cid-reply-0001")!.text_hash,
        updated_at: Date.now(),
      });
      const rRecovered = await client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-reply-0001" });
      assert.equal(rRecovered.verified, true);
      assert.equal(mockFeishu.getSendCount(), prevSendCount, "created 状态回读恢复绝不二次发包，即使 allow_reply=false 也可完成核验");
    } finally {
      gwService.stop();
      await gwServer.stop();
      gwStore.close();
      await mockFeishu.close();
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
