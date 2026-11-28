import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
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

      // 2) Wildcard / non-loopback TCP host rejected & required missing config throws (fail-closed)
      const badHostCfg = path.join(dir, "bad-host.yaml");
      fs.writeFileSync(badHostCfg, YAML.stringify({ data_dir: gwDir, listen: { socket: "", host: "0.0.0.0", port: 7879 } }));
      assert.throws(() => loadGatewayConfig(badHostCfg), /回环地址/);
      assert.throws(() => loadGatewayConfig(path.join(dir, "missing-gateway.yaml"), { required: true }), /找不到网关配置文件/);

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
        assert.equal(fs.statSync(gwDir).mode & 0o777, 0o700, "gateway data_dir must be 0700");
        assert.equal(fs.statSync(store.dbPath).mode & 0o777, 0o600, "gateway.db must be 0600");

        // Malformed unauthenticated HTTP target must return 400 invalid_url and NOT crash the server
        const rawResp = await new Promise<string>((resolve, reject) => {
          const sock = net.connect(sockPath, () => {
            sock.write("GET //[invalid HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
          });
          let out = "";
          sock.setEncoding("utf8");
          sock.on("data", (d) => (out += d));
          sock.on("end", () => resolve(out));
          sock.on("error", reject);
        });
        assert.match(rawResp, /400 Bad Request/);
        assert.match(rawResp, /invalid_url/);

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

        // POST /v1/context rejects unsafe anchor.position (> MAX_SAFE_INTEGER / int32) and non-finite limit
        await assert.rejects(
          client.readContext({
            anchor: { id: "1", conversationId: "chat-alpha", rootId: "", parentId: "", threadId: "", position: 1e17, createdAtMs: Date.now() },
          }),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 400 && e.code === "invalid_request",
        );
        await assert.rejects(
          client.readContext({
            anchor: { id: "1", conversationId: "chat-alpha", rootId: "", parentId: "", threadId: "", position: 5, createdAtMs: Date.now() },
            limit: Number.NaN,
          }),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 400 && e.code === "invalid_request",
        );

        // Missing token rejects Promise asynchronously (does not throw synchronously)
        const noTokClient = new FeishuGatewayClient({ socketPath: sockPath });
        await assert.rejects(
          () => noTokClient.health(),
          (e: unknown) => e instanceof GatewayHttpError && e.code === "missing_read_token",
        );
      } finally {
        await server.stop();
        store.close();
      }
      assert.equal(fs.existsSync(sockPath), false, "stopping server cleans up owned Unix socket");

      // Stale Unix socket (left behind after SIGKILL -> ECONNREFUSED) is safely recovered on startup
      const staleSock = path.join(dir, "run", "stale.sock");
      spawnSync(process.execPath, [
        "-e",
        `const net = require("node:net"); const s = net.createServer(); s.listen(${JSON.stringify(staleSock)}, () => process.kill(process.pid, "SIGKILL"));`,
      ]);
      assert.equal(fs.lstatSync(staleSock).isSocket(), true, "SIGKILL 模拟的陈旧 socket 文件应存在");
      const staleCfgPath = path.join(dir, "stale.yaml");
      fs.writeFileSync(staleCfgPath, YAML.stringify({ data_dir: gwDir, listen: { socket: staleSock, socket_mode: "0600" } }));
      const staleStore = new GatewayStore(gwDir);
      const staleSvc = new FeishuGatewayService(loadGatewayConfig(staleCfgPath), staleStore);
      const staleTokens = staleStore.resolveTokens();
      const staleSrv = await startGatewayServer(loadGatewayConfig(staleCfgPath), staleSvc, staleTokens);
      try {
        const staleClient = new FeishuGatewayClient({ socketPath: staleSock, readToken: staleTokens.readToken });
        assert.equal((await staleClient.health()).ok, true);
      } finally {
        await staleSrv.stop();
        staleStore.close();
      }

      // IPv4 + IPv6 loopback TCP (`[::1]`) works end-to-end (including config host bracket normalization)
      const ipv6CfgPath = path.join(dir, "tcp-ipv6.yaml");
      fs.writeFileSync(ipv6CfgPath, YAML.stringify({ data_dir: gwDir, listen: { socket: "", host: "[::1]", port: 7879 } }));
      assert.equal(loadGatewayConfig(ipv6CfgPath).listen.host, "::1");

      for (const host of ["127.0.0.1", "[::1]"]) {
        const tcpStore = new GatewayStore(gwDir);
        const tcpTokens = tcpStore.resolveTokens();
        const tcpCfg = { ...loadGatewayConfig(okCfgPath), socketPath: "", listen: { socket: "", socket_mode: "0600", host: host.replace(/^\[|\]$/g, ""), port: 0 } };
        const tcpSvc = new FeishuGatewayService(tcpCfg, tcpStore);
        let tcpSrv;
        try {
          tcpSrv = await startGatewayServer(tcpCfg, tcpSvc, tcpTokens);
        } catch (e) {
          tcpStore.close();
          if (host === "[::1]" && ["EADDRNOTAVAIL", "EAFNOSUPPORT"].includes((e as NodeJS.ErrnoException).code ?? "")) continue;
          throw e;
        }
        try {
          const tcpClient = new FeishuGatewayClient({ baseUrl: tcpSrv.url!, readToken: tcpTokens.readToken });
          const h = await tcpClient.health();
          assert.equal(h.ok, true);
        } finally {
          await tcpSrv.stop();
          tcpStore.close();
        }
      }

      // SSE catch-up error after writeHead(200) must cleanly drop ONLY that stream without crashing server (no ERR_HTTP_HEADERS_SENT)
      const errSock = path.join(dir, "run", "sse-err.sock");
      const errCfgPath = path.join(dir, "sse-err.yaml");
      fs.writeFileSync(errCfgPath, YAML.stringify({ data_dir: gwDir, listen: { socket: errSock, socket_mode: "0600" } }));
      const errStore = new GatewayStore(gwDir);
      const errSvc = new FeishuGatewayService(loadGatewayConfig(errCfgPath), errStore);
      const origList = errSvc.listEvents.bind(errSvc);
      let failOnce = true;
      errSvc.listEvents = ((after?: number, limit?: number) => {
        if (failOnce) {
          failOnce = false;
          throw new Error("simulated transient SQLITE_BUSY");
        }
        return origList(after, limit);
      }) as typeof errSvc.listEvents;
      const errTokens = errStore.resolveTokens();
      const errSrv = await startGatewayServer(loadGatewayConfig(errCfgPath), errSvc, errTokens);
      try {
        const errClient = new FeishuGatewayClient({ socketPath: errSock, readToken: errTokens.readToken });
        await assert.rejects(
          errClient.streamEvents({ after: 0, signal: new AbortController().signal, onEvent: () => undefined }),
          /stream_closed|socket hang up|ECONNRESET/i,
        );
        // Server must still be alive and healthy after the failed stream
        assert.equal((await errClient.health()).ok, true);
      } finally {
        await errSrv.stop();
        errStore.close();
      }
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

      // 5) Full prune (min_seq=0, latest_seq>0) sets truncated=true
      gwStore.db.prepare("DELETE FROM gw_events").run();
      const emptyGap = await gwClient.listEvents(1, 50);
      assert.equal(emptyGap.truncated, true, "全量清空后 min_seq=0 且 after < latest_seq 仍必须报 truncated=true");

      // 6) Newly added deny_chats scrubs already-cached history on gateway restart
      await gwService.handleMessage(makeWebMsg({ id: "m-newly-denied", conversationId: "chat-to-ban", text: "旧敏感消息" }));
      assert.ok(gwStore.listEvents(0, 50).events.some((e) => e.message_id === "m-newly-denied"));
      const gwCfgWithBan = { ...gwCfg, deny_chats: [...gwCfg.deny_chats, "chat-to-ban"] };
      const gwSvcAfterBan = new FeishuGatewayService(gwCfgWithBan, gwStore);
      assert.equal(
        gwSvcAfterBan.listEvents(0, 50).events.some((e) => e.message_id === "m-newly-denied"),
        false,
        "新增 deny_chats 重启后必须擦除已缓存的敏感消息",
      );

      // 7) Gateway DB reset (local cursor > latest_seq): SSE emits gap, bridge resets cursor, triggers onReconnect, and ingests new seq=1 message
      const freshDir = path.join(dir, "gw-reset");
      const resetSock = path.join(dir, "gw-reset.sock");
      const resetCfgPath = path.join(dir, "gw-reset.yaml");
      fs.writeFileSync(resetCfgPath, YAML.stringify({ data_dir: freshDir, listen: { socket: resetSock, socket_mode: "0600" } }));
      const resetCfg = loadGatewayConfig(resetCfgPath);
      const resetStore = new GatewayStore(resetCfg.dataDir);
      const resetSvc = new FeishuGatewayService(resetCfg, resetStore);
      const resetTokens = resetStore.resolveTokens();
      const resetServer = await startGatewayServer(resetCfg, resetSvc, resetTokens, { heartbeatMs: 1_000 });
      const resetClient = new FeishuGatewayClient({ socketPath: resetSock, readToken: resetTokens.readToken });
      app.store.set("ctx.pw_gateway.cursor", "9999");
      const resetReconnects: number[] = [];
      const bridge3 = new PersonalWebBridge(app, svc.store, {
        gatewayClient: resetClient,
        watchIntervalMs: 50,
        onFastTrigger: () => undefined,
        onReconnect: () => resetReconnects.push(Date.now()),
        onNeedsLogin: () => undefined,
      });
      try {
        bridge3.start();
        await waitUntil(() => resetReconnects.length >= 1 && bridge3.cursor() === 0);
        await resetSvc.handleMessage(makeWebMsg({ id: "m-new-db-1", conversationId: "chat-alpha", text: "新库第一条消息" }));
        await waitUntil(() => !!svc.store.obs("pw:m-new-db-1") && bridge3.cursor() === 1);
        assert.equal(svc.store.obs("pw:m-new-db-1")?.text, "新库第一条消息");
      } finally {
        bridge3.stop();
        await resetSvc.stop();
        await resetServer.stop();
        resetStore.close();
      }

      // 8) Slow onEvent consumer (> idleTimeoutMs) must NOT be killed by idleTimer while paused in pump()
      const slowCtrl = new AbortController();
      let slowSeen = 0;
      const slowStream = gwClient.streamEvents({
        after: 0,
        signal: slowCtrl.signal,
        idleTimeoutMs: 120,
        onEvent: async () => {
          slowSeen++;
          await new Promise((r) => setTimeout(r, 200));
          slowCtrl.abort();
        },
      });
      await gwService.handleMessage(makeWebMsg({ id: "m-slow-1", conversationId: "chat-alpha", text: "慢消费测试" }));
      await slowStream;
      assert.ok(slowSeen >= 1, "慢消费回调超过 idleTimeoutMs 时不得误报 stream_idle_timeout");
    } finally {
      bridge.stop();
      await gwService.stop();
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

      // 2b) 客户端已关闭发送（readback_only）：没有 created 记录时拒绝新发送
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "关掉开关后不应发出", cid: "cid-readback-only-1", readback_only: true }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "reply_disabled" && e.permanent === true,
      );
      // 2c) 客户端名称规则按实时会话名（“架构评审群”）核对，命中即拒绝
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "客户端规则命中", cid: "cid-client-deny-1", client_deny: ["评审"] }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "chat_denied" && e.permanent === true,
      );
      assert.equal(mockFeishu.getSendCount(), 1, "readback_only 与客户端排除规则都不能发包");

      // 2d) 事件库实例标识稳定，续拉游标覆盖被过滤的事件
      const st1 = await client.status();
      const st2 = await client.status();
      assert.ok(st1.db_epoch && st1.db_epoch === st2.db_epoch);
      assert.equal(gwStore.listEvents(0, 10).next_after, 0, "空库时 next_after 保持原游标");

      // 3) Reusing same cid with different text or different message_id -> permanent 409 cid_mismatch
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "改成周五上线", cid: "cid-reply-0001" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "cid_mismatch" && e.permanent === true,
      );
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-other", text: "收到，周四上线", cid: "cid-reply-0001" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "cid_mismatch" && e.permanent === true,
      );

      // 3b) expected_owner_id mismatch -> permanent 409 account_mismatch
      await assert.rejects(
        client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "新回复", cid: "cid-owner-mismatch", expected_owner_id: "99999" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "account_mismatch" && e.permanent === true,
      );

      // 4) Gateway deny_chats blocks reply with permanent 403 chat_denied
      await assert.rejects(
        client.sendReply({ chat_id: "chat-secret", message_id: "orig-100", text: "不允许发", cid: "cid-reply-denied-1" }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "chat_denied" && e.permanent === true,
      );

      // 5) Ambiguous sending record -> permanent 409 ambiguous_delivery; concurrent in-flight cid -> retryable 409 delivery_in_flight
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
      (gwService as unknown as { inFlightCids: Set<string> }).inFlightCids.add("cid-ambiguous-01");
      try {
        await assert.rejects(
          client.sendReply({ chat_id: "chat-alpha", message_id: "orig-100", text: "收到，周四上线", cid: "cid-ambiguous-01" }),
          (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 409 && e.code === "delivery_in_flight" && e.permanent === false,
        );
      } finally {
        (gwService as unknown as { inFlightCids: Set<string> }).inFlightCids.delete("cid-ambiguous-01");
      }
      assert.equal(mockFeishu.getSendCount(), 1);

      // 6) Created (readback-only) completes verification even after allow_reply is turned back to false
      const prevSendCount = mockFeishu.getSendCount();
      gwCfg.allow_reply = false;
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
      assert.equal(gwStore.getDelivery("cid-reply-0001")?.status, "verified", "回读恢复后必须落库为 verified");
      assert.equal(mockFeishu.getSendCount(), prevSendCount, "created 状态回读恢复绝不二次发包，即使 allow_reply=false 也可完成核验");

      // 6b) 查会话名失败且没有缓存名：即使网关没有命中的排除规则也不确认（客户端可能有按名称的规则）
      const failingClient = {
        owner: () => ({ id: "10001", name: "Owner" }),
        readChat: async () => {
          throw new Error("readChat timeout");
        },
      } as unknown as Parameters<FeishuGatewayService["handleMessage"]>[1];
      const unnamed = makeWebMsg({ id: "msg-unnamed-1", conversationId: "chat-unnamed", text: "@Owner 帮忙看下" });
      const prevDeny = gwCfg.deny_chats;
      gwCfg.deny_chats = [];
      try {
        await assert.rejects(gwService.handleMessage(unnamed, failingClient), /无缓存名称/, "网关没有排除规则时也不能在无名称的情况下放行");
        gwStore.upsertChat("chat-unnamed", "临时项目群");
        const ev = await gwService.handleMessage(unnamed, failingClient);
        assert.equal(ev?.kind === "message" ? ev.message.chatName : "", "临时项目群", "有缓存名时用缓存名下发");
      } finally {
        gwCfg.deny_chats = prevDeny;
      }
      const page = gwStore.listEvents(0, 1);
      assert.equal(page.next_after, page.events[0]?.seq);

      // 7) Live start()/stop() graceful shutdown completes cleanly before store.close()
      gwService.start();
      const waitLive = Date.now() + 3_000;
      while (gwService.status().state !== "listening" && Date.now() < waitLive) await new Promise((r) => setTimeout(r, 20));
      assert.equal(gwService.status().state, "listening");
      // Also test POST /v1/context on live connected gateway (allowed chat + denied chat)
      const ctxResp = await client.readContext({
        anchor: { id: "msg-trigger-11", conversationId: "chat-alpha", rootId: "", parentId: "", threadId: "", position: 11, createdAtMs: Date.now() },
        limit: 5,
      });
      assert.equal(ctxResp.owner_id, "10001");
      assert.ok(ctxResp.messages.some((m) => m.id === "orig-100"));
      await assert.rejects(
        client.readContext({
          anchor: { id: "msg-trigger-11", conversationId: "chat-secret", rootId: "", parentId: "", threadId: "", position: 11, createdAtMs: Date.now() },
        }),
        (e: unknown) => e instanceof GatewayHttpError && e.statusCode === 403 && e.code === "chat_denied",
      );
    } finally {
      await gwService.stop();
      await gwServer.stop();
      gwStore.close();
      await mockFeishu.close();
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
