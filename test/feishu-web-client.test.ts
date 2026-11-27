import assert from "node:assert/strict";
import http from "node:http";
import { describe, it } from "node:test";
import { WebSocketServer, type WebSocket as WsSocket } from "ws";
import {
  beginLogin,
  CHAT_KIND_GROUP,
  CHAT_MODE_TOPIC,
  CMD_CHAT_MODE,
  CMD_HISTORY,
  CMD_PUSH_PACKET,
  CMD_READ_MESSAGE,
  CMD_SEND_MESSAGE,
  decodeFrame,
  decodeRichText,
  encodeFrame,
  encodePacket,
  encodeRichText,
  FeishuWebClient,
  MessageNotFoundError,
  parseProto,
  pollLogin,
  ProtoWriter,
  SessionNeedsLoginError,
  UnusableOriginalMessageError,
  type WebEndpoints,
  type WebLogin,
  type WebMessage,
} from "../src/context/feishu-web/index.ts";

function buildMessageBytes(opts: {
  id: string;
  chatId: string;
  actorId: string;
  text: string;
  chatKind?: number;
  rootId?: string;
  parentId?: string;
  threadId?: string;
  cid?: string;
  position?: number;
  createdAtSec?: number;
  mentionOwnerId?: string;
  msgType?: number;
}): Buffer {
  const richContent = opts.mentionOwnerId
    ? encodeRichText([{ text: "@我", mentionId: opts.mentionOwnerId }, { text: opts.text }])
    : encodeRichText([{ text: opts.text }]);

  const w = new ProtoWriter()
    .str(1, opts.id)
    .uint(2, opts.msgType ?? 4)
    .str(3, opts.actorId)
    .uint(4, opts.createdAtSec ?? Math.floor(Date.now() / 1000))
    .bytes(5, new ProtoWriter().bytes(3, richContent).finish())
    .uint(7, 1) // USER_SENDER_TYPE
    .str(10, opts.chatId)
    .uint(13, opts.position ?? 10)
    .uint(46, opts.chatKind ?? CHAT_KIND_GROUP);
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

interface MockServer {
  endpoints: WebEndpoints;
  messages: Map<string, Buffer>;
  chats: Map<string, Buffer>;
  wsClients: Set<WsSocket>;
  acks: string[];
  setPollSequence: (seq: { status?: number; headers?: Record<string, string>; body: string }[]) => void;
  setProfileStatus: (status: number) => void;
  rotateCookieOnNextProfile: (cookie: string) => void;
  pushMessage: (sid: string, msgId: string, msgBytes: Buffer) => void;
  close: () => Promise<void>;
}

async function startMockFeishu(): Promise<MockServer> {
  const OWNER_ID = "7123456789012345678"; // > Number.MAX_SAFE_INTEGER to verify lossless 64-bit parsing
  const messages = new Map<string, Buffer>();
  const chats = new Map<string, Buffer>();
  const wsClients = new Set<WsSocket>();
  const acks: string[] = [];
  let pollSeq: { status?: number; headers?: Record<string, string>; body: string }[] = [];
  let profileStatus = 200;
  let nextProfileCookie = "";
  let replySeq = 1;

  const srv = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    const body = Buffer.concat(chunks);
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (url.pathname === "/messenger/") {
      res.writeHead(200, {
        "Content-Type": "text/html",
        "Set-Cookie": ["passport_web_did=did-100; Path=/", "swp_csrf_token=csrf-1; Path=/"],
      });
      res.end(`<script>window.passport_web_did="did-100"; var cfg={appKey:"app-key-1"};</script>`);
      return;
    }

    if (url.pathname === "/accounts/qrlogin/init") {
      res.writeHead(200, { "Content-Type": "application/json", "X-Flow-Key": "flow-1" });
      res.end(JSON.stringify({ code: 0, data: { step_info: { token: "tok-qr-1" } } }));
      return;
    }

    if (url.pathname === "/accounts/qrlogin/polling") {
      const next = pollSeq.shift() ?? {
        status: 200,
        headers: { "Set-Cookie": "session=sess-live-1; Path=/" },
        body: `{"code":0,"data":{"next_step":"enter_app","step_info":{"status":0,"front_user_id":${OWNER_ID}}}}`,
      };
      res.writeHead(next.status ?? 200, { "Content-Type": "application/json", ...(next.headers ?? {}) });
      res.end(next.body);
      return;
    }

    if (url.pathname === "/accounts/web/user") {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (nextProfileCookie) {
        headers["Set-Cookie"] = nextProfileCookie;
        nextProfileCookie = "";
      }
      if (profileStatus !== 200) {
        res.writeHead(profileStatus, headers);
        res.end("denied");
        return;
      }
      res.writeHead(200, headers);
      res.end(`{"code":0,"data":{"user":{"id":${OWNER_ID},"name":"李测试","open_id":"ou_owner"}}}`);
      return;
    }

    if (url.pathname === "/suite/passport/frontier_ticket/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ code: 0, ticket: "ticket-xyz" }));
      return;
    }

    if (url.pathname === "/im/gateway/") {
      const pkt = parseProto(body);
      const cmd = pkt.uint(3);
      const payload = pkt.bytes(5);
      const cid = pkt.str(6);

      if (cmd === CMD_READ_MESSAGE) {
        const reqFields = parseProto(payload);
        const id = reqFields.str(1);
        const found = messages.get(id);
        const respPayload = found ? new ProtoWriter().bytes(1, mapEntry(id, found)).finish() : Buffer.alloc(0);
        res.writeHead(200, { "Content-Type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }

      if (cmd === CMD_CHAT_MODE) {
        const chatId = parseProto(payload).str(1);
        const found = chats.get(chatId);
        const respPayload = found ? new ProtoWriter().bytes(1, mapEntry(chatId, found)).finish() : Buffer.alloc(0);
        res.writeHead(200, { "Content-Type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }

      if (cmd === CMD_HISTORY) {
        const out = new ProtoWriter();
        for (const [id, buf] of messages) out.bytes(1, mapEntry(id, buf));
        res.writeHead(200, { "Content-Type": "application/x-protobuf" });
        res.end(encodePacket(cmd, out.finish(), cid));
        return;
      }

      if (cmd === CMD_SEND_MESSAGE) {
        const reqFields = parseProto(payload);
        const chatId = reqFields.str(3);
        const rootId = reqFields.str(4);
        const parentId = reqFields.str(5);
        const msgCid = reqFields.str(6);
        const inThread = reqFields.uint(12) === 1;
        const contentFields = parseProto(reqFields.bytes(2));
        const sentText = decodeRichText(contentFields.bytes(14)).text;
        const replyId = `reply-${replySeq++}`;
        const replyBuf = buildMessageBytes({
          id: replyId,
          chatId,
          actorId: OWNER_ID,
          text: sentText,
          rootId,
          parentId,
          threadId: inThread || chats.has(chatId) ? `th-${rootId}` : "",
          cid: msgCid,
          position: 99,
        });
        messages.set(replyId, replyBuf);
        const respPayload = new ProtoWriter().bytes(1, replyBuf).finish();
        res.writeHead(200, { "Content-Type": "application/x-protobuf" });
        res.end(encodePacket(cmd, respPayload, cid));
        return;
      }
    }

    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({ noServer: true });
  srv.on("upgrade", (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wsClients.add(ws);
      ws.on("close", () => wsClients.delete(ws));
      ws.on("message", (raw, isBin) => {
        if (!isBin) return;
        const pkt = decodeFrame(Buffer.from(raw as Buffer));
        const sid = pkt.str(1);
        if (sid) acks.push(sid);
      });
    });
  });

  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  const endpoints: WebEndpoints = {
    messengerUrl: `${base}/messenger/`,
    qrInitUrl: `${base}/accounts/qrlogin/init`,
    qrPollUrl: `${base}/accounts/qrlogin/polling`,
    qrRedirectUri: `${base}/next/messenger`,
    profileUrl: `${base}/accounts/web/user?app_id=12`,
    gatewayUrl: `${base}/im/gateway/`,
    ticketUrl: `${base}/suite/passport/frontier_ticket/`,
    websocketUrl: `ws://127.0.0.1:${port}/ws/v2`,
    accountsOrigin: base,
    accountsReferer: `${base}/accounts/page/login`,
    messengerOrigin: base,
    allowInsecureHttp: true,
    extraAllowedHosts: ["127.0.0.1"],
  };

  return {
    endpoints,
    messages,
    chats,
    wsClients,
    acks,
    setPollSequence: (seq) => {
      pollSeq = [...seq];
    },
    setProfileStatus: (s) => {
      profileStatus = s;
    },
    rotateCookieOnNextProfile: (c) => {
      nextProfileCookie = c;
    },
    pushMessage: (sid, msgId, msgBytes) => {
      const pushPayload = new ProtoWriter().bytes(1, mapEntry(msgId, msgBytes)).finish();
      const pkt = new ProtoWriter().str(1, sid).uint(2, 1).uint(3, CMD_PUSH_PACKET).bytes(5, pushPayload).finish();
      const frame = encodeFrame(pkt);
      for (const ws of wsClients) ws.send(frame, { binary: true });
    },
    close: async () => {
      for (const ws of wsClients) ws.terminate();
      wss.close();
      await new Promise<void>((r) => srv.close(() => r()));
    },
  };
}

describe("feishu-web client end-to-end (mock Feishu HTTP + ws server)", () => {
  it("completes QR login with lossless 64-bit native ID and handles Retry-After on 429", async () => {
    const mock = await startMockFeishu();
    try {
      const challenge = await beginLogin({ endpoints: mock.endpoints });
      assert.equal(challenge.webId, "did-100");
      assert.equal(challenge.flowKey, "flow-1");
      assert.ok(challenge.qrCode.includes("tok-qr-1"));

      mock.setPollSequence([
        { status: 429, headers: { "Retry-After": "0" }, body: "rate limited" },
        { status: 200, body: JSON.stringify({ code: 0, data: { next_step: "qr_login_polling", step_info: { status: 2 } } }) },
        {
          status: 200,
          headers: { "Set-Cookie": "session=sess-live-1; Path=/" },
          body: `{"code":0,"data":{"next_step":"enter_app","step_info":{"status":0,"front_user_id":7123456789012345678}}}`,
        },
      ]);

      const seenStates: string[] = [];
      const login = await pollLogin(challenge, {
        endpoints: mock.endpoints,
        pollIntervalMs: 10,
        onProgress: (s) => seenStates.push(s),
      });
      assert.deepEqual(seenStates, ["scanned", "approved"]);
      assert.equal(login.owner_id, "7123456789012345678", "64-bit ID must not lose precision");
      assert.equal(login.owner_open_id, "ou_owner");
      assert.ok(login.session_id);
      assert.ok(login.cookies.some((c) => c.name === "session" && c.value === "sess-live-1"));
    } finally {
      await mock.close();
    }
  });

  it("persists rotated cookies, enforces backpressure ACK, and verifies replies via independent readback", async () => {
    const mock = await startMockFeishu();
    try {
      const challenge = await beginLogin({ endpoints: mock.endpoints });
      const login = await pollLogin(challenge, { endpoints: mock.endpoints, pollIntervalMs: 10 });

      // Connect & confirm rotated cookie callback fires
      mock.rotateCookieOnNextProfile("session=sess-rotated-2; Path=/");
      let persisted: WebLogin | undefined;
      const client = await FeishuWebClient.connect(login, {
        endpoints: mock.endpoints,
        heartbeatIntervalMs: 60_000,
        keepaliveIntervalMs: 60_000,
        reconnectBaseMs: 20,
        sessionDenialRetryMs: 20,
        onSessionConfirmed: (updated) => {
          persisted = updated;
          return updated;
        },
      });
      assert.ok(persisted?.cookies.some((c) => c.name === "session" && c.value === "sess-rotated-2"));

      // Seed chat and original @me message
      mock.chats.set("chat-100", buildChatBytes("chat-100", "核心研发群"));
      mock.messages.set(
        "msg-orig-1",
        buildMessageBytes({
          id: "msg-orig-1",
          chatId: "chat-100",
          actorId: "8888",
          text: " 请今天确认方案",
          mentionOwnerId: login.owner_id,
          position: 20,
        }),
      );
      mock.messages.set(
        "msg-bg-1",
        buildMessageBytes({
          id: "msg-bg-1",
          chatId: "chat-100",
          actorId: "9999",
          text: "先前的讨论背景",
          position: 19,
          createdAtSec: Math.floor(Date.now() / 1000) - 60,
        }),
      );

      // readContext fetches earlier history
      const hist = await client.readContext({
        id: "msg-orig-1",
        conversationId: "chat-100",
        rootId: "",
        parentId: "",
        threadId: "",
        position: 20,
        createdAtMs: Date.now(),
      });
      assert.equal(hist.length, 1);
      assert.equal(hist[0]?.id, "msg-bg-1");

      // sendVerifiedReply succeeds and passes independent readback
      const reply = await client.sendVerifiedReply({
        chatId: "chat-100",
        messageId: "msg-orig-1",
        text: "收到，下午前发结论。",
        cid: "cid-fixed-1",
        requireMentionOwnerId: login.owner_id,
      });
      assert.equal(reply.verified, true);
      assert.equal(reply.rootId, "msg-orig-1");
      assert.equal(reply.parentId, "msg-orig-1");

      // Missing message fails with MessageNotFoundError before sending
      await assert.rejects(
        () => client.sendVerifiedReply({ chatId: "chat-100", messageId: "msg-missing", text: "hi", cid: "cid-m" }),
        MessageNotFoundError,
      );

      // Recalled/empty message fails with UnusableOriginalMessageError
      mock.messages.set(
        "msg-empty",
        buildMessageBytes({ id: "msg-empty", chatId: "chat-100", actorId: "8888", text: "   ", msgType: 99 }),
      );
      await assert.rejects(
        () => client.sendVerifiedReply({ chatId: "chat-100", messageId: "msg-empty", text: "hi", cid: "cid-e" }),
        UnusableOriginalMessageError,
      );

      // Listener backpressure ACK: first push throws -> NO ACK; second push succeeds -> ACK sent
      const ctrl = new AbortController();
      const received: WebMessage[] = [];
      let failOnce = true;
      const states: string[] = [];

      const listenPromise = client.listen({
        signal: ctrl.signal,
        onState: (s) => {
          states.push(s);
          if (s === "listening" && received.length === 0) {
            mock.pushMessage("sid-no-ack", "msg-push-1", buildMessageBytes({ id: "msg-push-1", chatId: "chat-100", actorId: "8888", text: "第一条" }));
            setTimeout(() => {
              mock.pushMessage("sid-ack-ok", "msg-push-2", buildMessageBytes({ id: "msg-push-2", chatId: "chat-100", actorId: "8888", text: "第二条" }));
            }, 30);
          }
        },
        onMessage: async (m) => {
          if (failOnce && m.id === "msg-push-1") {
            failOnce = false;
            throw new Error("simulated sqlite busy");
          }
          received.push(m);
          if (m.id === "msg-push-2") {
            setTimeout(() => ctrl.abort(), 30);
          }
        },
      });
      await listenPromise;
      assert.ok(states.includes("publication_blocked"), "failed persistence enters publication_blocked");
      assert.equal(mock.acks.includes("sid-no-ack"), false, "failed push must NOT be ACKed");
      assert.equal(mock.acks.includes("sid-ack-ok"), true, "succeeded push MUST be ACKed");

      // 3 consecutive 401 denials escalate to SessionNeedsLoginError
      mock.setProfileStatus(401);
      await assert.rejects(
        () =>
          client.listen({
            signal: new AbortController().signal,
            onMessage: () => undefined,
          }),
        SessionNeedsLoginError,
      );
    } finally {
      await mock.close();
    }
  });
});
