import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";
import {
  BinaryWebSocket,
  CMD_READ_MESSAGE,
  decodeFrame,
  decodeMessage,
  decodeRichText,
  defaultCookiePath,
  encodeAckFrame,
  encodeFrame,
  encodePacket,
  encodeReplyPacket,
  encodeRichText,
  encodeQrMatrix,
  fetchWithJar,
  GatewayError,
  hasSessionCookie,
  isAllowedFeishuHost,
  parseProto,
  ProtoWireError,
  ProtoWriter,
  RecordingCookieJar,
  renderQrSvg,
  renderQrTerminal,
  unwrapGatewayPayload,
  WebHttpError,
  WebLoginStore,
} from "../src/context/feishu-web/index.ts";

function makeTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe("feishu-web QR code (qrcode library)", () => {
  it("encodes Feishu QR login payloads and renders theme-independent terminal ANSI + SVG", () => {
    const payload = JSON.stringify({ qrlogin: { token: "feishu-test-token-123456" } });
    const m = encodeQrMatrix(payload);
    assert.ok(m.size >= 21 && m.size % 4 === 1);
    assert.equal(m.modules.length, m.size * m.size);
    // Top-left 7x7 finder border is dark
    for (let i = 0; i < 7; i++) {
      assert.equal(m.modules[i], 1);
      assert.equal(m.modules[i * m.size], 1);
    }

    const term = renderQrTerminal(payload);
    assert.ok(term.includes("\x1b[30;47m"), "terminal QR uses explicit black-on-white ANSI");
    assert.ok(term.includes("\x1b[0m"));
    assert.ok(/[█▀▄]/.test(term));

    const svg = renderQrSvg(payload);
    assert.ok(svg.startsWith("<?xml version=\"1.0\""));
    assert.ok(svg.includes("<svg ") && svg.includes("<rect "));
  });

  it("supports long payloads > 213 bytes (ISO/IEC 18004 Versions > 10)", () => {
    const longText = "https://accounts.feishu.cn/qrlogin?" + "a".repeat(320);
    const m = encodeQrMatrix(longText);
    assert.ok(m.size > 57, `expected Version > 10 matrix size > 57, got ${m.size}`);
  });
});

describe("feishu-web cookies & encrypted WebLoginStore (tough-cookie)", () => {
  it("enforces Feishu allowlist, PSL rejection, RFC 6265 default-path & longest-path-first sorting", () => {
    assert.equal(defaultCookiePath("/accounts/qrlogin/polling"), "/accounts/qrlogin");
    assert.equal(defaultCookiePath("/single"), "/");
    assert.equal(isAllowedFeishuHost("accounts.feishu.cn"), true);
    assert.equal(isAllowedFeishuHost("open.larkoffice.com"), true);
    assert.equal(isAllowedFeishuHost("evilfeishu.cn"), false);

    const jar = new RecordingCookieJar();
    const t0 = Date.UTC(2026, 5, 1, 0, 0, 0);
    jar.setFromHeaders(
      new URL("https://accounts.feishu.cn/accounts/qrlogin/polling"),
      [
        "session=sess_1; Domain=.feishu.cn; Path=/; HttpOnly; Max-Age=60",
        "swp_csrf_token=root_csrf; Domain=.feishu.cn; Path=/",
        "evil_psl=1; Domain=cn; Path=/",
        "evil_other=1; Domain=attacker.com; Path=/",
      ],
      t0,
    );
    jar.setFromHeaders(
      new URL("https://internal-api-lark-api.feishu.cn/im/gateway/"),
      [
        "swp_csrf_token=im_csrf; Domain=.feishu.cn; Path=/im",
        "host_scoped=v1; Secure",
      ],
      t0,
    );

    const gwUrl = new URL("https://internal-api-lark-api.feishu.cn/im/gateway/");
    assert.equal(jar.cookieValue(gwUrl, "swp_csrf_token", t0 + 1000), "im_csrf", "longest path wins");
    assert.equal(jar.cookieValue(gwUrl, "session", t0 + 1000), "sess_1");
    assert.equal(jar.cookieValue(gwUrl, "host_scoped", t0 + 1000), "v1");
    assert.equal(jar.cookieValue(gwUrl, "evil_psl", t0 + 1000), "");
    assert.equal(jar.cookieValue(gwUrl, "evil_other", t0 + 1000), "");

    // Secure cookie must not be sent over non-local HTTP
    assert.equal(jar.cookieValue(new URL("http://internal-api-lark-api.feishu.cn/im/gateway/"), "host_scoped", t0 + 1000), "");

    // Expiry via Max-Age=60
    assert.equal(jar.cookieValue(gwUrl, "session", t0 + 61_000), "");

    // Deletion via Max-Age=0
    jar.setFromHeaders(gwUrl, "swp_csrf_token=; Domain=.feishu.cn; Path=/im; Max-Age=0", t0 + 2000);
    assert.equal(jar.cookieValue(gwUrl, "swp_csrf_token", t0 + 2000), "root_csrf");
    assert.equal(hasSessionCookie(jar.records(t0 + 1000)), true);
  });

  it("stages redirect cookies and discards them on 401/403 responses", async () => {
    const srv = http.createServer((req, res) => {
      if (req.url === "/step1") {
        res.writeHead(302, {
          Location: "/step2",
          "Set-Cookie": "session=rotated_bad; Path=/",
        });
        res.end();
        return;
      }
      if (req.url === "/step2") {
        res.writeHead(401, { "Set-Cookie": "swp_csrf_token=denied_csrf; Path=/" });
        res.end("unauthorized");
        return;
      }
      if (req.url === "/ok") {
        res.writeHead(200, { "Set-Cookie": "session=rotated_good; Path=/" });
        res.end("ok");
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    try {
      const jar = RecordingCookieJar.fromRecords(
        [{ name: "session", value: "orig", domain: "127.0.0.1", path: "/", host_only: true }],
        ["127.0.0.1"],
      );
      const denied = await fetchWithJar(jar, {
        method: "GET",
        url: `http://127.0.0.1:${port}/step1`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(denied.status, 401);
      assert.equal(denied.cookiesUpdated, false);
      assert.equal(jar.cookieValue(new URL(`http://127.0.0.1:${port}/`), "session"), "orig", "401 must not mutate jar");

      const ok = await fetchWithJar(jar, {
        method: "GET",
        url: `http://127.0.0.1:${port}/ok`,
        allowInsecureHttp: true,
        extraAllowedHosts: ["127.0.0.1"],
      });
      assert.equal(ok.status, 200);
      assert.equal(ok.cookiesUpdated, true);
      assert.equal(jar.cookieValue(new URL(`http://127.0.0.1:${port}/`), "session"), "rotated_good");
    } finally {
      srv.close();
    }
  });

  it("encrypts credentials with AES-256-GCM (0600), rejects plaintext, and guards session_id on saveIfSessionMatches", () => {
    const dir = makeTmp("pa-pw-store-");
    const prevKey = process.env.PA_FEISHU_WEB_KEY;
    const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
    try {
      delete process.env.PA_FEISHU_WEB_KEY;
      delete process.env.CREDENTIALS_DIRECTORY;

      const store = new WebLoginStore(dir);
      assert.equal(WebLoginStore.hasEncryptionKey(), false);
      assert.throws(
        () => store.save({ owner_id: "1001", owner_name: "Alice", cookies: [] }),
        /PA_FEISHU_WEB_KEY/,
      );

      process.env.PA_FEISHU_WEB_KEY = "unit-test-secret-key-2026";
      const saved = store.save({
        owner_id: "1001",
        owner_name: "Alice",
        cookies: [{ name: "session", value: "super-secret-cookie", domain: "feishu.cn", path: "/" }],
      });
      assert.ok(saved.session_id);

      const rawText = fs.readFileSync(store.file, "utf8");
      assert.ok(!rawText.includes("super-secret-cookie"), "disk file must not contain plaintext cookie");
      assert.equal(fs.statSync(store.file).mode & 0o777, 0o600);

      const loaded = store.load();
      assert.equal(loaded?.owner_id, "1001");
      assert.equal(loaded?.cookies[0]?.value, "super-secret-cookie");

      // Missing key reports missing_key
      delete process.env.PA_FEISHU_WEB_KEY;
      assert.equal(store.inspect().status, "missing_key");

      // Plaintext file rejected
      process.env.PA_FEISHU_WEB_KEY = "unit-test-secret-key-2026";
      fs.writeFileSync(store.file, JSON.stringify({ owner_id: "1001", cookies: [] }), "utf8");
      assert.equal(store.inspect().status, "plaintext_rejected");

      // Session guard: saveIfSessionMatches updates same session, refuses after logout or re-login
      const s1 = store.save({ owner_id: "1001", owner_name: "Alice", cookies: [{ name: "session", value: "v1", domain: "feishu.cn", path: "/" }] });
      const updated = store.saveIfSessionMatches({ ...s1, cookies: [{ name: "session", value: "v2", domain: "feishu.cn", path: "/" }] });
      assert.equal(updated?.cookies[0]?.value, "v2");

      // Re-login with new session_id -> old session save rejected
      const s2 = store.save({ owner_id: "1001", owner_name: "Alice", cookies: [{ name: "session", value: "v3", domain: "feishu.cn", path: "/" }] });
      assert.notEqual(s2.session_id, s1.session_id);
      assert.equal(store.saveIfSessionMatches({ ...s1, cookies: [{ name: "session", value: "stale", domain: "feishu.cn", path: "/" }] }), null);
      assert.equal(store.load()?.cookies[0]?.value, "v3");

      // Logout -> saveIfSessionMatches returns null and does not recreate file
      store.clear();
      assert.equal(store.saveIfSessionMatches(s2), null);
      assert.equal(store.exists(), false);
    } finally {
      if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
      else process.env.PA_FEISHU_WEB_KEY = prevKey;
      if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
      else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("feishu-web BinaryWebSocket (ws library)", () => {
  it("passes custom headers, handles binary/ping/pong/read-idle reset, 401 denial, and maxFrameBytes", async () => {
    const srv = http.createServer();
    const wss = new WebSocketServer({ noServer: true });
    let capturedOrigin = "";
    let capturedUa = "";
    let serverGotPong = "";

    srv.on("upgrade", (req, socket, head) => {
      if (req.url === "/deny") {
        socket.write("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        socket.destroy();
        return;
      }
      capturedOrigin = String(req.headers.origin ?? "");
      capturedUa = String(req.headers["user-agent"] ?? "");
      wss.handleUpgrade(req, socket, head, (client) => {
        if (req.url === "/oversize") {
          client.send(Buffer.alloc(256, 0x58), { binary: true });
          return;
        }
        client.on("pong", (p) => {
          serverGotPong = p.toString("utf8");
        });
        client.ping(Buffer.from("hb"));
        client.on("message", (data, isBin) => {
          if (isBin) {
            client.send(Buffer.concat([Buffer.from("ack:"), data as Buffer]), { binary: true });
          }
        });
      });
    });

    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;

    try {
      // 1) 401 classified as credential_denied
      await assert.rejects(
        () => BinaryWebSocket.dial(`ws://127.0.0.1:${port}/deny`),
        (err: unknown) => err instanceof WebHttpError && err.code === "credential_denied" && err.status === 401,
      );

      // 2) Normal binary echo + headers + auto-Pong
      const ws = await BinaryWebSocket.dial(`ws://127.0.0.1:${port}/ws`, {
        headers: { Origin: "https://open-dev.feishu.cn", "User-Agent": "AvatarTest/1.0" },
      });
      assert.equal(capturedOrigin, "https://open-dev.feishu.cn");
      assert.equal(capturedUa, "AvatarTest/1.0");
      await ws.writeBinary(Buffer.from("ping-payload"));
      const frame = await ws.read(3000);
      assert.equal(frame.kind, "binary");
      assert.equal(frame.data.toString("utf8"), "ack:ping-payload");
      assert.equal(serverGotPong, "hb");
      ws.close();

      // 3) maxFrameBytes enforced via ws maxPayload
      const limited = await BinaryWebSocket.dial(`ws://127.0.0.1:${port}/oversize`, { maxFrameBytes: 64 });
      await assert.rejects(() => limited.read(3000), /Max payload|关闭|error/i);
      limited.close();
    } finally {
      wss.close();
      srv.close();
    }
  });
});

describe("feishu-web protobuf & wire codec", () => {
  it("validates varint overflow, gateway envelopes, gzip frames, rich text, and reply parentId", () => {
    // 10th varint byte > 1 overflows uint64
    const badVarint = Buffer.from([0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
    assert.throws(() => parseProto(badVarint), ProtoWireError);

    // Gateway envelope checks
    const validEmpty = encodePacket(CMD_READ_MESSAGE, Buffer.alloc(0), "cid-1");
    assert.equal(unwrapGatewayPayload(validEmpty, { allowEmptyPayload: true, expectedCommand: CMD_READ_MESSAGE, expectedCid: "cid-1" }).length, 0);
    assert.throws(() => unwrapGatewayPayload(validEmpty, { allowEmptyPayload: false }), GatewayError);
    // Arbitrary protobuf lacking valid Packet header must be rejected even with allowEmptyPayload
    const bogusProto = new ProtoWriter().str(99, "not-a-packet").finish();
    assert.throws(() => unwrapGatewayPayload(bogusProto, { allowEmptyPayload: true }), GatewayError);

    // Frame gzip roundtrip + ACK
    const inner = encodePacket(CMD_READ_MESSAGE, Buffer.from("hello"), "cid-2");
    const decoded = decodeFrame(encodeFrame(inner, 1_700_000_000_000));
    assert.equal(decoded.uint(3), CMD_READ_MESSAGE);
    assert.equal(decoded.bytes(5).toString("utf8"), "hello");
    const ack = decodeFrame(encodeAckFrame("sid-42", 1_700_000_000_000));
    assert.equal(ack.str(1), "sid-42");

    // Rich text & reply packet preserving distinct rootId and parentId
    const rich = encodeRichText([{ text: "收到，马上处理" }]);
    assert.equal(decodeRichText(rich).text, "收到，马上处理");
    const replyPkt = encodeReplyPacket("chat-1", "root-1", "cid-r1", [{ text: "好的" }], true, "parent-2");
    const pktFields = parseProto(replyPkt);
    const reqFields = parseProto(pktFields.bytes(5));
    assert.equal(reqFields.str(3), "chat-1");
    assert.equal(reqFields.str(4), "root-1");
    assert.equal(reqFields.str(5), "parent-2");
    assert.equal(reqFields.str(6), "cid-r1");
    assert.equal(reqFields.uint(12), 1);

    // Message decoding with mention of owner
    const richBuf = encodeRichText([{ text: "@我", mentionId: "7001" }, { text: " 看下这个问题" }]);
    const msgBuf = new ProtoWriter()
      .str(1, "msg-99")
      .uint(2, 4)
      .str(3, "actor-2")
      .uint(4, 1_700_000_000)
      .bytes(5, new ProtoWriter().bytes(3, richBuf).finish())
      .uint(7, 1)
      .str(10, "chat-9")
      .uint(13, 12)
      .uint(46, 2)
      .finish();
    const decodedMsg = decodeMessage(msgBuf, "7001");
    assert.equal(decodedMsg.id, "msg-99");
    assert.equal(decodedMsg.conversationKind, "group");
    assert.equal(decodedMsg.mentions.length, 1);
    assert.equal(decodedMsg.mentions[0]?.id, "7001");
    assert.ok(decodedMsg.text.includes("看下这个问题"));
  });
});
