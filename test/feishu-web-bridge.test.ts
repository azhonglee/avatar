import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import YAML from "yaml";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { ContextService } from "../src/context/index.ts";
import { legacyPersonalWebArtifacts, verifyGatewayOwnerForWorkspace } from "../src/context/personal-web.ts";
import { runDoctor } from "../src/doctor.ts";
import { EventSupervisor } from "../src/events.ts";
import { FeishuGatewayClient } from "../src/gateway/client.ts";
import { loadGatewayConfig } from "../src/gateway/config.ts";
import { GATEWAY_USER_SENDER_TYPE, type GatewayMessagePayload } from "../src/gateway/protocol.ts";
import { startGatewayServer } from "../src/gateway/server.ts";
import { FeishuGatewayService } from "../src/gateway/service.ts";
import { GatewayStore } from "../src/gateway/store.ts";
import { scrubPersonalWebEnv } from "../src/harness.ts";

function makeTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function makeApp(dir: string, overrides: Record<string, unknown> = {}) {
  const cfgPath = path.join(dir, "config.yaml");
  const defaultSock = path.join(dir, "gw.sock");
  fs.writeFileSync(
    cfgPath,
    YAML.stringify({
      data_dir: dir,
      owner: { open_id: "ou_owner" },
      cards: { enabled: false },
      harnesses: {
        brain: { type: "acpx", agent: "claude" },
      },
      roles: {
        brain: "brain",
        worker: "brain",
        reviewer: "brain",
      },
      context: {
        enabled: true,
        understand: true,
        groups: "spoken",
        groups_deny: ["敏感群", "chat-denied"],
        personal_web: {
          enabled: true,
          gateway_socket: defaultSock,
          read_token_env: "TEST_GW_READ_TOKEN",
          reply_token_env: "TEST_GW_REPLY_TOKEN",
          fast_lane: true,
          debounce_ms: 0,
          pre_draft: false,
          send_replies: true,
        },
        ...(overrides.context as Record<string, unknown> | undefined),
      },
    }),
  );
  return createApp(loadConfig(cfgPath));
}

function makeGatewayMsg(overrides: Partial<GatewayMessagePayload> = {}): GatewayMessagePayload {
  return {
    id: "70001",
    conversationId: "chat-1",
    conversationKind: "group",
    chatName: "核心研发群",
    actorId: "actor-2",
    senderType: GATEWAY_USER_SENDER_TYPE,
    text: "请帮我确认下发布时间",
    createdAtMs: Date.now(),
    rootId: "",
    parentId: "",
    threadId: "",
    position: 10,
    mentions: [{ id: "owner-1", name: "@我", start: 0, end: 2 }],
    resources: [],
    ownerId: "owner-1",
    ownerName: "Owner",
    ...overrides,
  };
}

describe("feishu-web gateway client bridge, store dedup, drafts, and env scrub", () => {
  it("scrubPersonalWebEnv strips gateway keys, tokens, and custom configured token envs", () => {
    const dir = makeTmp("pa-pw-scrub-");
    const app = makeApp(dir, {
      context: {
        personal_web: {
          enabled: true,
          gateway_socket: path.join(dir, "gw.sock"),
          read_token_env: "CUSTOM_GW_READ_SECRET",
          reply_token_env: "CUSTOM_GW_REPLY_SECRET",
        },
      },
    });
    try {
      const cleaned = scrubPersonalWebEnv({
        PATH: "/usr/bin",
        HOME: "/home/dev",
        PA_FEISHU_WEB_KEY: "secret-key",
        PA_FEISHU_WEB_CRED_FILE: "/tmp/cred.json",
        FEISHU_GW_KEY: "gw-key",
        FEISHU_GW_READ_TOKEN: "rt-1",
        FEISHU_GW_REPLY_TOKEN: "wt-1",
        CUSTOM_GW_READ_SECRET: "custom-read",
        CUSTOM_GW_REPLY_SECRET: "custom-reply",
        CREDENTIALS_DIRECTORY: "/run/credentials",
      });
      assert.equal(cleaned.PATH, "/usr/bin");
      assert.equal(cleaned.HOME, "/home/dev");
      assert.equal(cleaned.PA_FEISHU_WEB_KEY, undefined);
      assert.equal(cleaned.PA_FEISHU_WEB_CRED_FILE, undefined);
      assert.equal(cleaned.FEISHU_GW_KEY, undefined);
      assert.equal(cleaned.FEISHU_GW_READ_TOKEN, undefined);
      assert.equal(cleaned.FEISHU_GW_REPLY_TOKEN, undefined);
      assert.equal(cleaned.CUSTOM_GW_READ_SECRET, undefined);
      assert.equal(cleaned.CUSTOM_GW_REPLY_SECRET, undefined);
      assert.equal(cleaned.CREDENTIALS_DIRECTORY, undefined);
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enforces groups_deny, mutedConvs, group scope, delete tombstone, and Fast Lane triggers", async () => {
    const dir = makeTmp("pa-pw-bridge-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const triggers: string[] = [];
      const bridge = svc.personalWeb;
      (bridge as unknown as { hooks: { onFastTrigger: (t: { trigger_obs_id: string }) => void } }).hooks.onFastTrigger = (t) =>
        triggers.push(t.trigger_obs_id);

      // 1) Denied chat ID dropped
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-denied", conversationId: "chat-denied" }));
      assert.equal(svc.store.obs("pw:m-denied"), undefined);

      // 2) Muted conv dropped
      svc.store.muteConv("pw_chat:chat-muted", "静音群", true);
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-muted", conversationId: "chat-muted", chatName: "静音群" }));
      assert.equal(svc.store.obs("pw:m-muted"), undefined);

      // 3) Unspoken group without @me ignored; after I speak, group is tracked
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-unspoken", conversationId: "chat-2", mentions: [] }));
      assert.equal(svc.store.obs("pw:m-unspoken"), undefined);
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-mine", conversationId: "chat-2", actorId: "owner-1", mentions: [], text: "我来跟进" }));
      assert.ok(svc.store.obs("pw:m-mine"));
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-after-spoken", conversationId: "chat-2", mentions: [], text: "好的谢谢" }));
      assert.ok(svc.store.obs("pw:m-after-spoken"));
      assert.equal(triggers.length, 0, "regular non-@me group message does not trigger fast lane");

      // 4) @me in group persists and triggers Fast Lane
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-atme", conversationId: "chat-1" }));
      assert.ok(svc.store.obs("pw:m-atme"));
      assert.deepEqual(triggers, ["pw:m-atme"]);

      // 5) Gateway delete tombstone event deletes existing local obs
      await bridge.handleGatewayEvent({ seq: 99, kind: "delete", message_id: "m-atme", chat_id: "chat-1", created_at: Date.now() });
      assert.equal(svc.store.obs("pw:m-atme"), undefined, "recalled message must be deleted locally");

      // 6) 网关未能核验会话名（chatNameResolved=false）且存在按名称排除规则：丢弃，不按“未命中”放行
      bridge.handleGatewayMessage(makeGatewayMsg({ id: "m-noname-unresolved", conversationId: "chat-1", chatName: "", chatNameResolved: false }));
      assert.equal(svc.store.obs("pw:m-noname-unresolved"), undefined, "unresolved missing chat name must not bypass name-based deny rules");

      // 7) 网关成功核验但飞书会话本身无名（如真实私聊 chatName="", chatNameResolved=true）：不得因存在 groups_deny 而误丢私聊
      bridge.handleGatewayMessage(
        makeGatewayMsg({ id: "m-dm-noname", conversationId: "dm-1", conversationKind: "dm", actorId: "actor-dm-1", chatName: "", chatNameResolved: true, mentions: [] }),
      );
      assert.ok(svc.store.obs("pw:m-dm-noname"), "resolved empty-name DM must be accepted even when name-based groups_deny exists");
      assert.ok(triggers.includes("pw:m-dm-noname"));

      // 8) 私聊无名但本地 pwAlias 已知对方为已静音联系人：仍必须拦截
      svc.store.setPwAlias("actor", "actor-muted-dm", "王五");
      svc.store.muteConv("oc_dm_ww", "私聊：王五", true);
      bridge.handleGatewayMessage(
        makeGatewayMsg({ id: "m-dm-muted-alias", conversationId: "dm-muted", conversationKind: "dm", actorId: "actor-muted-dm", chatName: "", chatNameResolved: true, mentions: [] }),
      );
      assert.equal(svc.store.obs("pw:m-dm-muted-alias"), undefined, "muted DM identified via actor alias must still be blocked");
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("sends readback_only and split client_deny/client_deny_exact rules, resets cursor on db epoch change, and safely isolates legacy credentials", async () => {
    const dir = makeTmp("pa-pw-epoch-");
    const extDir = makeTmp("pa-pw-ext-");
    const app = makeApp(dir);
    const svc = new ContextService(app);
    const bridge = svc.personalWeb;
    try {
      const hooks = (bridge as unknown as { hooks: { gatewayClient?: unknown; onReconnect: () => void } }).hooks;
      let captured: Record<string, unknown> | undefined;
      let streams = 0;
      hooks.onReconnect = () => undefined;
      hooks.gatewayClient = {
        sendReply: async (req: Record<string, unknown>) => {
          captured = req;
          return { replyId: "r1", rootId: "m1", parentId: "m1", threadId: "", verified: true };
        },
        streamEvents: async (o: { onStatus?: (st: unknown) => void }) => {
          streams++;
          o.onStatus?.({
            state: "listening", logged_in: true, credential_status: "ok", owner_id: "owner-1", owner_name: "Owner",
            since: Date.now(), last_message_at: null, last_error: "", allow_reply: true,
            min_seq: 1, latest_seq: 100, cached_events: 100, db_epoch: streams === 1 ? "epoch-a" : "epoch-b",
          });
          if (streams >= 2) bridge.stop();
        },
      };

      // 关闭 send_replies 后的收尾请求必须带 readback_only；groups_deny 进子串 client_deny，静音会话名进精确 client_deny_exact
      app.cfg.context.personal_web.send_replies = false;
      app.store.set("ctx.pw_reply_started.cid-readback-01", String(Date.now()));
      svc.store.muteConv("oc_muted_grp", "静音外部群", true);
      svc.store.muteConv("oc_dm_zs", "私聊：张三", true);
      await bridge.sendVerifiedReply({ chat_id: "chat-1", message_id: "m1", text: "测试", cid: "cid-readback-01" });
      assert.equal(captured?.readback_only, true);
      assert.ok((captured?.client_deny as string[]).includes("敏感群"));
      assert.ok(!(captured?.client_deny as string[]).includes("张三"), "静音私聊名不得进入子串 client_deny 误拦无关群");
      assert.ok((captured?.client_deny_exact as string[]).includes("静音外部群"));
      assert.ok((captured?.client_deny_exact as string[]).includes("张三"));

      // 网关事件库实例变化：重置游标
      app.store.set("ctx.pw_gateway.cursor", "50");
      bridge.start();
      const deadline = Date.now() + 5_000;
      while (streams < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
      assert.equal(streams, 2);
      assert.equal(bridge.cursor(), 0, "db epoch change must reset the local cursor");
      assert.equal(app.store.get("ctx.pw_gateway.db_epoch"), "epoch-b");

      // 旧版残留检测：区分 dataDir 内文件（含 .lock.db-journal）与外部 PA_FEISHU_WEB_CRED_FILE，且忽略目录防 EISDIR
      const localCred = path.join(app.cfg.dataDir, "feishu-web.json");
      const localJournal = `${localCred}.lock.db-journal`;
      const extCred = path.join(extDir, "shared-gw-cred.json");
      fs.writeFileSync(localCred, "{}");
      fs.writeFileSync(localJournal, "");
      fs.writeFileSync(extCred, "{}");

      const legacy = legacyPersonalWebArtifacts(app.cfg, { PA_FEISHU_WEB_KEY: "old-key", PA_FEISHU_WEB_CRED_FILE: extCred });
      assert.deepEqual(legacy.files.sort(), [localCred, localJournal].sort());
      assert.deepEqual(legacy.externalFiles, [extCred], "外部 PA_FEISHU_WEB_CRED_FILE 必须单独列出而非混入可自动删除的 files");
      assert.deepEqual(legacy.envKeys, ["PA_FEISHU_WEB_KEY", "PA_FEISHU_WEB_CRED_FILE"]);

      // PA_FEISHU_WEB_CRED_FILE 指向目录时不得收集为普通文件（防 rmSync 抛 EISDIR）
      const legacyDir = legacyPersonalWebArtifacts(app.cfg, { PA_FEISHU_WEB_CRED_FILE: extDir });
      assert.equal(legacyDir.externalFiles.length, 0);

      // doctor 体检项 personal_web_legacy 报告具体残留环境变量名与外部文件提示
      const doc = await runDoctor(app, { env: { ...process.env, PA_FEISHU_WEB_CRED_FILE: extCred } });
      const legacyCheck = doc.checks.find((c) => c.id === "personal_web_legacy");
      assert.equal(legacyCheck?.status, "warn");
      assert.match(legacyCheck?.detail ?? "", /shared-gw-cred\.json/);
      assert.match(legacyCheck?.fix ?? "", /PA_FEISHU_WEB_CRED_FILE/);
    } finally {
      bridge.stop();
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(extDir, { recursive: true, force: true });
    }
  });

  it("deduplicates cross-transport pw:* and im:* observations while respecting chat_type", () => {
    const dir = makeTmp("pa-pw-dedup-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const now = Date.now();
      const n1 = svc.store.addObs([
        {
          id: "pw:9001",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:c1",
          conv_name: "群聊(c1)",
          actor_id: "8888",
          actor_name: "8888",
          is_me: false,
          time: now,
          text: "明天评审一下方案",
          url: "",
          meta: { transport: "personal_web", native_message_id: "9001", native_chat_id: "c1", native_root_id: "9001", chat_type: "group" },
        },
      ]);
      assert.equal(n1, 1);

      // Same text in p2p chat must NOT merge into group obs
      const nDm = svc.store.addObs([
        {
          id: "im:om_dm",
          source: "im",
          kind: "p2p",
          conv: "oc_dm",
          conv_name: "私聊：张三",
          actor_id: "ou_zs",
          actor_name: "张三",
          is_me: false,
          time: now + 1000,
          text: "明天评审一下方案",
          url: "https://feishu.cn/dm",
          meta: { message_id: "om_dm", chat_type: "p2p" },
        },
      ]);
      assert.equal(nDm, 1, "DM and group messages with identical text must not collide");

      // Matching group message from lark-cli enriches pw:9001 without creating a duplicate
      const n2 = svc.store.addObs([
        {
          id: "im:om_grp_9001",
          source: "im",
          kind: "at_me",
          conv: "oc_grp_1",
          conv_name: "核心架构群",
          actor_id: "ou_zs",
          actor_name: "张三",
          is_me: false,
          time: now + 2000,
          text: "明天评审一下方案",
          url: "https://feishu.cn/grp",
          meta: { message_id: "om_grp_9001", chat_type: "group" },
        },
      ]);
      assert.equal(n2, 0, "matching lark-cli message is deduplicated against the existing pw:* obs");
      const weak = svc.store.obs("pw:9001")!;
      assert.equal(weak.conv_name, "群聊(c1)");
      assert.equal(weak.meta.open_message_id, undefined);

      // Strong match enriches open IDs and aliases
      svc.store.addObs([
        {
          id: "pw:9002",
          source: "im",
          kind: "group",
          conv: "pw_chat:c2",
          conv_name: "核心架构群",
          actor_id: "8888",
          actor_name: "8888",
          is_me: false,
          time: now + 3000,
          text: "收到",
          url: "",
          meta: { transport: "personal_web", native_message_id: "9002", native_chat_id: "c2", native_root_id: "9002", chat_type: "group" },
        },
      ]);
      const n3 = svc.store.addObs([
        {
          id: "im:om_grp_9002",
          source: "im",
          kind: "group",
          conv: "oc_grp_1",
          conv_name: "核心架构群",
          actor_id: "ou_zs",
          actor_name: "张三",
          is_me: false,
          time: now + 3500,
          text: "收到",
          url: "https://feishu.cn/grp",
          meta: { message_id: "om_grp_9002", chat_type: "group" },
        },
      ]);
      assert.equal(n3, 0);
      const enriched = svc.store.obs("pw:9002")!;
      assert.equal(enriched.actor_name, "张三");
      assert.equal(enriched.meta.open_message_id, "om_grp_9002");
      assert.equal(enriched.meta.open_chat_id, "oc_grp_1");
      assert.equal(svc.store.pwAlias("chat", "c2"), "oc_grp_1");
      assert.equal(svc.store.pwAlias("actor", "8888"), "张三");

      const n4 = svc.store.addObs([
        {
          id: "im:om_other_grp",
          source: "im",
          kind: "group",
          conv: "oc_grp_2",
          conv_name: "运营周会群",
          actor_id: "ou_ls",
          actor_name: "李四",
          is_me: false,
          time: now + 4000,
          text: "收到",
          url: "",
          meta: { message_id: "om_other_grp", chat_type: "group" },
        },
      ]);
      assert.equal(n4, 1, "same short text from a different chat must be stored separately");
      assert.equal(svc.store.obs("pw:9002")!.meta.open_message_id, "om_grp_9002");

      app.cfg.context.groups_deny = ["oc_grp_1"];
      assert.equal(svc.personalWeb.isDeniedChat("c2", ""), true);
      app.cfg.context.groups_deny = [];
      svc.store.muteConv("oc_grp_1", "核心架构群", true);
      assert.equal(svc.personalWeb.isDeniedChat("c2", ""), true, "mute recorded under the oc_ ID applies to the native chat");
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("routes drafts to pw.reply when only native ID exists and prefers lark-cli once open_message_id is enriched", () => {
    const dir = makeTmp("pa-pw-draft-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const now = Date.now();
      svc.store.addObs([
        {
          id: "pw:5001",
          source: "im",
          kind: "at_me",
          conv: "pw_chat:c5",
          conv_name: "项目群",
          actor_id: "8888",
          actor_name: "王五",
          is_me: false,
          time: now,
          text: "请确认排期",
          url: "",
          meta: { transport: "personal_web", native_message_id: "5001", native_chat_id: "c5", native_root_id: "5001", chat_type: "group" },
        },
      ]);
      const p = svc.store.upsertProject({ name: "测试项目" });
      const { item: it } = svc.store.upsertItem({ project_id: p.id, kind: "ask_me", title: "确认排期", priority: "high" });
      svc.store.addEvidence("item", it.id, "pw:5001", "请确认排期", now);

      const t1 = svc.drafter.target(it, "reply");
      assert.equal(t1.target.transport, "personal_web");
      const draft = svc.store.addDraft({ item_id: it.id, project_id: p.id, kind: "reply", target: t1.target, target_label: t1.label, content: "周四前完成" });
      const fx = svc.drafter.effectFor(draft, "周四前完成");
      assert.equal(fx.op, "pw.reply");

      svc.store.addObs([
        {
          id: "im:om_5001",
          source: "im",
          kind: "at_me",
          conv: "oc_5",
          conv_name: "项目群",
          actor_id: "ou_ww",
          actor_name: "王五",
          is_me: false,
          time: now + 500,
          text: "请确认排期",
          url: "https://feishu.cn/c5",
          meta: { message_id: "om_5001", chat_type: "group" },
        },
      ]);
      const t2 = svc.drafter.target(it, "reply");
      assert.equal(t2.target.transport, undefined);
      assert.equal(t2.target.message_id, "om_5001");
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verifies workspace owner binding and fast-fails permanent pw.reply errors on attempt 1", async () => {
    const dir = makeTmp("pa-pw-bind-");
    const app = makeApp(dir);
    try {
      app.store.set("ctx.personal_web.bound_owner_id", "1001");
      assert.doesNotThrow(() => verifyGatewayOwnerForWorkspace(app, "1001"));
      assert.throws(() => verifyGatewayOwnerForWorkspace(app, "2002"), /不一致/);

      const svc = new ContextService(app);
      const p = svc.store.upsertProject({ name: "失败速报项目" });
      const { item: it } = svc.store.upsertItem({ project_id: p.id, kind: "ask_me", title: "速报测试", priority: "high" });
      const d = svc.store.addDraft({
        item_id: it.id,
        project_id: p.id,
        kind: "reply",
        target: { transport: "personal_web", native_chat_id: "chat-1", native_message_id: "root-1", native_root_id: "root-1" },
        target_label: "回复对方",
        content: "确认方案",
      });
      app.cfg.context.personal_web.send_replies = false;
      await app.commands.exec("context.draft_approve", { id: d.id }, { source: "cli", actor: "owner" });
      await app.engine.drain(["effect"]);
      const fx = app.ledger.effectsOf(`ctx-draft:${d.id}`).at(-1)!;
      assert.equal(fx.state, "dead");
      assert.equal(fx.terminal, true);
      assert.equal(fx.attempts, 1, "不可重试的 pw.reply 失败必须在第 1 次就落 dead 终态");
      assert.equal(svc.store.draft(d.id)?.status, "failed");
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("matches p2p DMs strongly across channels, respects muted DMs, and preserves distinct pw background messages", () => {
    const dir = makeTmp("pa-pw-dm-strong-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const now = Date.now();

      assert.equal(
        svc.store.addObs([
          {
            id: "pw:dm_1",
            source: "im",
            kind: "p2p",
            conv: "pw_chat:native_dm_zs",
            conv_name: "张三",
            actor_id: "90001",
            actor_name: "张三",
            is_me: false,
            time: now,
            text: "好的",
            url: "",
            meta: { transport: "personal_web", native_message_id: "dm_1", native_chat_id: "native_dm_zs", native_root_id: "dm_1", chat_type: "p2p" },
          },
        ]),
        1,
      );
      assert.equal(
        svc.store.addObs([
          {
            id: "im:om_dm_1",
            source: "im",
            kind: "p2p",
            conv: "oc_dm_zs",
            conv_name: "私聊：张三",
            actor_id: "ou_zs",
            actor_name: "张三",
            is_me: false,
            time: now + 1000,
            text: "好的",
            url: "https://feishu.cn/dm/zs",
            meta: { message_id: "om_dm_1", chat_type: "p2p" },
          },
        ]),
        0,
        "短私聊在真实姓名一致时应强匹配合并",
      );
      const enriched = svc.store.obs("pw:dm_1")!;
      assert.equal(enriched.meta.open_message_id, "om_dm_1");
      assert.equal(enriched.meta.open_chat_id, "oc_dm_zs");
      assert.equal(svc.store.pwAlias("chat", "native_dm_zs"), "oc_dm_zs");

      assert.equal(
        svc.store.addObs([
          {
            id: "pw:dm_me_1",
            source: "im",
            kind: "mine",
            conv: "pw_chat:native_dm_a",
            conv_name: "张三",
            actor_id: "owner-1",
            actor_name: "我",
            is_me: true,
            time: now + 5000,
            text: "这个需求明天上午确认排期",
            url: "",
            meta: { transport: "personal_web", native_message_id: "dm_me_1", native_chat_id: "native_dm_a", chat_type: "p2p" },
          },
        ]),
        1,
      );
      assert.equal(
        svc.store.addObs([
          {
            id: "im:om_me_b",
            source: "im",
            kind: "mine",
            conv: "oc_dm_ls",
            conv_name: "私聊：李四",
            actor_id: "ou_owner",
            actor_name: "我",
            is_me: true,
            time: now + 6000,
            text: "这个需求明天上午确认排期",
            url: "",
            meta: { message_id: "om_me_b", chat_type: "p2p" },
          },
        ]),
        1,
        "不同私聊的本人同文本消息绝不能误合并",
      );

      svc.store.muteConv("oc_dm_ww", "私聊：王五", true);
      assert.equal(svc.personalWeb.isDeniedChat("native_dm_ww", "王五"), true);

      const bgAdded = svc.store.addBackgroundObs([
        {
          id: "pw:bg_1",
          source: "im",
          kind: "group",
          conv: "pw_chat:c9",
          conv_name: "发布群",
          actor_id: "111",
          actor_name: "111",
          is_me: false,
          time: now,
          text: "收到",
          url: "",
          meta: { transport: "personal_web", native_chat_id: "c9", chat_type: "group" },
        },
        {
          id: "pw:bg_2",
          source: "im",
          kind: "group",
          conv: "pw_chat:c9",
          conv_name: "发布群",
          actor_id: "222",
          actor_name: "222",
          is_me: false,
          time: now + 1000,
          text: "收到",
          url: "",
          meta: { transport: "personal_web", native_chat_id: "c9", chat_type: "group" },
        },
      ]);
      assert.equal(bgAdded, 2);
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("probes live gateway in doctor, defers concurrent fastCycle on same conv, and scrubs EventSupervisor env", async () => {
    const dir = makeTmp("pa-pw-conc-");
    const gwDir = path.join(dir, "gw");
    const sockPath = path.join(dir, "gw.sock");
    const gwCfgPath = path.join(dir, "gateway.yaml");
    fs.writeFileSync(
      gwCfgPath,
      YAML.stringify({
        data_dir: gwDir,
        listen: { socket: sockPath, socket_mode: "0600" },
        allow_reply: false,
      }),
    );

    const prevRead = process.env.TEST_GW_READ_TOKEN;
    const prevReply = process.env.TEST_GW_REPLY_TOKEN;
    const prevKey = process.env.FEISHU_GW_KEY;
    const prevCredDir = process.env.CREDENTIALS_DIRECTORY;

    const gwCfg = loadGatewayConfig(gwCfgPath);
    const gwStore = new GatewayStore(gwCfg.dataDir);
    const gwService = new FeishuGatewayService(gwCfg, gwStore);
    const tokens = gwStore.resolveTokens();
    const gwServer = await startGatewayServer(gwCfg, gwService, tokens);
    const app = makeApp(dir, {
      context: {
        personal_web: {
          enabled: true,
          gateway_socket: sockPath,
          read_token_env: "TEST_GW_READ_TOKEN",
          reply_token_env: "TEST_GW_REPLY_TOKEN",
          send_replies: false,
        },
      },
    });

    try {
      // 1) Missing read token -> doctor fails
      delete process.env.TEST_GW_READ_TOKEN;
      const docMissing = await runDoctor(app);
      const pwMissing = docMissing.checks.find((c) => c.id === "personal_web");
      assert.equal(pwMissing?.status, "fail");
      assert.match(pwMissing?.detail ?? "", /缺少网关只读令牌/);

      // 2) Wrong read token -> doctor fails with 401 auth error
      process.env.TEST_GW_READ_TOKEN = "wrong-token-value-123456";
      const docAuthFail = await runDoctor(app);
      const pwAuthFail = docAuthFail.checks.find((c) => c.id === "personal_web");
      assert.equal(pwAuthFail?.status, "fail");
      assert.match(pwAuthFail?.detail ?? "", /鉴权失败/);

      // 3) Valid read token, gateway has invalid encrypted cred -> doctor fails clearly
      process.env.FEISHU_GW_KEY = "key-original";
      gwService.loginStore.save({ owner_id: "1001", owner_name: "Owner", cookies: [{ name: "session", value: "s1", domain: "feishu.cn", path: "/" }] });
      process.env.FEISHU_GW_KEY = "key-wrong";
      process.env.TEST_GW_READ_TOKEN = tokens.readToken;
      const docInvalid = await runDoctor(app);
      const pwInvalid = docInvalid.checks.find((c) => c.id === "personal_web");
      assert.equal(pwInvalid?.status, "fail");
      assert.match(pwInvalid?.detail ?? "", /invalid|解密失败/);

      // 4) Valid key + valid read token -> doctor ok
      process.env.FEISHU_GW_KEY = "key-original";
      const docOk = await runDoctor(app);
      const pwOk = docOk.checks.find((c) => c.id === "personal_web");
      assert.equal(pwOk?.status, "ok");
      assert.match(pwOk?.detail ?? "", /Owner/);

      // 5) Same conv concurrent fastCycle deferred with refunded attempt
      const svc = new ContextService(app);
      (svc as unknown as { activeConvs: Set<string> }).activeConvs.add("pw_chat:busy");
      app.ledger.enqueue({
        id: "context:fast:busy:2",
        kind: "context",
        ref: "fast",
        payload: { task: "fast", conv: "pw_chat:busy", conv_name: "忙群", trigger_obs_id: "pw:2" },
      });
      const claimed = app.ledger.claim("context", 60_000)!;
      const h = svc.handler();
      const before = Date.now();
      await h.run(claimed as never, { signal: new AbortController().signal, attempt: claimed.attempts });
      const deferred = app.ledger.get(claimed.id)!;
      assert.equal(deferred.terminal, false);
      assert.equal(deferred.attempts, 0, "延后执行不应消耗尝试次数");
      assert.ok(deferred.next_at >= before + 2500);
      (svc as unknown as { activeConvs: Set<string> }).activeConvs.delete("pw_chat:busy");

      // 6) EventSupervisor strips gateway tokens & CREDENTIALS_DIRECTORY
      const probeBin = path.join(dir, "fake-lark");
      const envDump = path.join(dir, "event-env.txt");
      fs.writeFileSync(
        probeBin,
        `#!/bin/sh\necho "READ=\${TEST_GW_READ_TOKEN:-EMPTY} KEY=\${FEISHU_GW_KEY:-EMPTY} CRED=\${CREDENTIALS_DIRECTORY:-EMPTY}" > ${JSON.stringify(envDump)}\n`,
        { mode: 0o755 },
      );
      process.env.CREDENTIALS_DIRECTORY = "/tmp/leak-cred-dir";
      app.cfg.bins.lark = probeBin;
      const sup = new EventSupervisor(app.cfg, () => undefined);
      sup.start([{ key: "im.message.receive_v1", as: "bot" }]);
      const deadline = Date.now() + 3000;
      while (!fs.existsSync(envDump) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
      await sup.stop();
      assert.equal(fs.readFileSync(envDump, "utf8").trim(), "READ=EMPTY KEY=EMPTY CRED=EMPTY");

      // Verify FeishuGatewayClient rejects non-loopback HTTP URLs
      assert.throws(() => new FeishuGatewayClient({ baseUrl: "http://192.168.1.10:7879", readToken: tokens.readToken }), /回环地址/);

      // 7) sendVerifiedReply: pre-send ECONNREFUSED clears startedKey so toggling send_replies=false is NOT bypassed
      const deadSockApp = makeApp(dir, {
        context: {
          personal_web: {
            enabled: true,
            gateway_socket: path.join(dir, "nonexistent.sock"),
            read_token_env: "TEST_GW_READ_TOKEN",
            reply_token_env: "TEST_GW_REPLY_TOKEN",
            send_replies: true,
          },
        },
      });
      try {
        process.env.TEST_GW_REPLY_TOKEN = tokens.replyToken;
        const deadSvc = new ContextService(deadSockApp);
        await assert.rejects(
          deadSvc.personalWeb.sendVerifiedReply({ chat_id: "chat-1", message_id: "m1", text: "测试", cid: "cid-presend-001" }),
        );
        // Now toggle send_replies off: must fail permanently rather than bypassing via stale startedKey
        deadSockApp.cfg.context.personal_web.send_replies = false;
        await assert.rejects(
          deadSvc.personalWeb.sendVerifiedReply({ chat_id: "chat-1", message_id: "m1", text: "测试", cid: "cid-presend-001" }),
          /未开启个人 Web 回复/,
        );

        // 8) hydrateContext blocks denied chat before hitting gateway and rejects owner mismatch
        deadSvc.app.store.set("ctx.personal_web.bound_owner_id", "owner-expected");
        const deniedRes = await deadSvc.personalWeb.hydrateContext(
          { id: "m1", conversationId: "chat-denied", rootId: "", parentId: "", threadId: "", position: 5, createdAtMs: Date.now() },
          "pw_chat:chat-denied",
          "敏感群",
        );
        assert.equal(deniedRes, 0);
        // Inject a fake gatewayClient returning a different owner_id -> hydrateContext must reject & ingest 0 messages
        (deadSvc.personalWeb as unknown as { hooks: { gatewayClient?: unknown } }).hooks.gatewayClient = {
          readContext: async () => ({
            owner_id: "owner-other",
            owner_name: "Other",
            chat_name: "正常群",
            messages: [makeGatewayMsg({ id: "m-foreign-bg", conversationId: "chat-1", ownerId: "owner-other", text: "不该入库" })],
          }),
        };
        const mismatchRes = await deadSvc.personalWeb.hydrateContext(
          { id: "m2", conversationId: "chat-1", rootId: "", parentId: "", threadId: "", position: 5, createdAtMs: Date.now() },
          "pw_chat:chat-1",
          "正常群",
        );
        assert.equal(mismatchRes, 0);
        assert.equal(deadSvc.store.obs("pw:m-foreign-bg"), undefined, "跨账号网关返回的背景消息绝不得写入 ctx_obs");
      } finally {
        deadSockApp.store.db.close();
      }
    } finally {
      await gwService.stop();
      await gwServer.stop();
      gwStore.close();
      app.store.db.close();
      if (prevRead === undefined) delete process.env.TEST_GW_READ_TOKEN;
      else process.env.TEST_GW_READ_TOKEN = prevRead;
      if (prevReply === undefined) delete process.env.TEST_GW_REPLY_TOKEN;
      else process.env.TEST_GW_REPLY_TOKEN = prevReply;
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
      else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
