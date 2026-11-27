import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import YAML from "yaml";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { USER_SENDER_TYPE, WebLoginStore, type WebMessage } from "../src/context/feishu-web/index.ts";
import { ContextService } from "../src/context/index.ts";
import { verifyLoginForWorkspace } from "../src/context/personal-web.ts";
import { runDoctor } from "../src/doctor.ts";
import { EventSupervisor } from "../src/events.ts";
import { scrubPersonalWebEnv } from "../src/harness.ts";

function makeTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function makeApp(dir: string, overrides: Record<string, unknown> = {}) {
  const cfgPath = path.join(dir, "config.yaml");
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

function makeWebMsg(overrides: Partial<WebMessage> = {}): WebMessage {
  return {
    id: "70001",
    ownerId: "owner-1",
    kind: 4,
    messageType: "text",
    conversationId: "chat-1",
    conversationKind: "group",
    actorId: "actor-2",
    senderType: USER_SENDER_TYPE,
    text: "请帮我确认下发布时间",
    createdAtMs: Date.now(),
    rootId: "",
    parentId: "",
    threadId: "",
    cid: "cid-msg",
    position: 10,
    threadPosition: 0,
    sendToChat: false,
    mentions: [{ id: "owner-1", name: "@我", start: 0, end: 2 }],
    resources: [],
    partial: false,
    unsupported: false,
    ...overrides,
  };
}

describe("feishu-web bridge, store dedup, drafts, and env scrub", () => {
  it("scrubPersonalWebEnv strips credential env vars without touching unrelated variables", () => {
    const cleaned = scrubPersonalWebEnv({
      PATH: "/usr/bin",
      HOME: "/home/dev",
      PA_FEISHU_WEB_KEY: "secret-key",
      PA_FEISHU_WEB_CRED_FILE: "/tmp/cred.json",
    });
    assert.equal(cleaned.PATH, "/usr/bin");
    assert.equal(cleaned.HOME, "/home/dev");
    assert.equal(cleaned.PA_FEISHU_WEB_KEY, undefined);
    assert.equal(cleaned.PA_FEISHU_WEB_CRED_FILE, undefined);
  });

  it("enforces groups_deny, mutedConvs, group scope, recall deletion, and Fast Lane triggers", async () => {
    const dir = makeTmp("pa-pw-bridge-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const triggers: string[] = [];
      const bridge = svc.personalWeb;
      // Inject fake owner state & capture triggers
      (bridge as unknown as { state: { owner_id: string; owner_name: string } }).state.owner_id = "owner-1";
      (bridge as unknown as { hooks: { onFastTrigger: (t: { trigger_obs_id: string }) => void } }).hooks.onFastTrigger = (t) =>
        triggers.push(t.trigger_obs_id);

      // 1) Denied chat ID dropped
      await bridge.handleMessage(makeWebMsg({ id: "m-denied", conversationId: "chat-denied" }));
      assert.equal(svc.store.obs("pw:m-denied"), undefined);

      // 2) Muted conv dropped
      svc.store.muteConv("pw_chat:chat-muted", "静音群", true);
      await bridge.handleMessage(makeWebMsg({ id: "m-muted", conversationId: "chat-muted" }));
      assert.equal(svc.store.obs("pw:m-muted"), undefined);

      // 3) Unspoken group without @me ignored; after I speak, group is tracked
      await bridge.handleMessage(makeWebMsg({ id: "m-unspoken", conversationId: "chat-2", mentions: [] }));
      assert.equal(svc.store.obs("pw:m-unspoken"), undefined);
      await bridge.handleMessage(makeWebMsg({ id: "m-mine", conversationId: "chat-2", actorId: "owner-1", mentions: [], text: "我来跟进" }));
      assert.ok(svc.store.obs("pw:m-mine"));
      await bridge.handleMessage(makeWebMsg({ id: "m-after-spoken", conversationId: "chat-2", mentions: [], text: "好的谢谢" }));
      assert.ok(svc.store.obs("pw:m-after-spoken"));
      assert.equal(triggers.length, 0, "regular non-@me group message does not trigger fast lane");

      // 4) @me in group persists and triggers Fast Lane
      await bridge.handleMessage(makeWebMsg({ id: "m-atme", conversationId: "chat-1" }));
      assert.ok(svc.store.obs("pw:m-atme"));
      assert.deepEqual(triggers, ["pw:m-atme"]);

      // 5) Recalled/empty push deletes existing local obs
      await bridge.handleMessage(makeWebMsg({ id: "m-atme", conversationId: "chat-1", text: "", unsupported: true }));
      assert.equal(svc.store.obs("pw:m-atme"), undefined, "recalled message must be deleted locally");
    } finally {
      app.store.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
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
      // pw:9001 只有占位会话名（弱匹配）：只去重，不回填开放平台 ID 和名称
      const weak = svc.store.obs("pw:9001")!;
      assert.equal(weak.conv_name, "群聊(c1)");
      assert.equal(weak.meta.open_message_id, undefined);

      // 双方都有真实群名且一致（强匹配）：回填开放平台 ID 与姓名，并记下原生 ID 的对应关系
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

      // 另一个群里同一句短话：会话名不同，不得合并或回填
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

      // 按 oc_ ID 配置的排除在个人 Web 通道同样生效（借助跨通道记下的对应关系）
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

      // After cross-transport enrichment adds open_message_id, Drafter prefers official lark-cli im.reply
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

  it("verifies workspace owner binding and enforces idempotent delivery recovery", async () => {
    const dir = makeTmp("pa-pw-bind-");
    const prevKey = process.env.PA_FEISHU_WEB_KEY;
    process.env.PA_FEISHU_WEB_KEY = "bridge-test-key";
    const app = makeApp(dir);
    try {
      // open_id 按应用区分，网页端的 open_id 与 owner.open_id 不同不能据此拒绝（只告警）
      assert.doesNotThrow(() =>
        verifyLoginForWorkspace(app, {
          owner_id: "1001",
          owner_name: "Other",
          owner_open_id: "ou_someone_else",
          cookies: [],
        }),
      );

      // Matching open_id accepted and bound
      const loginStore = new WebLoginStore(dir);
      const saved = loginStore.save({
        owner_id: "1001",
        owner_name: "Owner",
        owner_open_id: "ou_owner",
        cookies: [{ name: "session", value: "s1", domain: "feishu.cn", path: "/" }],
      });
      verifyLoginForWorkspace(app, saved);
      app.store.set("ctx.personal_web.bound_owner_id", "1001");

      // Different native owner rejected unless forceSwitch
      assert.throws(
        () => verifyLoginForWorkspace(app, { owner_id: "2002", owner_name: "Other", cookies: [] }),
        /force-switch-account/,
      );
      verifyLoginForWorkspace(app, { owner_id: "2002", owner_name: "Other", cookies: [] }, { forceSwitch: true });

      // Idempotent delivery: already-verified cid returns without touching network
      const svc = new ContextService(app);
      app.store.set(
        "ctx.pw_delivery.cid-already-done",
        JSON.stringify({
          status: "verified",
          replyId: "rep-1",
          chatId: "chat-1",
          rootId: "root-1",
          parentId: "root-1",
          threaded: true,
          threadId: "th-1",
          updatedAt: Date.now(),
        }),
      );
      const res = await svc.personalWeb.sendVerifiedReply({
        chat_id: "chat-1",
        message_id: "root-1",
        text: "重复投递测试",
        cid: "cid-already-done",
      });
      assert.equal(res.verified, true);
      assert.equal(res.replyId, "rep-1");

      // 上次发包结果不明（sending）：拒绝自动重发，也不触网，且经 effectHandler 立刻落 dead 终态而非退避重试 10 次
      app.store.set(
        "ctx.pw_delivery.cid-uncertain",
        JSON.stringify({ status: "sending", replyId: "", chatId: "chat-1", rootId: "root-1", parentId: "root-1", threaded: true, updatedAt: Date.now() }),
      );
      await assert.rejects(
        svc.personalWeb.sendVerifiedReply({ chat_id: "chat-1", message_id: "root-1", text: "重复投递测试", cid: "cid-uncertain" }),
        /结果不明确/,
      );

      // 端到端验证：PermanentEffectError 经 engine.drain 仅尝试 1 次即落 dead，草稿立刻转为 failed
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
      app.store.set("ctx.pw_delivery.force", "");
      await app.commands.exec("context.draft_approve", { id: d.id }, { source: "cli", actor: "owner" });
      await app.engine.drain(["effect"]);
      const fx = app.ledger.effectsOf(`ctx-draft:${d.id}`).at(-1)!;
      assert.equal(fx.state, "dead");
      assert.equal(fx.terminal, true);
      assert.equal(fx.attempts, 1, "不可重试的 pw.reply 失败必须在第 1 次就落 dead 终态");
      assert.equal(svc.store.draft(d.id)?.status, "failed");
    } finally {
      app.store.db.close();
      if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
      else process.env.PA_FEISHU_WEB_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("matches p2p DMs strongly across channels, respects muted DMs, and preserves distinct pw background messages", () => {
    const dir = makeTmp("pa-pw-dm-strong-");
    const app = makeApp(dir);
    try {
      const svc = new ContextService(app);
      const now = Date.now();

      // 1) 短私聊（< 8 字）：pw 侧 conv_name="张三" vs lark-cli 侧 conv_name="私聊：张三" 应 strong 命中并回填开放平台 ID 与别名
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

      // 2) 本人给两个不同私聊 15 秒内发相同 >=8 字消息，不得误合并
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

      // 3) lark-cli 侧静音的私聊（name="私聊：王五"）必须拦住个人 Web（chatName="王五"）
      svc.store.muteConv("oc_dm_ww", "私聊：王五", true);
      assert.equal(svc.personalWeb.isDeniedChat("native_dm_ww", "王五"), true);

      // 4) addBackgroundObs 不得把同群 15 秒内两位不同成员的相同短消息误判为跨通道重复
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

  it("defers concurrent fastCycle on the same conv, flags invalid encryption key in doctor/status, and scrubs EventSupervisor env", async () => {
    const dir = makeTmp("pa-pw-conc-");
    const prevKey = process.env.PA_FEISHU_WEB_KEY;
    const prevCredDir = process.env.CREDENTIALS_DIRECTORY;
    const app = makeApp(dir);
    try {
      // 1) 密钥不匹配（invalid）时 doctor 报 fail(ready=false) 且 personalWeb.status() 报 needs_login + 解密失败原因
      process.env.PA_FEISHU_WEB_KEY = "key-original";
      const loginStore = new WebLoginStore(dir);
      loginStore.save({ owner_id: "1001", owner_name: "Owner", cookies: [{ name: "session", value: "s1", domain: "feishu.cn", path: "/" }] });
      process.env.PA_FEISHU_WEB_KEY = "key-wrong";

      const svc = new ContextService(app);
      const st = svc.personalWeb.status();
      assert.equal(st.state, "needs_login");
      assert.match(st.last_error, /解密失败|损坏/);

      const doc = await runDoctor(app);
      const pwCheck = doc.checks.find((c) => c.id === "personal_web");
      assert.equal(pwCheck?.status, "fail");
      assert.match(pwCheck?.detail ?? "", /解密失败|损坏/);

      // 2) 同会话并发 fast 任务互斥：当 conv 已在 activeConvs 中时，第 2 个 fast 任务延后 release 且退回 attempts
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

      // 3) EventSupervisor 直接 spawn 时也必须剥离 PA_FEISHU_WEB_KEY 与 CREDENTIALS_DIRECTORY
      const probeBin = path.join(dir, "fake-lark");
      const envDump = path.join(dir, "event-env.txt");
      fs.writeFileSync(
        probeBin,
        `#!/bin/sh\necho "KEY=\${PA_FEISHU_WEB_KEY:-EMPTY} CRED=\${CREDENTIALS_DIRECTORY:-EMPTY}" > ${JSON.stringify(envDump)}\n`,
        { mode: 0o755 },
      );
      process.env.PA_FEISHU_WEB_KEY = "leak-check-key";
      process.env.CREDENTIALS_DIRECTORY = "/tmp/leak-cred-dir";
      app.cfg.bins.lark = probeBin;
      const sup = new EventSupervisor(app.cfg, () => undefined);
      sup.start([{ key: "im.message.receive_v1", as: "bot" }]);
      const deadline = Date.now() + 3000;
      while (!fs.existsSync(envDump) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
      await sup.stop();
      assert.equal(fs.readFileSync(envDump, "utf8").trim(), "KEY=EMPTY CRED=EMPTY");
    } finally {
      app.store.db.close();
      if (prevKey === undefined) delete process.env.PA_FEISHU_WEB_KEY;
      else process.env.PA_FEISHU_WEB_KEY = prevKey;
      if (prevCredDir === undefined) delete process.env.CREDENTIALS_DIRECTORY;
      else process.env.CREDENTIALS_DIRECTORY = prevCredDir;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
