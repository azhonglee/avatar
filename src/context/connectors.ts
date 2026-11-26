import type { App } from "../app.ts";
import { runProcess } from "../util.ts";
import { hashId, norm, type ContextStore, type Obs } from "./store.ts";

/**
 * 采集器：只读地从飞书 / Meego 拉取信号，写成观测；Meego 待办和飞书任务直接成为事项（确定性，不需要模型）。
 * 增量游标存在 kv（ctx.cursor.*）。每个来源相互隔离，一个失败不影响其他。
 */

const DAY = 86_400_000;

export interface SourceReport {
  source: string;
  count: number;
  error: string;
  dropped?: number;
}

type Raw = Record<string, any>;

/** "2026-11-24 11:19" / ISO / 秒 / 毫秒 → 毫秒（无时区的本地时间按 owner.timezone 解释） */
export function parseTime(v: unknown, tz = "Asia/Shanghai"): number {
  const t = parseTimeRaw(v, tz);
  // 2000 年以前的时间都是占位值（Meego 未排期时返回 1970-01-01、飞书任务的 "0"）
  return t < 946_684_800_000 ? 0 : t;
}

function parseTimeRaw(v: unknown, tz: string): number {
  if (v === undefined || v === null || v === "") return 0;
  if (typeof v === "number") return v < 1e12 ? v * 1000 : v;
  const s = String(v).trim();
  if (/^\d{10}$/.test(s)) return Number(s) * 1000;
  if (/^\d{13}$/.test(s)) return Number(s);
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  if (m) {
    const utc = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] ?? 0), +(m[5] ?? 0), +(m[6] ?? 0));
    // 该时区在这个时刻的偏移
    const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" })
      .formatToParts(new Date(utc))
      .reduce<Record<string, number>>((a, p) => (p.type === "literal" ? a : { ...a, [p.type]: Number(p.value) }), {});
    const asUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
    return utc - (asUtc - utc);
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? 0 : t;
}

export function isoLocal(ms: number): string {
  const d = new Date(ms);
  const off = -d.getTimezoneOffset();
  const pad = (n: number) => String(Math.floor(Math.abs(n))).padStart(2, "0");
  return `${new Date(ms + off * 60_000).toISOString().slice(0, 19)}${off >= 0 ? "+" : "-"}${pad(off / 60)}:${pad(off % 60)}`;
}

/** 卡片 / 富文本 JSON 提取可读文字 */
export function textOf(raw: unknown): string {
  let t = typeof raw === "string" ? raw : JSON.stringify(raw ?? "");
  if (/^\s*[{[]/.test(t)) {
    try {
      const out: string[] = [];
      const walk = (o: unknown) => {
        if (Array.isArray(o)) return o.forEach(walk);
        if (o && typeof o === "object")
          for (const [k, v] of Object.entries(o)) {
            if (typeof v === "string" && ["text", "content", "title", "plain_text"].includes(k) && v.trim()) out.push(v.trim());
            else walk(v);
          }
      };
      walk(JSON.parse(t));
      if (out.length) t = out.join(" / ");
    } catch {
      // 不是 JSON
    }
  }
  return t.replace(/!\[Image\]\([^)]*\)/g, "[图]").replace(/<[^>]{1,200}>/g, " ").replace(/\s+/g, " ").trim();
}

function arr(o: any, key: string): any[] {
  if (Array.isArray(o)) return o;
  if (o && typeof o === "object") {
    if (Array.isArray(o[key])) return o[key];
    for (const v of Object.values(o)) {
      const r = arr(v, key);
      if (r.length) return r;
    }
  }
  return [];
}

export interface NativePollingExclusions {
  /** 已确认排除的群名（norm 后） */
  confirmedGroupNames: Set<string>;
  /** 存在无法实时解析的原生群排除规则（例如无在线 Web 客户端或 readChat 暂时失败）：需暂缓群入库且保留游标以便恢复后重试 */
  groupsInconclusive: boolean;
  /** 存在原生私聊排除规则或类型未知的无法解析排除规则：需暂缓私聊入库且保留游标 */
  dmsInconclusive: boolean;
}

export class Connectors {
  app: App;
  store: ContextStore;
  nativeExclusions?: () => Promise<NativePollingExclusions>;
  constructor(app: App, store: ContextStore, nativeExclusions?: () => Promise<NativePollingExclusions>) {
    this.app = app;
    this.store = store;
    this.nativeExclusions = nativeExclusions;
  }

  private get cfg() {
    return this.app.cfg;
  }
  private kv(k: string): string | undefined {
    return this.app.store.get(`ctx.${k}`);
  }
  private setKv(k: string, v: string): void {
    this.app.store.set(`ctx.${k}`, v);
  }

  private async lark(args: string[], timeoutMs = 180_000): Promise<any> {
    return this.app.lark.run(args, { as: "user", timeoutMs });
  }

  private async meego(args: string[]): Promise<any> {
    const r = await runProcess(this.cfg.bins.bytedcli, ["meego", ...args, "--json"], { timeoutMs: 120_000 });
    const t = r.stdout.trim();
    const j = t ? JSON.parse(t.slice(t.indexOf("{"))) : undefined;
    if (r.code !== 0 || !j || j.status === "error") throw new Error(`bytedcli meego ${args.slice(0, 2).join(" ")} 失败：${(r.stderr || JSON.stringify(j?.error ?? "")).trim().slice(0, 300)}`);
    return j.data?.result?.structuredContent ?? j.data;
  }

  /** 跑一轮所有启用的来源 */
  async pullAll(): Promise<SourceReport[]> {
    const s = this.cfg.context.sources;
    const out: SourceReport[] = [];
    const step = async (name: string, enabled: boolean, fn: () => Promise<Omit<SourceReport, "source" | "error">>) => {
      if (!enabled) return;
      try {
        const r = await fn();
        out.push({ source: name, error: "", ...r });
      } catch (e) {
        out.push({ source: name, count: 0, error: (e as Error).message.slice(0, 300) });
      }
      this.setKv(`source.${name}`, JSON.stringify({ at: Date.now(), ...out.at(-1) }));
    };
    await step("meego", s.meego, () => this.pullMeego());
    await step("tasks", s.tasks, () => this.pullTasks());
    await step("im", s.im, () => this.pullIm());
    await step("minutes", s.minutes, () => this.pullMinutes());
    await step("calendar", s.calendar, () => this.pullCalendar());
    await step("docs", s.docs, async () => this.pullComments());
    return out;
  }

  // ───────── Meego：待办快照 → 事项 ─────────

  async pullMeego(): Promise<{ count: number }> {
    const all: Raw[] = [];
    let total = 0;
    for (let page = 1; page <= 20; page++) {
      const sc = await this.meego(["todo", "list", "--action", "todo", "--todo-scope", "all", "--page", String(page)]);
      const list: Raw[] = sc?.list ?? [];
      total = Number(sc?.total ?? total);
      all.push(...list);
      if (!list.length || all.length >= total) break;
    }
    // 拉不全就不做“消失即完成”的推断，避免误关
    const complete = all.length >= total;
    const now = Date.now();
    const legacyCut = now - this.cfg.context.legacy_days * DAY;
    const seen = new Set<string>();
    const obs: Obs[] = [];
    const bySpace = new Map<string, Raw[]>();
    for (const x of all) {
      const k = String(x.project_name ?? x.project_key ?? "Meego");
      if (!bySpace.has(k)) bySpace.set(k, []);
      bySpace.get(k)!.push(x);
    }
    for (const [space, items] of bySpace) {
      // 空间内最近的排期时间：太久以前的空间视为历史遗留
      const latest = Math.max(0, ...items.map((x) => Math.max(parseTime(x.schedule?.end_time), parseTime(x.schedule?.start_time))));
      const legacy = latest > 0 ? latest < legacyCut : items.length > 30;
      const spaceProject = this.store.upsertProject(
        { id: hashId("sys_meego", space), name: `Meego · ${space}`, description: `Meego 空间「${space}」里分配给你的节点待办`, status: legacy ? "legacy" : "active", muted: legacy && this.cfg.context.autonomy.mute_legacy },
        latest || now,
      );
      // 每次按最新快照重新判断（你手动静音 / 恢复过的不再自动改）
      if (!spaceProject.pinned) {
        if (legacy && this.cfg.context.autonomy.mute_legacy) this.store.setProject(spaceProject.id, { status: "legacy", muted: true });
        else if (!legacy && spaceProject.status === "legacy") this.store.setProject(spaceProject.id, { status: "active", muted: false });
      }
      for (const x of items) {
        const w = x.work_item_info ?? {};
        const node = x.node_info?.node_name ?? "";
        const key = `meego:${w.work_item_id}:${x.node_info?.node_state_key ?? node}`;
        seen.add(key);
        const end = parseTime(x.schedule?.end_time);
        const url = `https://meego.larkoffice.com/${x.project_key}/${w.work_item_type_key ?? "story"}/detail/${w.work_item_id}`;
        // 已被理解层归到具体项目（refs 里有这个工作项）的，用具体项目
        const linked = this.store.findProject(`meego:${w.work_item_id}`);
        const oid = `meego_todo:${w.work_item_id}:${x.node_info?.node_state_key ?? node}`;
        obs.push({
          id: oid,
          source: "meego",
          kind: "meego_todo",
          conv: `meego:${w.work_item_id}`,
          conv_name: String(w.work_item_name ?? ""),
          actor_id: "",
          actor_name: "Meego",
          is_me: false,
          time: end || now,
          text: `[${w.work_item_type_key}#${w.work_item_id}] ${w.work_item_name}｜节点:${node}${end ? `｜截止 ${x.schedule?.end_time}` : ""}`,
          url,
          meta: { project_key: x.project_key, space },
        });
        const { item } = this.store.upsertItem(
          {
            strong_key: key,
            title: `${w.work_item_name}｜${node}`,
            kind: "todo",
            source: "meego",
            project_id: linked?.id ?? spaceProject.id,
            due: end || null,
            // 临近截止的加分由排序规则按到期时间给（避免和优先级重复计分）；只有逾期才算高优先级
            priority: end && end < now ? "high" : "medium",
            confidence: 1,
            status: "open",
            meta: { project_key: x.project_key, work_item_id: String(w.work_item_id), work_item_type: w.work_item_type_key, node, url, space, legacy },
          },
          now,
        );
        this.store.addEvidence("item", item.id, oid, `Meego 待办：${w.work_item_name}｜${node}`, now);
      }
    }
    this.store.addObs(obs);
    this.store.markProcessed(obs.map((o) => o.id));
    if (complete) {
      for (const it of this.store.items({ status: ["open", "snoozed"], source: "meego" })) {
        if (it.strong_key.startsWith("meego:") && !seen.has(it.strong_key)) {
          this.store.upsertItem({ ...it, status: "done", close_reason: "Meego 节点已不在你的待办里（已完成或已流转）" });
        }
      }
    }
    return { count: all.length };
  }

  // ───────── 飞书任务 → 事项 ─────────

  async pullTasks(): Promise<{ count: number }> {
    const data = await this.lark(["task", "+get-my-tasks", "--complete=false", "--page-all"]);
    const tasks = arr(data, "items");
    const now = Date.now();
    const legacyCut = now - this.cfg.context.legacy_days * DAY;
    const active = this.store.upsertProject({ id: "sys_tasks", name: "飞书任务", description: "分配给你的飞书任务" });
    const legacy = this.store.upsertProject({ id: "sys_tasks_legacy", name: "飞书任务（历史）", description: "很久以前创建、长期未处理的飞书任务", status: "legacy", muted: this.cfg.context.autonomy.mute_legacy });
    const seen = new Set<string>();
    for (const t of tasks) {
      const key = `task:${t.guid}`;
      seen.add(key);
      const created = parseTime(t.created_at);
      const due = parseTime(t.due_at) || null;
      const isLegacy = created > 0 && created < legacyCut && (!due || due < now - 30 * DAY);
      const oid = `task:${t.guid}`;
      this.store.addObs([{ id: oid, source: "task", kind: "task", conv: oid, conv_name: String(t.summary ?? ""), actor_id: "", actor_name: "飞书任务", is_me: false, time: created || now, text: String(t.summary ?? ""), url: String(t.url ?? ""), meta: {} }]);
      this.store.markProcessed([oid]);
      const linked = this.store.findProject(key);
      const { item } = this.store.upsertItem({
        strong_key: key,
        title: String(t.summary ?? "(无标题任务)"),
        kind: "todo",
        source: "task",
        project_id: linked?.id ?? (isLegacy ? legacy.id : active.id),
        due,
        priority: due && due < now + 2 * DAY && !isLegacy ? "high" : "medium",
        confidence: 1,
        status: "open",
        meta: { url: t.url, legacy: isLegacy },
      });
      this.store.addEvidence("item", item.id, oid, `飞书任务：${t.summary}`, created || now);
    }
    for (const it of this.store.items({ status: ["open", "snoozed"], source: "task" })) {
      if (it.strong_key.startsWith("task:") && !seen.has(it.strong_key)) this.store.upsertItem({ ...it, status: "done", close_reason: "飞书任务已完成" });
    }
    return { count: tasks.length };
  }

  // ───────── 飞书消息 → 观测 ─────────

  private botAllowed(m: Raw): boolean {
    const name = String(m.sender?.name ?? m.sender_name ?? "");
    const text = String(m.content ?? m.text ?? "");
    return this.cfg.context.bot_allow.some((p) => {
      try {
        const re = new RegExp(p, "i");
        return re.test(name) || re.test(text.slice(0, 300));
      } catch {
        return name.includes(p);
      }
    });
  }

  private classifyExclusion(
    chatId: string,
    chatName: string,
    chatType = "",
    nativeExcl?: NativePollingExclusions,
    requireName = true,
  ): "allowed" | "denied" | "inconclusive" {
    if (chatId && this.store.isConvMutedById(chatId)) return "denied";
    if (
      this.cfg.context.groups_deny.some((raw) => {
        const d = raw.trim();
        if (!d) return false;
        if (chatId === d) return true;
        // 仅 oc_* 与 pw_chat:* 视作会话 ID；纯数字（如 "2024"）保持原有群名关键词排除语义
        if (!d.startsWith("oc_") && !d.startsWith("pw_chat:") && chatName && chatName.includes(d)) return true;
        return false;
      })
    ) {
      return "denied";
    }
    if (!nativeExcl) return "allowed";
    const isDm = chatType === "p2p";
    if (isDm) return nativeExcl.dmsInconclusive ? "inconclusive" : "allowed";
    if (chatName && nativeExcl.confirmedGroupNames.has(norm(chatName))) return "denied";
    if (nativeExcl.groupsInconclusive) return "inconclusive";
    if (nativeExcl.confirmedGroupNames.size > 0 && !chatName && requireName) return "inconclusive";
    return "allowed";
  }

  private toObs(m: Raw, kind: string, me: string): Obs | undefined {
    const sender = m.sender ?? {};
    const senderType = String(sender.sender_type ?? sender.type ?? m.sender_type ?? "");
    const msgType = String(m.msg_type ?? m.message_type ?? "");
    if (["sticker", "system"].includes(msgType)) return undefined;
    const chatType = String(m.chat_type ?? "");
    const senderId = String(sender.id ?? sender.open_id ?? m.sender_id ?? "");
    const isMe = senderId === me;
    const text = textOf(m.content ?? m.text ?? "");
    if (!text) return undefined;
    return {
      id: `im:${m.message_id ?? m.id}`,
      source: "im",
      kind: senderType === "app" ? "bot" : isMe ? "mine" : chatType === "p2p" ? "p2p" : kind,
      conv: String(m.chat_id ?? ""),
      conv_name: String(m.chat_name ?? "") || (chatType === "p2p" ? `私聊` : "群聊"),
      actor_id: senderId,
      actor_name: String(sender.name ?? m.sender_name ?? ""),
      is_me: isMe,
      time: parseTime(m.create_time ?? m.time, this.cfg.owner.timezone),
      text: text.slice(0, 2000),
      url: m.chat_id ? `https://applink.feishu.cn/client/chat/open?openChatId=${m.chat_id}` : "",
      meta: { chat_type: chatType, message_id: m.message_id ?? m.id, thread_id: m.thread_id ?? "", parent_id: m.parent_id ?? m.root_id ?? "", sender_type: senderType },
    };
  }

  async pullIm(): Promise<{ count: number; dropped: number }> {
    const me = this.cfg.owner.open_id;
    const now = Date.now();
    const lookback = this.cfg.context.lookback_days * DAY;
    const since = Number(this.kv("cursor.im") ?? 0) || now - lookback;
    const start = isoLocal(since - 5 * 60_000); // 留 5 分钟重叠，靠 ID 去重
    const end = isoLocal(now);
    const search = async (extra: string[]) =>
      arr(await this.lark(["im", "+messages-search", "--start", start, "--end", end, "--page-all", "--page-limit", "40", "--page-size", "50", "--no-reactions", ...extra], 300_000), "messages");
    const raws: { m: Raw; kind: string }[] = [];
    for (const m of await search(["--is-at-me"])) raws.push({ m, kind: "at_me" });
    for (const m of await search(["--chat-type", "p2p"])) raws.push({ m, kind: "p2p" });
    const mine = await search(["--sender", me]);
    for (const m of mine) raws.push({ m, kind: "mine" });

    // 我发言过的群：记录最后发言时间，回看窗口内的群都继续读
    const spoken: Record<string, { name: string; at: number }> = JSON.parse(this.kv("spoken_groups") ?? "{}");
    for (const m of mine) {
      if (m.chat_type === "group" || m.chat_type === "topic_group") {
        const at = parseTime(m.create_time, this.cfg.owner.timezone);
        const cur = spoken[m.chat_id];
        if (!cur || at > cur.at) spoken[m.chat_id] = { name: String(m.chat_name ?? cur?.name ?? ""), at };
      }
    }
    for (const [id, v] of Object.entries(spoken)) if (v.at < now - lookback) delete spoken[id];
    this.setKv("spoken_groups", JSON.stringify(spoken));
    const nativeExcl = this.nativeExclusions ? await this.nativeExclusions() : undefined;
    let hadInconclusive = !!(nativeExcl?.groupsInconclusive || nativeExcl?.dmsInconclusive);
    const groups =
      this.cfg.context.groups === "allowlist"
        ? Object.fromEntries(
            this.cfg.context.groups_allow
              .map((s) => s.trim())
              // 仅保留开放平台群 ID，防止 pw_chat:* / 纯数字原生 ID 占用轮询 max_groups 配额
              .filter((id) => id && !id.startsWith("pw_chat:") && !/^\d+$/.test(id))
              .map((id) => [id, { name: spoken[id]?.name ?? "", at: now }]),
          )
        : spoken;
    const ranked = nativeExcl?.groupsInconclusive
      ? []
      : Object.entries(groups)
          .filter(([id, v]) => this.classifyExclusion(id, v.name, "group", nativeExcl, false) === "allowed")
          .sort((a, b) => b[1].at - a[1].at)
          .slice(0, this.cfg.context.max_groups);
    for (const [chatId, v] of ranked) {
      const cur = Number(this.kv(`cursor.chat.${chatId}`) ?? 0) || since;
      try {
        const data = await this.lark(["im", "+chat-messages-list", "--chat-id", chatId, "--start", isoLocal(cur - 60_000), "--end", end, "--order", "asc", "--page-all", "--page-limit", "4", "--no-reactions"]);
        let chatInconclusive = false;
        for (const m of arr(data, "messages")) {
          const enriched = { ...m, chat_name: m.chat_name || v.name, chat_type: m.chat_type || "group" };
          if (this.classifyExclusion(String(enriched.chat_id ?? chatId), String(enriched.chat_name ?? ""), String(enriched.chat_type ?? "group"), nativeExcl) === "inconclusive") {
            chatInconclusive = true;
            hadInconclusive = true;
            continue;
          }
          raws.push({ m: enriched, kind: "group" });
        }
        if (!chatInconclusive) this.setKv(`cursor.chat.${chatId}`, String(now));
      } catch {
        // 单个群失败下轮重试
      }
    }

    let dropped = 0;
    const obs: Obs[] = [];
    const seen = new Set<string>();
    for (const { m, kind } of raws) {
      const id = String(m.message_id ?? m.id ?? "");
      if (!id || seen.has(id)) continue;
      seen.add(id);
      const senderType = String(m.sender?.sender_type ?? m.sender?.type ?? m.sender_type ?? "");
      if (senderType === "app" && !this.botAllowed(m)) {
        dropped++;
        continue;
      }
      const excl = this.classifyExclusion(String(m.chat_id ?? ""), String(m.chat_name ?? ""), String(m.chat_type ?? ""), nativeExcl);
      if (excl === "denied") {
        dropped++;
        continue;
      }
      if (excl === "inconclusive") {
        // 排除规则无法实时确认：不入库也不当成正常丢弃，并保留 cursor.im 供恢复后补拉
        hadInconclusive = true;
        continue;
      }
      const o = this.toObs(m, kind, me);
      if (o) obs.push(o);
    }
    // 私聊没有会话名：用对方名字
    const p2pName = new Map<string, string>();
    for (const o of obs) if (o.meta.chat_type === "p2p" && !o.is_me && o.actor_name) p2pName.set(o.conv, o.actor_name);
    for (const o of obs) if (o.meta.chat_type === "p2p") o.conv_name = `私聊：${p2pName.get(o.conv) ?? o.conv_name}`;
    const n = this.store.addObs(obs);
    if (!hadInconclusive) this.setKv("cursor.im", String(now));
    return { count: n, dropped };
  }

  // ───────── 妙记 → 观测 ─────────

  async pullMinutes(): Promise<{ count: number }> {
    const now = Date.now();
    const since = Number(this.kv("cursor.minutes") ?? 0) || now - this.cfg.context.lookback_days * DAY;
    const list: Raw[] = [];
    let token: string | undefined;
    for (let i = 0; i < 5; i++) {
      const data = await this.lark(["minutes", "+search", "--participant-ids", "me", "--start", isoLocal(since), "--end", isoLocal(now), "--page-size", "30", ...(token ? ["--page-token", token] : [])]);
      list.push(...arr(data, "items"));
      token = data?.page_token;
      if (!data?.has_more || !token) break;
    }
    const tokens = list.map((x) => String(x.token ?? x.minute_token ?? "")).filter(Boolean);
    const obs: Obs[] = [];
    for (let i = 0; i < tokens.length; i += 10) {
      const d = await this.lark(["minutes", "+detail", "--minute-tokens", tokens.slice(i, i + 10).join(","), "--summary", "--todo"]);
      const details = arr(d, "minutes").length ? arr(d, "minutes") : [d];
      for (const m of details) {
        const tk = String(m.minute_token ?? "");
        if (!tk) continue;
        const a = m.artifacts ?? {};
        const meta = list.find((x) => (x.token ?? x.minute_token) === tk)?.meta_data ?? {};
        const todos = (Array.isArray(a.todos) ? a.todos : []).map((t: Raw) => `- ${textOf(t.content ?? t)}${t.is_done ? "（已完成）" : ""}`).join("\n");
        const startMatch = String(meta.description ?? "").match(/开始时间:\s*([\d.]+\s+[\d:]+)/);
        const time = startMatch ? parseTime(startMatch[1].replace(/\./g, "-"), this.cfg.owner.timezone) : now;
        obs.push({
          id: `minutes:${tk}`,
          source: "minutes",
          kind: "minutes",
          conv: `minutes:${tk}`,
          conv_name: `会议：${m.title ?? tk}`,
          actor_id: "",
          actor_name: "智能纪要",
          is_me: false,
          time,
          text: `会议「${m.title ?? ""}」\n摘要：${textOf(a.summary ?? "").slice(0, 3000)}\n待办：\n${todos || "（无）"}`,
          url: String(meta.app_link ?? `${this.cfg.lark_web}/minutes/${tk}`),
          meta: {},
        });
      }
    }
    const n = this.store.addObs(obs);
    this.setKv("cursor.minutes", String(now));
    return { count: n };
  }

  // ───────── 文档评论 @我：事件已落在 signals 表（capture.onComment），这里转成观测 ─────────

  pullComments(): { count: number } {
    const since = Number(this.kv("cursor.comments") ?? 0);
    const rows = this.store.db
      .prepare("SELECT id, text, link, at FROM signals WHERE id LIKE 'comment:%' AND at > ? ORDER BY at LIMIT 200")
      .all(since) as { id: string; text: string; link: string; at: number }[];
    if (!rows.length) return { count: 0 };
    const obs: Obs[] = rows.map((r) => ({
      id: `doc:${r.id}`,
      source: "doc",
      kind: "doc_comment",
      conv: `doc:${r.link}`,
      conv_name: `文档评论：${r.link.split("/").slice(-2).join("/")}`,
      actor_id: "",
      actor_name: "文档评论@我",
      is_me: false,
      time: r.at,
      text: textOf(r.text).slice(0, 2000),
      url: r.link,
      meta: {},
    }));
    const n = this.store.addObs(obs);
    this.setKv("cursor.comments", String(Math.max(...rows.map((r) => r.at))));
    return { count: n };
  }

  // ───────── 日历：今天和接下来两天的会议（只用于展示） ─────────

  async pullCalendar(): Promise<{ count: number }> {
    const now = Date.now();
    const startOfDay = parseTime(new Intl.DateTimeFormat("en-CA", { timeZone: this.cfg.owner.timezone }).format(new Date(now)), this.cfg.owner.timezone);
    const data = await this.lark(["calendar", "+agenda", "--start", isoLocal(startOfDay), "--end", isoLocal(startOfDay + 3 * DAY)]);
    const events = arr(data, "items").length ? arr(data, "items") : arr(data, "events");
    const t = (x: Raw) => parseTime(x?.datetime ?? x?.timestamp ?? x?.date ?? x, this.cfg.owner.timezone);
    const meetings = events
      .filter((e) => e.self_rsvp_status !== "decline")
      .map((e) => ({ start: t(e.start_time), end: t(e.end_time), summary: String(e.summary ?? "(无标题)"), url: String(e.app_link ?? "") }))
      .filter((m) => m.start > 0)
      .sort((a, b) => a.start - b.start);
    this.setKv("calendar", JSON.stringify(meetings));
    return { count: meetings.length };
  }
}

/** 一个 Meego 工作项是否被某项目引用（理解层把具体项目和工作项挂上后，事项从空间项目移到具体项目） */
export function relinkMeegoItems(store: ContextStore): number {
  let moved = 0;
  for (const it of store.items({ status: ["open", "snoozed"], source: "meego" })) {
    const id = String(it.meta.work_item_id ?? "");
    if (!id) continue;
    const p = store.findProject(`meego:${id}`);
    if (p && p.id !== it.project_id) {
      store.setItemField(it.id, { project_id: p.id });
      moved++;
    }
  }
  return moved;
}

export { hashId, norm };
