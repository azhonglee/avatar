import type { App } from "../app.ts";
import { deepFind, runProcess } from "../util.ts";
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

export interface SpokenGroupEntry {
  name: string;
  at: number;
}

export const OPEN_GROUP_NAMES_KV_KEY = "ctx.open_group_names";

export function loadSpokenGroups(store: App["store"]): Record<string, SpokenGroupEntry> {
  try {
    return JSON.parse(store.get("ctx.spoken_groups") ?? "{}") as Record<string, SpokenGroupEntry>;
  } catch {
    return {};
  }
}

export function loadKnownOpenGroupNames(store: App["store"]): Record<string, string> {
  try {
    const raw = JSON.parse(store.get(OPEN_GROUP_NAMES_KV_KEY) ?? "{}") as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v === "string" && v.trim()) out[k] = v.trim();
    }
    return out;
  } catch {
    return {};
  }
}

export function rememberOpenGroupName(store: App["store"], chatId: string, name: string): void {
  mergeKnownOpenGroupNames(store, new Map([[chatId, name]]));
}

/** 一次性合并增量学习到的开放平台群名，避免写事务内逐条重解析整个缓存或用旧快照覆盖在线监听刚刷新的群名 */
export function mergeKnownOpenGroupNames(store: App["store"], delta: ReadonlyMap<string, string>): void {
  if (delta.size === 0) return;
  const cur = loadKnownOpenGroupNames(store);
  let changed = false;
  for (const [rawId, rawName] of delta) {
    const id = rawId.trim();
    const clean = rawName.trim();
    if (!id || !clean || clean === "群聊" || clean.startsWith("私聊")) continue;
    if (cur[id] !== clean) {
      cur[id] = clean;
      changed = true;
    }
  }
  if (!changed) return;
  const keys = Object.keys(cur);
  if (keys.length > 500) {
    for (const old of keys.slice(0, keys.length - 500)) delete cur[old];
  }
  store.set(OPEN_GROUP_NAMES_KV_KEY, JSON.stringify(cur));
}

export function isOpenGroupDirectlyDenied(
  cfg: App["cfg"],
  store: ContextStore,
  chatId: string,
  chatName: string,
  nativeExcl?: NativePollingExclusions,
): boolean {
  if (chatId && store.isConvMutedById(chatId)) return true;
  if (
    cfg.context.groups_deny.some((raw) => {
      const d = raw.trim();
      if (!d) return false;
      if (chatId === d) return true;
      // 仅 oc_* 与 pw_chat:* 视作会话 ID；纯数字（如 "2024"）保持原有群名关键词排除语义
      if (!d.startsWith("oc_") && !d.startsWith("pw_chat:") && chatName && chatName.includes(d)) return true;
      return false;
    })
  ) {
    return true;
  }
  if (chatName && nativeExcl?.confirmedGroupNames.has(norm(chatName))) return true;
  return false;
}

/**
 * 统一的开放平台群（oc_*）生效范围选择：
 *   - `allowlist` 模式：去重保留开放平台群 ID，使用 spoken_groups / 已知群名缓存 / 观测记录补齐名称，
 *     先过滤被静音或按群名/ID 排除的群，再按 max_groups 截断（避免被群名排除的 A 占掉 B 的名额）；
 *   - `spoken` 模式：从回看窗口内的 spoken_groups 中过滤被静音/排除的群，按最近发言时间倒序取前 max_groups 个。
 * 由采集器 `pullIm` 与理解/起草范围过滤共享，保证两处口径完全一致。
 */
export function selectEffectiveOpenGroups(params: {
  cfg: App["cfg"];
  store: ContextStore;
  spoken: Record<string, SpokenGroupEntry>;
  knownNames?: Record<string, string>;
  nativeExcl?: NativePollingExclusions;
  now?: number;
}): [string, SpokenGroupEntry][] {
  const { cfg, store, spoken, knownNames, nativeExcl } = params;
  const now = params.now ?? Date.now();
  const lookback = cfg.context.lookback_days * DAY;
  const maxGroups = Math.max(0, cfg.context.max_groups);

  const resolveName = (id: string, fallback = ""): string => {
    const first = (fallback || knownNames?.[id] || spoken[id]?.name || "").trim();
    if (first && first !== "群聊" && !first.startsWith("私聊")) return first;
    const obsName = (store.latestConvObs(id)?.conv_name ?? "").trim();
    return obsName && obsName !== "群聊" && !obsName.startsWith("私聊") ? obsName : "";
  };

  if (cfg.context.groups === "allowlist") {
    if (maxGroups === 0) return [];
    const out: [string, SpokenGroupEntry][] = [];
    const seen = new Set<string>();
    for (const raw of cfg.context.groups_allow) {
      const id = raw.trim();
      if (!id || seen.has(id) || id.startsWith("pw_chat:") || /^\d+$/.test(id)) continue;
      seen.add(id);
      const name = resolveName(id);
      if (isOpenGroupDirectlyDenied(cfg, store, id, name, nativeExcl)) continue;
      out.push([id, { name, at: now }]);
      if (out.length >= maxGroups) break;
    }
    return out;
  }

  return Object.entries(spoken)
    .map(([id, v]): [string, SpokenGroupEntry] => [id, { name: resolveName(id, v.name), at: v.at }])
    .filter(([id, v]) => v.at >= now - lookback && !isOpenGroupDirectlyDenied(cfg, store, id, v.name, nativeExcl))
    .sort((a, b) => b[1].at - a[1].at)
    .slice(0, maxGroups);
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

  private hasNameDenyPatterns(): boolean {
    return this.cfg.context.groups_deny.some((raw) => {
      const d = raw.trim();
      return !!d && !d.startsWith("oc_") && !d.startsWith("pw_chat:");
    });
  }

  private pollingPolicySignature(): string {
    const mutes = this.store
      .mutedConvs()
      .map((m) => `${m.conv}=${m.name}`)
      .sort()
      .join("|");
    const deny = [...this.cfg.context.groups_deny].map((s) => s.trim()).sort().join("|");
    // 保留 groups_allow 顺序：在 max_groups 截断下，白名单顺序变化同样改变选中群集合；包含 lookback_days 以感知 spoken 回看窗口变化
    const allow = this.cfg.context.groups_allow.map((s) => s.trim()).join("|");
    return `${this.cfg.context.sources.im ? 1 : 0};${this.cfg.context.groups};${this.cfg.context.max_groups};${this.cfg.context.lookback_days};${allow};${deny};${mutes}`;
  }

  private async resolveCurrentChatMeta(chatId: string): Promise<{ name: string; chatType: "p2p" | "group" | "" } | undefined> {
    try {
      const res = (await this.lark(["im", "chats", "get", "--params", JSON.stringify({ chat_id: chatId })], 15_000)) as Record<string, unknown>;
      const name = String(deepFind(res, "name") ?? "").trim();
      const rawMode = String(deepFind(res, "chat_mode") ?? deepFind(res, "chat_type") ?? "").trim().toLowerCase();
      const chatType: "p2p" | "group" | "" =
        rawMode === "p2p" ? "p2p" : rawMode === "group" || rawMode === "topic" || rawMode === "topic_group" ? "group" : "";
      return { name, chatType };
    } catch {
      return undefined;
    }
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
    const ct = chatType.trim().toLowerCase();
    const isKnownDm = ct === "p2p";
    const isKnownGroup = ct === "group" || ct === "topic" || ct === "topic_group";
    const needsNameForRules = this.hasNameDenyPatterns() || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
    if (!nativeExcl) {
      if (!isKnownDm && !chatName && requireName && this.hasNameDenyPatterns()) return "inconclusive";
      return "allowed";
    }
    if (isKnownDm) return nativeExcl.dmsInconclusive ? "inconclusive" : "allowed";
    if (chatName && nativeExcl.confirmedGroupNames.has(norm(chatName))) return "denied";
    if (isKnownGroup) {
      if (nativeExcl.groupsInconclusive) return "inconclusive";
      if (needsNameForRules && !chatName && requireName) return "inconclusive";
      return "allowed";
    }
    // 缺失或未知 chat_type 时既可能是私聊也可能是群聊：只要任一可能类型受限即按 inconclusive 暂缓
    if (nativeExcl.dmsInconclusive || nativeExcl.groupsInconclusive) return "inconclusive";
    if (needsNameForRules && !chatName && requireName) return "inconclusive";
    return "allowed";
  }

  private toObs(m: Raw, kind: string, me: string, atMeWindowStartMs?: number): Obs | undefined {
    const sender = m.sender ?? {};
    const senderType = String(sender.sender_type ?? sender.type ?? m.sender_type ?? "");
    const msgType = String(m.msg_type ?? m.message_type ?? "");
    if (["sticker", "system"].includes(msgType)) return undefined;
    const chatType = String(m.chat_type ?? "");
    const senderId = String(sender.id ?? sender.open_id ?? m.sender_id ?? "");
    const isMe = senderId === me;
    const text = textOf(m.content ?? m.text ?? "");
    if (!text) return undefined;
    const msgTime = parseTime(m.create_time ?? m.time, this.cfg.owner.timezone);
    // 独立记录 @我 判定状态：
    //   - 命中 --is-at-me 时记 at_me: true（确保白名单机器人 kind="bot" 也被识别为真实 @我）；
    //   - 落在本次 --is-at-me 查询窗口内但未命中时，明确记 at_me: false（用于覆盖已被编辑移除的旧 @我 标记）；
    //   - 早于 --is-at-me 查询窗口的历史消息未参与本次 @我 检索，省略 at_me 以保留原值不误清。
    const atMeMeta: Record<string, unknown> =
      kind === "at_me"
        ? { at_me: true }
        : atMeWindowStartMs !== undefined && msgTime >= atMeWindowStartMs
          ? { at_me: false }
          : {};
    return {
      id: `im:${m.message_id ?? m.id}`,
      source: "im",
      kind: senderType === "app" ? "bot" : isMe ? "mine" : chatType === "p2p" ? "p2p" : kind,
      conv: String(m.chat_id ?? ""),
      conv_name: String(m.chat_name ?? "") || (chatType === "p2p" ? `私聊` : "群聊"),
      actor_id: senderId,
      actor_name: String(sender.name ?? m.sender_name ?? ""),
      is_me: isMe,
      time: msgTime,
      text: text.slice(0, 2000),
      url: m.chat_id ? `https://applink.feishu.cn/client/chat/open?openChatId=${m.chat_id}` : "",
      meta: {
        chat_type: chatType,
        message_id: m.message_id ?? m.id,
        thread_id: m.thread_id ?? "",
        parent_id: m.parent_id ?? m.root_id ?? "",
        sender_type: senderType,
        ...atMeMeta,
      },
    };
  }

  async pullIm(restartAttempt = 0): Promise<{ count: number; dropped: number }> {
    const me = this.cfg.owner.open_id;
    const now = Date.now();
    const lookback = this.cfg.context.lookback_days * DAY;
    const baseCursor = Number(this.kv("cursor.im") ?? 0) || now - lookback;
    const hadPriorAtMe = Number(this.kv("cursor.im.at_me") ?? 0) > 0;
    const hadPriorP2p = Number(this.kv("cursor.im.p2p") ?? 0) > 0;
    const hadPriorMine = Number(this.kv("cursor.im.mine") ?? 0) > 0;
    const hadPriorGroups = Number(this.kv("cursor.im.groups") ?? 0) > 0;
    const sinceAtMe = Number(this.kv("cursor.im.at_me") ?? 0) || baseCursor;
    const sinceP2p = Number(this.kv("cursor.im.p2p") ?? 0) || baseCursor;
    const sinceMine = Number(this.kv("cursor.im.mine") ?? 0) || baseCursor;
    const sinceGroups = Number(this.kv("cursor.im.groups") ?? 0) || baseCursor;
    const end = isoLocal(now);
    const SEARCH_PAGE_LIMIT = 40;
    const SEARCH_PAGE_SIZE = 50;
    const searchRaw = async (sinceMs: number, extra: string[]) =>
      this.lark(
        [
          "im",
          "+messages-search",
          "--start",
          isoLocal(sinceMs - 5 * 60_000),
          "--end",
          end,
          "--page-all",
          "--page-limit",
          String(SEARCH_PAGE_LIMIT),
          "--page-size",
          String(SEARCH_PAGE_SIZE),
          "--no-reactions",
          ...extra,
        ],
        300_000,
      );
    const searchFrom = async (sinceMs: number, extra: string[]) => arr(await searchRaw(sinceMs, extra), "messages");

    let policySig = this.pollingPolicySignature();
    const initialGroupsMode = this.cfg.context.groups;
    const initialMaxGroups = this.cfg.context.max_groups;
    const initialLookbackDays = this.cfg.context.lookback_days;
    const initialAllowOrder = this.cfg.context.groups_allow.map((s) => s.trim()).join("|");
    const atMeWindowStartMs = Math.ceil((sinceAtMe - 5 * 60_000) / 1000) * 1000;
    let nativeExcl = this.nativeExclusions ? await this.nativeExclusions() : undefined;

    const metaCache = new Map<string, { name: string; chatType: "p2p" | "group" | "" } | null>();
    const getChatMeta = async (chatId: string) => {
      if (metaCache.has(chatId)) return metaCache.get(chatId) ?? undefined;
      const resolved = await this.resolveCurrentChatMeta(chatId);
      metaCache.set(chatId, resolved ?? null);
      return resolved;
    };

    type StreamKind = "at_me" | "p2p" | "mine" | "group";
    const raws: { m: Raw; kind: string; stream: StreamKind; fallbackGroupName?: string }[] = [];
    const atMeRawResp = await searchRaw(sinceAtMe, ["--is-at-me"]);
    const atMeMsgs = arr(atMeRawResp, "messages");
    // 仅当 --is-at-me 返回完整未截断的结果集（无 has_more 且未触达 40×50 上限）时，才对窗口内未命中的群消息推断 at_me: false
    const atMeSearchTruncated =
      deepFind(atMeRawResp, "has_more") === true || atMeMsgs.length >= SEARCH_PAGE_LIMIT * SEARCH_PAGE_SIZE;
    const effectiveAtMeWindowStartMs = atMeSearchTruncated ? undefined : atMeWindowStartMs;
    for (const m of atMeMsgs) raws.push({ m, kind: "at_me", stream: "at_me" });
    const fetchedP2p = !nativeExcl?.dmsInconclusive;
    if (fetchedP2p) {
      // 保留查询条件已知的 chat_type="p2p"，防止接口缺省单行 chat_type 时落入群聊分支
      for (const m of await searchFrom(sinceP2p, ["--chat-type", "p2p"])) {
        raws.push({ m: { ...m, chat_type: m.chat_type || "p2p" }, kind: "p2p", stream: "p2p" });
      }
    }
    const mine = await searchFrom(sinceMine, ["--sender", me]);
    for (const m of mine) raws.push({ m, kind: "mine", stream: "mine" });

    // 我发言过的群：记录最后发言时间，回看窗口内的群都继续读
    const spoken: Record<string, SpokenGroupEntry> = loadSpokenGroups(this.app.store);
    const knownNames: Record<string, string> = loadKnownOpenGroupNames(this.app.store);
    // 仅追踪本轮轮询新学到的群名增量，提交时一次性合并进最新缓存，绝不把旧快照整体覆写回去
    const learnedNames = new Map<string, string>();
    const recordLearnedName = (cid: string, cname: string) => {
      const clean = cname.trim();
      if (!cid || !clean || clean === "群聊" || clean.startsWith("私聊")) return;
      knownNames[cid] = clean;
      if (cid.startsWith("oc_")) learnedNames.set(cid, clean);
    };
    for (const m of mine) {
      if (m.chat_type === "group" || m.chat_type === "topic_group") {
        const at = parseTime(m.create_time, this.cfg.owner.timezone);
        const cur = spoken[m.chat_id];
        const cname = String(m.chat_name ?? cur?.name ?? "").trim();
        if (!cur || at > cur.at) spoken[m.chat_id] = { name: cname, at };
        if (cname && m.chat_id) recordLearnedName(m.chat_id, cname);
      }
    }
    for (const [id, v] of Object.entries(spoken)) if (v.at < now - lookback) delete spoken[id];

    const scannedGroups = !nativeExcl?.groupsInconclusive;
    const needsNameForRanking = this.hasNameDenyPatterns() || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
    if (scannedGroups && needsNameForRanking && this.cfg.context.max_groups > 0) {
      const refreshCandidateNameIfNeeded = async (id: string, fallbackName = ""): Promise<string> => {
        let name = (knownNames[id] || spoken[id]?.name || fallbackName || this.store.latestConvObs(id)?.conv_name || "").trim();
        if (name === "群聊" || name.startsWith("私聊")) name = "";
        // 若名称缺失，或旧缓存名称正触发按名称排除，实时刷新一次当前群名（避免改名后的白名单/发言群永远困在旧排除缓存里）
        const excludedByCachedName = !!name && isOpenGroupDirectlyDenied(this.cfg, this.store, id, name, nativeExcl);
        if (!name || excludedByCachedName) {
          const fresh = await getChatMeta(id);
          if (fresh?.name) {
            name = fresh.name;
            if (spoken[id]) spoken[id].name = name;
            recordLearnedName(id, name);
          }
        }
        return name;
      };
      const isDeniedByDirectId = (id: string) =>
        this.store.isConvMutedById(id) || this.cfg.context.groups_deny.some((d) => d.trim() === id);

      if (this.cfg.context.groups === "allowlist") {
        const seenAllow = new Set<string>();
        let allowedCount = 0;
        for (const raw of this.cfg.context.groups_allow) {
          const id = raw.trim();
          if (!id || seenAllow.has(id) || id.startsWith("pw_chat:") || /^\d+$/.test(id)) continue;
          seenAllow.add(id);
          if (isDeniedByDirectId(id)) continue;
          const name = await refreshCandidateNameIfNeeded(id);
          if (!isOpenGroupDirectlyDenied(this.cfg, this.store, id, name, nativeExcl)) {
            allowedCount++;
            if (allowedCount >= this.cfg.context.max_groups) break;
          }
        }
      } else {
        let allowedCount = 0;
        const candidates = Object.entries(spoken)
          .filter(([, v]) => v.at >= now - lookback)
          .sort((a, b) => b[1].at - a[1].at);
        for (const [id, v] of candidates) {
          if (isDeniedByDirectId(id)) continue;
          const name = await refreshCandidateNameIfNeeded(id, v.name);
          if (!isOpenGroupDirectlyDenied(this.cfg, this.store, id, name, nativeExcl)) {
            allowedCount++;
            if (allowedCount >= this.cfg.context.max_groups) break;
          }
        }
      }
    }

    const initialSpokenSnapshot: Record<string, SpokenGroupEntry> = Object.fromEntries(
      Object.entries(spoken).map(([k, v]) => [k, { ...v }]),
    );
    const initialKnownNamesSnapshot: Record<string, string> = { ...knownNames };
    const ranked = !scannedGroups
      ? []
      : selectEffectiveOpenGroups({
          cfg: this.cfg,
          store: this.store,
          spoken: initialSpokenSnapshot,
          knownNames: initialKnownNamesSnapshot,
          nativeExcl,
          now,
        });
    const initialRankedKey = ranked.map(([id]) => id).join(",");
    const rankedSet = new Set(ranked.map(([id]) => id));

    const chatPollState = new Map<string, { startCur: number; hadPriorCursor: boolean; fetchFailed: boolean; hadInconclusiveRow: boolean }>();
    for (const [chatId, v] of ranked) {
      const priorRaw = this.kv(`cursor.chat.${chatId}`);
      const hadPriorCursor = !!priorRaw && Number(priorRaw) > 0;
      const startCur = (hadPriorCursor ? Number(priorRaw) : 0) || sinceGroups;
      const st = { startCur, hadPriorCursor, fetchFailed: false, hadInconclusiveRow: false };
      chatPollState.set(chatId, st);
      try {
        const data = await this.lark([
          "im",
          "+chat-messages-list",
          "--chat-id",
          chatId,
          "--start",
          isoLocal(startCur - 60_000),
          "--end",
          end,
          "--order",
          "asc",
          "--page-all",
          "--page-limit",
          "4",
          "--no-reactions",
        ]);
        for (const m of arr(data, "messages")) {
          raws.push({
            m: { ...m, chat_id: m.chat_id || chatId, chat_type: m.chat_type || "group" },
            kind: "group",
            stream: "group",
            fallbackGroupName: v.name,
          });
        }
      } catch {
        st.fetchFailed = true;
      }
    }

    // 先按 message_id 合并多路搜索/群拉取的字段（避免搜索命中缺 chat_name 提前占坑导致后续带完整元数据的群行被去重丢弃）
    const kindRank: Record<string, number> = { at_me: 4, p2p: 3, mine: 2, group: 1 };
    const mergedById = new Map<
      string,
      { m: Raw; kind: string; streams: Set<StreamKind>; fallbackGroupName: string }
    >();
    for (const row of raws) {
      const id = String(row.m.message_id ?? row.m.id ?? "");
      if (!id) continue;
      const existing = mergedById.get(id);
      if (!existing) {
        mergedById.set(id, {
          m: { ...row.m },
          kind: row.kind,
          streams: new Set([row.stream]),
          fallbackGroupName: row.fallbackGroupName ?? "",
        });
      } else {
        existing.streams.add(row.stream);
        if (!existing.m.chat_id && row.m.chat_id) existing.m.chat_id = row.m.chat_id;
        if (!String(existing.m.chat_name ?? "").trim() && String(row.m.chat_name ?? "").trim()) {
          existing.m.chat_name = row.m.chat_name;
        }
        if (!String(existing.m.chat_type ?? "").trim() && String(row.m.chat_type ?? "").trim()) {
          existing.m.chat_type = row.m.chat_type;
        }
        if (!existing.fallbackGroupName && row.fallbackGroupName) {
          existing.fallbackGroupName = row.fallbackGroupName;
        }
        if ((kindRank[row.kind] ?? 0) > (kindRank[existing.kind] ?? 0)) {
          existing.kind = row.kind;
        }
      }
    }

    const scopeSelectionChanged = (latestExcl?: NativePollingExclusions): boolean => {
      if (
        this.cfg.context.groups !== initialGroupsMode ||
        this.cfg.context.max_groups !== initialMaxGroups ||
        this.cfg.context.lookback_days !== initialLookbackDays ||
        this.cfg.context.groups_allow.map((s) => s.trim()).join("|") !== initialAllowOrder ||
        (!latestExcl?.groupsInconclusive) !== scannedGroups
      ) {
        return true;
      }
      const rechecked = !latestExcl?.groupsInconclusive
        ? selectEffectiveOpenGroups({
            cfg: this.cfg,
            store: this.store,
            spoken: initialSpokenSnapshot,
            knownNames: initialKnownNamesSnapshot,
            nativeExcl: latestExcl,
            now,
          })
            .map(([id]) => id)
            .join(",")
        : "";
      return rechecked !== initialRankedKey;
    };

    // 提交前检测静音/排除策略与选群集合是否在分页拉取期间变更：
    // 若选中群集合变化（例如 allowlist 从 A 改为 B 或静音触发 max_groups 补位），绝不落库旧群消息或推进游标，而是重启一轮拉取（最多 1 次，仍变更则直接丢弃）
    for (let attempt = 0; attempt < 2; attempt++) {
      const latestSig = this.pollingPolicySignature();
      if (latestSig !== policySig) {
        policySig = latestSig;
        nativeExcl = this.nativeExclusions ? await this.nativeExclusions() : undefined;
      }
      if (!this.cfg.context.sources.im) {
        return { count: 0, dropped: 0 };
      }
      if (scopeSelectionChanged(nativeExcl)) {
        if (restartAttempt < 1) {
          return this.pullIm(restartAttempt + 1);
        }
        return { count: 0, dropped: 0 };
      }

      let atMeBlocked = !!nativeExcl?.groupsInconclusive;
      let p2pBlocked = !!nativeExcl?.dmsInconclusive || !fetchedP2p;
      let mineBlocked = !!nativeExcl?.groupsInconclusive;
      let groupsBlocked = !!nativeExcl?.groupsInconclusive || !scannedGroups;
      for (const st of chatPollState.values()) st.hadInconclusiveRow = false;

      const needsCurrentName = this.hasNameDenyPatterns() || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
      const needsTypeLookup = !!(nativeExcl?.dmsInconclusive || nativeExcl?.groupsInconclusive);

      let dropped = 0;
      const obs: Obs[] = [];

      for (const entry of mergedById.values()) {
        const m = { ...entry.m };
        const senderType = String(m.sender?.sender_type ?? m.sender?.type ?? m.sender_type ?? "");
        if (senderType === "app" && !this.botAllowed(m)) {
          dropped++;
          continue;
        }
        const chatId = String(m.chat_id ?? "");
        let chatType = String(m.chat_type ?? "").trim();
        let chatName = String(m.chat_name ?? "").trim();

        // 对缺失 chat_name（有名称/原生静音规则）或缺失 chat_type（受限状态）的命中实时查一次 im chats get，不凭陈旧 spoken_groups 放行
        const shouldLookupMeta =
          !!chatId &&
          chatType.toLowerCase() !== "p2p" &&
          ((!chatName && needsCurrentName) || (!chatType && (needsTypeLookup || needsCurrentName)));
        if (shouldLookupMeta) {
          const fresh = await getChatMeta(chatId);
          if (fresh) {
            if (!chatName && fresh.name) chatName = fresh.name;
            if (!chatType && fresh.chatType) chatType = fresh.chatType;
          }
        }
        if (!chatName && !needsCurrentName && entry.fallbackGroupName) {
          chatName = entry.fallbackGroupName;
        }
        if (chatName && chatId) {
          if (spoken[chatId]) spoken[chatId].name = chatName;
          if (chatId.startsWith("oc_") && chatType.toLowerCase() !== "p2p") {
            recordLearnedName(chatId, chatName);
          }
        }
        m.chat_name = chatName;
        m.chat_type = chatType;

        const excl = this.classifyExclusion(chatId, chatName, chatType, nativeExcl);
        if (excl === "denied") {
          dropped++;
          continue;
        }
        if (excl === "inconclusive") {
          const isKnownDm = chatType.toLowerCase() === "p2p";
          if (isKnownDm) {
            p2pBlocked = true;
          } else {
            for (const s of entry.streams) {
              if (s === "p2p") p2pBlocked = true;
              else if (s === "at_me") atMeBlocked = true;
              else if (s === "mine") mineBlocked = true;
              else if (s === "group") {
                const st = chatPollState.get(chatId);
                if (st) st.hadInconclusiveRow = true;
                else groupsBlocked = true;
              }
            }
          }
          continue;
        }
        // allowlist 模式下，不在当前选中群集合里的非 @我 普通群消息（如本人发在白名单外群的消息）不入库
        if (
          this.cfg.context.groups === "allowlist" &&
          entry.kind !== "at_me" &&
          chatType.toLowerCase() !== "p2p" &&
          chatId.startsWith("oc_") &&
          !rankedSet.has(chatId)
        ) {
          dropped++;
          continue;
        }
        const o = this.toObs(m, entry.kind, me, effectiveAtMeWindowStartMs);
        if (o) obs.push(o);
      }

      // 若拉取消息期间学到的新群名导致生效群选排变化（例如群 A 改名命中排除规则，空出名额给群 B），
      // 先持久化新学到的群名，再不推进游标重启一轮拉取以补采接替群 B，避免推进 cursor.im.groups 遗漏 B 的消息
      if (learnedNames.size > 0 && !nativeExcl?.groupsInconclusive) {
        const learnedRankedKey = selectEffectiveOpenGroups({
          cfg: this.cfg,
          store: this.store,
          spoken,
          knownNames,
          nativeExcl,
          now,
        })
          .map(([id]) => id)
          .join(",");
        if (learnedRankedKey !== initialRankedKey) {
          mergeKnownOpenGroupNames(this.app.store, learnedNames);
          if (restartAttempt < 1) {
            return this.pullIm(restartAttempt + 1);
          }
          return { count: 0, dropped: 0 };
        }
      }

      // 私聊没有会话名：用对方名字
      const p2pName = new Map<string, string>();
      for (const o of obs) if (o.meta.chat_type === "p2p" && !o.is_me && o.actor_name) p2pName.set(o.conv, o.actor_name);
      for (const o of obs) if (o.meta.chat_type === "p2p") o.conv_name = `私聊：${p2pName.get(o.conv) ?? o.conv_name}`;

      // 原子事务提交前最后一次核对策略签名与群选择集合：若期间策略变更则重试/重启，绝不提交过期的观测或游标
      const commitRes = this.store.tx(() => {
        if (this.pollingPolicySignature() !== policySig || scopeSelectionChanged(nativeExcl)) {
          return { committed: false as const, count: 0 };
        }
        if (!this.cfg.context.sources.im) {
          return { committed: true as const, count: 0 };
        }
        const n = this.store.addObs(obs);
        this.setKv("spoken_groups", JSON.stringify(spoken));
        mergeKnownOpenGroupNames(this.app.store, learnedNames);
        for (const [chatId, st] of chatPollState) {
          if (st.fetchFailed || st.hadInconclusiveRow || nativeExcl?.groupsInconclusive) {
            // 首次拉取该群即受阻时，持久化原始起点 startCur，防止随后推进 cursor.im.groups 跳过未拉到的历史消息
            if (!st.hadPriorCursor) this.setKv(`cursor.chat.${chatId}`, String(st.startCur));
          } else {
            this.setKv(`cursor.chat.${chatId}`, String(now));
          }
        }
        // 任一未扫描或受阻的流，在尚无既有游标时持久化其原始起始游标（since*），
        // 避免新工作区下轮重算 Date.now() - lookback 而丢失首窗口开头的历史消息
        if (!atMeBlocked) this.setKv("cursor.im.at_me", String(now));
        else if (!hadPriorAtMe) this.setKv("cursor.im.at_me", String(sinceAtMe));

        if (!p2pBlocked) this.setKv("cursor.im.p2p", String(now));
        else if (!hadPriorP2p) this.setKv("cursor.im.p2p", String(sinceP2p));

        if (!mineBlocked) this.setKv("cursor.im.mine", String(now));
        else if (!hadPriorMine) this.setKv("cursor.im.mine", String(sinceMine));

        if (!groupsBlocked) this.setKv("cursor.im.groups", String(now));
        else if (!hadPriorGroups) this.setKv("cursor.im.groups", String(sinceGroups));

        if (!atMeBlocked && !p2pBlocked && !mineBlocked && !groupsBlocked) this.setKv("cursor.im", String(now));
        return { committed: true as const, count: n };
      });
      if (commitRes.committed) {
        return { count: commitRes.count, dropped };
      }
    }

    // 连续两轮策略均在提交瞬间变更：本轮安全跳过落库与游标推进，留待下轮按最新策略重试
    return { count: 0, dropped: 0 };
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
