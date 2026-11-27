import { randomUUID } from "node:crypto";
import type { App } from "../app.ts";
import { verifyActiveLarkUser } from "../lark.ts";
import { deepFind, errMsg, runProcess } from "../util.ts";
import { hasWorkspaceOwnerMismatch } from "./personal-web.ts";
import { hashId, norm, type ContextStore, type Obs } from "./store.ts";

/**
 * 采集器：只读地从飞书 / Meego 拉取信号，写成观测；Meego 待办和飞书任务直接成为事项（确定性，不需要模型）。
 * 增量游标存在 kv（ctx.cursor.*）。每个来源相互隔离，一个失败不影响其他。
 */

const DAY = 86_400_000;
const IM_POLL_CLAIM_KEY = "__poll_im__";

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

/** 仅解析显式整数修订版本号（edit_version），绝不与 epoch 时间戳混用同一标尺 */
function parseEditCounter(m: Raw): number | undefined {
  const raw = m.edit_version;
  if (typeof raw === "number" && Number.isFinite(raw) && Number.isInteger(raw) && raw > 0) return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw.trim())) {
    const n = Number(raw.trim());
    return Number.isSafeInteger(n) && n > 0 ? n : undefined;
  }
  return undefined;
}

/** 仅解析并归一化编辑/更新时间戳（update_time / edit_time → epoch 毫秒），绝不与 edit_version 计数混比 */
function parseEditTimeMs(m: Raw, tz: string): number | undefined {
  const vals = [m.update_time, m.edit_time]
    .map((v) => parseTime(v, tz))
    .filter((t) => Number.isFinite(t) && t > 0);
  if (!vals.length) return undefined;
  return Math.max(...vals);
}

/** 仅在同一时钟标尺下比较两条消息修订：计数对计数、归一化毫秒时间戳对时间戳；跨时钟返回 incomparable */
function compareRowRevisions(
  a: { editCounter?: number; editTimeMs?: number },
  b: { editCounter?: number; editTimeMs?: number },
): "a_newer" | "b_newer" | "equal" | "incomparable" {
  let comparedAny = false;
  let aNewer = false;
  let bNewer = false;
  if (a.editCounter !== undefined && b.editCounter !== undefined) {
    comparedAny = true;
    if (a.editCounter > b.editCounter) aNewer = true;
    else if (b.editCounter > a.editCounter) bNewer = true;
  }
  if (a.editTimeMs !== undefined && b.editTimeMs !== undefined) {
    comparedAny = true;
    if (a.editTimeMs > b.editTimeMs) aNewer = true;
    else if (b.editTimeMs > a.editTimeMs) bNewer = true;
  }
  if (aNewer && bNewer) return "incomparable";
  if (aNewer) return "a_newer";
  if (bNewer) return "b_newer";
  if (comparedAny) return "equal";
  const aHasAny = a.editCounter !== undefined || a.editTimeMs !== undefined;
  const bHasAny = b.editCounter !== undefined || b.editTimeMs !== undefined;
  if (!aHasAny && !bHasAny) return "equal";
  return "incomparable";
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

const isSyntheticDmLabel = (s: string): boolean => s === "私聊" || /^私聊[:：]/.test(s);

/** 一次性合并增量学习到的开放平台群名，避免写事务内逐条重解析整个缓存或用旧快照覆盖在线监听刚刷新的群名（保留真实以「私聊」开头的群名） */
export function mergeKnownOpenGroupNames(store: App["store"], delta: ReadonlyMap<string, string>): void {
  if (delta.size === 0) return;
  const cur = loadKnownOpenGroupNames(store);
  let changed = false;
  for (const [rawId, rawName] of delta) {
    const id = rawId.trim();
    const clean = rawName.trim();
    if (!id || !clean || clean === "群聊") continue;
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

  const authoritativeGroupName = (raw?: string): string => {
    const clean = (raw ?? "").trim();
    return clean && clean !== "群聊" ? clean : "";
  };
  const fallbackObsGroupName = (obs?: { kind?: string; conv_name?: string; meta?: Record<string, unknown> }): string => {
    if (!obs) return "";
    const ct = String(obs.meta?.chat_type ?? "").trim().toLowerCase();
    if (ct === "p2p" || obs.kind === "p2p") return "";
    const clean = (obs.conv_name ?? "").trim();
    if (!clean || clean === "群聊") return "";
    if (ct === "group" || ct === "topic_group" || obs.kind === "group") return clean;
    // 仅对无类型的遗留回退记录剔除合成私聊标签（“私聊”或“私聊：xxx”），绝不丢弃真实群名（如“私聊问题反馈”）
    return isSyntheticDmLabel(clean) ? "" : clean;
  };
  const resolveName = (id: string, fallback = ""): string =>
    authoritativeGroupName(knownNames?.[id]) ||
    authoritativeGroupName(spoken[id]?.name) ||
    authoritativeGroupName(fallback) ||
    fallbackObsGroupName(store.latestConvObs(id));

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
  syncDiskPolicy?: () => boolean;
  getDiskOwnerOpenId?: () => string;
  constructor(
    app: App,
    store: ContextStore,
    nativeExclusions?: () => Promise<NativePollingExclusions>,
    syncDiskPolicy?: () => boolean,
    getDiskOwnerOpenId?: () => string,
  ) {
    this.app = app;
    this.store = store;
    this.nativeExclusions = nativeExclusions;
    this.syncDiskPolicy = syncDiskPolicy;
    this.getDiskOwnerOpenId = getDiskOwnerOpenId;
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

  private assertPinnedOwnerSync(actionLabel: string, pinnedOwnerOpenId: string): void {
    if (this.syncDiskPolicy && !this.syncDiskPolicy()) {
      throw new Error(`磁盘隐私配置无法核验，已中止${actionLabel}`);
    }
    const currentOwner = this.cfg.owner.open_id.trim();
    const diskOwner = this.getDiskOwnerOpenId ? this.getDiskOwnerOpenId().trim() : currentOwner;
    if (currentOwner !== pinnedOwnerOpenId || diskOwner !== pinnedOwnerOpenId) {
      throw new Error(`工作区 owner.open_id 在采集期间发生变化，已中止${actionLabel}`);
    }
    if (hasWorkspaceOwnerMismatch(this.app.store, pinnedOwnerOpenId) || hasWorkspaceOwnerMismatch(this.app.store, diskOwner)) {
      throw new Error(`工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已阻断${actionLabel}`);
    }
  }

  /** 核验当前 lark-cli 登录用户 open_id 与本轮锁定的工作区主人一致，防止切换配置或 CLI 账号后跨账号拉取私聊/任务/妙记/日历 */
  async verifyActiveLarkOwner(
    actionLabel = "用户态来源采集",
    pinnedOwnerOpenId?: string,
  ): Promise<{ ok: true; status: Record<string, unknown> } | { ok: false; error: string }> {
    try {
      const targetOwner = pinnedOwnerOpenId ?? this.cfg.owner.open_id.trim();
      this.assertPinnedOwnerSync(actionLabel, targetOwner);
      const { status } = await verifyActiveLarkUser(this.app.lark, targetOwner, actionLabel);
      this.assertPinnedOwnerSync(actionLabel, targetOwner);
      return { ok: true, status };
    } catch (err) {
      return { ok: false, error: errMsg(err) };
    }
  }

  private async assertActiveLarkOwner(actionLabel: string, pinnedOwnerOpenId: string): Promise<Record<string, unknown>> {
    this.assertPinnedOwnerSync(actionLabel, pinnedOwnerOpenId);
    const { status } = await verifyActiveLarkUser(this.app.lark, pinnedOwnerOpenId, actionLabel);
    this.assertPinnedOwnerSync(actionLabel, pinnedOwnerOpenId);
    return status;
  }

  /** 跑一轮所有启用的来源（各来源相互隔离；整轮锁定初始工作区主人并在每个用户态来源的拉取前、提交前及写事务内校验同一主人身份） */
  async pullAll(pinnedOwnerOpenId?: string): Promise<SourceReport[]> {
    if (this.syncDiskPolicy && !this.syncDiskPolicy()) {
      return [{ source: "config", count: 0, error: "磁盘隐私配置无法核验，已暂缓本轮采集" }];
    }
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    const out: SourceReport[] = [];
    const step = async (name: string, isEnabled: () => boolean, fn: () => Promise<Omit<SourceReport, "source" | "error">>) => {
      if (this.syncDiskPolicy && !this.syncDiskPolicy()) return;
      if (!isEnabled()) return;
      try {
        const r = await fn();
        out.push({ source: name, error: "", ...r });
      } catch (e) {
        out.push({ source: name, count: 0, error: (e as Error).message.slice(0, 300) });
      }
      this.setKv(`source.${name}`, JSON.stringify({ at: Date.now(), ...out.at(-1) }));
    };
    await step("meego", () => this.cfg.context.sources.meego, () => this.pullMeego(pinnedOwner));
    await step("tasks", () => this.cfg.context.sources.tasks, () => this.pullTasks(pinnedOwner));
    await step("im", () => this.cfg.context.sources.im, () => this.pullIm(0, pinnedOwner));
    await step("minutes", () => this.cfg.context.sources.minutes, () => this.pullMinutes(pinnedOwner));
    await step("calendar", () => this.cfg.context.sources.calendar, () => this.pullCalendar(pinnedOwner));
    await step("docs", () => this.cfg.context.sources.docs, async () => this.pullComments(pinnedOwner));
    return out;
  }

  // ───────── Meego：待办快照 → 事项 ─────────

  async pullMeego(pinnedOwnerOpenId?: string): Promise<{ count: number }> {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    this.assertPinnedOwnerSync("拉取 Meego 待办", pinnedOwner);
    if (!this.cfg.context.sources.meego) return { count: 0 };
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
    const count = this.store.tx(() => {
      this.assertPinnedOwnerSync("提交 Meego 待办", pinnedOwner);
      if (!this.cfg.context.sources.meego) return 0;
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
      return all.length;
    });
    return { count };
  }

  // ───────── 飞书任务 → 事项 ─────────

  async pullTasks(pinnedOwnerOpenId?: string): Promise<{ count: number }> {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    await this.assertActiveLarkOwner("拉取飞书任务", pinnedOwner);
    const data = await this.lark(["task", "+get-my-tasks", "--complete=false", "--page-all"]);
    // 提交前再次核验活跃 lark-cli 用户与锁定的工作区主人身份，防止拉取期间配置或账号同时切换导致他人任务落入本工作区
    await this.assertActiveLarkOwner("提交飞书任务", pinnedOwner);
    const tasks = arr(data, "items");
    const now = Date.now();
    const legacyCut = now - this.cfg.context.legacy_days * DAY;
    const committedCount = this.store.tx(() => {
      this.assertPinnedOwnerSync("提交飞书任务", pinnedOwner);
      if (!this.cfg.context.sources.tasks) return 0;
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
      return tasks.length;
    });
    return { count: committedCount };
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
    const diskOk = this.syncDiskPolicy ? this.syncDiskPolicy() : true;
    const mutes = this.store
      .mutedConvs()
      .map((m) => [m.conv, m.name] as const)
      .sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
    const deny = [...this.cfg.context.groups_deny].map((s) => s.trim()).sort();
    // 保留 groups_allow 顺序：在 max_groups 截断下，白名单顺序变化同样改变选中群集合；包含 lookback_days、bot_allow 与磁盘配置健康态以感知外部修改
    const allow = this.cfg.context.groups_allow.map((s) => s.trim());
    const bots = [...this.cfg.context.bot_allow].map((s) => s.trim()).sort();
    return JSON.stringify([
      diskOk ? 1 : 0,
      this.cfg.context.sources.im ? 1 : 0,
      this.cfg.context.groups,
      this.cfg.context.max_groups,
      this.cfg.context.lookback_days,
      allow,
      deny,
      mutes,
      bots,
    ]);
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
    const dmPeerName = isKnownDm ? chatName.replace(/^私聊[:：]?/, "").trim() : "";
    const needsNameForRules = this.hasNameDenyPatterns() || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
    if (!nativeExcl) {
      if (isKnownDm) {
        if (!dmPeerName && requireName && this.hasNameDenyPatterns()) return "inconclusive";
        return "allowed";
      }
      if (!chatName && requireName && this.hasNameDenyPatterns()) return "inconclusive";
      return "allowed";
    }
    if (isKnownDm) {
      if (nativeExcl.dmsInconclusive) return "inconclusive";
      if (!dmPeerName && requireName && this.hasNameDenyPatterns()) return "inconclusive";
      return "allowed";
    }
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

  private explicitMentionsMe(m: Raw, me: string): boolean | undefined {
    const mentions = m.mentions;
    if (!Array.isArray(mentions)) return undefined;
    return mentions.some((x: unknown) => {
      if (typeof x === "string") return x === me;
      if (!x || typeof x !== "object") return false;
      const r = x as Record<string, unknown>;
      return r.id === me || r.open_id === me || r.user_id === me;
    });
  }

  private toObs(m: Raw, kind: string, me: string, atMeWindowStartMs?: number, pollObservedAt?: number): Obs | undefined {
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
    const editCounter = parseEditCounter(m);
    const editTimeMs = parseEditTimeMs(m, this.cfg.owner.timezone);
    // 独立记录 @我 判定状态：
    //   - 当抓回正文明确带有 mentions 列表时，无论消息是否早于 --is-at-me 搜索窗口或搜索是否截断，直接以显式 mentions 列表的布尔结果为准（显式移除 @我 必须立即清零旧 at_me: true）；
    //   - 仅在正文不含 mentions 字段时，才按流标签与 --is-at-me 窗口覆盖决定：命中 at_me 记 true，窗口内未命中记 false，窗口外省略以保留原值。
    const explicitAtMe = this.explicitMentionsMe(m, me);
    const atMeMeta: Record<string, unknown> =
      explicitAtMe !== undefined
        ? { at_me: explicitAtMe }
        : kind === "at_me"
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
        ...(editCounter !== undefined ? { edit_version: editCounter } : {}),
        ...(editTimeMs !== undefined ? { edit_time: editTimeMs } : {}),
        ...(pollObservedAt !== undefined ? { poll_observed_at: pollObservedAt } : {}),
        ...atMeMeta,
      },
    };
  }

  async pullIm(restartAttempt = 0, pinnedOwnerOpenId?: string): Promise<{ count: number; dropped: number }> {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    const procOwner = this.app.ledger.owner;
    const pollToken = `poll_im:${randomUUID().slice(0, 8)}`;
    // 通过跨进程 SQLite 租约串行化 IM 轮询，防止并发轮询中较慢的旧快照后提交覆盖较新的消息编辑或回退游标
    if (!this.store.claimConv(IM_POLL_CLAIM_KEY, pollToken, procOwner, 120_000)) {
      return { count: 0, dropped: 0 };
    }
    const heartbeat = setInterval(() => {
      this.store.renewConv(IM_POLL_CLAIM_KEY, pollToken, procOwner, 120_000);
    }, 30_000);
    heartbeat.unref?.();
    try {
      return await this.pullImInner(restartAttempt, { token: pollToken, procOwner }, pinnedOwner);
    } finally {
      clearInterval(heartbeat);
      this.store.releaseConv(IM_POLL_CLAIM_KEY, pollToken, procOwner);
    }
  }

  private async pullImInner(
    restartAttempt: number,
    lease: { token: string; procOwner: string },
    pinnedOwner: string,
  ): Promise<{ count: number; dropped: number }> {
    await this.assertActiveLarkOwner("拉取飞书消息", pinnedOwner);
    const me = pinnedOwner;
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
    const initialAllowOrder = JSON.stringify(this.cfg.context.groups_allow.map((s) => s.trim()));
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
      if (!cid || !clean || clean === "群聊") return;
      knownNames[cid] = clean;
      if (cid.startsWith("oc_")) learnedNames.set(cid, clean);
    };
    for (const m of mine) {
      if (m.chat_type === "group" || m.chat_type === "topic_group") {
        const at = parseTime(m.create_time, this.cfg.owner.timezone);
        const cur = spoken[m.chat_id];
        const suppliedName = String(m.chat_name ?? "").trim();
        const existingKnown = m.chat_id ? knownNames[m.chat_id] ?? "" : "";
        const effectiveName = suppliedName || existingKnown || cur?.name || "";
        if (!cur || at > cur.at) spoken[m.chat_id] = { name: effectiveName, at };
        // 仅记录响应实际返回的群名，绝不把旧 spoken_groups 回退值写回 knownNames，
        // 也绝不让旧搜索行覆盖已核实的改名/排除群名（避免选群重试死循环）
        if (suppliedName && m.chat_id) {
          const keepExistingKnown =
            !!existingKnown &&
            existingKnown !== suppliedName &&
            (isOpenGroupDirectlyDenied(this.cfg, this.store, m.chat_id, existingKnown, nativeExcl) || (!!cur && at <= cur.at));
          if (!keepExistingKnown) recordLearnedName(m.chat_id, suppliedName);
        }
      }
    }
    for (const [id, v] of Object.entries(spoken)) if (v.at < now - lookback) delete spoken[id];

    const scannedGroups = !nativeExcl?.groupsInconclusive;
    const needsNameForRanking = this.hasNameDenyPatterns() || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
    if (scannedGroups && needsNameForRanking && this.cfg.context.max_groups > 0) {
      const authoritativeGroupName = (raw?: string): string => {
        const clean = (raw ?? "").trim();
        return clean && clean !== "群聊" ? clean : "";
      };
      const fallbackObsName = (id: string): string => {
        const latest = this.store.latestConvObs(id);
        if (!latest) return "";
        const ct = String(latest.meta?.chat_type ?? "").trim().toLowerCase();
        if (ct === "p2p" || latest.kind === "p2p") return "";
        const clean = (latest.conv_name ?? "").trim();
        if (!clean || clean === "群聊") return "";
        if (ct === "group" || ct === "topic_group" || latest.kind === "group") return clean;
        return isSyntheticDmLabel(clean) ? "" : clean;
      };
      const refreshCandidateNameIfNeeded = async (id: string, fallbackName = ""): Promise<string> => {
        let name =
          authoritativeGroupName(knownNames[id]) ||
          authoritativeGroupName(spoken[id]?.name) ||
          authoritativeGroupName(fallbackName) ||
          fallbackObsName(id);
        // 若名称缺失，或旧缓存名称正触发按名称排除，实时刷新一次当前群名（避免改名后的白名单/发言群永远困在旧排除缓存里）
        const excludedByCachedName = !!name && isOpenGroupDirectlyDenied(this.cfg, this.store, id, name, nativeExcl);
        if (!name || excludedByCachedName) {
          const fresh = await getChatMeta(id);
          if (fresh?.name && fresh.chatType !== "p2p") {
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
    const initialRankedKey = JSON.stringify(ranked.map(([id]) => id));
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

    // 先按 message_id 合并多路搜索/群拉取的字段：
    //   - 合并稳定的会话元数据（chat_id / chat_name / chat_type / fallbackGroupName）；
    //   - 当多路拉取返回不同修订版本（例如先跑 --is-at-me 搜索、再跑群拉取期间消息被编辑）时，
    //     以更高 edit_version/update_time 的行作为正文、可变字段与 @mention 分类的权威来源，避免陈旧版本覆盖新编辑。
    // 严格区分整数修订计数（edit_version）与归一化毫秒时间戳（update_time / edit_time），仅在同一时钟标尺下比较新旧；
    // 若同一消息在多路拉取中内容或 @mention 状态不同、且两行没有可比时钟（例如一行仅含 update_time、另一行仅含 edit_version），
    // 标记 needsVerify 并通过 `im +messages-mget` 权威回读最新版本，绝不拿时间戳原值压过修订计数。
    const rowMentionsMe = (m: Raw): boolean | undefined => this.explicitMentionsMe(m, me);
    // 当抓回的消息正文明确带有 mentions 列表时，以正文的真实 mentions 列表为准，
    // 防止 `--is-at-me` 先按旧索引命中 ID、随后抓正文期间对方已编辑移除 @我 时，旧搜索流标签绕过白名单/群范围约束。
    const rowEffectiveAtMe = (m: Raw, k: string): boolean => {
      const explicit = rowMentionsMe(m);
      if (explicit !== undefined) return explicit;
      return k === "at_me";
    };
    const fallbackKindWithoutAtMe = (m: Raw, origKind: string): string => {
      if (origKind !== "at_me") return origKind;
      const ct = String(m.chat_type ?? "").trim().toLowerCase();
      if (ct === "p2p") return "p2p";
      const s = m.sender ?? {};
      const sid = String(s.id ?? s.open_id ?? m.sender_id ?? "");
      return sid === me ? "mine" : "group";
    };
    const rowBodyConflict = (aM: Raw, aKind: string, bM: Raw, bKind: string): boolean => {
      const aText = textOf(aM.content ?? aM.text ?? "");
      const bText = textOf(bM.content ?? bM.text ?? "");
      if (aText !== bText) return true;
      const aMent = rowMentionsMe(aM);
      const bMent = rowMentionsMe(bM);
      if (aMent !== undefined && bMent !== undefined && aMent !== bMent) return true;
      if (aKind === "at_me" && bMent === false) return true;
      if (bKind === "at_me" && aMent === false) return true;
      return false;
    };
    const kindRank: Record<string, number> = { at_me: 4, p2p: 3, mine: 2, group: 1 };
    const mergeNewerImRow = (prev: Raw, next: Raw, clearOmittedMentions: boolean): Raw => {
      const mergedChatId = prev.chat_id || next.chat_id;
      const mergedChatName = String(next.chat_name ?? "").trim() || String(prev.chat_name ?? "").trim();
      const mergedChatType = String(next.chat_type ?? "").trim() || String(prev.chat_type ?? "").trim();
      const mergedThreadId = next.thread_id || prev.thread_id;
      const mergedParentId = next.parent_id || prev.parent_id;
      const mergedRootId = next.root_id || prev.root_id;
      const mergedSender = next.sender ?? prev.sender;
      const mergedSenderId = next.sender_id ?? prev.sender_id;
      const mergedSenderName = next.sender_name ?? prev.sender_name;
      const mergedCreateTime = next.create_time ?? prev.create_time;
      // 仅沿用稳定会话/话题/发送者/创建时间字段，绝不展开 prev 继承旧修订的 mentions 或其他可变内容字段
      const out: Raw = {
        ...next,
        ...(mergedChatId ? { chat_id: mergedChatId } : {}),
        ...(mergedChatName ? { chat_name: mergedChatName } : {}),
        ...(mergedChatType ? { chat_type: mergedChatType } : {}),
        ...(mergedThreadId ? { thread_id: mergedThreadId } : {}),
        ...(mergedParentId ? { parent_id: mergedParentId } : {}),
        ...(mergedRootId ? { root_id: mergedRootId } : {}),
        ...(mergedSender !== undefined ? { sender: mergedSender } : {}),
        ...(mergedSenderId !== undefined ? { sender_id: mergedSenderId } : {}),
        ...(mergedSenderName !== undefined ? { sender_name: mergedSenderName } : {}),
        ...(mergedCreateTime !== undefined ? { create_time: mergedCreateTime } : {}),
      };
      if (clearOmittedMentions && !Array.isArray(next.mentions)) {
        out.mentions = [];
      }
      return out;
    };

    const mergedById = new Map<
      string,
      {
        m: Raw;
        kind: string;
        editCounter?: number;
        editTimeMs?: number;
        streams: Set<StreamKind>;
        fallbackGroupName: string;
        needsVerify: boolean;
        verifyFailed?: boolean;
        deleted?: boolean;
        authoritativeLive?: boolean;
        candidates: { text: string; kind: string; atMe: boolean }[];
      }
    >();
    for (const row of raws) {
      const id = String(row.m.message_id ?? row.m.id ?? "");
      if (!id) continue;
      const rowCounter = parseEditCounter(row.m);
      const rowTimeMs = parseEditTimeMs(row.m, this.cfg.owner.timezone);
      const rowText = textOf(row.m.content ?? row.m.text ?? "");
      const rowDeleted = row.m.deleted === true || row.m.is_deleted === true;
      const rowAtMe = rowEffectiveAtMe(row.m, row.kind);
      const rowEffKind = rowAtMe ? "at_me" : fallbackKindWithoutAtMe(row.m, row.kind);
      const existing = mergedById.get(id);
      if (!existing) {
        mergedById.set(id, {
          m: { ...row.m },
          kind: rowEffKind,
          deleted: rowDeleted,
          editCounter: rowCounter,
          editTimeMs: rowTimeMs,
          streams: new Set([row.stream]),
          fallbackGroupName: row.fallbackGroupName ?? "",
          needsVerify: false,
          candidates: [{ text: rowText, kind: rowEffKind, atMe: rowAtMe }],
        });
      } else {
        existing.streams.add(row.stream);
        existing.candidates.push({ text: rowText, kind: rowEffKind, atMe: rowAtMe });
        const cmp = compareRowRevisions(
          { editCounter: rowCounter, editTimeMs: rowTimeMs },
          { editCounter: existing.editCounter, editTimeMs: existing.editTimeMs },
        );

        const mergedChatId = existing.m.chat_id || row.m.chat_id;
        const mergedChatName = String(row.m.chat_name ?? "").trim() || String(existing.m.chat_name ?? "").trim();
        const mergedChatType = String(existing.m.chat_type ?? "").trim() || String(row.m.chat_type ?? "").trim();
        const mergedThreadId = existing.m.thread_id || row.m.thread_id;
        const mergedParentId = existing.m.parent_id || row.m.parent_id;
        const mergedRootId = existing.m.root_id || row.m.root_id;
        if (!existing.fallbackGroupName && row.fallbackGroupName) {
          existing.fallbackGroupName = row.fallbackGroupName;
        }

        if (cmp === "a_newer") {
          const hadPriorMentions = Array.isArray(existing.m.mentions) || existing.kind === "at_me";
          const nextRow = mergeNewerImRow(existing.m, row.m, hadPriorMentions && rowEffKind !== "at_me");
          if (!rowDeleted) {
            delete nextRow.deleted;
            delete nextRow.is_deleted;
          }
          existing.m = nextRow;
          if (rowCounter !== undefined) existing.editCounter = rowCounter;
          if (rowTimeMs !== undefined) existing.editTimeMs = rowTimeMs;
          existing.kind = rowEffKind;
          existing.deleted = rowDeleted;
          existing.needsVerify = false;
        } else if (cmp === "b_newer") {
          if (mergedChatId) existing.m.chat_id = mergedChatId;
          if (!String(existing.m.chat_name ?? "").trim() && String(row.m.chat_name ?? "").trim()) {
            existing.m.chat_name = row.m.chat_name;
          }
          if (!String(existing.m.chat_type ?? "").trim() && String(row.m.chat_type ?? "").trim()) {
            existing.m.chat_type = row.m.chat_type;
          }
        } else {
          // 同修订（equal）或跨时钟不可比（incomparable）：若正文或 @mention 冲突则标记权威回读，否则安全合并稳定元数据与互补时钟
          if (mergedChatId) existing.m.chat_id = mergedChatId;
          if (!String(existing.m.chat_name ?? "").trim() && String(row.m.chat_name ?? "").trim()) {
            existing.m.chat_name = row.m.chat_name;
          }
          if (!String(existing.m.chat_type ?? "").trim() && String(row.m.chat_type ?? "").trim()) {
            existing.m.chat_type = row.m.chat_type;
          }
          if ((existing.deleted === true) !== rowDeleted || rowBodyConflict(existing.m, existing.kind, row.m, rowEffKind)) {
            existing.needsVerify = true;
          } else {
            if (existing.editCounter === undefined && rowCounter !== undefined) {
              existing.editCounter = rowCounter;
              existing.m.edit_version = row.m.edit_version;
            }
            if (existing.editTimeMs === undefined && rowTimeMs !== undefined) {
              existing.editTimeMs = rowTimeMs;
              if (row.m.update_time !== undefined) existing.m.update_time = row.m.update_time;
              if (row.m.edit_time !== undefined) existing.m.edit_time = row.m.edit_time;
            }
            if ((kindRank[rowEffKind] ?? 0) > (kindRank[existing.kind] ?? 0)) {
              existing.kind = rowEffKind;
            }
          }
        }
      }
    }

    // 对跨时钟或内容冲突的重复消息批量调用 `im +messages-mget` 权威回读最新版本
    const verifyIds = [...mergedById.entries()].filter(([, e]) => e.needsVerify).map(([id]) => id);
    if (verifyIds.length > 0) {
      const freshById = new Map<string, Raw>();
      for (let i = 0; i < verifyIds.length; i += 50) {
        const chunk = verifyIds.slice(i, i + 50);
        try {
          const data = await this.lark(
            ["im", "+messages-mget", "--message-ids", chunk.join(","), "--no-reactions"],
            15_000,
          );
          const list = arr(data, "messages").length ? arr(data, "messages") : arr(data, "items");
          for (const fm of list) {
            const fid = String(fm.message_id ?? fm.id ?? "");
            if (fid) freshById.set(fid, fm);
          }
        } catch {
          // 回读失败时保留 verifyFailed，下方将阻止提交陈旧副本并保留游标
        }
      }
      for (const id of verifyIds) {
        const entry = mergedById.get(id);
        if (!entry) continue;
        const fresh = freshById.get(id);
        if (!fresh) {
          entry.verifyFailed = true;
          continue;
        }
        const mergedChatType = String(fresh.chat_type ?? "").trim() || String(entry.m.chat_type ?? "").trim();
        const freshText = textOf(fresh.content ?? fresh.text ?? "");
        const freshCounter = parseEditCounter(fresh);
        const freshTimeMs = parseEditTimeMs(fresh, this.cfg.owner.timezone);
        if (freshCounter !== undefined) entry.editCounter = freshCounter;
        if (freshTimeMs !== undefined) entry.editTimeMs = freshTimeMs;
        if (fresh.deleted === true || fresh.is_deleted === true || !freshText) {
          entry.deleted = true;
          entry.needsVerify = false;
          continue;
        }
        const hadPriorMentions = Array.isArray(entry.m.mentions) || entry.kind === "at_me";
        const sender = fresh.sender ?? entry.m.sender ?? {};
        const senderId = String(sender.id ?? sender.open_id ?? fresh.sender_id ?? entry.m.sender_id ?? "");
        const explicitAtMe = rowMentionsMe(fresh);
        let nextKind: string;
        if (explicitAtMe === true) {
          nextKind = "at_me";
        } else if (explicitAtMe === false) {
          nextKind = mergedChatType.toLowerCase() === "p2p" ? "p2p" : senderId === me ? "mine" : "group";
        } else {
          // 若 +messages-mget 未返回 mentions 字段，仅当全部与权威正文一致的候选对是否 @我 达成一致时才推断 kind；
          // 若候选正文相同却在 @我 归类上冲突，按未决处理并保留游标待下次重试，绝不偏袒先到的 --is-at-me 流
          const matchingCands = entry.candidates.filter((c) => c.text === freshText);
          if (matchingCands.length > 0) {
            const atMeValues = new Set(matchingCands.map((c) => c.atMe));
            if (atMeValues.size > 1) {
              entry.verifyFailed = true;
              continue;
            }
            const matched = matchingCands[0];
            nextKind = matched.atMe ? "at_me" : matched.kind;
          } else {
            nextKind = mergedChatType.toLowerCase() === "p2p" ? "p2p" : senderId === me ? "mine" : "group";
          }
        }
        const liveMerged = mergeNewerImRow(entry.m, fresh, hadPriorMentions && nextKind !== "at_me");
        delete liveMerged.deleted;
        delete liveMerged.is_deleted;
        entry.m = liveMerged;
        entry.kind = nextKind;
        entry.deleted = false;
        entry.authoritativeLive = true;
        entry.editCounter = parseEditCounter(fresh);
        entry.editTimeMs = parseEditTimeMs(fresh, this.cfg.owner.timezone);
        entry.needsVerify = false;
      }
    }

    // 预扫描本批全部私聊行，提取已知 p2p 会话集合及对方姓名（确保在排除规则判定前即可匹配 groups_deny 名称关键词）
    const knownP2pChats = new Set<string>();
    const peerNameByChat = new Map<string, string>();
    for (const entry of mergedById.values()) {
      const cid = String(entry.m.chat_id ?? "");
      const ct = String(entry.m.chat_type ?? "").trim().toLowerCase();
      if (cid && ct === "p2p") knownP2pChats.add(cid);
    }
    for (const entry of mergedById.values()) {
      const cid = String(entry.m.chat_id ?? "");
      if (!cid || !knownP2pChats.has(cid)) continue;
      const sender = entry.m.sender ?? {};
      const senderId = String(sender.id ?? sender.open_id ?? entry.m.sender_id ?? "");
      const senderName = String(sender.name ?? entry.m.sender_name ?? "").trim();
      if (senderId && senderId !== me && senderName) {
        peerNameByChat.set(cid, senderName);
      }
    }

    const scopeSelectionChanged = (latestExcl?: NativePollingExclusions): boolean => {
      if (
        this.cfg.context.groups !== initialGroupsMode ||
        this.cfg.context.max_groups !== initialMaxGroups ||
        this.cfg.context.lookback_days !== initialLookbackDays ||
        JSON.stringify(this.cfg.context.groups_allow.map((s) => s.trim())) !== initialAllowOrder ||
        (!latestExcl?.groupsInconclusive) !== scannedGroups
      ) {
        return true;
      }
      const rechecked = !latestExcl?.groupsInconclusive
        ? JSON.stringify(
            selectEffectiveOpenGroups({
              cfg: this.cfg,
              store: this.store,
              spoken: initialSpokenSnapshot,
              knownNames: initialKnownNamesSnapshot,
              nativeExcl: latestExcl,
              now,
            }).map(([id]) => id),
          )
        : "[]";
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
      if (!this.cfg.context.sources.im || (this.syncDiskPolicy && !this.syncDiskPolicy())) {
        return { count: 0, dropped: 0 };
      }
      if (scopeSelectionChanged(nativeExcl)) {
        if (restartAttempt < 1) {
          return this.pullImInner(restartAttempt + 1, lease, pinnedOwner);
        }
        return { count: 0, dropped: 0 };
      }

      let atMeBlocked = !!nativeExcl?.groupsInconclusive;
      let p2pBlocked = !!nativeExcl?.dmsInconclusive || !fetchedP2p;
      let mineBlocked = !!nativeExcl?.groupsInconclusive;
      let groupsBlocked = !!nativeExcl?.groupsInconclusive || !scannedGroups;
      for (const st of chatPollState.values()) st.hadInconclusiveRow = false;

      const hasNameDeny = this.hasNameDenyPatterns();
      const needsCurrentName = hasNameDeny || !!(nativeExcl && nativeExcl.confirmedGroupNames.size > 0);
      const needsTypeLookup = !!(nativeExcl?.dmsInconclusive || nativeExcl?.groupsInconclusive);

      let dropped = 0;
      const obs: Obs[] = [];
      const retiredEntries: {
        id: string;
        editVersion?: number;
        editTimeMs?: number;
        pollObservedAt: number;
        conv?: string;
        kind?: string;
        time?: number;
      }[] = [];

      for (const entry of mergedById.values()) {
        const msgId = String(entry.m.message_id ?? entry.m.id ?? "");
        const rawChatId = String(entry.m.chat_id ?? "");
        if (entry.verifyFailed) {
          for (const s of entry.streams) {
            if (s === "p2p") p2pBlocked = true;
            else if (s === "at_me") atMeBlocked = true;
            else if (s === "mine") mineBlocked = true;
            else if (s === "group") {
              const st = chatPollState.get(rawChatId);
              if (st) st.hadInconclusiveRow = true;
              else groupsBlocked = true;
            }
          }
          continue;
        }
        if (entry.deleted || entry.m.deleted === true || entry.m.is_deleted === true) {
          if (msgId) {
            retiredEntries.push({
              id: `im:${msgId}`,
              editVersion: entry.editCounter,
              editTimeMs: entry.editTimeMs,
              pollObservedAt: now,
              conv: rawChatId || "im",
              kind: entry.kind,
              time: parseTime(entry.m.create_time ?? entry.m.created_at ?? entry.m.timestamp, this.cfg.owner.timezone) || now,
            });
          }
          dropped++;
          continue;
        }
        const m = { ...entry.m };
        const senderType = String(m.sender?.sender_type ?? m.sender?.type ?? m.sender_type ?? "");
        if (senderType === "app" && !this.botAllowed(m)) {
          dropped++;
          continue;
        }
        const chatId = String(m.chat_id ?? "");
        let chatType = String(m.chat_type ?? "").trim();
        if (!chatType && chatId && knownP2pChats.has(chatId)) chatType = "p2p";
        const isP2p = chatType.toLowerCase() === "p2p";
        let chatName = String(m.chat_name ?? "").trim();
        if (isP2p && chatName.replace(/^私聊[:：]?/, "").trim() === "") chatName = "";
        let nameSupplied = !!chatName;

        // 对缺失 chat_name 的私聊先使用同批提取的对方姓名，仍未知且配置了名称排除规则时再查 im chats get
        if (isP2p && !chatName && chatId) {
          const peer = peerNameByChat.get(chatId);
          if (peer) chatName = peer;
        }

        // 对缺失 chat_name（群有名称/原生静音规则，私聊有名称排除规则）或缺失 chat_type（受限状态）的命中实时查一次 im chats get，不凭陈旧 spoken_groups 放行
        const shouldLookupMeta =
          !!chatId &&
          (isP2p
            ? !chatName && hasNameDeny
            : (!chatName && needsCurrentName) || (!chatType && (needsTypeLookup || needsCurrentName)));
        if (shouldLookupMeta) {
          const fresh = await getChatMeta(chatId);
          if (fresh) {
            if (!chatName && fresh.name) {
              chatName = fresh.name;
              nameSupplied = true;
            }
            if (!chatType && fresh.chatType) chatType = fresh.chatType;
          }
        }
        const isP2pFinal = chatType.toLowerCase() === "p2p";
        if (isP2pFinal && !chatName && chatId) {
          const peer = peerNameByChat.get(chatId);
          if (peer) chatName = peer;
        }
        if (isP2pFinal && !chatName && chatId && hasNameDeny) {
          // 仅含本人发出的无名私聊且 im chats get 仍未给出对方姓名时：
          // 若本地历史观测已记录过对方姓名且命中排除规则则直接丢弃，否则保留空名由 classifyExclusion 按 inconclusive 暂缓
          const stalePeer = (this.store.latestConvObs(chatId)?.conv_name ?? "").replace(/^私聊[:：]?/, "").trim();
          if (stalePeer && this.classifyExclusion(chatId, stalePeer, "p2p", nativeExcl) === "denied") {
            dropped++;
            continue;
          }
        }
        if (!isP2pFinal && !chatName && !needsCurrentName && entry.fallbackGroupName) {
          chatName = entry.fallbackGroupName;
        }
        if (nameSupplied && chatName && chatId) {
          if (spoken[chatId]) spoken[chatId].name = chatName;
          const isAuthoritativeGroup = chatType === "group" || chatType === "topic_group";
          if (chatId.startsWith("oc_") && !isP2pFinal && (isAuthoritativeGroup || !isSyntheticDmLabel(chatName))) {
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
          if (isP2pFinal) p2pBlocked = true;
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
          continue;
        }
        // 范围外群的非 @我 消息（含曾命中 --is-at-me 搜索但正文已被编辑移除 @我 的白名单外/排位外群消息）不入库，
        // 并按修订水位撤回该 ID 此前可能入库的 @我 待处理记录
        const outOfScopeGroup =
          entry.kind !== "at_me" &&
          !isP2pFinal &&
          chatId.startsWith("oc_") &&
          !rankedSet.has(chatId) &&
          (this.cfg.context.groups === "allowlist" || entry.kind !== "mine");
        if (outOfScopeGroup) {
          if (msgId && entry.streams.has("at_me")) {
            retiredEntries.push({
              id: `im:${msgId}`,
              editVersion: entry.editCounter,
              editTimeMs: entry.editTimeMs,
              pollObservedAt: now,
              conv: chatId,
              kind: entry.kind,
              time: parseTime(m.create_time ?? m.created_at ?? m.timestamp, this.cfg.owner.timezone) || now,
            });
          }
          dropped++;
          continue;
        }
        const o = this.toObs(m, entry.kind, me, effectiveAtMeWindowStartMs, now);
        if (o) {
          if (entry.authoritativeLive) o.meta.authoritative_live = true;
          obs.push(o);
        }
      }

      // 若拉取消息期间学到的新群名导致生效群选排变化（例如群 A 改名命中排除规则，空出名额给群 B），
      // 先持久化新学到的群名，再不推进游标重启一轮拉取以补采接替群 B，避免推进 cursor.im.groups 遗漏 B 的消息
      if (learnedNames.size > 0 && !nativeExcl?.groupsInconclusive) {
        const learnedRankedKey = JSON.stringify(
          selectEffectiveOpenGroups({
            cfg: this.cfg,
            store: this.store,
            spoken,
            knownNames,
            nativeExcl,
            now,
          }).map(([id]) => id),
        );
        if (learnedRankedKey !== initialRankedKey) {
          await this.assertActiveLarkOwner("保存学到的群名", pinnedOwner);
          mergeKnownOpenGroupNames(this.app.store, learnedNames);
          if (restartAttempt < 1) {
            return this.pullImInner(restartAttempt + 1, lease, pinnedOwner);
          }
          return { count: 0, dropped: 0 };
        }
      }

      // 私聊没有会话名：用对方名字（避免拼出「私聊：私聊：xxx」或「私聊：私聊」）
      const p2pName = new Map<string, string>(peerNameByChat);
      for (const o of obs) if (o.meta.chat_type === "p2p" && !o.is_me && o.actor_name) p2pName.set(o.conv, o.actor_name);
      for (const o of obs) {
        if (o.meta.chat_type === "p2p") {
          const cleanPeer = (p2pName.get(o.conv) ?? o.conv_name).replace(/^私聊[:：]?/, "").trim();
          o.conv_name = cleanPeer ? `私聊：${cleanPeer}` : "私聊";
        }
      }

      // 落库提交前再次核验活跃 lark-cli 用户与锁定工作区主人，防止拉取分页期间切换配置或账号导致他人消息写入本工作区或推进游标
      await this.assertActiveLarkOwner("提交飞书消息", pinnedOwner);

      // 原子事务提交前最后一次核对轮询租约、锁定主人、策略签名与群选择集合：
      // 若租约丢失则立刻中止（防过期慢轮询覆写新编辑）；若主人或策略变更则中止/重启，绝不提交过期或跨账号观测与游标
      const commitRes = this.store.tx(() => {
        if (!this.store.isConvClaimedBy(IM_POLL_CLAIM_KEY, lease.token, lease.procOwner)) {
          return { committed: false as const, lostLease: true as const, count: 0 };
        }
        this.assertPinnedOwnerSync("提交飞书消息", pinnedOwner);
        if (this.pollingPolicySignature() !== policySig || scopeSelectionChanged(nativeExcl)) {
          return { committed: false as const, lostLease: false as const, count: 0 };
        }
        if (!this.cfg.context.sources.im || (this.syncDiskPolicy && !this.syncDiskPolicy())) {
          return { committed: true as const, lostLease: false as const, count: 0 };
        }
        const n = this.store.addObs(obs);
        for (const r of retiredEntries) {
          this.store.retirePendingObs(r.id, {
            editVersion: r.editVersion,
            editTimeMs: r.editTimeMs,
            pollObservedAt: r.pollObservedAt,
            conv: r.conv,
            source: "im",
            kind: r.kind,
            time: r.time,
          });
        }
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
        return { committed: true as const, lostLease: false as const, count: n };
      });
      if (commitRes.lostLease) {
        return { count: 0, dropped: 0 };
      }
      if (commitRes.committed) {
        return { count: commitRes.count, dropped };
      }
    }

    // 连续两轮策略均在提交瞬间变更：本轮安全跳过落库与游标推进，留待下轮按最新策略重试
    return { count: 0, dropped: 0 };
  }

  // ───────── 妙记 → 观测 ─────────

  async pullMinutes(pinnedOwnerOpenId?: string): Promise<{ count: number }> {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    await this.assertActiveLarkOwner("拉取飞书妙记", pinnedOwner);
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
    await this.assertActiveLarkOwner("提交飞书妙记", pinnedOwner);
    const n = this.store.tx(() => {
      this.assertPinnedOwnerSync("提交飞书妙记", pinnedOwner);
      if (!this.cfg.context.sources.minutes) return 0;
      const added = this.store.addObs(obs);
      this.setKv("cursor.minutes", String(now));
      return added;
    });
    return { count: n };
  }

  // ───────── 文档评论 @我：事件已落在 signals 表（capture.onComment），这里转成观测 ─────────

  pullComments(pinnedOwnerOpenId?: string): { count: number } {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    const n = this.store.tx(() => {
      this.assertPinnedOwnerSync("提交文档评论", pinnedOwner);
      if (!this.cfg.context.sources.docs) return 0;
      const since = Number(this.kv("cursor.comments") ?? 0);
      const rows = this.store.db
        .prepare("SELECT id, text, link, at FROM signals WHERE id LIKE 'comment:%' AND at > ? ORDER BY at LIMIT 200")
        .all(since) as { id: string; text: string; link: string; at: number }[];
      if (!rows.length) return 0;
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
      const added = this.store.addObs(obs);
      this.setKv("cursor.comments", String(Math.max(...rows.map((r) => r.at))));
      return added;
    });
    return { count: n };
  }

  // ───────── 日历：今天和接下来两天的会议（只用于展示） ─────────

  async pullCalendar(pinnedOwnerOpenId?: string): Promise<{ count: number }> {
    const pinnedOwner = (pinnedOwnerOpenId ?? this.cfg.owner.open_id).trim();
    await this.assertActiveLarkOwner("拉取飞书日历", pinnedOwner);
    const now = Date.now();
    const startOfDay = parseTime(new Intl.DateTimeFormat("en-CA", { timeZone: this.cfg.owner.timezone }).format(new Date(now)), this.cfg.owner.timezone);
    const data = await this.lark(["calendar", "+agenda", "--start", isoLocal(startOfDay), "--end", isoLocal(startOfDay + 3 * DAY)]);
    await this.assertActiveLarkOwner("提交飞书日历", pinnedOwner);
    const events = arr(data, "items").length ? arr(data, "items") : arr(data, "events");
    const t = (x: Raw) => parseTime(x?.datetime ?? x?.timestamp ?? x?.date ?? x, this.cfg.owner.timezone);
    const meetings = events
      .filter((e) => e.self_rsvp_status !== "decline")
      .map((e) => ({ start: t(e.start_time), end: t(e.end_time), summary: String(e.summary ?? "(无标题)"), url: String(e.app_link ?? "") }))
      .filter((m) => m.start > 0)
      .sort((a, b) => a.start - b.start);
    const committed = this.store.tx(() => {
      this.assertPinnedOwnerSync("提交飞书日历", pinnedOwner);
      if (!this.cfg.context.sources.calendar) return 0;
      this.setKv("calendar", JSON.stringify(meetings));
      return meetings.length;
    });
    return { count: committed };
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
