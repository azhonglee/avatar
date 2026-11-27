import path from "node:path";
import type { App } from "../app.ts";
import type { CtxDraftKind } from "../api/types.ts";
import type { Effect } from "../ledger.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import { render, truncate } from "../util.ts";
import { BOUND_OWNER_KV_KEY, BOUND_WORKSPACE_OWNER_KV_KEY, isReadbackOnlyDelivery } from "./personal-web.ts";
import { obsRevision, type ContextStore, type DraftRow, type ItemRow, type Obs } from "./store.ts";

/**
 * 草稿（M3 推进）：为事项起草回复 / 跟进 / Meego 评论，或按周起草项目周报。
 * 草稿只是建议：你确认后才变成 outbox 里的对外动作（以你本人身份执行）。
 */

const DAY = 86_400_000;

const fmt = (ms: number, tz: string) =>
  new Intl.DateTimeFormat("zh-CN", { timeZone: tz, month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(ms));

/** 事项默认适合哪种草稿 */
export function defaultDraftKind(it: ItemRow): CtxDraftKind | undefined {
  if (it.source === "meego" && it.meta.work_item_id) return "meego_comment";
  if (it.kind === "waiting_on") return "followup";
  if (["ask_me", "my_commitment", "risk", "meeting_action", "todo"].includes(it.kind) && it.source === "im") return "reply";
  return undefined;
}

/** 草稿目标会话或目标消息因静音/排除/移出采集范围而不可起草时抛出（用于区分自动预起草跳过与真实故障） */
export class DraftTargetIneligibleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DraftTargetIneligibleError";
  }
}

/** 目标会话的排除状态因网络抖动或在线 Web 客户端暂不可用而暂时无法核验时抛出（自动预起草应延迟重排而非永久跳过） */
export class DraftTargetUncertainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DraftTargetUncertainError";
  }
}

export class Drafter {
  app: App;
  store: ContextStore;
  filterObs?: (conv: string, obs: Obs[]) => Obs[] | Promise<Obs[]>;
  checkConvAllowed?: (conv: string, convName: string) => Promise<"allowed" | "excluded" | "uncertain">;
  policySignature?: () => string;
  runner: typeof runHarness;
  constructor(
    app: App,
    store: ContextStore,
    filterObs?: (conv: string, obs: Obs[]) => Obs[] | Promise<Obs[]>,
    checkConvAllowed?: (conv: string, convName: string) => Promise<"allowed" | "excluded" | "uncertain">,
    policySignature?: () => string,
    runner: typeof runHarness = runHarness,
  ) {
    this.app = app;
    this.store = store;
    this.filterObs = filterObs;
    this.checkConvAllowed = checkConvAllowed;
    this.policySignature = policySignature;
    this.runner = runner;
  }
  private get cfg() {
    return this.app.cfg;
  }

  private isEligibleImObs(o: Obs, activeNativeOwner: string | null): boolean {
    if (o.source !== "im" || o.meta.withdrawn === true) return false;
    if (o.id.startsWith("pw:") || o.meta.transport === "personal_web") {
      const obsOwner = String(o.meta.native_owner_id ?? "").trim();
      return !!activeNativeOwner && obsOwner === activeNativeOwner;
    }
    return true;
  }

  private buildTargetForObs(
    it: ItemRow,
    kind: CtxDraftKind,
    obs: Obs,
    asReplyToOther: boolean,
  ): { target: Record<string, string>; label: string; conv: Obs } {
    if (asReplyToOther) {
      if (obs.meta.transport === "personal_web") {
        if (obs.meta.native_message_id && obs.meta.native_chat_id) {
          const nativeOwnerId = String(obs.meta.native_owner_id ?? "").trim();
          if (!nativeOwnerId) throw new Error("该个人 Web 消息缺少归属账号标识（native_owner_id），拒绝起草");
          return {
            target: {
              transport: "personal_web",
              obs_id: obs.id,
              native_owner_id: nativeOwnerId,
              native_message_id: String(obs.meta.native_message_id),
              native_chat_id: String(obs.meta.native_chat_id),
              native_root_id: String(obs.meta.native_root_id ?? obs.meta.native_message_id),
              url: obs.url,
            },
            label: `回复 ${obs.actor_name || "对方"}（${obs.conv_name} · 个人 Web）`,
            conv: obs,
          };
        }
        throw new Error("该个人 Web 消息缺少可回复的原消息标识");
      }
      const openMsgId = String(obs.meta.message_id ?? obs.id.replace(/^im:/, ""));
      if (!openMsgId) throw new Error("该消息缺少可回复的消息标识");
      return {
        target: {
          obs_id: obs.id,
          message_id: openMsgId,
          chat_id: obs.conv,
          url: obs.url,
        },
        label: `回复 ${obs.actor_name || "对方"}（${obs.conv_name}）`,
        conv: obs,
      };
    }
    if (obs.meta.transport === "personal_web") {
      if (obs.meta.native_message_id && obs.meta.native_chat_id) {
        const nativeOwnerId = String(obs.meta.native_owner_id ?? "").trim();
        if (!nativeOwnerId) throw new Error("该个人 Web 会话缺少归属账号标识（native_owner_id），拒绝起草");
        return {
          target: {
            transport: "personal_web",
            obs_id: obs.id,
            native_owner_id: nativeOwnerId,
            native_message_id: String(obs.meta.native_message_id),
            native_chat_id: String(obs.meta.native_chat_id),
            native_root_id: String(obs.meta.native_root_id ?? obs.meta.native_message_id),
            url: obs.url,
          },
          label: `${kind === "followup" ? "跟进" : "回复"} ${obs.conv_name}（个人 Web）`,
          conv: obs,
        };
      }
      throw new Error("该个人 Web 会话缺少可发送的消息标识");
    }
    return {
      target: { obs_id: obs.id, chat_id: obs.conv, url: obs.url },
      label: `${kind === "followup" ? "跟进" : "发到"} ${obs.conv_name}${it.counterpart ? `（${it.counterpart}）` : ""}`,
      conv: obs,
    };
  }

  /** 草稿的发送目标：回复哪条消息 / 发到哪个会话 / 评论哪个 Meego 工作项（起草本身不发消息；严格跳过已撤回及无主/跨账号个人 Web 证据） */
  target(it: ItemRow, kind: CtxDraftKind): { target: Record<string, string>; label: string; conv?: Obs } {
    if (kind === "meego_comment") {
      const key = String(it.meta.project_key ?? "");
      const id = String(it.meta.work_item_id ?? "");
      if (!key || !id) throw new DraftTargetIneligibleError("这个事项没有关联 Meego 工作项");
      return { target: { project_key: key, work_item_id: id, url: String(it.meta.url ?? "") }, label: `Meego #${id} 评论` };
    }
    const activeNativeOwner = this.activeBoundNativeOwner();
    const fromOther = this.store.lastEvidenceObs("item", it.id, (o) => this.isEligibleImObs(o, activeNativeOwner) && !o.is_me);
    const any = fromOther ?? this.store.lastEvidenceObs("item", it.id, (o) => this.isEligibleImObs(o, activeNativeOwner));
    if (!any) throw new DraftTargetIneligibleError("找不到这个事项对应的飞书会话，没法起草消息");
    return this.buildTargetForObs(it, kind, any, kind === "reply" && !!fromOther);
  }

  /**
   * 按当前排除规则与群采集范围解析起草目标：
   *   - 按时间倒序遍历事项全部有效 IM 证据（优先对方消息，再回退本人消息）；
   *   - 逐条校验会话排除状态（checkConvAllowed）与目标证据本身的范围资格（filterObs）；
   *   - 若最新证据因群被移出白名单/静音而失效，自动改选事项上的其他有效目标；若全部目标均不在当前范围内，在调用模型前立即停止。
   */
  async resolveEligibleTarget(
    it: ItemRow,
    kind: CtxDraftKind,
    excludeObsIds?: ReadonlySet<string>,
  ): Promise<{ target: Record<string, string>; label: string; conv?: Obs }> {
    if (kind === "meego_comment") return this.target(it, kind);
    const activeNativeOwner = this.activeBoundNativeOwner();
    const allObs: Obs[] = [];
    const seenIds = new Set<string>();
    for (const e of this.store.evidence("item", it.id, 50)) {
      if (seenIds.has(e.obs_id) || excludeObsIds?.has(e.obs_id)) continue;
      const o = this.store.obs(e.obs_id);
      if (o && this.isEligibleImObs(o, activeNativeOwner)) {
        seenIds.add(o.id);
        allObs.push(o);
      }
    }
    if (!allObs.length) {
      if (excludeObsIds?.size) {
        throw new DraftTargetIneligibleError("该事项对应的目标消息已不在当前采集范围内，已停止起草回复");
      }
      throw new DraftTargetIneligibleError("找不到这个事项对应的飞书会话，没法起草消息");
    }
    const ordered = [...allObs.filter((o) => !o.is_me), ...allObs.filter((o) => o.is_me)];
    const convAllowedCache = new Map<string, "allowed" | "excluded" | "uncertain">();
    let sawExcluded = false;
    let sawUncertain = false;
    let sawOutOfScope = false;

    for (const cand of ordered) {
      if (this.checkConvAllowed) {
        let elig = convAllowedCache.get(cand.conv);
        if (elig === undefined) {
          elig = await this.checkConvAllowed(cand.conv, cand.conv_name);
          convAllowedCache.set(cand.conv, elig);
        }
        if (elig === "excluded") {
          sawExcluded = true;
          continue;
        }
        if (elig === "uncertain") {
          sawUncertain = true;
          continue;
        }
      }
      if (this.filterObs) {
        const checkedSelf = await this.filterObs(cand.conv, [cand]);
        if (!checkedSelf.length) {
          sawOutOfScope = true;
          continue;
        }
      }
      return this.buildTargetForObs(it, kind, cand, kind === "reply" && !cand.is_me);
    }

    if (sawUncertain) {
      throw new DraftTargetUncertainError("无法实时确认该会话的排除状态，已按安全策略暂缓起草回复");
    }
    if (sawExcluded) {
      throw new DraftTargetIneligibleError("该会话已被静音或排除，已停止起草回复");
    }
    if (sawOutOfScope) {
      throw new DraftTargetIneligibleError("该事项对应的目标消息已不在当前采集范围内，已停止起草回复");
    }
    throw new DraftTargetIneligibleError("找不到这个事项对应的飞书会话，没法起草消息");
  }

  private async llm(prompt: string, name: string): Promise<string> {
    const harness = this.cfg.context.harness || this.cfg.roles.brain;
    const logFile = path.join(this.cfg.dataDir, "runs", `draft-${name}-${Date.now()}.log`);
    const r = await this.runner(this.cfg, {
      harness,
      prompt,
      cwd: path.join(this.cfg.dataDir, "workspace", "context"),
      tools: "none",
      lark: "none",
      timeoutSec: 300,
      logFile,
    });
    const text = r.text.replace(/^```[\w]*\n?|```$/g, "").trim();
    if (!text) throw new Error(`起草失败（exit ${r.exitCode}${r.timedOut ? "，超时" : ""}）`);
    return text;
  }

  private isConvSyncBlocked(conv: string): boolean {
    if (!this.cfg.context.sources.im) return true;
    if (this.store.isConvMutedById(conv)) return true;
    if (conv.startsWith("pw_chat:") && this.store.isConvMutedById(conv.slice("pw_chat:".length))) return true;
    return false;
  }

  private activeBoundNativeOwner(): string | null {
    const boundNative = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
    if (!boundNative) return null;
    const cfgWs = this.cfg.owner.open_id.trim();
    const boundWs = (this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    if (cfgWs !== boundWs) return null;
    return boundNative;
  }

  async forItem(
    itemId: string,
    kind?: CtxDraftKind,
    opts?: { beforeInfer?: () => boolean; auto?: boolean },
  ): Promise<DraftRow> {
    const it = this.store.item(itemId);
    if (!it) throw new Error(`没有这个事项：${itemId}`);
    const k = kind ?? defaultDraftKind(it);
    if (!k || k === "weekly_report") throw new Error("这个事项没有合适的草稿类型");
    if (opts?.auto && this.store.hasProposedDraft(it.id, k)) {
      throw new DraftTargetIneligibleError("该事项已有待确认草稿，自动预起草跳过替换以保护你正在审阅的回复");
    }
    const tz = this.cfg.owner.timezone;
    const p = this.store.project(it.project_id);
    const excludedTargets = new Set<string>();
    let chosen: { target: Record<string, string>; label: string; conv?: Obs } | undefined;
    let effectiveConvObs: Obs[] = [];
    let verifiedOwner: string | null = null;
    let verifiedConv = "";
    let verifiedConvName = "";
    let verifiedTargetObsId = "";
    let verifiedTargetRev = "";
    let verifiedWindowRevs: [string, string][] = [];
    for (let attempt = 0; attempt < 6; attempt++) {
      const policyBefore = this.policySignature?.() ?? "";
      const ownerBefore = this.activeBoundNativeOwner();
      const cand = await this.resolveEligibleTarget(it, k, excludedTargets);
      if (!cand.conv) {
        chosen = cand;
        effectiveConvObs = [];
        verifiedOwner = ownerBefore;
        break;
      }
      // 异步解析目标返回后必须从 SQLite 重读最新目标记录：绝不从旧快照补回已被撤回或删除的消息
      const ownerMid = this.activeBoundNativeOwner();
      const freshTarget = this.store.obs(cand.conv.id);
      if (!freshTarget || !this.isEligibleImObs(freshTarget, ownerMid) || this.isConvSyncBlocked(freshTarget.conv)) {
        excludedTargets.add(cand.conv.id);
        continue;
      }
      if (obsRevision(freshTarget) !== obsRevision(cand.conv) || ownerMid !== ownerBefore) {
        continue;
      }
      const targetRev = obsRevision(freshTarget);
      const rawConvObs = this.store
        .convObs(freshTarget.conv, Date.now() - 7 * DAY, 30, ownerMid)
        .filter((o) => this.isEligibleImObs(o, ownerMid));
      // 若 freshTarget 早于最近 7 天窗口但仍未撤回且有效，仅并入刚从数据库重读的 freshTarget
      const combinedRaw = rawConvObs.some((o) => o.id === freshTarget.id)
        ? rawConvObs
        : [...rawConvObs, freshTarget].sort((a, b) => a.time - b.time);
      const scopedConvObs = this.filterObs ? await this.filterObs(freshTarget.conv, combinedRaw) : combinedRaw;

      // 送模型推理前最终同步核验：策略签名（静音/排除/开关/主人绑定）、目标及全部窗口观测修订均须与当前数据库一致
      const ownerAfter = this.activeBoundNativeOwner();
      const policyAfter = this.policySignature?.() ?? "";
      if (ownerAfter !== ownerBefore || policyAfter !== policyBefore) {
        continue;
      }
      if (this.isConvSyncBlocked(freshTarget.conv)) {
        excludedTargets.add(freshTarget.id);
        continue;
      }
      if (!scopedConvObs.some((o) => o.id === freshTarget.id)) {
        excludedTargets.add(freshTarget.id);
        continue;
      }
      const targetNow = this.store.obs(freshTarget.id);
      if (!targetNow || !this.isEligibleImObs(targetNow, ownerAfter)) {
        excludedTargets.add(freshTarget.id);
        continue;
      }
      if (obsRevision(targetNow) !== targetRev) {
        continue;
      }
      let windowStale = false;
      const verifiedWindow: Obs[] = [];
      for (const o of scopedConvObs) {
        const cur = this.store.obs(o.id);
        if (!cur || !this.isEligibleImObs(cur, ownerAfter) || obsRevision(cur) !== obsRevision(o)) {
          windowStale = true;
          break;
        }
        verifiedWindow.push(cur);
      }
      if (windowStale) {
        continue;
      }
      chosen = this.buildTargetForObs(it, k, targetNow, k === "reply" && !targetNow.is_me);
      effectiveConvObs = verifiedWindow;
      verifiedOwner = ownerAfter;
      verifiedConv = targetNow.conv;
      verifiedConvName = targetNow.conv_name;
      verifiedTargetObsId = targetNow.id;
      verifiedTargetRev = targetRev;
      verifiedWindowRevs = verifiedWindow.map((o) => [o.id, obsRevision(o)]);
      break;
    }
    if (!chosen) {
      throw new DraftTargetIneligibleError("该事项对应的目标消息已不在当前采集范围内或状态已变更，已停止起草回复");
    }
    const { target, label } = chosen;
    const convText = effectiveConvObs.length
      ? effectiveConvObs
          .map((o) => `${fmt(o.time, tz)} ${o.is_me ? "【我】" : o.actor_name}: ${truncate(o.text, 300)}`)
          .join("\n")
      : "（无）";
    const task = {
      reply: `回复 ${target.message_id || target.native_message_id ? "对方最近的这条消息" : "对方"}，就「${it.title}」给出答复或进展。`,
      followup: `礼貌地跟进「${it.title}」，询问对方（${it.counterpart || "相关同事"}）的进展或预计时间。`,
      meego_comment: `为 Meego 工作项写一条进展评论：说明「${it.title}」当前的实际进展、下一步和预计时间。`,
    }[k];
    const prompt = render(loadPrompt("context-draft.md"), {
      owner_name: this.app.store.get("ctx.owner_name") ?? "主人",
      now: new Date().toLocaleString("zh-CN", { timeZone: tz }),
      task,
      item: `${it.title}（类型 ${it.kind}，对方 ${it.counterpart || "-"}，建议下一步：${it.next_step || "-"}）`,
      project: p ? `${p.name}：${p.stage || p.description || ""}\n${this.store.knowledge({ project_id: p.id, limit: 5 }).map((x) => `- ${x.title}：${truncate(x.content, 120)}`).join("\n")}` : "（无）",
      conversation: convText,
      format: k === "meego_comment" ? "3~6 行，可用「进展 / 下一步 / 风险」分行。" : "1~4 句话，不超过 200 字。",
    });
    // 紧贴模型调用前同步复检自动预起草资格（防止在异步解析目标与会话期间被关闭 pre_draft、静音项目或关闭事项）
    if (opts?.beforeInfer && !opts.beforeInfer()) {
      throw new DraftTargetIneligibleError("自动预起草资格在推理前已失效，已跳过起草");
    }
    const content = await this.llm(prompt, k);
    // 模型推理返回后、落库与发布草稿卡前，重新核验自动资格、本会话排除状态与全部输入观测是否仍在当前范围内；
    // 若 spoken 模式下因主人在无关群发言导致全局 policySignature 变化，仅对本草稿自身目标和窗口复检，仍合法则正常保留，不误丢弃。
    for (let recheck = 0; recheck < 3; recheck++) {
      const postSigBefore = this.policySignature?.() ?? "";
      if (this.activeBoundNativeOwner() !== verifiedOwner) {
        throw new DraftTargetIneligibleError("工作区绑定账号在推理期间已变更，已丢弃过期草稿");
      }
      if (opts?.beforeInfer && !opts.beforeInfer()) {
        throw new DraftTargetIneligibleError("自动预起草资格在推理期间已失效，已丢弃过期草稿");
      }
      if (verifiedConv) {
        if (this.checkConvAllowed) {
          const postDecision = await this.checkConvAllowed(verifiedConv, verifiedConvName);
          if (postDecision === "uncertain") {
            throw new DraftTargetUncertainError("目标会话在推理后暂时无法实时核验排除状态，已暂缓发布草稿");
          }
          if (postDecision !== "allowed") {
            throw new DraftTargetIneligibleError("目标会话在推理期间已被静音、排除，已丢弃过期草稿");
          }
        }
        if (this.filterObs && effectiveConvObs.length > 0) {
          const rescoped = await this.filterObs(verifiedConv, effectiveConvObs);
          const rescopedIds = new Set(rescoped.map((o) => o.id));
          if (!rescopedIds.has(verifiedTargetObsId) || verifiedWindowRevs.some(([id]) => !rescopedIds.has(id))) {
            throw new DraftTargetIneligibleError("目标消息或会话上下文在推理期间已移出当前采集范围，已丢弃过期草稿");
          }
        }
      }
      const txRes = this.store.tx((): { saved: DraftRow } | { retry: true } => {
        const latestItem = this.store.item(itemId);
        if (!latestItem) {
          throw new DraftTargetIneligibleError("事项在推理期间已不存在，已丢弃过期草稿");
        }
        if (opts?.beforeInfer && !opts.beforeInfer()) {
          throw new DraftTargetIneligibleError("自动预起草资格在落库前已失效，已丢弃过期草稿");
        }
        if (opts?.auto && this.store.hasProposedDraft(latestItem.id, k)) {
          throw new DraftTargetIneligibleError("该事项已有待确认草稿，自动预起草在落库事务内跳过覆盖");
        }
        if (this.activeBoundNativeOwner() !== verifiedOwner) {
          throw new DraftTargetIneligibleError("工作区绑定账号在推理期间已变更，已丢弃过期草稿");
        }
        if (verifiedTargetObsId) {
          if (this.isConvSyncBlocked(verifiedConv)) {
            throw new DraftTargetIneligibleError("目标会话在推理期间已被静音或关闭 IM 采集，已丢弃过期草稿");
          }
          const postTarget = this.store.obs(verifiedTargetObsId);
          if (!postTarget || !this.isEligibleImObs(postTarget, verifiedOwner) || obsRevision(postTarget) !== verifiedTargetRev) {
            throw new DraftTargetIneligibleError("目标消息在推理期间已被编辑、撤回或移出范围，已丢弃过期草稿");
          }
          for (const [obsId, rev] of verifiedWindowRevs) {
            const cur = this.store.obs(obsId);
            if (!cur || !this.isEligibleImObs(cur, verifiedOwner) || obsRevision(cur) !== rev) {
              throw new DraftTargetIneligibleError("会话上下文在推理期间已发生变更，已丢弃过期草稿");
            }
          }
        }
        // 若在本次异步复检（checkConvAllowed / filterObs）期间策略签名又发生变化，重试复检本草稿的实际资格
        if ((this.policySignature?.() ?? "") !== postSigBefore) {
          return { retry: true };
        }
        return {
          saved: this.store.addDraft({
            item_id: latestItem.id,
            project_id: latestItem.project_id,
            kind: k,
            target,
            target_label: label,
            content,
          }),
        };
      });
      if ("saved" in txRes) return txRes.saved;
    }
    throw new DraftTargetIneligibleError("采集或排除策略在落库复检期间持续变动，已丢弃过期草稿");
  }

  /** 周报草稿：按项目汇总这段时间的动态、知识、关闭和打开的事项 */
  async weekly(days = 7): Promise<DraftRow> {
    const since = Date.now() - days * DAY;
    const tz = this.cfg.owner.timezone;
    const projects = this.store.projects();
    const lines: string[] = [];
    for (const p of projects) {
      const ups = this.store.updates({ project_id: p.id, since, limit: 10 });
      const done = this.store.items({ status: ["done"], project_id: p.id, limit: 50 }).filter((i) => (i.closed_at ?? 0) >= since);
      const open = this.store.items({ status: ["open"], project_id: p.id, limit: 50 }).filter((i) => !i.meta.legacy);
      if (!ups.length && !done.length) continue;
      lines.push(`## ${p.name}（${p.stage || "阶段未知"}）`);
      for (const u of ups) lines.push(`- 动态 ${fmt(u.time, tz)}：${u.summary}`);
      for (const i of done.slice(0, 10)) lines.push(`- 完成：${i.title}`);
      for (const i of open.filter((x) => x.priority === "high" || x.kind === "risk").slice(0, 6)) lines.push(`- 进行中/风险：${i.title}`);
    }
    if (!lines.length) throw new Error("这段时间没有可写进周报的进展");
    const prompt = render(loadPrompt("context-draft.md"), {
      owner_name: this.app.store.get("ctx.owner_name") ?? "主人",
      now: new Date().toLocaleString("zh-CN", { timeZone: tz }),
      task: `根据下面整理好的素材，写一份最近 ${days} 天的个人工作周报。`,
      item: "（见项目背景）",
      project: lines.join("\n"),
      conversation: "（无）",
      format: "Markdown：按项目分节，每节 2~5 条要点（本周进展 / 风险 / 下周计划），开头一句总述。",
    });
    const content = await this.llm(prompt, "weekly");
    const date = new Intl.DateTimeFormat("en-CA", { timeZone: tz }).format(new Date());
    return this.store.addDraft({ item_id: "", project_id: "", kind: "weekly_report", target: { title: `周报 ${date}` }, target_label: `我的文档库 · 周报 ${date}`, content });
  }

  /** 确认草稿：变成对外动作（outbox）；严格沿用草稿原始传输通道与路由，绝不把话题回复降级为群顶层消息，绝不跨账号发送 */
  effectFor(d: DraftRow, content: string): Effect {
    const obs = d.target.obs_id ? this.store.obs(d.target.obs_id) : undefined;
    const lockedRoute = d.target.delivery_route || "";

    const buildPwReply = (): Effect => {
      if (lockedRoute && lockedRoute !== "pw.reply") {
        throw new Error(`草稿已绑定发送路由 ${lockedRoute}，拒绝切换为 pw.reply`);
      }
      if (!d.target.native_chat_id || !d.target.native_message_id) {
        throw new Error("该个人 Web 草稿缺少原会话或原消息 ID，无法发送");
      }
      const currentBound = this.activeBoundNativeOwner();
      const ownerId = (d.target.native_owner_id || String(obs?.meta.native_owner_id ?? "")).trim();
      if (!ownerId) {
        throw new Error("该个人 Web 草稿缺少明确的归属账号 ID，拒绝发送");
      }
      if (!currentBound) {
        throw new Error("当前工作区尚未完成有效个人 Web 账号绑定或工作区主人已变更，拒绝发送");
      }
      if (currentBound !== ownerId) {
        throw new Error(`该草稿归属账号 (${ownerId}) 与当前工作区绑定账号 (${currentBound}) 不一致，拒绝发送`);
      }
      // 若飞书已创建该精确草稿回复（仅缺回读确认），即使已关闭 send_replies 或原消息后续被撤回，仍放行只读回读恢复；
      // 但若尚未发出且目标观测已被编辑撤回（withdrawn），必须拒绝发起新的外部发送。
      const readbackRecovery = isReadbackOnlyDelivery(this.app.store, {
        draft_id: d.id,
        owner_id: ownerId,
        chat_id: d.target.native_chat_id,
        message_id: d.target.native_message_id,
        text: content,
      });
      if (!readbackRecovery && obs?.meta.withdrawn === true) {
        throw new Error("该草稿对应的原个人 Web 消息已被编辑移出触发范围或撤回，拒绝发送新回复");
      }
      if (!readbackRecovery && !this.cfg.context.sources.im) {
        throw new Error("已关闭 IM 采集（context.sources.im: false），拒绝发送个人 Web 回复");
      }
      if (!readbackRecovery && this.isConvSyncBlocked(`pw_chat:${d.target.native_chat_id}`)) {
        throw new Error("该草稿对应的个人 Web 会话已被静音或排除，拒绝发送新回复");
      }
      if (!this.cfg.context.personal_web.send_replies && !readbackRecovery) {
        throw new Error("该草稿目标来自个人 Web 实时消息；为避免偏离原话题，请在设置中开启 context.personal_web.send_replies 后再发送");
      }
      return {
        op: "pw.reply",
        args: {
          owner_id: ownerId,
          chat_id: d.target.native_chat_id,
          message_id: d.target.native_message_id,
          root_id: d.target.native_root_id,
          text: content,
          draft_id: d.id,
        },
      };
    };

    const assertCliDraftSourceEligible = () => {
      if (d.target.obs_id) {
        if (!obs || obs.meta.withdrawn === true) {
          throw new Error("该草稿对应的原消息已被撤回或不存在，拒绝发送");
        }
        if (this.isConvSyncBlocked(obs.conv)) {
          throw new Error("该草稿对应的会话已被静音或已关闭 IM 采集，拒绝发送");
        }
      } else if (d.target.chat_id && this.isConvSyncBlocked(d.target.chat_id)) {
        throw new Error("该草稿目标会话已被静音或已关闭 IM 采集，拒绝发送");
      }
    };

    switch (d.kind) {
      case "reply": {
        if (lockedRoute === "pw.reply" || d.target.transport === "personal_web") {
          return buildPwReply();
        }
        if (d.target.message_id) {
          if (lockedRoute && lockedRoute !== "im.reply") {
            throw new Error(`草稿已绑定发送路由 ${lockedRoute}，拒绝切换为 im.reply`);
          }
          assertCliDraftSourceEligible();
          return { op: "im.reply", args: { message_id: d.target.message_id, text: content, draft_id: d.id } };
        }
        if (lockedRoute === "im.reply") {
          throw new Error("该草稿已绑定按原消息回复（im.reply），但缺少 message_id，拒绝降级为顶层消息");
        }
        if (!d.target.chat_id) {
          throw new Error("该回复草稿缺少目标会话 ID");
        }
        assertCliDraftSourceEligible();
        return { op: "im.send", args: { chat_id: d.target.chat_id, text: content, draft_id: d.id } };
      }
      case "followup": {
        if (lockedRoute === "pw.reply" || d.target.transport === "personal_web") {
          return buildPwReply();
        }
        if (lockedRoute && lockedRoute !== "im.send") {
          throw new Error(`草稿已绑定发送路由 ${lockedRoute}，拒绝切换为 im.send`);
        }
        if (!d.target.chat_id) {
          throw new Error("该跟进草稿缺少目标会话 ID");
        }
        assertCliDraftSourceEligible();
        return { op: "im.send", args: { chat_id: d.target.chat_id, text: content, draft_id: d.id } };
      }
      case "meego_comment":
        return { op: "meego.comment", args: { project_key: d.target.project_key, work_item_id: d.target.work_item_id, content, draft_id: d.id } };
      case "weekly_report":
        return { op: "doc.create", args: { title: d.target.title || "周报", markdown: content, draft_id: d.id } };
    }
  }
}
