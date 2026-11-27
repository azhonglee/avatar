import { createHash, randomUUID } from "node:crypto";
import { Cron } from "croner";
import { z } from "zod";
import type { App } from "../app.ts";
import { isWorkBlockedByOwner } from "../api/queries.ts";
import type { CtxCycleReport, CtxDraftKind, CtxItemStatus, CtxItemView, CommandResult } from "../api/types.ts";
import { consoleBaseUrl, serverToken, signLoginTicket } from "../server/index.ts";
import { CommandError } from "../commands.ts";
import { card as cardEffect, notify } from "../effects.ts";
import type { Handler } from "../engine.ts";
import { detectIsolatedCodexKeyringConflict } from "../harness.ts";
import type { Effect, NotifyKind } from "../ledger.ts";
import { deepFind, errMsg, log, truncate } from "../util.ts";
import { draftCard, eveningCard, itemCard, KIND_LABEL, morningCard, type CtxRenderCtx } from "./cards.ts";
import { Connectors, relinkMeegoItems, textOf } from "./connectors.ts";
import { defaultDraftKind, Drafter, DraftTargetIneligibleError, DraftTargetUncertainError } from "./drafts.ts";
import { PersonalWebBridge, type FastAnchor } from "./personal-web.ts";
import { ContextStore, obsRevision, obsRevisionToken, type ItemRow } from "./store.ts";
import { splitProject, Understander, UnderstandParseError, type SplitResult } from "./understand.ts";
import { ContextViews, startOfDay } from "./views.ts";

/**
 * 工作上下文模块：
 *   采集（Meego / 飞书任务 / 消息 / 妙记 / 日历 + 个人 Web 实时推送快通道） → 理解（模型抽取项目、事项、知识、动态、人、冲突，带证据）
 *   → 视图（今天 / 项目 / 事项 / 知识 / 动态 / 人） → 主动反馈（晨间卡、收尾卡、实时提醒）
 *   → 推进（起草回复 / 跟进 / Meego 评论 / 周报，你确认后以你本人身份执行；可选委托给 Agent）。
 *
 * 自主等级：
 *   L0 提醒（卡片）  L1 起草（需确认）  L2 只影响你自己的低风险动作（autonomy 开关）  L3 委托（dispatch.create）
 * 对外可见的动作（发消息、写 Meego、建文档）永远只在你确认草稿后发生。
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

type CtxPayload = (
  | { task: "cycle" }
  | { task: "fast"; conv: string; conv_name: string; trigger_obs_id: string; anchor?: FastAnchor; anchors?: FastAnchor[] }
  | { task: "draft"; item_id: string; kind?: CtxDraftKind; auto?: boolean; trigger_keys?: string[] }
  | { task: "weekly"; days: number }
  | { task: "split"; project_id: string }
) & { owner_open_id?: string };

export class ContextService {
  app: App;
  store: ContextStore;
  connectors: Connectors;
  understander: Understander;
  views: ContextViews;
  drafter: Drafter;
  personalWeb: PersonalWebBridge;
  running = false;

  constructor(app: App) {
    this.app = app;
    this.store = new ContextStore(app.store.db);
    this.connectors = new Connectors(
      app,
      this.store,
      () => this.personalWeb.resolveNativeExclusionsForPolling(),
      () => this.personalWeb.syncDiskPrivacyConfig({ throwOnError: false }),
      () => this.personalWeb.effectiveDiskOwnerOpenId(),
    );
    this.understander = new Understander(app, this.store);
    this.views = new ContextViews(app, this.store);
    this.drafter = new Drafter(
      app,
      this.store,
      async (conv, obs) => {
        const nativeExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
        return this.personalWeb.filterWindowByCurrentScope(conv, obs, nativeExcl);
      },
      (conv, convName) => this.personalWeb.checkConvAllowedForUnderstand(conv, convName),
      () => this.personalWeb.policySignature(),
    );
    this.personalWeb = new PersonalWebBridge(app, this.store, {
      onFastTrigger: (t) => {
        // 使用确定性哈希作为账本 work ID，避免 work.changed SSE 事件直接暴露宿主机旧主人的原生会话/消息 ID；原生标识保留在受主人校验的 payload 中
        const fastKey = createHash("sha256")
          .update(`${t.conv}\0${t.trigger_obs_id}\0g${t.rev_gen}\0${t.text_hash}`)
          .digest("hex")
          .slice(0, 24);
        this.enqueue(`fast:${fastKey}`, {
          task: "fast",
          conv: t.conv,
          conv_name: t.conv_name,
          trigger_obs_id: t.trigger_obs_id,
          anchor: t.anchor,
          anchors: t.anchors,
        });
      },
      onReconnect: () => {
        // 个人 Web 断线重连成功后触发一次 lark-cli 补采，填补断线期间遗漏的消息
        this.enqueue(`cycle:pw-reconnect-${Math.floor(Date.now() / 60_000)}`, { task: "cycle" });
      },
      onNeedsLogin: (reason) => {
        // 仅在本地日志与受主人校验的诊断接口中保留详细原因，对外私信通知脱敏以免向新配置的主人暴露旧绑定账号 ID
        log("warn", "飞书个人 Web 实时通道需要重新登录或确认绑定", { reason: truncate(reason, 200) });
        const day = this.today();
        this.app.ledger.emit(
          "context:pw-needs-login",
          [notify("⚠️ 飞书个人 Web 实时通道登录已失效或需要重新确认绑定，请运行 `pa context web-login` 重新扫码或在控制台查看详情；期间每 10 分钟的飞书定时采集仍继续兜底。", "failure")],
          `pw-needs-login-${day}`,
        );
        this.app.engine.kick();
      },
    });
  }

  private get cfg() {
    return this.app.cfg;
  }

  isWorkspaceOwnerMismatched(): boolean {
    return this.personalWeb.isWorkspaceOwnerMismatched();
  }

  assertWorkspaceOwnerMatches(): void {
    if (this.isWorkspaceOwnerMismatched()) {
      throw new CommandError(
        "conflict",
        "当前工作区 config.yaml 的 owner.open_id 与已绑定的个人 Web 主人不一致；为防止旧主人的私聊摘要或草稿泄漏给新主人，已阻断访问上下文视图与对外动作，请切回原主人或使用全新的 data_dir",
      );
    }
  }

  /**
   * 审批或真正投递 CLI 草稿（`im.reply` / `im.send`）前实时核验源消息与会话策略：
   *   - 刷新磁盘隐私策略并确认工作区主人一致、IM 采集未关闭；
   *   - 若草稿绑定了源观测 `target.obs_id`，核验源观测存在、未被撤回、会话未被静音/排除且仍在当前群范围或仍保留 @本人；
   *   - 若草稿仅含 `chat_id`，核验目标会话未被静音或排除。
   */
  /**
   * 审批与投递基于草稿的 CLI 会话消息（`im.reply` / `im.send`）前实时核验：
   *   - 同步磁盘隐私策略、核验工作区主人未切换且 `context.enabled` 与 `context.sources.im` 均开启；
   *   - 若绑定源观测或源消息 ID，除校验本地未撤回与会话允许外，还经 `im +messages-mget` 实时回读飞书远端确认原消息未撤回/删除且在范围外群仍显式 @本人；
   *   - 若仅含 `chat_id`，同时校验会话未静音/排除且群聊仍在当前允许群范围内；
   *   - 所有异步校验完成后再次同步复检磁盘隐私配置、主人绑定、IM 开关、源观测撤回与会话静音，防止异步等待期间策略变更竞态。
   */
  async verifyCliDraftTargetForDelivery(
    draftId: string,
    fallbackChatId?: string,
    fallbackMessageId?: string,
  ): Promise<void> {
    this.personalWeb.syncDiskPrivacyConfig({ throwOnError: true });
    this.assertWorkspaceOwnerMatches();
    if (!this.cfg.context.enabled || !this.cfg.context.sources.im) {
      throw new Error("工作上下文或 IM 采集已关闭，拒绝投递基于会话消息起草的草稿");
    }
    const d = draftId ? this.store.draft(draftId) : undefined;
    if (draftId && !d) {
      throw new Error("草稿记录不存在，拒绝发送");
    }
    const obsId = d?.target.obs_id || (fallbackMessageId ? `im:${fallbackMessageId}` : "");
    const obs = obsId ? this.store.obs(obsId) : undefined;
    if (d?.target.obs_id && (!obs || obs.meta.withdrawn === true)) {
      throw new Error("该草稿对应的原消息已被撤回或移除，拒绝发送");
    }
    if (!d?.target.obs_id && obs?.meta.withdrawn === true) {
      throw new Error("该回复目标对应的原消息已被撤回，拒绝发送");
    }
    const targetConv = obs?.conv || d?.target.chat_id || fallbackChatId || "";
    if (targetConv) {
      const convDecision = await this.personalWeb.checkConvAllowedForUnderstand(targetConv, obs?.conv_name ?? "");
      if (convDecision !== "allowed") {
        throw new Error("该草稿目标会话已被静音、排除或暂时无法确认排除状态，拒绝发送");
      }
    }
    const nativeExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
    if (obs) {
      const kept = this.personalWeb.filterWindowByCurrentScope(obs.conv, [obs], nativeExcl);
      if (!kept.length) {
        throw new Error("该草稿对应的原消息已移出当前允许的群范围或已移除 @本人，拒绝发送");
      }
    }

    const liveMessageId =
      d?.target.message_id ||
      fallbackMessageId ||
      (obs?.id.startsWith("im:") ? String(obs.meta.message_id ?? obs.id.slice(3)) : "");
    if (liveMessageId) {
      let data: Record<string, unknown>;
      try {
        data = (await this.app.lark.run(
          ["im", "+messages-mget", "--message-ids", liveMessageId, "--no-reactions"],
          { as: "user" },
        )) as Record<string, unknown>;
      } catch (err) {
        throw new Error(`发送前实时回读原消息失败，按安全原则中止发送：${errMsg(err)}`);
      }
      const list = Array.isArray(data?.messages)
        ? (data.messages as Record<string, unknown>[])
        : Array.isArray(data?.items)
          ? (data.items as Record<string, unknown>[])
          : [];
      const fresh = list.find((m) => String(m.message_id ?? m.id ?? "") === liveMessageId);
      const freshText = fresh ? textOf(fresh.content ?? fresh.text ?? "") : "";
      if (!fresh || fresh.deleted === true || fresh.is_deleted === true || !freshText) {
        if (obs) this.store.retirePendingObs(obs.id);
        throw new Error("发送前实时核验发现原消息已被撤回、删除或不可读，已中止发送");
      }
      const liveChatId = String(fresh.chat_id ?? "") || targetConv;
      const liveChatType = String(fresh.chat_type ?? obs?.meta.chat_type ?? "").trim().toLowerCase();
      if (liveChatId && liveChatId !== targetConv) {
        const liveConvDecision = await this.personalWeb.checkConvAllowedForUnderstand(
          liveChatId,
          String(fresh.chat_name ?? obs?.conv_name ?? ""),
        );
        if (liveConvDecision !== "allowed") {
          throw new Error("发送前实时核验发现目标会话已被静音、排除或暂时无法确认排除状态，已中止发送");
        }
      }
      const isDm =
        liveChatType === "p2p" || obs?.kind === "p2p" || (!!liveChatId && this.store.isDmConv(liveChatId));
      if (!isDm && liveChatId.startsWith("oc_")) {
        const inScope = this.personalWeb.isGroupConvInCurrentScope(liveChatId, nativeExcl);
        if (!inScope) {
          const me = this.cfg.owner.open_id.trim();
          if (this.connectors.explicitMentionsMe(fresh, me) !== true) {
            if (obs) this.store.retirePendingObs(obs.id);
            throw new Error("发送前实时核验发现范围外群原消息已不再 @本人（可能已被编辑移除 @mention），已中止发送");
          }
        }
      }
    } else {
      if (!targetConv) {
        throw new Error("草稿缺少目标会话 ID，拒绝发送");
      }
      const isDm = this.store.isDmConv(targetConv);
      if (!isDm && targetConv.startsWith("oc_") && !this.personalWeb.isGroupConvInCurrentScope(targetConv, nativeExcl)) {
        throw new Error("该草稿目标群已移出当前允许的群范围，拒绝发送");
      }
    }

    // 所有异步回读完成后再次同步核验磁盘策略、主人一致、IM 开关、源观测未撤回与会话未静音
    this.personalWeb.syncDiskPrivacyConfig({ throwOnError: true });
    this.assertWorkspaceOwnerMatches();
    if (!this.cfg.context.enabled || !this.cfg.context.sources.im) {
      throw new Error("工作上下文或 IM 采集在核验期间已关闭，拒绝发送");
    }
    if (obsId) {
      const latestObs = this.store.obs(obsId);
      if ((d?.target.obs_id && !latestObs) || latestObs?.meta.withdrawn === true) {
        throw new Error("核验期间检测到原消息已被撤回或移除，拒绝发送");
      }
      if (latestObs) {
        if (this.store.isConvMutedById(latestObs.conv)) {
          throw new Error("核验期间检测到目标会话已被静音，拒绝发送");
        }
        const postKept = this.personalWeb.filterWindowByCurrentScope(latestObs.conv, [latestObs], nativeExcl);
        if (!postKept.length) {
          throw new Error("核验期间检测到原消息已移出当前允许范围，拒绝发送");
        }
      }
    }
    if (targetConv && this.store.isConvMutedById(targetConv)) {
      throw new Error("核验期间检测到目标会话已被静音，拒绝发送");
    }
  }

  renderCtx(notice?: string): CtxRenderCtx {
    const { cfg } = this;
    return {
      consoleBase: cfg.server.enabled ? consoleBaseUrl(cfg.server.host, cfg.server.port) : "",
      consoleTicket: cfg.server.enabled ? signLoginTicket(serverToken(this.app)) : undefined,
      timezone: cfg.owner.timezone,
      notice,
    };
  }

  cardsOn(): boolean {
    return !!this.app.ext.cards && this.cfg.cards.enabled;
  }

  private emitCard(key: string, json: Record<string, unknown>, kind?: NotifyKind, dedupe?: string): void {
    this.app.ledger.emit(`card:${key}`, [cardEffect(key, json, kind)], dedupe);
    this.app.engine.kick();
  }

  draftable(it: Pick<CtxItemView, "id">): boolean {
    const row = this.store.item(it.id);
    if (!row) return false;
    const k = defaultDraftKind(row);
    if (!k) return false;
    try {
      this.drafter.target(row, k);
      return true;
    } catch {
      return false;
    }
  }

  // ───────── 周期 ─────────

  enqueue(id: string, payload: CtxPayload): boolean {
    const boundPayload: CtxPayload = {
      ...payload,
      ...(this.cfg.owner.open_id.trim() ? { owner_open_id: this.cfg.owner.open_id.trim() } : {}),
    };
    const added = this.app.ledger.enqueue({ id: `context:${id}`, kind: "context", ref: payload.task, payload: boundPayload });
    if (added) this.app.engine.kick();
    return added;
  }

  /** 一轮：唤醒稍后事项 → 采集 → 理解 → 挂接 → 提醒 / 自主动作 */
  async cycle(workId: string, signal?: AbortSignal): Promise<CtxCycleReport> {
    const rep: CtxCycleReport = { skipped: false, sources: [], convs: 0, created: 0, closed: 0, knowledge: 0, updates: 0, conflicts: 0, rejected: 0, nudged: 0, errors: [] };
    if (this.personalWeb.hasDiskPolicyError()) {
      return { ...rep, skipped: true, errors: ["磁盘隐私配置无法核验，已按安全策略暂缓上下文周期执行"] };
    }
    if (this.isWorkspaceOwnerMismatched()) {
      return { ...rep, skipped: true, errors: ["工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已阻断上下文周期执行"] };
    }
    if (this.running) return { ...rep, skipped: true };
    this.running = true;
    const pinnedCycleOwner = this.cfg.owner.open_id.trim();
    const kv = this.app.store;
    try {
      this.store.wakeSnoozed();
      // 各来源按采集契约相互隔离：整轮周期锁定初始工作区主人身份 pinnedCycleOwner；
      // 即使运行中途外部磁盘配置与 CLI 账号同时切换，后续采集与提交也会立即拒绝跨账号写入。
      rep.sources = await this.connectors.pullAll(pinnedCycleOwner);
      for (const s of rep.sources) if (s.error) rep.errors.push(`${s.source}: ${s.error}`);
      if (this.personalWeb.hasDiskPolicyError() || this.cfg.owner.open_id.trim() !== pinnedCycleOwner || this.isWorkspaceOwnerMismatched()) {
        return { ...rep, skipped: true };
      }
      const larkAuthBlocked = rep.sources.some(
        (s) =>
          (s.source === "tasks" || s.source === "im" || s.source === "minutes" || s.source === "calendar") &&
          !!s.error &&
          /lark-cli 登录用户|lark-cli auth status|lark-cli 账号归属/.test(s.error),
      );
      if (!larkAuthBlocked) {
        await this.ensureOwnerName();
      }
      const created: ItemRow[] = [];
      const touched: ItemRow[] = [];
      const touchedFreshObsByItem: Record<string, string[]> = {};
      const ctxHarnessName = this.cfg.context.harness || this.cfg.roles.brain;
      const keyringConflict = this.cfg.context.understand
        ? detectIsolatedCodexKeyringConflict(this.cfg, process.env, ctxHarnessName)
        : undefined;
      if (keyringConflict?.severity === "error") {
        rep.errors.push(keyringConflict.message);
      } else if (this.cfg.context.understand) {
        // 每轮最多理解 max_convs_per_cycle 个会话批次；并行跑 understand_parallel 批（通过绑定进程与唯一令牌的 SQLite 租约+心跳跨进程互斥）
        let budget = this.cfg.context.max_convs_per_cycle;
        const par = this.cfg.context.understand_parallel;
        const skippedInCycle = new Set<string>();
        let policyRestarts = 0;
        while (budget > 0 && !signal?.aborted) {
          if (
            this.personalWeb.hasDiskPolicyError() ||
            this.cfg.owner.open_id.trim() !== pinnedCycleOwner ||
            this.isWorkspaceOwnerMismatched() ||
            !this.cfg.context.understand
          ) {
            break;
          }
          // 每轮动态重算启用的来源，防止运行中途关闭文档/妙记开关后后续批次仍选中已停用来源；
          // 若本轮 lark-cli 用户身份未通过核验，跳过依赖 lark-cli 的妙记与 CLI 轮询 IM 观测，
          // 但仍保留本地文档评论与已通过独立个人 Web 认证且绑定当前主人的 `pw:*` IM 观测
          const activeNativeOwner = this.personalWeb.activeBoundNativeOwner();
          const allowImInCycle = this.cfg.context.sources.im && (!larkAuthBlocked || !!activeNativeOwner);
          const activeSources = [
            ...(allowImInCycle ? ["im"] : []),
            ...(this.cfg.context.sources.minutes && !larkAuthBlocked ? ["minutes"] : []),
            ...(this.cfg.context.sources.docs ? ["doc"] : []),
          ];
          if (!activeSources.length) break;
          // 在解析原生排除快照与筛选候选之前捕获策略签名，确保筛选过程一旦发生静音/白名单/开关变化就重启筛选而非带着旧快照送模型
          const selectionPolicySig = this.personalWeb.policySignature();
          const nativeExclSnapshot = await this.personalWeb.resolveNativeExclusionsForPolling();
          const targetCount = Math.min(budget, 8 * par);
          const eligible: { conv: string; conv_name: string; n: number }[] = [];
          const scanned = new Set<string>(skippedInCycle);
          const procOwner = this.app.ledger.owner;
          const claimToken = `${workId}:${procOwner}:${randomUUID().slice(0, 8)}`;
          const batchAbort = new AbortController();
          const onParentAbort = () => batchAbort.abort();
          if (signal?.aborted) {
            batchAbort.abort();
          } else {
            signal?.addEventListener("abort", onParentAbort, { once: true });
          }
          // 从首批选坑开始即启动续租心跳，防止大量候选的异步排除校验耗时超过 120s 租约，失去任一租约时立即中止
          const claimHeartbeat = setInterval(() => {
            for (const c of eligible) {
              if (!this.store.renewConv(c.conv, claimToken, procOwner)) {
                batchAbort.abort();
                break;
              }
            }
          }, 30_000);
          claimHeartbeat.unref?.();
          let groups: (typeof eligible)[] = [];
          let results: PromiseSettledResult<Awaited<ReturnType<Understander["runBatch"]>>>[] = [];
          let restartedForPolicy = false;
          try {
            // 持续翻页跳过被排除/占用的会话，直到凑满目标批次或待处理队列真正耗尽，避免后续会议/文档饿死
            while (eligible.length < targetCount && !signal?.aborted) {
              const page = this.store.pendingConvs(Math.max(targetCount * 2, 16), activeSources, {
                excludeConvs: scanned,
                activeNativeOwner,
                excludeCliIm: larkAuthBlocked,
              });
              if (!page.length) break;
              for (const c of page) {
                if (eligible.length >= targetCount) break;
                scanned.add(c.conv);
                const decision = await this.personalWeb.checkConvAllowedForUnderstand(c.conv, c.conv_name, nativeExclSnapshot);
                if (decision !== "allowed") {
                  skippedInCycle.add(c.conv);
                  continue;
                }
                // 按当前群范围/白名单过滤：不在生效群集合时先在 SQL LIMIT 前筛选真实 @我，避免大量旧普通消息饿死后到的 @我
                const onlyMentions = this.personalWeb.isConvMentionsOnly(c.conv, nativeExclSnapshot);
                const scopedPreview = this.personalWeb.filterWindowByCurrentScope(
                  c.conv,
                  this.store.convWindow(c.conv, 60, 12, activeNativeOwner, { onlyMentions, excludeCliIm: larkAuthBlocked }),
                  nativeExclSnapshot,
                );
                if (!scopedPreview.some((o) => this.store.obsPending(o.id))) {
                  skippedInCycle.add(c.conv);
                  continue;
                }
                if (!this.store.claimConv(c.conv, claimToken, procOwner)) {
                  skippedInCycle.add(c.conv);
                  continue;
                }
                eligible.push(c);
              }
            }
            if (signal?.aborted) throw new Error("aborted");
            if (this.isWorkspaceOwnerMismatched() || !this.cfg.context.understand) break;
            if (this.personalWeb.policySignature() !== selectionPolicySig) {
              // 候选筛选与排除核验期间策略发生了变化：释放占坑并用新策略重新筛选
              restartedForPolicy = true;
            } else {
              // 推理前逐个续租并核实占坑所有权仍属于当前执行者，丢弃已失联的占坑
              const pending = eligible.filter((c) => this.store.renewConv(c.conv, claimToken, procOwner));
              if (!pending.length) break;
              groups = Array.from({ length: Math.min(par, pending.length) }, () => []);
              pending.forEach((c, i) => groups[i % groups.length].push(c));
              results = await Promise.allSettled(
                groups.map((g) => {
                  // 每个并发批次独立记录刚核验过的策略快照版本，并在写事务提交边界再次同步核对
                  let verifiedPolicySig = selectionPolicySig;
                  const validateBeforeApply = async (
                    usedConvs: { conv: string; conv_name: string }[],
                    batchObs: import("./store.ts").Obs[],
                  ): Promise<Set<string>> => {
                    const disallowed = new Set<string>();
                    if (this.isWorkspaceOwnerMismatched() || !this.cfg.context.understand || this.personalWeb.hasDiskPolicyError()) {
                      verifiedPolicySig = "";
                      for (const c of usedConvs) disallowed.add(c.conv);
                      return disallowed;
                    }
                    if (this.personalWeb.policySignature() === selectionPolicySig) {
                      verifiedPolicySig = selectionPolicySig;
                      return disallowed;
                    }
                    const sigBeforeValidate = this.personalWeb.policySignature();
                    const freshExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
                    for (const c of usedConvs) {
                      const elig = await this.personalWeb.checkConvAllowedForUnderstand(c.conv, c.conv_name, freshExcl);
                      if (elig !== "allowed") {
                        disallowed.add(c.conv);
                        continue;
                      }
                      // 逐条复核实际送入模型的精确观测行：只要其中任一行在新策略下不再允许（例如混合了普通消息和 @我的群被移出白名单），整体放弃本批
                      const sentRows = batchObs.filter((o) => o.conv === c.conv);
                      const stillAllowed = this.personalWeb.filterWindowByCurrentScope(c.conv, sentRows, freshExcl);
                      if (stillAllowed.length < sentRows.length) {
                        disallowed.add(c.conv);
                      }
                    }
                    if (this.personalWeb.policySignature() !== sigBeforeValidate) {
                      // 异步复核期间发生第二次策略漂移：标记整批失效并令 commitGuard 拒绝提交
                      verifiedPolicySig = "";
                      for (const c of usedConvs) disallowed.add(c.conv);
                      return disallowed;
                    }
                    verifiedPolicySig = sigBeforeValidate;
                    return disallowed;
                  };
                  return this.understander.runBatch(workId, g, batchAbort.signal, activeNativeOwner, validateBeforeApply, {
                    filterObs: (conv, win) => {
                      const noCliIm = larkAuthBlocked
                        ? win.filter((o) => !(o.source === "im" && !o.id.startsWith("pw:")))
                        : win;
                      return this.personalWeb.filterWindowByCurrentScope(conv, noCliIm, nativeExclSnapshot);
                    },
                    isMentionsOnly: (conv) => this.personalWeb.isConvMentionsOnly(conv, nativeExclSnapshot),
                    excludeCliIm: larkAuthBlocked,
                    claimCheck: { convs: g.map((x) => x.conv), holder: claimToken, procOwner },
                    commitGuard: () =>
                      !this.isWorkspaceOwnerMismatched() &&
                      !this.personalWeb.hasDiskPolicyError() &&
                      this.cfg.context.understand &&
                      !!verifiedPolicySig &&
                      this.personalWeb.policySignature() === verifiedPolicySig,
                  });
                }),
              );
              // 在仍持有会话占坑租约期间处理连续解析失败跳过：仅标记本批实际送入模型的精确观测及修订，绝不波及同群未送入模型的普通消息
              results.forEach((res, gi) => {
                if (res.status !== "rejected" || !(res.reason instanceof UnderstandParseError)) return;
                const reason = truncate(errMsg(res.reason), 300);
                const submittedMap = new Map(
                  (res.reason.submittedByConv ?? []).map((s) => [s.conv, s.entries]),
                );
                for (const c of groups[gi]) {
                  const entries = submittedMap.get(c.conv);
                  if (!entries?.length) continue;
                  const n = Number(kv.get(`ctx.fail.${c.conv}`) ?? 0) + 1;
                  kv.set(`ctx.fail.${c.conv}`, String(n));
                  if (n >= 3) {
                    const skipped = this.store.skipObsIfClaimed(c.conv, entries, claimToken, procOwner);
                    log("warn", "会话理解连续失败，已按提交观测精确跳过", { conv: c.conv_name, skipped, err: reason });
                  }
                }
              });
            }
          } finally {
            signal?.removeEventListener("abort", onParentAbort);
            clearInterval(claimHeartbeat);
            for (const c of eligible) this.store.releaseConv(c.conv, claimToken, procOwner);
          }
          if (restartedForPolicy) {
            if (++policyRestarts >= 3) break;
            skippedInCycle.clear();
            continue;
          }
          if (signal?.aborted) throw new Error("aborted");
          let progress = 0;
          results.forEach((res, gi) => {
            if (res.status === "fulfilled") {
              const r = res.value;
              progress += r.fresh;
              budget -= Math.max(1, r.convs.length);
              rep.convs += r.convs.length;
              rep.created += r.created.length;
              rep.closed += r.closed.length;
              rep.knowledge += r.knowledge;
              rep.updates += r.updates;
              rep.conflicts += r.conflicts;
              rep.rejected += r.rejected;
              created.push(...r.created);
              touched.push(...r.touched);
              for (const [itemId, oids] of Object.entries(r.touchedFreshObsByItem)) {
                const dst = touchedFreshObsByItem[itemId] ?? (touchedFreshObsByItem[itemId] = []);
                for (const oid of oids) if (!dst.includes(oid)) dst.push(oid);
              }
              for (const c of r.convs) kv.db.prepare("DELETE FROM kv WHERE k = ?").run(`ctx.fail.${c}`);
              return;
            }
            budget -= groups[gi].length;
            const reason = truncate(errMsg(res.reason), 300);
            rep.errors.push(`理解失败：${reason}`);
            log("warn", "理解批次失败", { err: reason, convs: groups[gi].map((c) => c.conv_name) });
          });
          if (!progress) break; // 本轮全部失败或没有进展：等下一轮
        }
      }
      relinkMeegoItems(this.store);
      this.store.mergeConflicts();
      this.markNotImportant();
      this.syncDrafts();
      rep.nudged = this.nudge(created);
      this.autonomy(created);
      // 若周期理解在快通道防抖窗口内抢先消费了原生私聊或 @本人 触发消息，无论是新建高优 ask_me 事项还是把原生证据补充到已有事项上，
      // 均以与快通道相同的幂等作业 ID 补入自动预起草（严格限定仅本批新鲜原生触发证据可触发，避免陈旧历史 DM 被无关群消息误触发）
      this.enqueueAutoPreDrafts([...created, ...touched], true, touchedFreshObsByItem);
      kv.set("ctx.last_cycle", String(Date.now()));
      kv.set("ctx.last_error", rep.errors.join("\n").slice(0, 1000));
      kv.set("ctx.last_report", JSON.stringify(rep));
      return rep;
    } catch (e) {
      kv.set("ctx.last_error", truncate(errMsg(e), 1000));
      throw e;
    } finally {
      this.running = false;
    }
  }

  /**
   * 从防抖合并保存的全部锚点（及主触发 ID）中挑选仍然待处理、未撤回、归属当前绑定账号，
   * 且当前仍符合快通道触发条件（对方私聊或真实 @本人）的锚点集合与最新目标观测 ID。
   */
  private selectEligibleFastTriggers(
    conv: string,
    anchors: FastAnchor[],
    fallbackTriggerId: string,
    activeNativeOwner: string | null,
  ): { targetObsId: string; eligibleAnchors: FastAnchor[] } | undefined {
    if (!activeNativeOwner) return undefined;
    const isQualifying = (obsId: string): boolean => {
      const o = this.store.obs(obsId);
      if (!o || o.conv !== conv || o.is_me || o.meta.withdrawn === true) return false;
      if (!this.store.obsPending(obsId)) return false;
      if (o.id.startsWith("pw:") && String(o.meta.native_owner_id ?? "").trim() !== activeNativeOwner) return false;
      const isDm = String(o.meta.chat_type ?? "") === "p2p" || o.kind === "p2p";
      const isAtMe = o.meta.at_me === true || o.kind === "at_me";
      return isDm || isAtMe;
    };

    const eligibleAnchors = anchors.filter((a) => isQualifying(`pw:${a.id}`));
    if (eligibleAnchors.length > 0) {
      const latest = eligibleAnchors[eligibleAnchors.length - 1];
      return { targetObsId: `pw:${latest.id}`, eligibleAnchors };
    }
    if (fallbackTriggerId && isQualifying(fallbackTriggerId)) {
      return { targetObsId: fallbackTriggerId, eligibleAnchors: [] };
    }
    return undefined;
  }

  /**
   * 快通道单会话理解：收到个人 Web 的「@我」或对方私聊时触发，
   * 不等待 10 分钟定时周期与全量来源采集，直接以仍有效的触发消息为中心构建窗口理解并立刻推送提醒卡片（可选预起草，仍需你确认才发）。
   * 若该会话正在被另一批次理解，返回 busy: true 由调度层延迟重排，避免重复扣费与重复写入。
   */
  async fastCycle(
    workId: string,
    p: { conv: string; conv_name: string; trigger_obs_id: string; anchor?: FastAnchor; anchors?: FastAnchor[] },
    signal?: AbortSignal,
  ): Promise<{ busy?: boolean; deferMs?: number; fresh: number; created: number; nudged: number; pre_drafted: number }> {
    if (signal?.aborted) throw new Error("aborted");
    if (
      this.isWorkspaceOwnerMismatched() ||
      this.personalWeb.hasDiskPolicyError() ||
      !this.cfg.context.understand ||
      !this.cfg.context.sources.im ||
      !this.personalWeb.isEffectivePersonalWebEnabled() ||
      !this.cfg.context.personal_web.fast_lane
    ) {
      return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
    }
    const activeNativeOwner = this.personalWeb.activeBoundNativeOwner();
    const rawAnchors = p.anchors?.length ? p.anchors : p.anchor ? [p.anchor] : [];
    const preSelected = this.selectEligibleFastTriggers(p.conv, rawAnchors, p.trigger_obs_id, activeNativeOwner);
    // 触发观测均已处理或已撤回时安全结束，避免在无待处理消息时反复延迟重试
    if (!preSelected) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
    const eligBefore = await this.personalWeb.checkConvAllowedForUnderstand(p.conv, p.conv_name);
    if (signal?.aborted) throw new Error("aborted");
    if (eligBefore === "excluded") return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
    // 仅明确 excluded 时永久结束；因网络抖动或独立 CLI 缺少在线 Web 客户端导致 uncertain 时延迟重排，保留快通道自动预起草能力
    if (eligBefore === "uncertain") return { busy: true, deferMs: 5_000, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
    const keyringConflict = detectIsolatedCodexKeyringConflict(
      this.cfg,
      process.env,
      this.cfg.context.harness || this.cfg.roles.brain,
    );
    if (keyringConflict?.severity === "error") {
      throw new Error(keyringConflict.message);
    }
    const procOwner = this.app.ledger.owner;
    const claimToken = `${workId}:${procOwner}:${randomUUID().slice(0, 8)}`;
    if (!this.store.claimConv(p.conv, claimToken, procOwner)) {
      return { busy: true, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
    }
    const batchAbort = new AbortController();
    const onParentAbort = () => batchAbort.abort();
    if (signal?.aborted) {
      batchAbort.abort();
    } else {
      signal?.addEventListener("abort", onParentAbort, { once: true });
    }
    const claimHeartbeat = setInterval(() => {
      if (!this.store.renewConv(p.conv, claimToken, procOwner)) {
        batchAbort.abort();
      }
    }, 30_000);
    claimHeartbeat.unref?.();
    const isFastSwitchEnabled = () =>
      !this.personalWeb.hasDiskPolicyError() &&
      !this.isWorkspaceOwnerMismatched() &&
      this.cfg.context.understand &&
      this.cfg.context.sources.im &&
      this.personalWeb.isEffectivePersonalWebEnabled() &&
      this.cfg.context.personal_web.fast_lane;
    try {
      await this.ensureOwnerName();
      if (signal?.aborted) throw new Error("aborted");
      if (!isFastSwitchEnabled()) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      const selectedBefore = this.selectEligibleFastTriggers(p.conv, rawAnchors, p.trigger_obs_id, activeNativeOwner);
      if (!selectedBefore) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      if (selectedBefore.eligibleAnchors.length) {
        await this.personalWeb.hydrateContext(selectedBefore.eligibleAnchors, p.conv, p.conv_name, batchAbort.signal);
        if (signal?.aborted) throw new Error("aborted");
      }
      // 补读历史结束后重新核验 understand / fast_lane / sources.im / 主人开关与排除策略（策略快照先于异步校验捕获）
      if (!isFastSwitchEnabled()) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      const fastPolicySig = this.personalWeb.policySignature();
      const fastNativeExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
      if (signal?.aborted) throw new Error("aborted");
      const eligAfter = await this.personalWeb.checkConvAllowedForUnderstand(p.conv, p.conv_name, fastNativeExcl);
      if (signal?.aborted) throw new Error("aborted");
      if (eligAfter === "excluded") return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      if (eligAfter === "uncertain") return { busy: true, deferMs: 5_000, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      if (!isFastSwitchEnabled()) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      if (this.personalWeb.policySignature() !== fastPolicySig) {
        return { busy: true, deferMs: 2_000, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      }
      const selectedAfter = this.selectEligibleFastTriggers(p.conv, rawAnchors, p.trigger_obs_id, activeNativeOwner);
      if (!selectedAfter) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      const onlyMentions = this.personalWeb.isConvMentionsOnly(p.conv, fastNativeExcl);
      const window = this.personalWeb.filterWindowByCurrentScope(
        p.conv,
        this.store.convWindowAround(p.conv, selectedAfter.targetObsId, 60, 12, activeNativeOwner, { onlyMentions }),
        fastNativeExcl,
      );
      if (!window.some((o) => this.store.obsPending(o.id))) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      if (!this.store.renewConv(p.conv, claimToken, procOwner)) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      let verifiedFastPolicySig = fastPolicySig;
      const validateBeforeApply = async (
        usedConvs: { conv: string; conv_name: string }[],
        batchObs: import("./store.ts").Obs[],
      ): Promise<Set<string>> => {
        const disallowed = new Set<string>();
        if (!isFastSwitchEnabled() || signal?.aborted) {
          verifiedFastPolicySig = "";
          for (const c of usedConvs) disallowed.add(c.conv);
          return disallowed;
        }
        if (this.personalWeb.policySignature() === fastPolicySig) {
          verifiedFastPolicySig = fastPolicySig;
          return disallowed;
        }
        const sigBeforeValidate = this.personalWeb.policySignature();
        const freshExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
        for (const c of usedConvs) {
          const elig = await this.personalWeb.checkConvAllowedForUnderstand(c.conv, c.conv_name, freshExcl);
          if (elig !== "allowed") {
            disallowed.add(c.conv);
            continue;
          }
          const sentRows = batchObs.filter((o) => o.conv === c.conv);
          const stillAllowed = this.personalWeb.filterWindowByCurrentScope(c.conv, sentRows, freshExcl);
          if (stillAllowed.length < sentRows.length) {
            disallowed.add(c.conv);
          }
        }
        if (this.personalWeb.policySignature() !== sigBeforeValidate) {
          verifiedFastPolicySig = "";
          for (const c of usedConvs) disallowed.add(c.conv);
          return disallowed;
        }
        verifiedFastPolicySig = sigBeforeValidate;
        return disallowed;
      };
      const r = await this.understander.runBatch(
        workId,
        [{ conv: p.conv, conv_name: p.conv_name, target_obs_id: selectedAfter.targetObsId }],
        batchAbort.signal,
        activeNativeOwner,
        validateBeforeApply,
        {
          filterObs: (conv, win) => this.personalWeb.filterWindowByCurrentScope(conv, win, fastNativeExcl),
          isMentionsOnly: (conv) => this.personalWeb.isConvMentionsOnly(conv, fastNativeExcl),
          claimCheck: { convs: [p.conv], holder: claimToken, procOwner },
          commitGuard: () =>
            isFastSwitchEnabled() &&
            !this.personalWeb.hasDiskPolicyError() &&
            !!verifiedFastPolicySig &&
            this.personalWeb.policySignature() === verifiedFastPolicySig,
        },
      );
      if (signal?.aborted) throw new Error("aborted");
      // 若本批推理结果因背景消息被编辑、策略瞬时漂移或丢租约被整体丢弃，且触发消息本身仍待处理并符合快通道资格，
      // 则延迟重排该快通道作业而非直接标为 done，避免触发 @我 错失自动预起草而退化到定时轮询
      if (r.discarded || (r.fresh === 0 && this.store.obsPending(selectedAfter.targetObsId))) {
        if (!isFastSwitchEnabled()) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
        const postNativeOwner = this.personalWeb.activeBoundNativeOwner();
        const stillEligible = this.selectEligibleFastTriggers(p.conv, rawAnchors, p.trigger_obs_id, postNativeOwner);
        if (!stillEligible) return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
        const postExcl = await this.personalWeb.resolveNativeExclusionsForPolling();
        if (signal?.aborted) throw new Error("aborted");
        const eligPost = await this.personalWeb.checkConvAllowedForUnderstand(p.conv, p.conv_name, postExcl);
        if (signal?.aborted) throw new Error("aborted");
        if (eligPost === "excluded") return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
        if (eligPost === "uncertain") return { busy: true, deferMs: 5_000, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
        const postOnlyMentions = this.personalWeb.isConvMentionsOnly(p.conv, postExcl);
        const postWindow = this.personalWeb.filterWindowByCurrentScope(
          p.conv,
          this.store.convWindowAround(p.conv, stillEligible.targetObsId, 60, 12, postNativeOwner, { onlyMentions: postOnlyMentions }),
          postExcl,
        );
        if (postWindow.some((o) => this.store.obsPending(o.id))) {
          return { busy: true, deferMs: 2_000, fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
        }
        return { fresh: 0, created: 0, nudged: 0, pre_drafted: 0 };
      }
      relinkMeegoItems(this.store);
      this.store.mergeConflicts();
      this.markNotImportant();
      this.syncDrafts();
      const nudged = this.nudge(r.created);
      this.autonomy(r.created);

      // 可选：为高优先级「别人在等你」自动预起草回复草稿（标记 auto: true，入队与执行复用同一资格判据；永远不自动发送）；
      // 除本批新建事项外，对被本批新鲜原生私聊/@本人 证据更新的已有 open 事项同样以幂等 ID 补入预起草
      const createdIds = new Set(r.created.map((c) => c.id));
      const updatedTouched = r.touched.filter((t) => !createdIds.has(t.id));
      const preDrafted =
        this.enqueueAutoPreDrafts(r.created, false, r.touchedFreshObsByItem, selectedAfter.targetObsId) +
        this.enqueueAutoPreDrafts(updatedTouched, true, r.touchedFreshObsByItem);
      if (r.fresh > 0 && !this.isWorkspaceOwnerMismatched() && (this.app.store.get("ctx.last_error") ?? "").startsWith("快通道")) {
        this.app.store.set("ctx.last_error", "");
      }
      return { fresh: r.fresh, created: r.created.length, nudged, pre_drafted: preDrafted };
    } finally {
      signal?.removeEventListener("abort", onParentAbort);
      clearInterval(claimHeartbeat);
      this.store.releaseConv(p.conv, claimToken, procOwner);
    }
  }

  /**
   * 为刚产出或被本批新鲜原生证据更新的高优 ask_me 事项以幂等 ID 入队自动预起草：
   *   - requireNativeTriggerEvidence=true 时，严格要求本批新绑定到该事项的观测中至少有一条属于当前绑定账号的原生私聊或 @本人；
   *   - 若该事项此前已生成的幂等预起草作业曾因开关关闭或临时不可达而进入 skipped 终态，当本批带来新的触发观测/修订时原子重新武装为 pending。
   */
  private enqueueAutoPreDrafts(
    items: ItemRow[],
    requireNativeTriggerEvidence: boolean,
    freshObsByItem: Record<string, string[]> = {},
    fallbackTriggerObsId?: string,
  ): number {
    if (!items.length) return 0;
    const activeNativeOwner = requireNativeTriggerEvidence ? this.personalWeb.activeBoundNativeOwner() : null;
    if (requireNativeTriggerEvidence && !activeNativeOwner) return 0;
    const seen = new Set<string>();
    const isQualifyingNativeTrigger = (oid: string): boolean => {
      if (!oid.startsWith("pw:")) return false;
      const o = this.store.obs(oid);
      if (!o || o.is_me || o.meta.withdrawn === true) return false;
      if (activeNativeOwner && String(o.meta.native_owner_id ?? "").trim() !== activeNativeOwner) return false;
      const isDm = String(o.meta.chat_type ?? "").trim().toLowerCase() === "p2p" || o.kind === "p2p";
      const isAtMe =
        (o.kind === "at_me" || o.meta.at_me === true) &&
        o.meta.at_me !== false &&
        o.meta.is_mention_me !== false;
      return isDm || isAtMe;
    };
    const obsKey = (oid: string): string => {
      const o = this.store.obs(oid);
      if (!o) return oid;
      const editGen = typeof o.meta.edit_gen === "number" && Number.isFinite(o.meta.edit_gen) ? o.meta.edit_gen : 0;
      const digest = createHash("sha256").update(obsRevision(o)).digest("hex").slice(0, 12);
      return `${oid}#g${editGen}:${digest}`;
    };
    let count = 0;
    for (const c of items) {
      if (seen.has(c.id)) continue;
      seen.add(c.id);
      const it = this.store.item(c.id);
      if (!this.canAutoPreDraft(it)) continue;
      const batchObsIds = freshObsByItem[it.id] ?? [];
      let triggerKeys: string[];
      if (requireNativeTriggerEvidence) {
        const qualifyingIds = batchObsIds.filter(isQualifyingNativeTrigger);
        if (!qualifyingIds.length) continue;
        triggerKeys = [...new Set(qualifyingIds.map(obsKey))];
      } else {
        const ids = batchObsIds.length ? batchObsIds : fallbackTriggerObsId ? [fallbackTriggerObsId] : [];
        triggerKeys = [...new Set(ids.map(obsKey))];
      }
      const key = `draft:${it.id}:reply:fast`;
      const payload: CtxPayload = {
        task: "draft",
        item_id: it.id,
        kind: "reply",
        auto: true,
        ...(triggerKeys.length ? { trigger_keys: triggerKeys } : {}),
      };
      if (this.enqueue(key, payload)) {
        count++;
        continue;
      }
      // 已被跳过（如先前执行前关闭了 pre_draft）的同一事项幂等预起草作业：收到新触发证据/修订后原子重新武装
      if (triggerKeys.length > 0) {
        const workId = `context:${key}`;
        const existingJob = this.app.ledger.get<CtxPayload>(workId);
        if (existingJob && existingJob.terminal && existingJob.state === "skipped") {
          const prevKeys = new Set(existingJob.payload.task === "draft" ? (existingJob.payload.trigger_keys ?? []) : []);
          const hasNewTrigger = triggerKeys.some((k) => !prevKeys.has(k));
          if (hasNewTrigger) {
            const mergedKeys = [...new Set([...prevKeys, ...triggerKeys])].slice(-50);
            const ownerOpenId = this.cfg.owner.open_id || existingJob.payload.owner_open_id;
            const nextPayload: CtxPayload = {
              task: "draft",
              item_id: it.id,
              kind: "reply",
              auto: true,
              trigger_keys: mergedKeys,
              ...(ownerOpenId ? { owner_open_id: ownerOpenId } : {}),
            };
            if (this.app.ledger.rearmSkipped(workId, nextPayload)) {
              count++;
            }
          }
        }
      }
    }
    return count;
  }

  /** 判断事项是否满足快通道自动预起草资格（入队与执行前复用同一判据，防止开关关闭或后续降级后仍送模型） */
  private canAutoPreDraft(it: ItemRow | undefined): it is ItemRow {
    if (this.personalWeb.hasDiskPolicyError()) return false;
    const pw = this.cfg.context.personal_web;
    if (!this.cfg.context.understand || !this.cfg.context.sources.im || !this.personalWeb.isEffectivePersonalWebEnabled() || !pw.fast_lane || !pw.pre_draft) {
      return false;
    }
    if (!it || it.status !== "open" || it.kind !== "ask_me" || it.priority !== "high") return false;
    if (this.store.hidden(this.store.project(it.project_id))) return false;
    if (it.meta.needs_review || it.feedback === "unimportant" || !this.draftable(it)) return false;
    if (this.store.hasProposedDraft(it.id, "reply")) return false;
    return true;
  }

  private async ensureOwnerName(prefetchedStatus?: Record<string, unknown>): Promise<void> {
    if (this.app.store.get("ctx.owner_name")) return;
    try {
      const st = prefetchedStatus ?? (await this.app.lark.authStatus());
      const ids = (st.identities ?? {}) as Record<string, { userName?: string; user_name?: string } | undefined>;
      const name = String(ids.user?.userName ?? ids.user?.user_name ?? deepFind(st, "userName") ?? deepFind(st, "user_name") ?? deepFind(st, "name") ?? "");
      if (name) this.app.store.set("ctx.owner_name", name);
    } catch (e) {
      log("warn", "取不到你的飞书名字", { err: errMsg(e) });
    }
  }

  /** 你说不重要的类型（context.not_important）：标题匹配的未关闭事项自动降为不重要 */
  markNotImportant(): number {
    const res = this.cfg.context.not_important.flatMap((p) => {
      try {
        return [new RegExp(p, "i")];
      } catch {
        return [];
      }
    });
    if (!res.length) return 0;
    let n = 0;
    for (const it of this.store.items({ status: ["open", "snoozed"], limit: 5000 })) {
      if (it.feedback || !res.some((re) => re.test(it.title))) continue;
      this.store.setItemField(it.id, { feedback: "unimportant", meta: { auto_unimportant: true } });
      n++;
    }
    return n;
  }

  /** 实时提醒：新出现的、近期的、高优先级的请求 / 风险 / 快到期的承诺。每轮最多 3 条。 */
  nudge(created: ItemRow[], now = Date.now()): number {
    if (!this.cfg.context.nudge || this.isWorkspaceOwnerMismatched()) return 0;
    const picks = created
      .map((c) => this.store.item(c.id))
      .filter((it): it is ItemRow => !!it && it.status === "open" && !it.nudged_at && !it.meta.needs_review && !it.meta.legacy && !it.feedback && it.last_seen >= now - 6 * HOUR)
      .filter((it) => {
        const p = this.store.project(it.project_id);
        if (this.store.hidden(p)) return false;
        const urgent = (it.kind === "ask_me" || it.kind === "risk") && it.priority === "high";
        const dueSoon = !!it.due && it.due < now + 2 * DAY && (it.kind === "ask_me" || it.kind === "my_commitment");
        return urgent || dueSoon;
      })
      .slice(0, 3);
    for (const it of picks) {
      this.store.setItemField(it.id, { nudged_at: now });
      this.sendItem(it.id, undefined, "nudge", `ctx-nudge-${it.id}`);
    }
    return picks.length;
  }

  sendItem(id: string, notice?: string, kind?: NotifyKind, dedupe?: string): void {
    if (this.isWorkspaceOwnerMismatched()) return;
    const d = this.views.itemDetail(id, []);
    if (!d) return;
    if (this.cardsOn()) return this.emitCard(`ctx-item:${id}`, itemCard(d, this.renderCtx(notice), this.draftable(d)), kind, dedupe);
    if (notice) return; // 没启用卡片时，操作结果不再私信
    const ev = d.evidence[0];
    const text = `**${KIND_LABEL[d.kind] ?? "提醒"}：${d.title}**\n${[d.project_name, d.counterpart && `对方 ${d.counterpart}`, d.next_step && `建议：${d.next_step}`].filter(Boolean).join(" ｜ ")}${ev ? `\n> ${truncate(ev.quote, 120)}` : ""}`;
    this.app.ledger.emit(`context:item:${id}`, [notify(text, kind)], dedupe);
    this.app.engine.kick();
  }

  /** L2：只影响你自己的低风险动作 */
  autonomy(created: ItemRow[]): void {
    if (!this.cfg.context.autonomy.create_own_todo || this.isWorkspaceOwnerMismatched()) return;
    for (const it of created) {
      const cur = this.store.item(it.id);
      if (!cur || cur.kind !== "my_commitment" || cur.status !== "open" || cur.meta.needs_review || cur.meta.own_task) continue;
      const ev = this.store.lastEvidenceObs("item", cur.id);
      const e: Effect = {
        op: "task.create_own",
        args: { summary: cur.title, description: `${cur.next_step ? `下一步：${cur.next_step}\n` : ""}${ev?.url ? `来源：${ev.url}` : ""}`.trim() || cur.title, due: cur.due ? new Date(cur.due).toISOString() : undefined, item_id: cur.id },
      };
      this.store.setItemField(cur.id, { meta: { own_task: true } });
      this.app.ledger.emit(`context:own-todo:${cur.id}`, [e], `ctx-own-${cur.id}`);
    }
  }

  // ───────── 晨间 / 收尾 ─────────

  today(): string {
    return new Intl.DateTimeFormat("en-CA", { timeZone: this.cfg.owner.timezone }).format(new Date());
  }

  renderMorning(date: string, notice?: string, dedupe?: string): void {
    if (this.isWorkspaceOwnerMismatched()) return;
    const t = { ...this.views.today(this.running, this.personalWeb.status()), date };
    const draftable = (it: CtxItemView) => this.draftable(it);
    this.emitCard(`ctx-morning:${date}`, morningCard(t, this.renderCtx(notice), draftable), notice ? undefined : "brief", dedupe);
  }

  eveningView(date: string) {
    const sod = startOfDay(this.cfg.owner.timezone);
    const open = this.views.openItems();
    return {
      date,
      closed: this.store.closedSince(sod).map((i) => this.views.itemView(i)),
      asks: open.filter((i) => i.kind === "ask_me"),
      tomorrow: open.filter((i) => !i.needs_review).slice(0, 3),
      changes: this.store.updates({ since: sod, limit: 20 }).map((u) => this.views.updateView(u)),
    };
  }

  renderEvening(date: string, notice?: string, dedupe?: string): void {
    if (this.isWorkspaceOwnerMismatched()) return;
    this.emitCard(`ctx-evening:${date}`, eveningCard(this.eveningView(date), this.renderCtx(notice)), notice ? undefined : "brief", dedupe);
  }

  sendDigest(mode: "morning" | "evening"): void {
    if (this.isWorkspaceOwnerMismatched()) return;
    const date = this.today();
    if (this.cardsOn()) {
      if (mode === "morning") this.renderMorning(date, undefined, `ctx-morning-${date}`);
      else this.renderEvening(date, undefined, `ctx-evening-${date}`);
      return;
    }
    this.app.ledger.emit("context:digest", [notify(this.digestText(mode), "brief")], `ctx-${mode}-${date}`);
    this.app.engine.kick();
  }

  digestText(mode: "morning" | "evening"): string {
    if (this.isWorkspaceOwnerMismatched()) {
      return "⚠️ 当前工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已暂停展示上下文摘要以防跨账号泄漏。";
    }
    const tz = this.cfg.owner.timezone;
    if (mode === "morning") {
      const t = this.views.today(this.running);
      const lines = [`**今天 · ${t.date}**`];
      if (t.focus.length) lines.push("**先做这几件**", ...t.focus.slice(0, 6).map((i, n) => `${n + 1}. 【${KIND_LABEL[i.kind]}】${i.title}${i.project_name ? `（${i.project_name}）` : ""}`));
      if (t.conflicts.length) lines.push("**需要你判断**", ...t.conflicts.slice(0, 3).map((c) => `- ${c.topic}`));
      if (t.meetings.length) lines.push("**今天的会**", ...t.meetings.map((m) => `- ${new Date(m.start).toLocaleTimeString("zh-CN", { timeZone: tz, hour: "2-digit", minute: "2-digit" })} ${m.summary}`));
      return lines.join("\n");
    }
    const v = this.eveningView(this.today());
    return [`**收尾 · ${v.date}**`, `今天关掉 ${v.closed.length} 件，还欠着别人 ${v.asks.length} 件。`, ...v.tomorrow.map((i, n) => `${n + 1}. ${i.title}`)].join("\n");
  }

  // ───────── 草稿 ─────────

  renderDraft(id: string, notice?: string): void {
    if (this.isWorkspaceOwnerMismatched()) return;
    const d = this.store.draft(id);
    if (!d || !this.cardsOn()) return;
    const it = d.item_id ? this.store.item(d.item_id) : undefined;
    this.emitCard(`ctx-draft:${id}`, draftCard(this.views.draftView(d), this.renderCtx(notice), it?.title ?? ""));
  }

  /**
   * 草稿对应的对外动作落定后，回写草稿状态。状态从 outbox 推导（总线只是提示）：
   * 落定事件、每轮周期、每次读取草稿列表时都会对一遍，进程中途退出也不会卡在“发送中”。
   */
  syncDraft(id: string, render = true): void {
    const d = this.store.draft(id);
    if (!d || d.status !== "approved") return;
    const fx = this.app.ledger.effectsOf(`ctx-draft:${id}`).at(-1);
    if (!fx || !fx.terminal) return;
    if (fx.state === "done") {
      const url = this.app.store.get(`effect.result.${fx.id}`);
      this.store.setDraft(d.id, { status: "sent", error: "", ...(url ? { target: { ...d.target, url } } : {}) });
      // 回复 / 评论发出去了：记一笔，不自动关闭事项，等下一轮证据（对方确认等）
      if (d.item_id) this.store.setItemField(d.item_id, { meta: { replied_at: Date.now() } });
    } else {
      this.store.setDraft(d.id, { status: "failed", error: fx.error || `发送失败（${fx.state}）` });
    }
    if (render) this.renderDraft(d.id);
  }

  syncDrafts(): void {
    for (const d of this.store.drafts({ status: ["approved"] })) this.syncDraft(d.id);
  }

  // ───────── 引擎 ─────────

  handler(): Handler<CtxPayload> {
    return {
      kind: "context",
      concurrency: 2,
      maxAttempts: 2,
      run: async (item, ctx) => {
        if (isWorkBlockedByOwner(this.app, item)) {
          this.app.ledger.transition(item, { state: "skipped", terminal: true });
          return;
        }
        const p = item.payload;
        if (p.task === "cycle") {
          const r = await this.cycle(item.id, ctx.signal);
          this.app.ledger.transition(item, { state: r.skipped ? "skipped" : "done", terminal: true, payload: { ...p, report: r } as never });
          return;
        }
        if (p.task === "fast") {
          const r = await this.fastCycle(item.id, p, ctx.signal);
          if (r.busy) {
            this.app.ledger.release(item.id, { nextAt: Date.now() + (r.deferMs ?? 2_000), refund: true });
            return;
          }
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, result: r } as never });
          return;
        }
        if (p.task === "draft") {
          if (this.isWorkspaceOwnerMismatched()) {
            this.app.ledger.transition(item, { state: "skipped", terminal: true });
            return;
          }
          if (p.auto) {
            // 自动预起草执行前复用完整入队资格判据，防止开关关闭或事项降级后仍送模型
            const it = this.store.item(p.item_id);
            if (!this.canAutoPreDraft(it)) {
              this.app.ledger.transition(item, { state: "skipped", terminal: true });
              return;
            }
          }
          try {
            const d = await this.drafter.forItem(
              p.item_id,
              p.kind,
              p.auto
                ? {
                    auto: true,
                    beforeInfer: () =>
                      !this.isWorkspaceOwnerMismatched() && this.canAutoPreDraft(this.store.item(p.item_id)),
                  }
                : undefined,
            );
            this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, draft_id: d.id } as never });
            this.renderDraft(d.id);
          } catch (err) {
            // 暂时无法实时确认目标会话排除状态（网络抖动/在线 Web 客户端恢复中）：
            // 对自动预起草延迟重排且退回重试次数，不落库也不永久跳过，待连通恢复后再核验起草
            if (p.auto && err instanceof DraftTargetUncertainError) {
              this.app.ledger.release(item.id, { nextAt: Date.now() + 5_000, refund: true });
              return;
            }
            // 已入队的自动预起草若目标会话/消息已被明确静音、排除或移出采集范围，静默跳过不送模型也不刷失败通知
            if (p.auto && err instanceof DraftTargetIneligibleError) {
              this.app.ledger.transition(item, { state: "skipped", terminal: true });
              return;
            }
            throw err;
          }
          return;
        }
        if (p.task === "split") {
          if (this.isWorkspaceOwnerMismatched()) {
            this.app.ledger.transition(item, { state: "skipped", terminal: true });
            return;
          }
          const r = await splitProject(this.understander, item.id, p.project_id, ctx.signal);
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, result: r } as never });
          return;
        }
        if (p.task === "weekly") {
          if (this.isWorkspaceOwnerMismatched()) {
            this.app.ledger.transition(item, { state: "skipped", terminal: true });
            return;
          }
          const d = await this.drafter.weekly(p.days);
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, draft_id: d.id } as never });
          this.renderDraft(d.id);
          return;
        }
        this.app.ledger.transition(item, { state: "skipped", terminal: true });
      },
      onExhausted: (item, err) => {
        if (isWorkBlockedByOwner(this.app, item)) {
          return { patch: { state: "errored" } };
        }
        const p = item.payload;
        if (p.task === "fast") {
          if (!this.isWorkspaceOwnerMismatched()) {
            const label = p.conv_name ? `快通道（${p.conv_name}）` : "快通道";
            this.app.store.set("ctx.last_error", truncate(`${label}失败：${err}`, 1000));
          }
          return { patch: { state: "errored" } };
        }
        if (p.task === "cycle") return { patch: { state: "errored" } };
        const what = p.task === "draft" ? "起草" : p.task === "split" ? "拆分子项目" : "周报草稿";
        return { patch: { state: "errored" }, effects: [notify(`⚠️ ${what}没有成功：${truncate(err, 300)}`, "failure")] };
      },
    };
  }

  /** 常驻进程的定时任务 */
  start(): { stop(): void } {
    const c = this.cfg.context;
    const opts = { timezone: this.cfg.owner.timezone, protect: true };
    const slot = (cr: Cron) => (cr.currentRun() ?? new Date()).toISOString().slice(0, 16);
    const guard = (name: string, fn: (cr: Cron) => void) => (cr: Cron) => {
      try {
        fn(cr);
      } catch (e) {
        log("error", `${name} 失败`, { err: errMsg(e) });
      }
    };
    const crons = [
      new Cron(c.schedule, opts, guard("工作上下文采集", (cr) => void this.enqueue(`cycle:${slot(cr)}`, { task: "cycle" }))),
      new Cron(c.morning, opts, guard("晨间卡", () => this.sendDigest("morning"))),
      new Cron(c.evening, opts, guard("收尾卡", () => this.sendDigest("evening"))),
      new Cron(c.weekly, opts, guard("周报草稿", (cr) => void this.enqueue(`weekly:${slot(cr)}`, { task: "weekly", days: 7 }))),
    ];
    // 启动后先跑一轮（停机期间的消息）
    const t = setTimeout(() => this.enqueue(`cycle:start-${Date.now()}`, { task: "cycle" }), 5000);
    // 个人 Web 协议长连接（仅在 context.personal_web.enabled 为 true 时启动）
    const pw = this.personalWeb.start();
    return {
      stop: () => {
        clearTimeout(t);
        pw.stop();
        crons.forEach((x) => x.stop());
      },
    };
  }

  /** 立即拆分一个项目（命令行用） */
  async splitNow(key: string): Promise<SplitResult> {
    const p = this.store.findProject(key);
    if (!p) throw new Error(`没有找到项目：${key}`);
    const id = `split:${p.id}:${Date.now()}`;
    this.enqueue(id, { task: "split", project_id: p.id });
    await this.app.engine.drain(["context"]);
    const w = this.app.ledger.get<{ result?: SplitResult }>(`context:${id}`);
    if (w?.payload.result) return w.payload.result;
    throw new Error(`拆分没有完成：${w?.state ?? "未知"}${w?.error ? `（${w.error}）` : ""}`);
  }

  async runOnce(): Promise<CtxCycleReport> {
    const id = `cycle:manual-${Date.now()}`;
    this.enqueue(id, { task: "cycle" });
    await this.app.engine.drain(["context", "effect"]);
    const w = this.app.ledger.get<{ report?: CtxCycleReport }>(`context:${id}`);
    if (w?.payload.report) return w.payload.report;
    throw new Error(`采集没有完成：${w?.state ?? "未知"}${w?.error ? `（${w.error}）` : ""}`);
  }

  // ───────── 查询 ─────────

  items(f: { status?: string; kind?: string; project?: string; q?: string }): CtxItemView[] {
    let list: CtxItemView[];
    if (!f.status || f.status === "open") list = this.views.openItems();
    else if (f.status === "review") list = this.views.openItems().filter((i) => i.needs_review);
    else {
      const status = f.status === "all" ? undefined : ([f.status] as CtxItemStatus[]);
      list = this.store.items({ status, limit: 1000 }).map((i) => this.views.itemView(i));
    }
    if (f.kind) list = list.filter((i) => i.kind === f.kind);
    if (f.project) list = list.filter((i) => i.project_id === f.project);
    if (f.q) {
      const q = f.q.toLowerCase();
      list = list.filter((i) => `${i.title} ${i.counterpart} ${i.project_name} ${i.next_step}`.toLowerCase().includes(q));
    }
    return list.slice(0, 500);
  }

  itemActions(id: string): string[] {
    const it = this.store.item(id);
    if (!it) return [];
    const a: string[] = it.status === "open" ? ["context.item_done", "context.item_snooze", "context.feedback"] : ["context.item_reopen"];
    if (it.status === "open" && this.draftable(it)) a.push("context.draft_create");
    if (it.status === "open" && this.app.commands.has("dispatch.create")) a.push("context.item_delegate");
    return a;
  }
}

const id = z.string().min(1);

export function registerContext(app: App): ContextService | undefined {
  if (!app.cfg.context.enabled) return undefined;
  const svc = new ContextService(app);
  const { commands, ledger, bus } = app;
  app.engine.register(svc.handler());
  app.effectHooks.pwReply = async (args) => {
    await svc.personalWeb.sendVerifiedReply(args);
  };
  app.effectHooks.shouldDeferPwReply = (cid, isDaemon) =>
    svc.personalWeb.shouldDeferReplyToCredentialedConsumer(cid, isDaemon);
  app.effectHooks.isContextOwnerMismatched = () => svc.isWorkspaceOwnerMismatched();
  app.effectHooks.verifyCliDraftDelivery = async ({ draft_id, chat_id, message_id }) => {
    await svc.verifyCliDraftTargetForDelivery(draft_id ?? "", chat_id, message_id);
  };
  bus.on("effect.settled", (e) => {
    if (e.ref.startsWith("ctx-draft:")) svc.syncDraft(e.ref.slice("ctx-draft:".length));
  });

  const ok = (message: string, target = ""): CommandResult => ({ ok: true, message, target });
  const needItem = (itemId: string) => {
    svc.assertWorkspaceOwnerMatches();
    const it = svc.store.item(itemId);
    if (!it) throw new CommandError("not_found", `没有这个事项：${itemId}`);
    return it;
  };
  const snapshot = (it: ItemRow) => `${it.kind}｜${it.title}｜${svc.store.lastEvidenceObs("item", it.id)?.text.slice(0, 160) ?? ""}`;

  commands.register({
    name: "context.refresh",
    title: "立即采集并理解最新的消息与待办",
    schema: z.object({}).strict() as never,
    target: () => "context",
    run: async () => {
      svc.assertWorkspaceOwnerMatches();
      if (svc.running) return ok("正在采集中，稍后自动刷新");
      svc.enqueue(`cycle:manual-${Date.now()}`, { task: "cycle" });
      return ok("开始采集，完成后页面会自动刷新");
    },
  });

  commands.register({
    name: "context.item_done",
    title: "把事项标为完成",
    schema: z.object({ id, note: z.string().max(500).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      if (it.status === "done") throw new CommandError("conflict", "已经是完成状态");
      svc.store.setItemStatus(it.id, "done", { reason: a.note || "你标记完成" });
      svc.store.addFeedback("item", it.id, "right", "done", snapshot(it));
      return ok("已完成", it.id);
    },
  });

  commands.register({
    name: "context.item_reopen",
    title: "重新打开事项",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      if (it.status === "open") throw new CommandError("conflict", "事项本来就是打开的");
      svc.store.setItemStatus(it.id, "open", { lock: false });
      if (it.feedback === "wrong") svc.store.setItemField(it.id, { feedback: "" });
      return ok("已重新打开", it.id);
    },
  });

  commands.register({
    name: "context.item_snooze",
    title: "稍后再提醒",
    schema: z.object({ id, hours: z.coerce.number().min(0.25).max(24 * 30).optional(), until: z.string().optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      const until = a.until ? Date.parse(a.until) : Date.now() + (a.hours ?? 4) * HOUR;
      if (Number.isNaN(until) || until <= Date.now()) throw new CommandError("invalid", "提醒时间不对");
      svc.store.setItemStatus(it.id, "snoozed", { snoozeUntil: until, lock: false });
      const when = new Date(until).toLocaleString("zh-CN", { timeZone: app.cfg.owner.timezone, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
      return ok(`${when} 再提醒你`, it.id);
    },
  });

  commands.register({
    name: "context.item_delegate",
    title: "把事项交给 Agent 执行（新建派单）",
    schema: z.object({ id, harness: z.string().optional(), repo: z.string().optional() }),
    target: (a) => a.id,
    run: async (a, ctx) => {
      svc.assertWorkspaceOwnerMatches();
      const it = needItem(a.id);
      if (!commands.has("dispatch.create")) throw new CommandError("unavailable", "派单功能未启用");
      const ev = svc.views.evidence("item", it.id, 5);
      const description = [
        it.next_step ? `目标：${it.next_step}` : "",
        it.counterpart ? `相关的人：${it.counterpart}` : "",
        ev.length ? `背景（来自工作上下文）：\n${ev.map((e) => `- ${e.actor_name}${e.conv_name ? `@${e.conv_name}` : ""}：${e.quote}${e.url ? ` ${e.url}` : ""}`).join("\n")}` : "",
      ]
        .filter(Boolean)
        .join("\n\n");
      const originOwner = app.cfg.owner.open_id.trim();
      const r = await commands.exec(
        "dispatch.create",
        { summary: it.title.slice(0, 120), description, harness: a.harness, repo: a.repo },
        { ...ctx, contextOwner: originOwner },
      );
      if (r.target) {
        app.store.set(`ctx.dispatch_owner.${r.target}`, originOwner);
        const createdWork = ledger.get(r.target);
        // 无论 dispatch.create 返回的是 work ID（dispatch:<guid>:…）还是尚未对账的纯任务 GUID，均同步写入 ref 归属映射
        const taskGuid =
          createdWork?.ref ||
          (r.target.startsWith("dispatch:") ? (r.target.split(":")[1] ?? "") : r.target);
        if (taskGuid) {
          app.store.set(`ctx.dispatch_ref_owner.${taskGuid}`, originOwner);
        }
      }
      svc.store.setItemField(it.id, { meta: { delegated: r.target ?? "" } });
      return { ...r, message: `已交给 Agent：${r.message}` };
    },
  });

  commands.register({
    name: "context.feedback",
    title: "告诉我识别得对不对",
    schema: z.object({ entity: z.enum(["item", "project", "knowledge", "update", "person"]), id, verdict: z.enum(["right", "wrong", "unimportant"]), note: z.string().max(500).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const note = a.note ?? "";
      switch (a.entity) {
        case "item": {
          const it = needItem(a.id);
          svc.store.addFeedback("item", it.id, a.verdict, note, snapshot(it));
          svc.store.setItemField(it.id, { feedback: a.verdict });
          if (a.verdict === "wrong") svc.store.setItemStatus(it.id, "dismissed", { reason: note || "你说识别错了" });
          return ok(a.verdict === "wrong" ? "已移除，之后会参考这次判断" : a.verdict === "unimportant" ? "已降低优先级" : "收到，识别正确", it.id);
        }
        case "project": {
          const p = svc.store.project(a.id);
          if (!p) throw new CommandError("not_found", "没有这个项目");
          svc.store.addFeedback("project", p.id, a.verdict, note, `项目｜${p.name}`);
          if (a.verdict === "wrong") svc.store.setProject(p.id, { status: "archived", muted: true, pinned: true });
          if (a.verdict === "unimportant") svc.store.setProject(p.id, { muted: true, pinned: true });
          return ok("收到", p.id);
        }
        case "knowledge":
        case "update": {
          svc.store.addFeedback(a.entity, a.id, a.verdict, note, "");
          if (a.verdict === "wrong") svc.store.deleteEntity(a.entity, a.id);
          return ok(a.verdict === "wrong" ? "已删除" : "收到", a.id);
        }
        case "person":
          svc.store.addFeedback("person", a.id, a.verdict, note, "");
          return ok("收到", a.id);
      }
    },
  });

  commands.register({
    name: "context.project_mute",
    title: "静音 / 取消静音项目",
    schema: z.object({ id, muted: z.boolean() }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const p = svc.store.project(a.id);
      if (!p) throw new CommandError("not_found", "没有这个项目");
      svc.store.setProject(p.id, a.muted ? { muted: true, pinned: true } : { muted: false, status: "active", pinned: true });
      return ok(a.muted ? `已静音「${p.name}」，它的事项不再出现在今天` : `已恢复「${p.name}」`, p.id);
    },
  });

  commands.register({
    name: "context.project_split",
    title: "把项目拆成子项目",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const p = svc.store.project(a.id);
      if (!p) throw new CommandError("not_found", "没有这个项目");
      if (p.parent_id) throw new CommandError("invalid", "只能拆分顶层项目");
      const busy = ledger.list({ kinds: ["context"], states: ["pending"], ref: "split", limit: 20 }).some((w) => (w.payload as { project_id?: string }).project_id === p.id && !w.terminal);
      if (busy) return ok("正在拆分中", p.id);
      svc.enqueue(`split:${p.id}:${Date.now()}`, { task: "split", project_id: p.id });
      return ok(`正在把「${p.name}」拆成子项目，完成后页面会自动刷新`, p.id);
    },
  });

  commands.register({
    name: "context.conv_mute",
    title: "不再读取某个会话",
    schema: z.object({ conv: id, muted: z.boolean(), name: z.string().optional() }),
    target: (a) => a.conv,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      svc.store.muteConv(a.conv, a.name ?? "", a.muted);
      return ok(a.muted ? "这个会话之后不再读取" : "已恢复读取", a.conv);
    },
  });

  commands.register({
    name: "context.conflict_resolve",
    title: "确认冲突的结论",
    schema: z.object({
      id,
      choice: z.coerce.number().int().min(0).optional(),
      obs_rev: z.string().optional(),
      resolution: z.string().max(1000).optional(),
    }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const c = svc.store.conflict(a.id);
      if (!c) throw new CommandError("not_found", "没有这个冲突");
      if (c.status === "resolved") throw new CommandError("conflict", "已经确认过了");
      const chosen = a.choice !== undefined ? c.claims[a.choice] : undefined;
      if (a.choice !== undefined && !chosen) {
        throw new CommandError("invalid", "选择的说法不存在");
      }
      if (chosen?.obs_id) {
        const srcObs = svc.store.obs(chosen.obs_id);
        if (srcObs?.meta.withdrawn === true) {
          throw new CommandError("conflict", "该说法对应的原消息已被撤回，无法以此为准，请刷新后重新选择或手写结论");
        }
        const curRev = srcObs ? obsRevisionToken(srcObs) : "";
        if (
          (srcObs && chosen.obs_rev && curRev !== chosen.obs_rev) ||
          (a.obs_rev && chosen.obs_rev && a.obs_rev !== chosen.obs_rev) ||
          (a.obs_rev && srcObs && curRev !== a.obs_rev)
        ) {
          throw new CommandError("conflict", "该说法对应的原消息已被编辑，旧选项已失效，请刷新后重新选择或手写结论");
        }
      }
      const resolution = a.resolution?.trim() || chosen?.claim;
      if (!resolution) throw new CommandError("invalid", "请选择一个说法或写下结论");
      svc.store.resolveConflict(c.id, resolution);
      // 你的判断沉淀为一条决策知识
      const k = svc.store.upsertKnowledge({ project_id: c.project_id, kind: "decision", title: c.topic, content: resolution, confidence: 1 });
      if (chosen) svc.store.addEvidence("knowledge", k.id, chosen.obs_id, chosen.quote, chosen.time);
      return ok(`已确认：${truncate(resolution, 60)}`, c.id);
    },
  });

  commands.register({
    name: "context.draft_create",
    title: "为事项起草回复 / 跟进 / Meego 评论",
    schema: z.object({ item_id: id, kind: z.enum(["reply", "followup", "meego_comment"]).optional() }),
    target: (a) => a.item_id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const it = needItem(a.item_id);
      const k = a.kind ?? defaultDraftKind(it);
      if (!k) throw new CommandError("invalid", "这个事项没有合适的草稿类型");
      try {
        svc.drafter.target(it, k);
      } catch (e) {
        throw new CommandError("invalid", errMsg(e));
      }
      const running = ledger.list({ kinds: ["context"], states: ["pending"], ref: "draft", limit: 50 }).some((w) => (w.payload as { item_id?: string }).item_id === it.id && !w.terminal);
      if (running) return ok("正在起草中", it.id);
      svc.enqueue(`draft:${it.id}:${k}:${Date.now()}`, { task: "draft", item_id: it.id, kind: k });
      return ok(svc.cardsOn() ? "正在起草，好了会发草稿卡片给你确认" : "正在起草，好了会出现在草稿列表", it.id);
    },
  });

  commands.register({
    name: "context.draft_approve",
    title: "确认草稿并以你本人身份发送",
    schema: z.object({ id, content: z.string().max(8000).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      const d = svc.store.draft(a.id);
      if (!d) throw new CommandError("not_found", "没有这份草稿");
      if (d.status !== "proposed" && d.status !== "failed") {
        throw new CommandError("conflict", d.status === "sent" ? "已经发送过了" : d.status === "discarded" ? "草稿已丢弃" : "正在发送中");
      }
      const content = a.content?.trim() || d.content;
      if (!content.trim()) throw new CommandError("invalid", "内容不能为空");
      let effect: Effect;
      try {
        svc.personalWeb.syncDiskPrivacyConfig({ throwOnError: true });
        svc.assertWorkspaceOwnerMatches();
        effect = svc.drafter.effectFor(d, content);
        if (effect.op === "im.reply" || effect.op === "im.send") {
          await svc.verifyCliDraftTargetForDelivery(d.id, d.target.chat_id, d.target.message_id);
        }
      } catch (e) {
        if (e instanceof CommandError) throw e;
        throw new CommandError("invalid", errMsg(e));
      }
      if (!svc.store.casDraft(d.id, ["proposed", "failed"], "approved", content)) {
        const latestStatus = svc.store.draft(d.id)?.status;
        throw new CommandError("conflict", latestStatus === "sent" ? "已经发送过了" : latestStatus === "discarded" ? "草稿已丢弃" : "正在发送中");
      }
      svc.store.setDraft(d.id, {
        target: {
          ...d.target,
          delivery_route: effect.op,
          ...(effect.op === "pw.reply" ? { native_owner_id: effect.args.owner_id } : {}),
        },
      });
      ledger.emit(`ctx-draft:${d.id}`, [effect], `ctx-draft-${d.id}-${Date.now()}`);
      return ok(d.kind === "weekly_report" ? "正在新建文档" : "正在以你的身份发送", d.id);
    },
  });

  commands.register({
    name: "context.draft_discard",
    title: "丢弃草稿",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      if (!svc.store.casDraft(a.id, ["proposed", "failed"], "discarded")) throw new CommandError("conflict", "这份草稿已经处理过了");
      return ok("已丢弃", a.id);
    },
  });

  commands.register({
    name: "context.weekly_report",
    title: "起草周报",
    schema: z.object({ days: z.coerce.number().int().min(1).max(31).optional() }),
    target: () => "weekly",
    run: async (a) => {
      svc.assertWorkspaceOwnerMatches();
      svc.enqueue(`weekly:manual-${Date.now()}`, { task: "weekly", days: a.days ?? 7 });
      return ok("正在起草周报，好了会出现在草稿里");
    },
  });

  // 卡片：操作后原地刷新
  const cards = app.ext.cards;
  if (cards?.register) {
    cards.register("ctx-item", (itemId, notice) => svc.sendItem(itemId, notice), (itemId) => ({ id: itemId }));
    cards.register("ctx-draft", (draftId, notice) => svc.renderDraft(draftId, notice), (draftId) => ({ id: draftId }));
    cards.register("ctx-morning", (date, notice) => svc.renderMorning(date, notice));
    cards.register("ctx-evening", (date, notice) => svc.renderEvening(date, notice));
  }

  app.ext.context = {
    today: () => (svc.assertWorkspaceOwnerMatches(), svc.syncDrafts(), svc.views.today(svc.running, svc.personalWeb.status())),
    projects: (o) => (svc.assertWorkspaceOwnerMatches(), svc.views.projects(!!o.legacy)),
    project: (pid) => (svc.assertWorkspaceOwnerMatches(), svc.views.projectDetail(pid)),
    items: (f) => (svc.assertWorkspaceOwnerMatches(), svc.items(f)),
    item: (iid) => (svc.assertWorkspaceOwnerMatches(), svc.views.itemDetail(iid, svc.itemActions(iid))),
    knowledge: (f) => (svc.assertWorkspaceOwnerMatches(), svc.store.knowledge({ q: f.q, project_id: f.project }).map((k) => svc.views.knowledgeView(k))),
    updates: (f) => (svc.assertWorkspaceOwnerMatches(), svc.store.updates({ since: Date.now() - (f.days ?? 7) * DAY, project_id: f.project, limit: 300 }).map((u) => svc.views.updateView(u))),
    people: () => (svc.assertWorkspaceOwnerMatches(), svc.views.people()),
    conflicts: (status) => (
      svc.assertWorkspaceOwnerMatches(),
      svc.store
        .conflicts(status)
        .map((c) => svc.views.conflictView(c))
        .filter((c) => c.status === "resolved" || c.claims.length > 0)
    ),
    drafts: (status) => (svc.assertWorkspaceOwnerMatches(), svc.syncDrafts(), svc.store).drafts(status ? { status: status.split(",") as never } : {}).map((d) => svc.views.draftView(d)),
    status: () => svc.views.status(svc.running, svc.personalWeb.status(), svc.isWorkspaceOwnerMismatched()),
    start: () => svc.start(),
    refresh: () => void svc.enqueue(`cycle:hint-${Math.floor(Date.now() / 60_000)}`, { task: "cycle" }),
    runOnce: () => (svc.assertWorkspaceOwnerMatches(), svc.runOnce()),
    split: (key) => (svc.assertWorkspaceOwnerMatches(), svc.splitNow(key)),
    sendDigest: (mode) => (svc.assertWorkspaceOwnerMatches(), svc.sendDigest(mode)),
  };
  return svc;
}
