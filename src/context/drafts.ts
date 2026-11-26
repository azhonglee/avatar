import path from "node:path";
import type { App } from "../app.ts";
import type { CtxDraftKind } from "../api/types.ts";
import type { Effect } from "../ledger.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import { render, truncate } from "../util.ts";
import { BOUND_OWNER_KV_KEY } from "./personal-web.ts";
import type { ContextStore, DraftRow, ItemRow, Obs } from "./store.ts";

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

export class Drafter {
  app: App;
  store: ContextStore;
  constructor(app: App, store: ContextStore) {
    this.app = app;
    this.store = store;
  }
  private get cfg() {
    return this.app.cfg;
  }

  /** 草稿的发送目标：回复哪条消息 / 发到哪个会话 / 评论哪个 Meego 工作项（起草本身不发消息，允许为个人 Web 实时消息先起草） */
  target(it: ItemRow, kind: CtxDraftKind): { target: Record<string, string>; label: string; conv?: Obs } {
    if (kind === "meego_comment") {
      const key = String(it.meta.project_key ?? "");
      const id = String(it.meta.work_item_id ?? "");
      if (!key || !id) throw new Error("这个事项没有关联 Meego 工作项");
      return { target: { project_key: key, work_item_id: id, url: String(it.meta.url ?? "") }, label: `Meego #${id} 评论` };
    }
    const fromOther = this.store.lastEvidenceObs("item", it.id, (o) => o.source === "im" && !o.is_me);
    const any = fromOther ?? this.store.lastEvidenceObs("item", it.id, (o) => o.source === "im");
    if (!any) throw new Error("找不到这个事项对应的飞书会话，没法起草消息");
    if (kind === "reply" && fromOther) {
      if (fromOther.meta.transport === "personal_web") {
        if (fromOther.meta.native_message_id && fromOther.meta.native_chat_id) {
          const nativeOwnerId = String(fromOther.meta.native_owner_id ?? this.app.store.get(BOUND_OWNER_KV_KEY) ?? "");
          return {
            target: {
              transport: "personal_web",
              obs_id: fromOther.id,
              native_owner_id: nativeOwnerId,
              native_message_id: String(fromOther.meta.native_message_id),
              native_chat_id: String(fromOther.meta.native_chat_id),
              native_root_id: String(fromOther.meta.native_root_id ?? fromOther.meta.native_message_id),
              url: fromOther.url,
            },
            label: `回复 ${fromOther.actor_name || "对方"}（${fromOther.conv_name} · 个人 Web）`,
            conv: fromOther,
          };
        }
        throw new Error("该个人 Web 消息缺少可回复的原消息标识");
      }
      const openMsgId = String(fromOther.meta.message_id ?? fromOther.id.replace(/^im:/, ""));
      if (!openMsgId) throw new Error("该消息缺少可回复的消息标识");
      return {
        target: {
          obs_id: fromOther.id,
          message_id: openMsgId,
          chat_id: fromOther.conv,
          url: fromOther.url,
        },
        label: `回复 ${fromOther.actor_name || "对方"}（${fromOther.conv_name}）`,
        conv: fromOther,
      };
    }
    if (any.meta.transport === "personal_web") {
      if (any.meta.native_message_id && any.meta.native_chat_id) {
        const nativeOwnerId = String(any.meta.native_owner_id ?? this.app.store.get(BOUND_OWNER_KV_KEY) ?? "");
        return {
          target: {
            transport: "personal_web",
            obs_id: any.id,
            native_owner_id: nativeOwnerId,
            native_message_id: String(any.meta.native_message_id),
            native_chat_id: String(any.meta.native_chat_id),
            native_root_id: String(any.meta.native_root_id ?? any.meta.native_message_id),
            url: any.url,
          },
          label: `${kind === "followup" ? "跟进" : "回复"} ${any.conv_name}（个人 Web）`,
          conv: any,
        };
      }
      throw new Error("该个人 Web 会话缺少可发送的消息标识");
    }
    return {
      target: { obs_id: any.id, chat_id: any.conv, url: any.url },
      label: `${kind === "followup" ? "跟进" : "发到"} ${any.conv_name}${it.counterpart ? `（${it.counterpart}）` : ""}`,
      conv: any,
    };
  }

  private async llm(prompt: string, name: string): Promise<string> {
    const harness = this.cfg.context.harness || this.cfg.roles.brain;
    const logFile = path.join(this.cfg.dataDir, "runs", `draft-${name}-${Date.now()}.log`);
    const r = await runHarness(this.cfg, {
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

  async forItem(itemId: string, kind?: CtxDraftKind): Promise<DraftRow> {
    const it = this.store.item(itemId);
    if (!it) throw new Error(`没有这个事项：${itemId}`);
    const k = kind ?? defaultDraftKind(it);
    if (!k || k === "weekly_report") throw new Error("这个事项没有合适的草稿类型");
    const { target, label, conv } = this.target(it, k);
    const tz = this.cfg.owner.timezone;
    const p = this.store.project(it.project_id);
    const convText = conv
      ? this.store
          .convObs(conv.conv, Date.now() - 7 * DAY, 30)
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
    const content = await this.llm(prompt, k);
    return this.store.addDraft({ item_id: it.id, project_id: it.project_id, kind: k, target, target_label: label, content });
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
      if (!this.cfg.context.personal_web.send_replies) {
        throw new Error("该草稿目标来自个人 Web 实时消息；为避免偏离原话题，请在设置中开启 context.personal_web.send_replies 后再发送");
      }
      if (!d.target.native_chat_id || !d.target.native_message_id) {
        throw new Error("该个人 Web 草稿缺少原会话或原消息 ID，无法发送");
      }
      const ownerId = d.target.native_owner_id || String(obs?.meta.native_owner_id ?? "") || this.app.store.get(BOUND_OWNER_KV_KEY) || "";
      if (!ownerId) {
        throw new Error("该个人 Web 草稿缺少绑定账号 ID，拒绝发送");
      }
      const currentBound = this.app.store.get(BOUND_OWNER_KV_KEY);
      if (currentBound && currentBound !== ownerId) {
        throw new Error(`该草稿归属账号 (${ownerId}) 与当前工作区绑定账号 (${currentBound}) 不一致，拒绝发送`);
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

    switch (d.kind) {
      case "reply": {
        if (lockedRoute === "pw.reply" || d.target.transport === "personal_web") {
          return buildPwReply();
        }
        if (d.target.message_id) {
          if (lockedRoute && lockedRoute !== "im.reply") {
            throw new Error(`草稿已绑定发送路由 ${lockedRoute}，拒绝切换为 im.reply`);
          }
          return { op: "im.reply", args: { message_id: d.target.message_id, text: content, draft_id: d.id } };
        }
        if (lockedRoute === "im.reply") {
          throw new Error("该草稿已绑定按原消息回复（im.reply），但缺少 message_id，拒绝降级为顶层消息");
        }
        if (!d.target.chat_id) {
          throw new Error("该回复草稿缺少目标会话 ID");
        }
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
        return { op: "im.send", args: { chat_id: d.target.chat_id, text: content, draft_id: d.id } };
      }
      case "meego_comment":
        return { op: "meego.comment", args: { project_key: d.target.project_key, work_item_id: d.target.work_item_id, content, draft_id: d.id } };
      case "weekly_report":
        return { op: "doc.create", args: { title: d.target.title || "周报", markdown: content, draft_id: d.id } };
    }
  }
}
