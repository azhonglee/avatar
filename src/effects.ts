import { createHash } from "node:crypto";
import type { Board, SectionKey } from "./board.ts";
import { deepFind, errMsg, runProcess } from "./util.ts";
import type { Store } from "./store.ts";
import type { Config } from "./config.ts";
import type { Handler } from "./engine.ts";
import type { Effect, Ledger, NotifyKind } from "./ledger.ts";
import type { Lark } from "./lark.ts";

/** 确定不可重试的副作用失败：立刻落 dead 终态，不进入 10 次退避重试循环 */
export class PermanentEffectError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "PermanentEffectError";
  }
}

/**
 * 发布器：投递 outbox 里的飞书写操作。
 * 每条 effect 在提交状态迁移的同一事务里落库，所以“本地已到某状态、飞书却没跟上”只会是暂时的——
 * 发布器会一直重试到成功（或耗尽后记为 dead，晨报里提示）。同一工作的 effect 按顺序投递。
 *
 * 幂等：私信用 effect id 作为飞书的 idempotency-key；移动卡片本身幂等；评论在重试时先查重再发。
 */
export interface EffectHooks {
  /**
   * 通知类副作用（私信、卡片）投递前调用：返回时间戳表示延后到那时再发（免打扰），返回 false 表示按偏好不发。
   * 由通知偏好模块设置。
   */
  gate?: (kind: NotifyKind | undefined, e: Effect) => number | false | undefined;
  /**
   * 个人 Web 协议回复执行器（由工作上下文模块注册，只在用户确认草稿后触发，带发送前核验与独立回读确认）。
   */
  pwReply?: (args: { chat_id: string; message_id: string; root_id?: string; text: string; cid: string }) => Promise<void>;
}

export function effectHandler(cfg: Config, ledger: Ledger, board: Board, lark: Lark, store: Store, hooks: EffectHooks = {}): Handler<Effect> {
  return {
    kind: "effect",
    concurrency: 1,
    maxAttempts: cfg.engine.effect_attempts,
    async run(item) {
      const e = item.payload;
      if (e.op === "notify" || e.op === "card.upsert") {
        const g = hooks.gate?.(e.args.kind, e);
        if (g === false) return void ledger.transition(item, { state: "skipped", terminal: true });
        if (typeof g === "number" && g > Date.now()) {
          // 延后投递：退回本次尝试，不计入重试次数
          return void ledger.release(item.id, { nextAt: g, refund: true });
        }
      }
      switch (e.op) {
        case "task.move":
          await board.move(e.args.guid, e.args.section as SectionKey);
          break;
        case "task.comment":
          // 重试（上次可能已经发出去但没来得及记结果）：先查一下，避免重复评论
          if (item.attempts > 1 && (await board.hasComment(e.args.guid, e.args.content))) break;
          await board.comment(e.args.guid, e.args.content);
          break;
        case "task.complete":
          await lark.run(["task", "+complete", "--task-id", e.args.guid], { as: "user" });
          break;
        case "notify":
          await lark.notifyOwner(e.args.markdown, item.id);
          break;
        case "card.upsert":
          await upsertCard(lark, store, cfg.owner.open_id, e.args.key, e.args.card);
          break;
        // ── 以下只会在你确认草稿 / 开启对应自主动作后产生，均以你本人身份执行 ──
        case "im.reply":
          await lark.run(["im", "+messages-reply", "--message-id", e.args.message_id, "--text", "-", "--idempotency-key", item.id.slice(0, 50)], {
            as: "user",
            input: e.args.text,
          });
          break;
        case "im.send":
          await lark.run(["im", "+messages-send", "--chat-id", e.args.chat_id, "--text", "-", "--idempotency-key", item.id.slice(0, 50)], {
            as: "user",
            input: e.args.text,
          });
          break;
        case "pw.reply": {
          if (!hooks.pwReply) throw new Error("个人 Web 回复未注册");
          // 按草稿 + 正文生成 cid：同一草稿再次确认（新的 effect id）也命中同一条投递记录，不会重复发送；改了正文才算新回复
          const textHash = createHash("sha256").update(e.args.text.replace(/\r\n/g, "\n").trim()).digest("hex");
          const key = e.args.draft_id ? `draft:${e.args.draft_id}:${textHash}` : item.id;
          const cid = createHash("sha256").update(`avatar-pw\0${key}`).digest("hex").slice(0, 32);
          try {
            await hooks.pwReply({
              chat_id: e.args.chat_id,
              message_id: e.args.message_id,
              root_id: e.args.root_id,
              text: e.args.text,
              cid,
            });
          } catch (err) {
            if (err instanceof PermanentEffectError) {
              ledger.transition(item, { state: "dead", terminal: true, error: errMsg(err) });
              return;
            }
            throw err;
          }
          break;
        }
        case "meego.comment": {
          const r = await runProcess(cfg.bins.bytedcli, [
            "meego", "comment", "create", "--project-key", e.args.project_key, "--work-item-id", e.args.work_item_id, "--content", e.args.content, "--json",
          ], { timeoutMs: 60_000 });
          if (r.code !== 0) throw new Error(`Meego 评论失败：${(r.stderr || r.stdout).trim().slice(0, 300)}`);
          break;
        }
        case "doc.create": {
          const out = await lark.run(["docs", "+create", "--doc-format", "markdown", "--title", e.args.title, "--parent-position", "my_library", "--content", "-"], {
            as: "user",
            input: e.args.markdown,
          });
          const url = String(deepFind(out, "url") ?? "");
          if (url) store.set(`effect.result.${item.id}`, url);
          break;
        }
        case "task.create_own": {
          await store.once(`task.create_own.${e.args.item_id ?? item.id}`, async () => {
            const args = ["task", "+create", "--summary", e.args.summary, "--description", e.args.description, "--assignee", cfg.owner.open_id];
            if (e.args.due) args.push("--due", e.args.due);
            const out = await lark.run(args, { as: "user" });
            return String(deepFind(out, "guid") ?? "created");
          });
          break;
        }
        default:
          throw new Error(`未知的 effect：${JSON.stringify(e)}`);
      }
      ledger.transition(item, { state: "done", terminal: true });
    },
    onExhausted: () => ({ patch: { state: "dead" } }),
  };
}

export const move = (guid: string, section: SectionKey): Effect => ({ op: "task.move", args: { guid, section } });
export const comment = (guid: string, content: string): Effect => ({ op: "task.comment", args: { guid, content } });
export const notify = (markdown: string, kind?: NotifyKind): Effect => ({ op: "notify", args: { markdown, kind } });
export const card = (key: string, c: Record<string, unknown>, kind?: NotifyKind): Effect => ({ op: "card.upsert", args: { key, card: c, kind } });

/**
 * 同一个 key 只有一张卡片：没发过就以机器人身份私信主人（幂等键 = key），记下 message_id；发过就原地更新。
 * 原地更新失败（如消息已被撤回/过期）时重新发一张。
 */
export async function upsertCard(lark: Lark, store: Store, owner: string, key: string, c: Record<string, unknown>): Promise<string> {
  const k = `card.msg.${key}`;
  const content = JSON.stringify(c);
  const existing = store.get(k);
  if (existing) {
    try {
      await lark.run(["im", "messages", "patch", "--params", JSON.stringify({ message_id: existing }), "--data", JSON.stringify({ content })], { as: "bot" });
      return existing;
    } catch {
      // 更新失败：重新发一张
    }
  }
  const idem = `card-${key}`.slice(0, 50) + (existing ? `-${Date.now() % 100000}` : "");
  const sent = await lark.run(
    ["im", "+messages-send", "--user-id", owner, "--msg-type", "interactive", "--content", "-", "--idempotency-key", idem.slice(0, 50)],
    { as: "bot", input: content },
  );
  const id = String(deepFind(sent, "message_id") ?? "");
  if (!id) throw new Error(`发送卡片失败：${JSON.stringify(sent).slice(0, 200)}`);
  store.set(k, id);
  return id;
}
