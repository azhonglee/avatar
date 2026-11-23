import type { Board, SectionKey } from "./board.ts";
import { deepFind } from "./util.ts";
import type { Store } from "./store.ts";
import type { Config } from "./config.ts";
import type { Handler } from "./engine.ts";
import type { Effect, Ledger, NotifyKind } from "./ledger.ts";
import type { Lark } from "./lark.ts";

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
