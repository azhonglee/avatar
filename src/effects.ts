import type { Board, SectionKey } from "./board.ts";
import type { Config } from "./config.ts";
import type { Handler } from "./engine.ts";
import type { Effect, Ledger } from "./ledger.ts";
import type { Lark } from "./lark.ts";

/**
 * 发布器：投递 outbox 里的飞书写操作。
 * 每条 effect 在提交状态迁移的同一事务里落库，所以“本地已到某状态、飞书却没跟上”只会是暂时的——
 * 发布器会一直重试到成功（或耗尽后记为 dead，晨报里提示）。同一工作的 effect 按顺序投递。
 *
 * 幂等：私信用 effect id 作为飞书的 idempotency-key；移动卡片本身幂等；评论在重试时先查重再发。
 */
export function effectHandler(cfg: Config, ledger: Ledger, board: Board, lark: Lark): Handler<Effect> {
  return {
    kind: "effect",
    concurrency: 1,
    maxAttempts: cfg.engine.effect_attempts,
    async run(item) {
      const e = item.payload;
      switch (e.op) {
        case "task.move":
          await board.move(e.args.guid, e.args.section as SectionKey);
          break;
        case "task.comment":
          // 重试（上次可能已经发出去但没来得及记结果）：先查一下，避免重复评论
          if (item.attempts > 1 && (await board.hasComment(e.args.guid, e.args.content))) break;
          await board.comment(e.args.guid, e.args.content);
          break;
        case "notify":
          await lark.notifyOwner(e.args.markdown, item.id);
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
export const notify = (markdown: string): Effect => ({ op: "notify", args: { markdown } });
