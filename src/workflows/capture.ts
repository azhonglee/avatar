import type { Board } from "../board.ts";
import type { Config } from "../config.ts";
import type { Lark } from "../lark.ts";
import type { Store } from "../store.ts";
import { errMsg, isoWithOffset, log, truncate } from "../util.ts";
import { triage, type Signal } from "./triage.ts";

type SearchMessage = Record<string, unknown> & { message_id: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 任务识别：把各处信号（@我 的消息、私聊、文档评论 @我、妙记待办）收进本地队列，
 * 批量分诊后，把像任务的建成飞书任务放进看板“待确认”（高置信直接进 Inbox）。
 */
export class Capture {
  cfg: Config;
  lark: Lark;
  store: Store;
  board: Board;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(cfg: Config, lark: Lark, store: Store, board: Board) {
    this.cfg = cfg;
    this.lark = lark;
    this.store = store;
    this.board = board;
  }

  /** 串行化，避免定时任务和事件同时分诊同一批信号。 */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.chain.then(fn, fn);
    this.chain = next.catch(() => undefined);
    return next;
  }

  chatLink(chatId: string): string {
    return chatId ? `https://${this.cfg.applink_host}/client/chat/open?openChatId=${chatId}` : "";
  }

  /** 单页调用让我们能检查每个续页游标，不受 CLI --page-all 的页数上限影响。 */
  private async searchMessages(args: string[]): Promise<SearchMessage[]> {
    const messages: SearchMessage[] = [];
    const tokens = new Set<string>();
    let token: string | undefined;
    do {
      const data = await this.lark.run(token ? [...args, "--page-token", token] : args, { as: "user" });
      if (!isRecord(data)) throw new Error("消息搜索返回格式无效");
      if ("message_ids" in data) throw new Error("消息搜索仅返回 ID，消息详情获取失败");
      if (!Array.isArray(data.messages) || typeof data.has_more !== "boolean") {
        throw new Error("消息搜索缺少消息列表或分页状态");
      }
      for (const message of data.messages) {
        if (!isRecord(message) || typeof message.message_id !== "string" || !message.message_id.trim()) {
          throw new Error("消息搜索返回了无效的消息");
        }
        messages.push({ ...message, message_id: message.message_id });
      }
      if (!data.has_more) break;
      if (typeof data.page_token !== "string" || !data.page_token.trim() || tokens.has(data.page_token)) {
        throw new Error("消息搜索返回了缺失或重复的分页游标");
      }
      token = data.page_token;
      tokens.add(token);
    } while (true);
    return messages;
  }

  /** 增量拉取 @我 的消息和别人发给我的私聊（这两类机器人收不到事件，只能以本人身份拉）。 */
  async pollMessages(): Promise<number> {
    const end = new Date();
    const cursor = this.store.get("capture.cursor");
    const start = cursor ? new Date(cursor) : new Date(end.getTime() - this.cfg.capture.lookback_hours * 3_600_000);
    const range = ["--start", isoWithOffset(start), "--end", isoWithOffset(end)];
    const common = ["im", "+messages-search", "--query", "", "--no-reactions", "--page-size", "50", ...range];
    const batches = await Promise.all([
      this.searchMessages([...common, "--is-at-me"]),
      this.searchMessages([...common, "--chat-type", "p2p", "--exclude-sender-type", "bot"]),
    ]);
    let added = 0;
    for (const m of batches.flat()) {
      const sender = (m.sender ?? {}) as Record<string, unknown>;
      const senderId = String(sender.id ?? sender.open_id ?? "");
      if (m.deleted || senderId === this.cfg.owner.open_id) continue;
      const id = `msg:${m.message_id}`;
      const chat = String(m.chat_name ?? (m.chat_type === "p2p" ? "私聊" : "群聊"));
      const inserted = this.store.addSignal({
        id,
        source: m.chat_type === "p2p" ? "私聊" : "群聊@我",
        text: `[${chat}] ${sender.name ?? senderId}（${m.create_time ?? ""}）：${typeof m.content === "string" ? m.content : JSON.stringify(m.content)}`,
        link: this.chatLink(String(m.chat_id ?? "")),
      });
      if (inserted) added++;
    }
    // signals.id 去重；中途退出时可以重拉，已入库信号不会重插。
    this.store.set("capture.cursor", end.toISOString());
    return added;
  }

  /**
   * 文档评论 @我（drive.notice.comment_add_v1，事件只带 ID，正文要再查一次）。
   * 幂等：只在信号成功入库后才算处理过；拉正文失败会抛错，由 inbox 重试。返回是否新增了信号。
   */
  async onComment(ev: Record<string, unknown>): Promise<boolean> {
    if (!ev.is_mentioned || ev.from_open_id === this.cfg.owner.open_id) return false;
    const id = `comment:${ev.comment_id}:${ev.reply_id ?? ""}`;
    if (this.store.hasSignal(id)) return false;
    const data = await this.lark.run(
      ["drive", "+batch-query-comments", "--token", String(ev.file_token), "--type", String(ev.file_type), "--comment-ids", String(ev.comment_id)],
      { as: "user" },
    );
    return this.store.addSignal({
      id,
      source: "文档评论@我",
      text: `文档 ${ev.file_type}/${ev.file_token} 的评论：${truncate(JSON.stringify(data), 3000)}`,
      link: `${this.cfg.lark_web}/${ev.file_type}/${ev.file_token}`,
    });
  }

  /** 妙记生成（minutes.minute.generated_v1）：拉取纪要和待办，入库等待分诊。幂等，失败抛错由 inbox 重试。 */
  async onMinutes(ev: Record<string, unknown>): Promise<boolean> {
    const token = String(ev.minute_token ?? "");
    const id = `minutes:${token}`;
    if (!token || this.store.hasSignal(id)) return false;
    const data = await this.lark.run(["minutes", "+detail", "--minute-tokens", token, "--summary", "--todo"], { as: "user" });
    return this.store.addSignal({
      id,
      source: "会议妙记",
      text: `会议「${ev.title ?? ""}」的纪要与待办：${truncate(JSON.stringify(data), 6000)}`,
      link: `${this.cfg.lark_web}/minutes/${token}`,
    });
  }

  /** 一轮完整的识别：拉消息 + 分诊所有待处理信号。 */
  run(): Promise<{ added: number; created: number }> {
    return this.serial(async () => {
      const added = await this.pollMessages();
      const created = await this.processInner();
      return { added, created };
    });
  }

  process(): Promise<number> {
    return this.serial(() => this.processInner());
  }

  private async processInner(): Promise<number> {
    const pending = this.store.pendingSignals();
    if (pending.length === 0) return 0;
    const existing = [
      ...(await this.board.listSection("pending")),
      ...(await this.board.listSection("inbox")),
    ].map((t) => t.summary);
    let created = 0;
    for (let i = 0; i < pending.length; i += 20) {
      const batch: Signal[] = pending.slice(i, i + 20);
      let verdicts;
      try {
        verdicts = await triage(this.cfg, batch, existing);
      } catch (e) {
        log("error", "分诊失败，信号保留到下一轮", { err: errMsg(e), count: batch.length });
        return created;
      }
      const bySignal = new Map(verdicts.map((v) => [v.signal_id, v]));
      for (const s of batch) {
        const v = bySignal.get(s.id);
        if (!v || !v.is_task || v.confidence < this.cfg.capture.min_confidence) {
          this.store.setVerdict(s.id, v ? `ignored(${v.confidence}) ${v.reason}` : "ignored(无结论)");
          continue;
        }
        const section = v.confidence >= this.cfg.capture.auto_inbox_confidence ? "inbox" : "pending";
        const description = [
          `来源：${s.source}${s.link ? `  ${s.link}` : ""}`,
          `判断依据：${v.reason}（置信度 ${v.confidence}）`,
          "",
          "原文摘录：",
          truncate(s.text, 1500),
          "",
          `[pa:signal=${s.id}]`,
        ].join("\n");
        try {
          // 以信号 id 为幂等键：建好后“移到列/记结论”失败重试，不会再建一张
          const guid = await this.board.createTask({ summary: v.summary, description, due: v.due ?? undefined, section, opKey: `signal:${s.id}` });
          this.store.setVerdict(s.id, `task(${v.confidence})`, guid);
          existing.push(v.summary);
          created++;
          log("info", "识别到任务", { summary: v.summary, section, confidence: v.confidence });
        } catch (e) {
          log("error", "创建任务失败，信号保留到下一轮", { err: errMsg(e), signal: s.id });
        }
      }
    }
    return created;
  }
}
