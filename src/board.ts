import type { Config } from "./config.ts";
import type { Lark } from "./lark.ts";
import type { Store } from "./store.ts";
import { deepFind, findItems, log } from "./util.ts";

export type SectionKey = keyof Config["board"]["sections"];

export interface BoardTask {
  guid: string;
  summary: string;
  description: string;
  dueMs: number | null;
  url: string;
}

/** 飞书任务清单做看板：分组 = 列。guid 等 ID 由 pa init 创建后存进本地 kv。 */
export class Board {
  cfg: Config;
  lark: Lark;
  store: Store;
  constructor(cfg: Config, lark: Lark, store: Store) {
    this.cfg = cfg;
    this.lark = lark;
    this.store = store;
  }

  get tasklistGuid(): string {
    const g = this.store.get("board.tasklist");
    if (!g) throw new Error("看板未初始化，请先运行 pa init");
    return g;
  }

  section(key: SectionKey): string {
    const g = this.store.get(`board.section.${key}`);
    if (!g) throw new Error(`看板分组 ${key} 未初始化，请先运行 pa init`);
    return g;
  }

  /** 幂等：找到同名清单/分组就复用，找不到才创建。 */
  async init(): Promise<void> {
    let tasklist = this.store.get("board.tasklist");
    if (!tasklist) {
      const found = await this.lark.run(["task", "+tasklist-search", "--query", this.cfg.board.name], { as: "user" });
      tasklist = findItems(found, "guid").find((t) => t.name === this.cfg.board.name)?.guid as string | undefined;
      if (!tasklist) {
        const created = await this.lark.run(["task", "+tasklist-create", "--name", this.cfg.board.name], { as: "user" });
        tasklist = String(deepFind(created, "guid") ?? "");
        if (!tasklist) throw new Error(`创建任务清单失败：${JSON.stringify(created)}`);
        log("info", "已创建任务清单", { name: this.cfg.board.name, guid: tasklist });
      }
      this.store.set("board.tasklist", tasklist);
    }
    const listed = await this.lark.run(
      ["task", "sections", "list", "--params", JSON.stringify({ resource_type: "tasklist", resource_id: tasklist, page_size: 50 })],
      { as: "user" },
    );
    const existing = new Map(findItems(listed, "guid").map((s) => [String(s.name), String(s.guid)]));
    let prev = "";
    for (const [key, name] of Object.entries(this.cfg.board.sections)) {
      let guid = existing.get(name);
      if (!guid) {
        const data: Record<string, string> = { name, resource_type: "tasklist", resource_id: tasklist };
        if (prev) data.insert_after = prev;
        const created = await this.lark.run(["task", "sections", "create", "--data", JSON.stringify(data)], { as: "user" });
        guid = String(deepFind(created, "guid") ?? "");
        if (!guid) throw new Error(`创建分组 ${name} 失败：${JSON.stringify(created)}`);
        log("info", "已创建看板分组", { name, guid });
      }
      this.store.set(`board.section.${key}`, guid);
      prev = guid;
    }
  }

  /** 列出某一列里未完成的任务（拖动卡片不产生事件，所以靠定时拉取）。 */
  async listSection(key: SectionKey): Promise<BoardTask[]> {
    // 必须翻完所有页：对账依据“卡片不在列里”来判断取消，漏一页就会误取消
    const out: BoardTask[] = [];
    const seen = new Set<string>();
    let token: string | undefined;
    do {
      const params: Record<string, unknown> = { section_guid: this.section(key), completed: false, page_size: 50 };
      if (token) params.page_token = token;
      const data = await this.lark.run(["task", "sections", "tasks", "--params", JSON.stringify(params)], { as: "user" });
      out.push(...findItems(data, "guid").map(toBoardTask));
      const more = deepFind(data, "has_more") === true;
      const next = deepFind(data, "page_token");
      if (!more) break;
      if (typeof next !== "string" || !next || seen.has(next)) throw new Error(`列出看板分组 ${key} 时分页游标缺失或重复`);
      seen.add(next);
      token = next;
    } while (true);
    return out;
  }

  async getTask(guid: string): Promise<BoardTask> {
    const data = await this.lark.run(["task", "tasks", "get", "--params", JSON.stringify({ task_guid: guid })], { as: "user" });
    const t = deepFind(data, "task") ?? data;
    return toBoardTask(t as Record<string, unknown>);
  }

  /**
   * 建任务并放进某一列。给了 opKey 时幂等：同一 opKey 只建一次（建好后“移到列”失败重试，不会再建一张）。
   */
  async createTask(t: { summary: string; description: string; due?: string; section: SectionKey; opKey?: string }): Promise<string> {
    const create = async () => {
      const args = ["task", "+create", "--summary", t.summary, "--description", t.description, "--tasklist-id", this.tasklistGuid];
      if (t.due) args.push("--due", t.due);
      if (this.cfg.owner.open_id) args.push("--assignee", this.cfg.owner.open_id);
      const created = await this.lark.run(args, { as: "user" });
      const guid = String(deepFind(created, "guid") ?? "");
      if (!guid) throw new Error(`创建任务失败：${JSON.stringify(created)}`);
      return guid;
    };
    const guid = t.opKey ? await this.store.once(`task.create.${t.opKey}`, create) : await create();
    await this.move(guid, t.section);
    return guid;
  }

  /** 所有分组都已初始化（升级后新增分组时为 false，需要再跑一次 init）。 */
  isInitialized(): boolean {
    return !!this.store.get("board.tasklist") && Object.keys(this.cfg.board.sections).every((k) => this.store.get(`board.section.${k}`));
  }

  /** 把任务移到看板的某一列。 */
  async move(guid: string, key: SectionKey): Promise<void> {
    await this.lark.run(
      ["task", "+tasklist-task-add", "--tasklist-id", this.tasklistGuid, "--section-guid", this.section(key), "--task-id", guid],
      { as: "user" },
    );
  }

  /** 任务下是否已有内容相同的评论（重试投递评论前去重用；查询失败返回 false，退化为至少一次）。 */
  async hasComment(guid: string, content: string): Promise<boolean> {
    try {
      const data = await this.lark.run(
        ["task", "comments", "list", "--params", JSON.stringify({ resource_type: "task", resource_id: guid, page_size: 100, direction: "desc" })],
        { as: "user" },
      );
      return findItems(data, "content").some((c) => String(c.content).trim() === content.trim());
    } catch (e) {
      log("warn", "查询任务评论失败，按未发送处理", { guid, err: String(e) });
      return false;
    }
  }

  async comment(guid: string, content: string): Promise<void> {
    await this.lark.run(["task", "+comment", "--task-id", guid, "--content", content], { as: "user" });
  }
}

export function toBoardTask(t: Record<string, unknown>): BoardTask {
  const due = t.due as { timestamp?: string } | undefined;
  return {
    guid: String(t.guid ?? ""),
    summary: String(t.summary ?? ""),
    description: String(t.description ?? ""),
    dueMs: due?.timestamp ? Number(due.timestamp) : null,
    url: String(t.url ?? ""),
  };
}

export class KnowledgeBase {
  cfg: Config;
  lark: Lark;
  store: Store;
  constructor(cfg: Config, lark: Lark, store: Store) {
    this.cfg = cfg;
    this.lark = lark;
    this.store = store;
  }

  node(title: string): string {
    const n = this.store.get(`kb.node.${title}`);
    if (!n) throw new Error(`知识库节点「${title}」未初始化，请先运行 pa init`);
    return n;
  }

  /** 幂等：找到同名空间/节点就复用。agent 只往这个空间里写。 */
  async init(): Promise<void> {
    let space = this.store.get("kb.space");
    if (!space) {
      const spaces = await this.lark.run(["wiki", "+space-list"], { as: "user" });
      space = findItems(spaces, "space_id").find((s) => s.name === this.cfg.kb.space_name)?.space_id as string | undefined;
      if (!space) {
        const created = await this.lark.run(["wiki", "+space-create", "--name", this.cfg.kb.space_name, "--description", "由 personal-agent 维护"], { as: "user" });
        space = String(deepFind(created, "space_id") ?? "");
        if (!space) throw new Error(`创建知识空间失败：${JSON.stringify(created)}`);
        log("info", "已创建知识空间", { name: this.cfg.kb.space_name, space });
      }
      this.store.set("kb.space", space);
    }
    const nodes = await this.lark.run(["wiki", "+node-list", "--space-id", space], { as: "user" });
    const existing = new Map(findItems(nodes, "node_token").map((n) => [String(n.title), String(n.node_token)]));
    for (const title of this.cfg.kb.nodes) {
      let token = existing.get(title);
      if (!token) {
        const created = await this.lark.run(["wiki", "+node-create", "--space-id", space, "--title", title], { as: "user" });
        token = String(deepFind(created, "node_token") ?? "");
        if (!token) throw new Error(`创建知识库节点 ${title} 失败：${JSON.stringify(created)}`);
        log("info", "已创建知识库节点", { title, token });
      }
      this.store.set(`kb.node.${title}`, token);
    }
  }

  /** 在指定节点下新建一篇 Markdown 文档，返回文档链接。 */
  async createDoc(parentTitle: string, title: string, markdown: string): Promise<string> {
    const created = await this.lark.run(
      ["docs", "+create", "--doc-format", "markdown", "--title", title, "--parent-token", this.node(parentTitle), "--content", "-"],
      { as: "user", input: markdown },
    );
    return String(deepFind(created, "url") ?? deepFind(created, "document_id") ?? "");
  }
}
