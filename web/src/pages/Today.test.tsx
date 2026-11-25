import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CtxDraftView, CtxItemView, CtxToday, Meta } from "../api/types.ts";
import { App } from "../App.tsx";
import { ToastProvider } from "../lib/toast.tsx";

const meta: Meta = {
  version: "0.2.0",
  owner: { open_id: "ou_test", timezone: "Asia/Shanghai" },
  harnesses: ["claude", "codex"],
  roles: { brain: "claude", reviewer: "codex", default_harness: "codex" },
  repos: [],
  providers: [],
  features: { cards: true, delivery: true, usage: true, settings: true, doctor: false, candidates: true, context: true },
  lark_web: "https://feishu.cn",
};

const item = (o: Partial<CtxItemView>): CtxItemView => ({
  id: "itm_1",
  title: "给出 v2 灰度方案结论",
  kind: "ask_me",
  status: "open",
  priority: "high",
  project_id: "prj_1",
  project_name: "Ark v2 发布",
  due: null,
  counterpart: "王五",
  next_step: "周三前回复方案结论",
  confidence: 0.9,
  source: "im",
  strong_key: "",
  first_seen: Date.now() - 3600_000,
  last_seen: Date.now() - 600_000,
  closed_at: null,
  close_reason: "",
  snooze_until: null,
  score: 60,
  why: ["别人在等你", "高优先级"],
  needs_review: false,
  feedback: "",
  url: "https://applink.feishu.cn/client/chat/open?openChatId=oc_1",
  draft_kind: "reply",
  ...o,
});

const draft: CtxDraftView = {
  id: "drf_1",
  item_id: "itm_1",
  project_id: "prj_1",
  kind: "reply",
  target_label: "回复 王五（Ark 发布群）",
  content: "方案今天下班前给你。",
  status: "proposed",
  error: "",
  created: Date.now(),
  updated: Date.now(),
  url: "",
};

const today = (): CtxToday => {
  const a = item({});
  const c = item({ id: "itm_2", title: "周三给王五方案", kind: "my_commitment", priority: "medium", why: ["你答应过"], draft_kind: "reply" });
  return {
    date: "2026-11-25",
    focus: [a, c],
    asks: [a],
    commitments: [c],
    waiting: [],
    risks: [],
    due_soon: [],
    needs_review: [],
    conflicts: [
      {
        id: "cfl_1",
        project_id: "prj_1",
        project_name: "Ark v2 发布",
        topic: "上线时间",
        claims: [
          { claim: "周五上线", quote: "定在周五", time: Date.now() - 7200_000, url: "" },
          { claim: "下周一上线", quote: "改到下周一", time: Date.now() - 3600_000, url: "" },
        ],
        status: "open",
        resolution: "",
        created: Date.now(),
      },
    ],
    drafts: [draft],
    meetings: [{ start: Date.now() + 3600_000, end: Date.now() + 7200_000, summary: "Ark 周会", url: "" }],
    changes: [{ id: "upd_1", project_id: "prj_1", project_name: "Ark v2 发布", time: Date.now() - 1800_000, summary: "上线时间从周五改到下周一", evidence: [] }],
    projects: [{ id: "prj_1", name: "Ark v2 发布", description: "", my_role: "负责人", stage: "灰度中", status: "active", muted: false, health: "risk", open_items: 2, high_items: 1, last_activity: Date.now(), refs: [], parent_id: "", parent_name: "", children: 0 }],
    status: {
      last_cycle: Date.now() - 300_000,
      last_error: "",
      running: false,
      sources: [
        { source: "meego", last_pull: Date.now(), last_count: 3, error: "" },
        { source: "im", last_pull: Date.now(), last_count: 20, error: "" },
      ],
      pending_obs: 0,
      totals: { projects: 1, open_items: 2, knowledge: 1, people: 1 },
      understand_enabled: true,
    },
  };
};

function mockApi() {
  const posts: { name: string; args: unknown }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    const ok = (v: unknown) => new Response(JSON.stringify(v), { status: 200 });
    if (init?.method === "POST") {
      const name = url.split("/").pop()!;
      posts.push({ name, args: JSON.parse(String(init.body)).args });
      return ok({ ok: true, message: "已完成", target: "" });
    }
    if (url === "/api/meta") return ok(meta);
    if (url === "/api/context/today") return ok(today());
    if (url.startsWith("/api/context/items")) return ok([item({}), item({ id: "itm_3", title: "补文档", kind: "my_commitment", why: ["你答应过"] })]);
    return ok({});
  });
  return posts;
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <App live={false} />
      </ToastProvider>
    </MemoryRouter>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("工作上下文", () => {
  it("启用后首页是「今天」，派单类页面收进「更多」", async () => {
    mockApi();
    renderAt("/");
    expect(await screen.findByRole("heading", { name: /今天 · 11 月 25 日/ })).toBeTruthy();
    const nav = screen.getByRole("navigation", { name: "主导航" });
    for (const n of ["今天", "项目", "事项", "知识", "动态", "人", "草稿", "派单概览", "派单"]) expect(within(nav).getByRole("link", { name: new RegExp(`^.?\\s*${n}$`) })).toBeTruthy();
    expect(within(nav).getByText("更多")).toBeTruthy();
    expect(screen.getByText(/1 件别人在等你，1 件你答应过，1 处说法不一致/)).toBeTruthy();
    expect(screen.getByText("Ark 周会")).toBeTruthy();
    expect(screen.getAllByText("上线时间从周五改到下周一").length).toBeGreaterThan(0);
  });

  it("在「先做这几件」里完成一件事、确认冲突", async () => {
    const posts = mockApi();
    const user = userEvent.setup();
    renderAt("/");
    await screen.findByRole("heading", { name: /今天 · / });
    const focus = screen.getByRole("region", { name: /先做这几件/ });
    await user.click(within(focus).getAllByRole("button", { name: "完成" })[0]);
    await waitFor(() => expect(posts).toContainEqual({ name: "context.item_done", args: { id: "itm_1" } }));
    await user.click(screen.getAllByRole("button", { name: "以此为准" })[1]);
    await waitFor(() => expect(posts).toContainEqual({ name: "context.conflict_resolve", args: { id: "cfl_1", choice: 1 } }));
  });

  it("草稿可以先改再发；发送前写明发到哪里", async () => {
    const posts = mockApi();
    const user = userEvent.setup();
    renderAt("/");
    const box = await screen.findByRole("textbox", { name: "草稿内容" });
    await user.clear(box);
    await user.type(box, "排期周五前给你。");
    await user.click(screen.getByRole("button", { name: "以我的身份发送" }));
    const dlg = await screen.findByRole("dialog", { name: "以你本人的身份发送？" });
    expect(within(dlg).getByText("回复 王五（Ark 发布群）")).toBeTruthy();
    expect(posts.some((p) => p.name === "context.draft_approve")).toBe(false);
    await user.click(within(dlg).getByRole("button", { name: "发送" }));
    await waitFor(() => expect(posts).toContainEqual({ name: "context.draft_approve", args: { id: "drf_1", content: "排期周五前给你。" } }));
  });

  it("事项页：按类型筛选，每件带排序依据", async () => {
    mockApi();
    renderAt("/items");
    expect(await screen.findByRole("heading", { name: "事项" })).toBeTruthy();
    expect(await screen.findByRole("link", { name: "补文档" })).toBeTruthy();
    expect(screen.getAllByText("别人在等你").length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "起草回复" }).length).toBe(2);
  });
});
