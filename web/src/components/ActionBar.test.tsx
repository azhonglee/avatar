import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { CommandName, DispatchDetail, Meta } from "../api/types.ts";
import { MetaProvider } from "../lib/meta.ts";
import { ToastProvider } from "../lib/toast.tsx";
import { DispatchDetailPage } from "../pages/DispatchDetail.tsx";
import { ActionBar } from "./ActionBar.tsx";

const META: Meta = {
  version: "0.1.0",
  owner: { open_id: "ou_test", timezone: "Asia/Shanghai" },
  harnesses: ["claude", "codex"],
  roles: { brain: "claude", reviewer: "codex", default_harness: "codex" },
  repos: [{ alias: "demo", path: "/tmp/demo", verify: "npm test" }],
  providers: [{ name: "github", type: "github" }],
  features: { cards: true, delivery: true, usage: true, settings: true, doctor: true, candidates: true, context: false },
  lark_web: "https://feishu.cn",
};

function makeDispatch(overrides: Partial<DispatchDetail> = {}): DispatchDetail {
  return {
    id: "dispatch:t1:abc",
    task_guid: "t1",
    task_url: "",
    summary: "给登录接口加上限流",
    state: "accepted",
    terminal: true,
    reason: "校验全部通过",
    harness: "codex",
    reviewer: "claude",
    repo: "demo",
    round: 1,
    max_rounds: 2,
    attempts: 1,
    active: false,
    cancel_requested: false,
    created: Date.now() - 120_000,
    updated: Date.now() - 10_000,
    cost_usd: 0.042,
    delivery: "none",
    delivery_url: "",
    description: "repo: demo",
    cwd: "/tmp/demo-wt",
    branch: "pa/t1",
    base: "abc1234567",
    verify: "npm test",
    report: "已完成限流中间件",
    feedback: "",
    error: "",
    rounds: [],
    steps: [],
    effects: [],
    previous: [],
    diff_stat: "",
    actions: ["dispatch.retry", "dispatch.rework", "delivery.create_pr", "delivery.merge_local", "delivery.discard"],
    audit: [],
    ...overrides,
  };
}

function renderActionBar(actions: CommandName[], extra: Partial<DispatchDetail> = {}) {
  const d = makeDispatch({ actions, ...extra });
  return render(
    <MemoryRouter initialEntries={[`/dispatches/${encodeURIComponent(d.id)}`]}>
      <ToastProvider>
        <MetaProvider value={META}>
          <Routes>
            <Route path="/dispatches/:id" element={<ActionBar d={d} />} />
          </Routes>
        </MetaProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("ActionBar", () => {
  it("renders exact buttons from actions in order and nothing when empty", () => {
    const { unmount } = renderActionBar(["dispatch.rework", "delivery.merge_local", "delivery.discard"]);
    const buttons = within(screen.getByRole("group", { name: "派单操作" })).getAllByRole("button");
    expect(buttons.map((b) => b.getAttribute("data-action"))).toEqual(["dispatch.rework", "delivery.merge_local", "delivery.discard"]);
    unmount();

    renderActionBar([]);
    expect(screen.queryByRole("group", { name: "派单操作" })).toBeNull();
  });

  it("opens confirmation dialog for delivery.merge_local before firing command", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true, message: "已合并到本地分支" }), { status: 200 }));

    renderActionBar(["delivery.merge_local"]);
    await user.click(screen.getByRole("button", { name: "合并到本地分支" }));

    expect(fetchSpy).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", { name: "合并到本地分支？" });
    expect(dialog.textContent).toContain("合并会直接改动你的本地仓库");

    await user.type(within(dialog).getByLabelText("目标分支（可选）"), "main");
    await user.click(within(dialog).getByRole("button", { name: "确认合并" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/commands/delivery.merge_local",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ args: { id: "dispatch:t1:abc", target_branch: "main" } }),
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("opens confirmation dialog for delivery.discard and cancels without firing", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true, message: "已放弃" }), { status: 200 }));

    renderActionBar(["delivery.discard"]);
    await user.click(screen.getByRole("button", { name: "放弃" }));

    const dialog = screen.getByRole("dialog", { name: "放弃这次结果？" });
    expect(fetchSpy).not.toHaveBeenCalled();

    // Cancel first
    await user.click(within(dialog).getByRole("button", { name: "再想想" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();

    // Reopen and confirm
    await user.click(screen.getByRole("button", { name: "放弃" }));
    const dialog2 = screen.getByRole("dialog", { name: "放弃这次结果？" });
    await user.click(within(dialog2).getByRole("button", { name: "放弃" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/commands/delivery.discard",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ args: { id: "dispatch:t1:abc" } }),
      }),
    );
  });

  it("opens confirmation dialog for dispatch.cancel before firing command", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true, message: "已请求取消" }), { status: 200 }));

    renderActionBar(["dispatch.cancel"], { state: "executing", terminal: false });
    await user.click(screen.getByRole("button", { name: "取消派单" }));

    expect(fetchSpy).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", { name: "取消这次派单？" });
    await user.click(within(dialog).getByRole("button", { name: "取消派单" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/commands/dispatch.cancel",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ args: { id: "dispatch:t1:abc" } }),
      }),
    );
  });

  it("requires non-empty feedback in dispatch.rework dialog and surfaces command errors cleanly", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "conflict", message: "这张卡片已经有更新的派单" } }), { status: 409 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, message: "已带着你的意见重新派单", target: "dispatch:t1:new" }), { status: 200 }));

    renderActionBar(["dispatch.rework"]);
    await user.click(screen.getByRole("button", { name: "带意见返工" }));

    const dialog = screen.getByRole("dialog", { name: "带意见返工" });
    await user.click(within(dialog).getByRole("button", { name: "提交并返工" }));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(within(dialog).getByRole("alert").textContent).toContain("请写下返工意见");

    await user.type(within(dialog).getByLabelText("返工意见"), "  补上边界条件单测  ");
    await user.click(within(dialog).getByRole("button", { name: "提交并返工" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    // Error toast surfaces cleanly, dialog stays open so user doesn't lose text
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((el) => el.textContent?.includes("这张卡片已经有更新的派单"))).toBe(true);
    expect(screen.getByRole("dialog", { name: "带意见返工" })).toBeTruthy();

    // Retry succeeds and closes dialog
    await user.click(within(dialog).getByRole("button", { name: "提交并返工" }));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2));
    expect(fetchSpy.mock.calls[1][1]).toMatchObject({
      body: JSON.stringify({ args: { id: "dispatch:t1:abc", feedback: "补上边界条件单测" } }),
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
});

describe("DispatchDetailPage", () => {
  it("loads dispatch detail and renders backend actions", async () => {
    const detail = makeDispatch({ actions: ["dispatch.rework", "delivery.discard"] });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(detail), { status: 200 }));

    render(
      <MemoryRouter initialEntries={[`/dispatches/${encodeURIComponent(detail.id)}`]}>
        <ToastProvider>
          <MetaProvider value={META}>
            <Routes>
              <Route path="/dispatches/:id" element={<DispatchDetailPage />} />
            </Routes>
          </MetaProvider>
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: "给登录接口加上限流" })).toBeTruthy();
    const bar = screen.getByRole("group", { name: "派单操作" });
    expect(within(bar).getAllByRole("button").map((b) => b.getAttribute("data-action"))).toEqual(["dispatch.rework", "delivery.discard"]);
  });
});
