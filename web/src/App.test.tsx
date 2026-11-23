import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { Meta, Overview } from "./api/types.ts";
import { App } from "./App.tsx";
import { ToastProvider } from "./lib/toast.tsx";

function makeMeta(features?: Partial<Meta["features"]>): Meta {
  return {
    version: "0.1.0",
    owner: { open_id: "ou_test", timezone: "Asia/Shanghai" },
    harnesses: ["claude", "codex"],
    roles: { brain: "claude", reviewer: "codex", default_harness: "codex" },
    repos: [],
    providers: [],
    features: { cards: false, delivery: false, usage: true, settings: true, doctor: true, candidates: true, ...features },
    lark_web: "https://feishu.cn",
  };
}

const OVERVIEW: Overview = {
  attention: { needs_human: [], to_review: [], candidates: 0, failures: 0 },
  running: [],
  today: { dispatched: 0, accepted: 0, needs_human: 0, errored: 0, cost_usd: 0, budget_usd: 0 },
  health: { ok: true, pending_events: 0, pending_effects: 0, dead: 0, daemon_owner: "host:1:abc" },
};

function renderApp(initialPath = "/") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <ToastProvider>
        <App live={false} />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("App", () => {
  it("shows NeedLogin screen on 401 and recovers on retry", async () => {
    const user = userEvent.setup();
    let authed = false;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (!authed) {
        return new Response(JSON.stringify({ error: { code: "unauthorized", message: "未登录" } }), { status: 401 });
      }
      if (url === "/api/meta") return new Response(JSON.stringify(makeMeta({ doctor: false })), { status: 200 });
      if (url === "/api/overview") return new Response(JSON.stringify(OVERVIEW), { status: 200 });
      return new Response("{}", { status: 200 });
    });

    renderApp("/");
    expect(await screen.findByRole("heading", { name: "需要登录" })).toBeTruthy();
    expect(screen.getByText(/pa console/)).toBeTruthy();

    authed = true;
    await user.click(screen.getByRole("button", { name: "我已登录，重试" }));
    expect(await screen.findByRole("heading", { name: "概览" })).toBeTruthy();
  });

  it("shows friendly 未启用 state when a feature endpoint returns 501", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === "/api/meta") return new Response(JSON.stringify(makeMeta({ usage: true })), { status: 200 });
      if (url.startsWith("/api/usage")) {
        return new Response(JSON.stringify({ error: { code: "unavailable", message: "该功能未启用" } }), { status: 501 });
      }
      return new Response("{}", { status: 200 });
    });

    renderApp("/usage");
    const note = await screen.findByRole("note");
    expect(note.textContent).toContain("用量统计未启用");
    expect(note.textContent).toContain("这个模块在当前版本或配置中没有启用");
  });

  it("gates navigation links and pages by Meta.features", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === "/api/meta") {
        return new Response(JSON.stringify(makeMeta({ candidates: false, usage: false, settings: false, doctor: false })), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    });

    renderApp("/candidates");
    const note = await screen.findByRole("note");
    expect(note.textContent).toContain("候选任务未启用");

    // Disabled features should not appear in navigation or trigger API fetch
    await waitFor(() => {
      expect(screen.queryByRole("link", { name: /候选任务/ })).toBeNull();
      expect(screen.queryByRole("link", { name: /花费/ })).toBeNull();
      expect(screen.queryByRole("link", { name: /设置/ })).toBeNull();
      expect(screen.queryByRole("link", { name: /初始化向导/ })).toBeNull();
    });
    expect(fetchSpy.mock.calls.some(([u]) => String(u).startsWith("/api/candidates"))).toBe(false);
  });

  it("switches to NeedLogin when a later page request returns 401", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === "/api/meta") return new Response(JSON.stringify(makeMeta({ doctor: false })), { status: 200 });
      if (url === "/api/overview") {
        return new Response(JSON.stringify({ error: { code: "unauthorized", message: "会话已失效" } }), { status: 401 });
      }
      return new Response("{}", { status: 200 });
    });

    renderApp("/");
    expect(await screen.findByRole("heading", { name: "需要登录" })).toBeTruthy();
  });
});
