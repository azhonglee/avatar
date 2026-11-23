import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { Meta, SettingsUpdateResult, SettingsView } from "../api/types.ts";
import { MetaProvider } from "../lib/meta.ts";
import { ToastProvider } from "../lib/toast.tsx";
import { SettingsPage } from "./Settings.tsx";

const META: Meta = {
  version: "0.1.0",
  owner: { open_id: "ou_test", timezone: "Asia/Shanghai" },
  harnesses: ["claude", "codex"],
  roles: { brain: "claude", reviewer: "codex", default_harness: "codex" },
  repos: [],
  providers: [],
  features: { cards: true, delivery: true, usage: true, settings: true, doctor: true, candidates: true },
  lark_web: "https://feishu.cn",
};

function makeSettingsView(overrides: Partial<SettingsView> = {}): SettingsView {
  return {
    file: "/tmp/config.yaml",
    restart_required: false,
    hot_reload: {
      roles: true,
      dispatch: true,
      acceptance: true,
      budget: true,
      notify: true,
      schedules: false,
      delivery: true,
    },
    config: {
      harnesses: {
        claude: { agent: "claude", model: "sonnet" },
        codex: { agent: "codex" },
      },
      roles: { brain: "claude", reviewer: "codex" },
      dispatch: { default_harness: "codex", max_parallel: 2, timeout_sec: 3600, fix_rounds: 1, max_attempts: 2, repos: {} },
      acceptance: { on_unverified: "needs_human", review_retries: 1, review_timeout_sec: 1200, verify_timeout_sec: 1800 },
      budget: { daily_usd: 10, per_task_usd: 2, pricing: {} },
      notify: { quiet_start: "", quiet_end: "", types: { candidate: true, progress: true, result: true, failure: true, brief: true } },
      schedules: { capture: "*/15 * * * *", dispatch: "*/5 * * * *", brief_morning: "30 8 * * 1-5", brief_evening: "30 18 * * 1-5" },
      delivery: { default_provider: "", providers: {}, discard_retention_days: 7 },
    },
    ...overrides,
  };
}

function renderSettings() {
  return render(
    <MemoryRouter initialEntries={["/settings"]}>
      <ToastProvider>
        <MetaProvider value={META}>
          <SettingsPage />
        </MetaProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("SettingsPage", () => {
  it("displays field-level errors from SettingsUpdateResult.errors on 400", async () => {
    const user = userEvent.setup();
    const view = makeSettingsView();
    const errRes: SettingsUpdateResult = {
      ok: false,
      restart_required: false,
      errors: [{ path: "budget.daily_usd", message: "每日预算不能为负数" }],
    };

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(view), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(errRes), { status: 400 }));

    renderSettings();

    const dailyInput = await screen.findByLabelText("每日预算");
    await user.clear(dailyInput);
    await user.type(dailyInput, "-5");

    const saveBtn = screen.getByRole("button", { name: "保存" });
    expect((saveBtn as HTMLButtonElement).disabled).toBe(false);
    await user.click(saveBtn);

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2));
    // Verify only the changed leaf was sent in PUT body
    const putInit = fetchSpy.mock.calls[1][1] as RequestInit;
    expect(putInit.method).toBe("PUT");
    expect(JSON.parse(String(putInit.body))).toEqual({ budget: { daily_usd: -5 } });

    // Top banner + field-level inline error both show the message
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((el) => el.textContent?.includes("没有保存：有 1 处需要修改"))).toBe(true);
    expect(dailyInput.getAttribute("aria-invalid")).toBe("true");
    const field = dailyInput.closest('[data-path="budget.daily_usd"]');
    expect(field?.textContent).toContain("每日预算不能为负数");
  });

  it("displays restart_required banner after saving cold-reload settings", async () => {
    const user = userEvent.setup();
    const view = makeSettingsView();
    const updatedView = makeSettingsView({
      restart_required: true,
      config: {
        ...view.config,
        schedules: { capture: "*/10 * * * *", dispatch: "*/5 * * * *", brief_morning: "30 8 * * 1-5", brief_evening: "30 18 * * 1-5" },
      },
    });
    const okRes: SettingsUpdateResult = { ok: true, errors: [], restart_required: true };

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(view), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(okRes), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(updatedView), { status: 200 }));

    renderSettings();

    const cronInput = await screen.findByLabelText("收集候选任务");
    await user.clear(cronInput);
    await user.type(cronInput, "*/10 * * * *");
    await user.click(screen.getByRole("button", { name: "保存" }));

    const banners = await screen.findAllByRole("status");
    expect(banners.some((b) => b.textContent?.includes("需要重启常驻进程"))).toBe(true);
  });

  it("sends null in patch when deleting a configured provider so YAML removes the key", async () => {
    const user = userEvent.setup();
    const view = makeSettingsView();
    view.config.delivery = {
      default_provider: "",
      discard_retention_days: 7,
      providers: {
        gh: { type: "github", token_env: "GITHUB_TOKEN", remote: "origin" },
      },
    };
    const okRes: SettingsUpdateResult = { ok: true, errors: [], restart_required: false };
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(view), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(okRes), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(makeSettingsView()), { status: 200 }));

    renderSettings();
    const delBtn = await screen.findByRole("button", { name: "删除代码平台 gh" });
    await user.click(delBtn);
    await user.click(screen.getByRole("button", { name: "保存" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3));
    const putInit = fetchSpy.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(String(putInit.body))).toEqual({ delivery: { providers: { gh: null } } });
  });
});
