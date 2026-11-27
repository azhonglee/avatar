import { describe, expect, it, vi } from "vitest";
import { ApiRequestError, api, errorMessage, onUnauthorized, request } from "./client.ts";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(body === undefined ? "" : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api client", () => {
  it("sends Accept JSON header and credentials on GET", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse({ ok: true }));
    const res = await api.get<{ ok: boolean }>("/api/meta");
    expect(res).toEqual({ ok: true });
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/meta",
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        body: undefined,
      }),
    );
  });

  it("sends Content-Type application/json and serialized body on POST command", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse({ ok: true, message: "已取消", target: "dispatch:1" }));
    const res = await api.command("dispatch.cancel", { id: "dispatch:1" });
    expect(res.ok).toBe(true);
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/commands/dispatch.cancel",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ args: { id: "dispatch:1" } }),
      }),
    );
  });

  it("handles 401 unauthorized, parses ApiError, and notifies listeners", async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    try {
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        jsonResponse({ error: { code: "unauthorized", message: "未登录：请运行 pa console" } }, 401),
      );
      let caught: unknown;
      try {
        await api.get("/api/overview");
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ApiRequestError);
      const err = caught as ApiRequestError;
      expect(err.status).toBe(401);
      expect(err.unauthorized).toBe(true);
      expect(err.unavailable).toBe(false);
      expect(err.code).toBe("unauthorized");
      expect(err.message).toBe("未登录：请运行 pa console");
      expect(listener).toHaveBeenCalledTimes(1);
    } finally {
      off();
    }
  });

  it("handles 501 unavailable with fallback message when body is not ApiError", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("Not Implemented", { status: 501 }));
    let caught: unknown;
    try {
      await api.get("/api/usage");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApiRequestError);
    const err = caught as ApiRequestError;
    expect(err.status).toBe(501);
    expect(err.unavailable).toBe(true);
    expect(err.unauthorized).toBe(false);
    expect(err.code).toBe("unavailable");
    expect(err.message).toBe("该功能未启用");
  });

  it("parses 400 and 409 ApiError code and message", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse({ error: { code: "invalid", message: "请填写任务描述" } }, 400))
      .mockResolvedValueOnce(jsonResponse({ error: { code: "conflict", message: "派单已经结束" } }, 409));

    await expect(api.command("dispatch.create", { summary: "" })).rejects.toMatchObject({
      status: 400,
      code: "invalid",
      message: "请填写任务描述",
    });
    await expect(api.command("dispatch.cancel", { id: "dispatch:1" })).rejects.toMatchObject({
      status: 409,
      code: "conflict",
      message: "派单已经结束",
    });
  });

  it("returns body without throwing for statuses listed in accept", async () => {
    const payload = { ok: false, errors: [{ path: "budget.daily_usd", message: "必须 >= 0" }], restart_required: false };
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse(payload, 400));
    const res = await request<typeof payload>("/api/settings", { method: "PUT", body: { budget: { daily_usd: -1 } }, accept: [400] });
    expect(res).toEqual(payload);
  });

  it("wraps network errors as ApiRequestError with status 0", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new TypeError("Failed to fetch"));
    let caught: unknown;
    try {
      await api.get("/api/meta");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApiRequestError);
    const err = caught as ApiRequestError;
    expect(err.status).toBe(0);
    expect(err.code).toBe("network");
    expect(errorMessage(err)).toContain("无法连接控制台服务");
  });
});
