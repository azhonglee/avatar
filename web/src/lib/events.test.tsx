import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { eventTags, useServerEvents } from "./events.ts";
import { useQuery } from "./query.ts";

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  readyState = 0;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  emitOpen() {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  emitData(data: unknown) {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(data) }));
  }

  emitError(readyState = 0) {
    this.readyState = readyState;
    this.onerror?.(new Event("error"));
  }

  close() {
    this.closed = true;
    this.readyState = 2;
  }
}

const origEventSource = globalThis.EventSource;

afterEach(() => {
  MockEventSource.instances = [];
  globalThis.EventSource = origEventSource;
});

describe("eventTags", () => {
  it("maps ServerEvent variants to affected query tags", () => {
    expect(eventTags({ type: "work", id: "dispatch:1", kind: "dispatch", ref: "t1", state: "executing", terminal: false })).toEqual([
      "overview",
      "dispatches",
      "dispatch:dispatch:1",
      "card:t1",
      "usage",
    ]);
    expect(eventTags({ type: "work", id: "job:1", kind: "job", ref: "kb", state: "done", terminal: true })).toEqual(["jobs", "health", "overview"]);
    expect(eventTags({ type: "candidate", signal_id: "s1" })).toEqual(["candidates", "overview"]);
    expect(eventTags({ type: "command", name: "dispatch.cancel", ok: true, target: "dispatch:1" })).toEqual(["dispatch:dispatch:1", "audit"]);
    expect(eventTags({ type: "refresh" })).toBe("all");
    expect(eventTags({ type: "ping", at: 1 })).toEqual([]);
  });
});

describe("useServerEvents + useQuery integration", () => {
  function Harness() {
    const live = useServerEvents(true);
    const dispatch = useQuery<{ count: number }>("/api/dispatches/dispatch%3A1", { tags: ["dispatch:dispatch:1"], debounceMs: 10 });
    const jobs = useQuery<{ count: number }>("/api/jobs", { tags: ["jobs"], debounceMs: 10 });
    return (
      <div>
        <div data-testid="live">{live}</div>
        <div data-testid="dispatch">{dispatch.data?.count ?? "loading"}</div>
        <div data-testid="jobs">{jobs.data?.count ?? "loading"}</div>
      </div>
    );
  }

  it("refetches only matching queries on work event and all queries on refresh", async () => {
    globalThis.EventSource = MockEventSource as unknown as typeof EventSource;
    const calls: Record<string, number> = { dispatch: 0, jobs: 0 };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith("/api/dispatches/")) {
        calls.dispatch++;
        return new Response(JSON.stringify({ count: calls.dispatch }), { status: 200 });
      }
      if (url === "/api/jobs") {
        calls.jobs++;
        return new Response(JSON.stringify({ count: calls.jobs }), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    });

    render(<Harness />);
    await waitFor(() => {
      expect(screen.getByTestId("dispatch").textContent).toBe("1");
      expect(screen.getByTestId("jobs").textContent).toBe("1");
    });

    expect(MockEventSource.instances).toHaveLength(1);
    const es = MockEventSource.instances[0];
    expect(es.url).toBe("/api/events");

    act(() => es.emitOpen());
    expect(screen.getByTestId("live").textContent).toBe("open");

    // Matching dispatch event -> refetches dispatch only
    act(() => {
      es.emitData({ type: "work", id: "dispatch:1", kind: "dispatch", ref: "task1", state: "verifying", terminal: false });
    });
    await waitFor(() => {
      expect(screen.getByTestId("dispatch").textContent).toBe("2");
    });
    expect(screen.getByTestId("jobs").textContent).toBe("1");

    // Refresh event -> refetches all mounted queries
    act(() => {
      es.emitData({ type: "refresh" });
    });
    await waitFor(() => {
      expect(screen.getByTestId("dispatch").textContent).toBe("3");
      expect(screen.getByTestId("jobs").textContent).toBe("2");
    });

    // Disconnect and reconnect -> triggers full refresh
    act(() => es.emitError(0));
    expect(screen.getByTestId("live").textContent).toBe("reconnecting");
    act(() => es.emitOpen());
    expect(screen.getByTestId("live").textContent).toBe("open");
    await waitFor(() => {
      expect(screen.getByTestId("dispatch").textContent).toBe("4");
      expect(screen.getByTestId("jobs").textContent).toBe("3");
    });
  });
});
