import { createContext, useContext, useEffect, useState } from "react";
import type { ServerEvent } from "../api/types.ts";
import { invalidate } from "./query.ts";

/** 一条实时事件影响哪些资源（标签与 useQuery 的 tags 对应）。 */
export function eventTags(e: ServerEvent): string[] | "all" {
  switch (e.type) {
    case "work":
      switch (e.kind) {
        case "dispatch":
          return ["overview", "dispatches", `dispatch:${e.id}`, `card:${e.ref}`, "usage"];
        case "effect":
          // 飞书写入：ref 是产生它的工作（派单 id 等）
          return ["health", "overview", `dispatch:${e.ref}`];
        case "delivery":
          return ["overview", "dispatches", `dispatch:${e.ref}`, "health"];
        case "job":
          return ["jobs", "health", "overview"];
        case "event":
          return ["health", "overview", "candidates"];
        default:
          return ["overview", "health"];
      }
    case "candidate":
      return ["candidates", "overview"];
    case "command":
      return e.target.startsWith("dispatch:") ? [`dispatch:${e.target}`, "audit"] : ["audit"];
    case "refresh":
      return "all";
    default:
      return [];
  }
}

export type LiveState = "connecting" | "open" | "reconnecting" | "off";

const LiveContext = createContext<LiveState>("off");
export const LiveProvider = LiveContext.Provider;
export function useLiveState(): LiveState {
  return useContext(LiveContext);
}

/**
 * 订阅 /api/events：按事件 invalidate 受影响的资源。断线后自动重连，重连成功时整体刷新一次（补上断线期间的变化）。
 */
export function useServerEvents(enabled: boolean, o: { url?: string; retryMs?: number; onEvent?: (e: ServerEvent) => void } = {}): LiveState {
  const [state, setState] = useState<LiveState>(enabled ? "connecting" : "off");
  const url = o.url ?? "/api/events";
  const retryMs = o.retryMs ?? 5000;
  const onEvent = o.onEvent;
  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") {
      setState("off");
      return;
    }
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let hadError = false;
    let closed = false;
    const connect = () => {
      es = new EventSource(url);
      es.onopen = () => {
        setState("open");
        if (hadError) invalidate("all");
        hadError = false;
      };
      es.onmessage = (m) => {
        let e: ServerEvent;
        try {
          e = JSON.parse(m.data) as ServerEvent;
        } catch {
          return;
        }
        onEvent?.(e);
        invalidate(eventTags(e));
      };
      es.onerror = () => {
        hadError = true;
        setState("reconnecting");
        // 浏览器会自动重连；如果已经彻底关闭（例如 401），我们自己隔一段时间再试
        if (es && es.readyState === 2 && !closed) {
          es.close();
          timer = setTimeout(connect, retryMs);
        }
      };
    };
    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      es?.close();
    };
  }, [enabled, url, retryMs, onEvent]);
  return state;
}
