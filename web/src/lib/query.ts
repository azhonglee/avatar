import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client.ts";

/**
 * 极简的数据层：每个 useQuery 在全局登记自己的标签；SSE 事件或命令成功后按标签 invalidate，
 * 只有当前挂载（可见）的资源会重新拉取。重新拉取时保留旧数据，不闪烁。
 */

interface Sub {
  tags: readonly string[];
  refetch: () => void;
}
const subs = new Set<Sub>();

export function invalidate(tags: readonly string[] | "all"): void {
  if (tags !== "all" && !tags.length) return;
  for (const s of subs) if (tags === "all" || s.tags.some((t) => tags.includes(t))) s.refetch();
}

/** 测试用：当前登记的资源数 */
export function subscriberCount(): number {
  return subs.size;
}

export interface QueryState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  /** 已有数据、后台刷新中 */
  refreshing: boolean;
  refetch: () => Promise<void>;
}

export interface QueryOptions {
  /** 被这些标签 invalidate 时重新拉取；缺省用路径第一段（/api/overview → overview） */
  tags?: readonly string[];
  /** 合并短时间内的多次 invalidate（毫秒） */
  debounceMs?: number;
}

export function defaultTag(path: string): string {
  return path.replace(/^\/api\//, "").split(/[/?]/)[0];
}

export function useQuery<T>(path: string | null, o: QueryOptions = {}): QueryState<T> {
  const [state, setState] = useState<{ data: T | undefined; error: unknown; loading: boolean; refreshing: boolean }>({
    data: undefined,
    error: undefined,
    loading: !!path,
    refreshing: false,
  });
  const ctrl = useRef<AbortController | null>(null);
  const seq = useRef(0);
  const pathRef = useRef(path);
  pathRef.current = path;

  const load = useCallback(async () => {
    const p = pathRef.current;
    if (!p) return;
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const my = ++seq.current;
    setState((s) => ({ ...s, loading: s.data === undefined, refreshing: s.data !== undefined }));
    try {
      const data = await api.get<T>(p, c.signal);
      if (my === seq.current) setState({ data, error: undefined, loading: false, refreshing: false });
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return;
      if (my === seq.current) setState((s) => ({ data: s.data, error: e, loading: false, refreshing: false }));
    }
  }, []);

  // 路径变化：清空并重新加载
  useEffect(() => {
    setState({ data: undefined, error: undefined, loading: !!path, refreshing: false });
    if (path) void load();
    return () => ctrl.current?.abort();
  }, [path, load]);

  const tagKey = (o.tags ?? (path ? [defaultTag(path)] : [])).join("\u0000");
  const debounce = o.debounceMs ?? 250;
  useEffect(() => {
    if (!path) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const sub: Sub = {
      tags: tagKey.split("\u0000").filter(Boolean),
      refetch: () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => void load(), debounce);
      },
    };
    subs.add(sub);
    return () => {
      subs.delete(sub);
      if (timer) clearTimeout(timer);
    };
  }, [path, tagKey, debounce, load]);

  return { ...state, refetch: load };
}
