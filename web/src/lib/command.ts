import { useCallback, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, errorMessage } from "../api/client.ts";
import type { CommandArgs, CommandName, CommandResult } from "../api/types.ts";
import { invalidate } from "./query.ts";
import { useToast } from "./toast.tsx";

export interface CommandRunner {
  /** 执行命令；失败时已经 toast 过，返回 undefined */
  run<N extends CommandName>(name: N, args: CommandArgs[N], o?: { navigate?: boolean; key?: string }): Promise<CommandResult | undefined>;
  /** 正在执行的命令键（缺省为命令名；同一页面多个对象时用 key 区分） */
  pending: ReadonlySet<string>;
  isPending(key: string): boolean;
}

/**
 * 执行写操作：执行期间对应按钮禁用；成功/失败都 toast 后端的消息；
 * 返回的 target 是一项新派单时跳转过去（除非 navigate: false 或就是当前页）。
 */
export function useCommand(): CommandRunner {
  const toast = useToast();
  const navigate = useNavigate();
  const params = useParams();
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set());
  const inflight = useRef(new Set<string>());

  const run = useCallback(
    async <N extends CommandName>(name: N, args: CommandArgs[N], o: { navigate?: boolean; key?: string } = {}) => {
      const key = o.key ?? name;
      if (inflight.current.has(key)) return undefined;
      inflight.current.add(key);
      setPending(new Set(inflight.current));
      try {
        const r = await api.command(name, args);
        toast.push(r.ok ? "success" : "error", r.message || (r.ok ? "已完成" : "操作未成功"), r.url ? { label: "打开", href: r.url } : undefined);
        invalidate("all");
        const current = params.id ? decodeURIComponent(params.id) : "";
        if (r.ok && o.navigate !== false && r.target?.startsWith("dispatch:") && r.target !== current) {
          navigate(`/dispatches/${encodeURIComponent(r.target)}`);
        }
        return r;
      } catch (e) {
        toast.push("error", errorMessage(e));
        return undefined;
      } finally {
        inflight.current.delete(key);
        setPending(new Set(inflight.current));
      }
    },
    [toast, navigate, params.id],
  );

  return { run, pending, isPending: (k: string) => pending.has(k) };
}
