import { useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../api/client.ts";
import type { LogChunk } from "../api/types.ts";
import { Spinner } from "./ui.tsx";

const MAX_CHARS = 1_000_000;

/**
 * 步骤日志：从 offset 分段拉取；步骤仍在运行时到达末尾后定时继续拉（tail -f）。
 * 只保留最后 1MB 文本；用户滚到底部时自动跟随。
 */
export function LogViewer({ stepId, pollMs = 1500 }: { stepId: number; pollMs?: number }) {
  const [text, setText] = useState("");
  const [clipped, setClipped] = useState(false);
  const [status, setStatus] = useState<"loading" | "tailing" | "done" | "error">("loading");
  const [error, setError] = useState("");
  const [follow, setFollow] = useState(true);
  const box = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const ctrl = new AbortController();
    let offset = 0;
    setText("");
    setClipped(false);
    setStatus("loading");
    const step = async () => {
      try {
        const c = await api.get<LogChunk>(`/api/steps/${stepId}/log?offset=${offset}`, ctrl.signal);
        if (stop) return;
        offset = c.next_offset;
        if (c.text)
          setText((t) => {
            const n = t + c.text;
            if (n.length > MAX_CHARS) {
              setClipped(true);
              return n.slice(n.length - MAX_CHARS);
            }
            return n;
          });
        if (!c.eof) return void (timer = setTimeout(step, 0));
        if (c.running) {
          setStatus("tailing");
          timer = setTimeout(step, pollMs);
        } else setStatus("done");
      } catch (e) {
        if (stop || (e as Error)?.name === "AbortError") return;
        setError(errorMessage(e));
        setStatus("error");
      }
    };
    void step();
    return () => {
      stop = true;
      ctrl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [stepId, pollMs]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [text, follow]);

  return (
    <div className="logview">
      <div className="logview-bar">
        <span className="small muted" aria-live="polite">
          {status === "loading" && (
            <>
              <Spinner /> 读取日志…
            </>
          )}
          {status === "tailing" && (
            <>
              <span className="live-dot live-open" aria-hidden /> 实时跟随中
            </>
          )}
          {status === "done" && `共 ${text.length.toLocaleString()} 字符`}
          {status === "error" && <span className="text-danger">读取失败：{error}</span>}
        </span>
        <label className="check small">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          自动滚动到底部
        </label>
      </div>
      {clipped && <div className="small muted">（日志较长，只显示最后 1MB）</div>}
      <pre
        ref={box}
        className="pre logview-text"
        tabIndex={0}
        aria-label="步骤日志"
        onScroll={(e) => {
          const el = e.currentTarget;
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          if (atBottom !== follow) setFollow(atBottom);
        }}
      >
        {text || (status === "done" ? "（没有日志输出）" : "")}
      </pre>
    </div>
  );
}
