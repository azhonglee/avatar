import { useMemo, useState } from "react";
import type { DiffView } from "../api/types.ts";
import { parseDiff, type DiffFile } from "../lib/diff.ts";
import { useQuery } from "../lib/query.ts";
import { Empty, QueryView, Spinner } from "./ui.tsx";

const STATUS_LABEL: Record<DiffFile["status"], string> = { modified: "修改", added: "新增", deleted: "删除", renamed: "重命名", binary: "二进制" };
const BIG = 400;

function FileDiff({ f, idx, open, onToggle }: { f: DiffFile; idx: number; open: boolean; onToggle: () => void }) {
  return (
    <section className="dfile" id={`dfile-${idx}`}>
      <h4 className="dfile-head">
        <button className="dfile-toggle" aria-expanded={open} onClick={onToggle}>
          <span className="chev" aria-hidden>
            {open ? "▾" : "▸"}
          </span>
          <span className={`dfile-status ds-${f.status}`}>{STATUS_LABEL[f.status]}</span>
          <span className="dfile-path">
            {f.status === "renamed" && f.oldPath ? `${f.oldPath} → ` : ""}
            {f.path}
          </span>
          <span className="dfile-count">
            <span className="text-add">+{f.adds}</span> <span className="text-del">−{f.dels}</span>
          </span>
        </button>
      </h4>
      {open &&
        (f.lines.length ? (
          <div className="dcode" role="table" aria-label={`${f.path} 的改动`}>
            {f.lines.map((l, i) => (
              <div key={i} className={`dl dl-${l.kind}`} role="row">
                <span className="dl-no" role="cell" aria-hidden>
                  {l.oldNo ?? ""}
                </span>
                <span className="dl-no" role="cell" aria-hidden>
                  {l.newNo ?? ""}
                </span>
                <span className="dl-sign" role="cell" aria-hidden>
                  {l.kind === "add" ? "+" : l.kind === "del" ? "−" : " "}
                </span>
                <span className="dl-text" role="cell">
                  {l.text || " "}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="muted small dfile-empty">{f.status === "binary" ? "二进制文件，不显示内容" : "没有内容改动（可能只改了权限）"}</div>
        ))}
    </section>
  );
}

export function DiffBody({ diff }: { diff: DiffView }) {
  const files = useMemo(() => parseDiff(diff.patch), [diff.patch]);
  const [openSet, setOpenSet] = useState<Set<number> | null>(null);
  const defaults = useMemo(() => new Set(files.map((f, i) => (files.length <= 20 && f.lines.length <= BIG ? i : -1)).filter((i) => i >= 0)), [files]);
  const open = openSet ?? defaults;
  const toggle = (i: number) => {
    const n = new Set(open);
    if (n.has(i)) n.delete(i);
    else n.add(i);
    setOpenSet(n);
  };
  if (!files.length) return <Empty title="没有改动">{diff.base ? "工作区与基线一致。" : "这次派单没有在 git 仓库中执行，或 worktree 已被清理。"}</Empty>;
  const adds = files.reduce((a, f) => a + f.adds, 0);
  const dels = files.reduce((a, f) => a + f.dels, 0);
  return (
    <div className="diff">
      <div className="diff-summary">
        <span>
          {files.length} 个文件 · <span className="text-add">+{adds}</span> <span className="text-del">−{dels}</span>
        </span>
        <span className="muted small">
          基线 <code>{diff.base.slice(0, 10)}</code>
          {diff.head && (
            <>
              {" "}
              → <code>{diff.head.slice(0, 10)}</code>
            </>
          )}
        </span>
        <span className="diff-bulk">
          <button className="btn btn-link small" onClick={() => setOpenSet(new Set(files.map((_, i) => i)))}>
            全部展开
          </button>
          <button className="btn btn-link small" onClick={() => setOpenSet(new Set())}>
            全部折叠
          </button>
        </span>
      </div>
      {diff.truncated && (
        <div className="inline-warn" role="status">
          改动太大，只显示了前面一部分。完整内容请在开发机上用 <code>git diff {diff.base.slice(0, 10)}</code> 查看。
        </div>
      )}
      <nav className="diff-files" aria-label="改动的文件">
        <ul>
          {files.map((f, i) => (
            <li key={i}>
              <a
                href={`#dfile-${i}`}
                onClick={() => {
                  if (!open.has(i)) toggle(i);
                }}
              >
                <span className={`dfile-status ds-${f.status}`}>{STATUS_LABEL[f.status]}</span> {f.path}
              </a>
              <span className="dfile-count small">
                <span className="text-add">+{f.adds}</span> <span className="text-del">−{f.dels}</span>
              </span>
            </li>
          ))}
        </ul>
      </nav>
      {files.map((f, i) => (
        <FileDiff key={`${f.path}-${i}`} f={f} idx={i} open={open.has(i)} onToggle={() => toggle(i)} />
      ))}
    </div>
  );
}

export function DiffViewer({ id }: { id: string }) {
  const q = useQuery<DiffView>(`/api/dispatches/${encodeURIComponent(id)}/diff`, { tags: [`diff:${id}`] });
  return (
    <div>
      <div className="diff-toolbar">
        <button className="btn btn-sm" onClick={() => void q.refetch()} disabled={q.refreshing || q.loading}>
          {q.refreshing && <Spinner />}
          刷新改动
        </button>
      </div>
      <QueryView q={q} loading={<div className="state state-loading"><Spinner /> 正在计算改动…</div>}>
        {(d) => <DiffBody diff={d} />}
      </QueryView>
    </div>
  );
}
