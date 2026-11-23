import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { DispatchSummary } from "../api/types.ts";
import { DispatchRow } from "../components/dispatch.tsx";
import { Dialog, Empty, Field, PageHeader, QueryView, Spinner, Tabs } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

type Filter = "active" | "attention" | "review" | "done" | "all";
const FILTERS: { key: Filter; label: string; empty: string }[] = [
  { key: "active", label: "进行中", empty: "没有进行中的派单" },
  { key: "attention", label: "需介入", empty: "没有需要介入的派单" },
  { key: "review", label: "待验收", empty: "没有待验收的派单" },
  { key: "done", label: "已结束", empty: "还没有已结束的派单" },
  { key: "all", label: "全部", empty: "还没有派单" },
];

export function NewDispatchDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const meta = useMeta();
  const cmd = useCommand();
  const [summary, setSummary] = useState("");
  const [description, setDescription] = useState("");
  const [harness, setHarness] = useState("");
  const [repo, setRepo] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    if (open) {
      setSummary("");
      setDescription("");
      setHarness("");
      setRepo("");
      setErr("");
    }
  }, [open]);
  const busy = cmd.isPending("dispatch.create");
  const submit = async () => {
    if (!summary.trim()) return setErr("请填写要做什么");
    const r = await cmd.run("dispatch.create", {
      summary: summary.trim(),
      description: description.trim() || undefined,
      harness: harness || undefined,
      repo: repo || undefined,
    });
    // 返回新派单 id 时 useCommand 已经跳转到详情页，这里不要再改地址栏
    if (r?.ok && !r.target?.startsWith("dispatch:")) onClose();
  };
  return (
    <Dialog
      open={open}
      title="新建派单"
      onClose={onClose}
      size="lg"
      footer={
        <>
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button className="btn btn-primary" onClick={() => void submit()} disabled={busy}>
            {busy && <Spinner label="创建中" />}
            派出去
          </button>
        </>
      }
    >
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="要做什么" error={err} hint="一句话，会成为飞书任务的标题" htmlFor="nd-summary">
          <input
            id="nd-summary"
            className="input"
            value={summary}
            maxLength={200}
            data-autofocus
            onChange={(e) => (setSummary(e.target.value), setErr(""))}
            placeholder="例如：给登录接口加上限流"
          />
        </Field>
        <Field label="详细说明（可选）" hint="背景、验收标准、注意事项" htmlFor="nd-desc">
          <textarea id="nd-desc" className="input textarea" rows={5} maxLength={5000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <div className="form-row">
          <Field label="执行者" htmlFor="nd-harness">
            <select id="nd-harness" className="input" value={harness} onChange={(e) => setHarness(e.target.value)}>
              <option value="">默认（{meta.roles.default_harness}）</option>
              {meta.harnesses.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          </Field>
          <Field label="仓库" hint={repo ? meta.repos.find((r) => r.alias === repo)?.path : "不指定则不在 git worktree 中执行"} htmlFor="nd-repo">
            <select id="nd-repo" className="input" value={repo} onChange={(e) => setRepo(e.target.value)}>
              <option value="">不指定</option>
              {meta.repos.map((r) => (
                <option key={r.alias} value={r.alias}>
                  {r.alias}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {repo && meta.repos.find((r) => r.alias === repo)?.verify && (
          <p className="muted small">
            完成后会运行校验命令 <code>{meta.repos.find((r) => r.alias === repo)!.verify}</code>
            {meta.roles.reviewer ? `，并由 ${meta.roles.reviewer} 交叉审查` : ""}。
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

export function DispatchesPage() {
  const [sp, setSp] = useSearchParams();
  const filter = (FILTERS.some((f) => f.key === sp.get("filter")) ? sp.get("filter") : "active") as Filter;
  const q = sp.get("q") ?? "";
  const [text, setText] = useState(q);
  useEffect(() => setText(q), [q]);
  useEffect(() => {
    if (text === q) return;
    const t = setTimeout(() => {
      const n = new URLSearchParams(sp);
      if (text.trim()) n.set("q", text.trim());
      else n.delete("q");
      setSp(n, { replace: true });
    }, 300);
    return () => clearTimeout(t);
  }, [text, q, sp, setSp]);

  const params = new URLSearchParams({ filter });
  if (q) params.set("q", q);
  const list = useQuery<DispatchSummary[]>(`/api/dispatches?${params}`, { tags: ["dispatches"] });
  const creating = sp.get("new") === "1";
  const setParam = (k: string, v: string | null) => {
    const n = new URLSearchParams(sp);
    if (v === null) n.delete(k);
    else n.set(k, v);
    setSp(n, { replace: k !== "filter" });
  };
  const f = FILTERS.find((x) => x.key === filter)!;

  return (
    <div className="page">
      <PageHeader
        title="派单"
        subtitle="派给 Agent 的每一件事，从排队、执行到验收与交付"
        actions={
          <button className="btn btn-primary" onClick={() => setParam("new", "1")}>
            ＋ 新建派单
          </button>
        }
      />
      <div className="toolbar">
        <Tabs label="按状态筛选" value={filter} onChange={(k) => setParam("filter", k)} items={FILTERS.map(({ key, label }) => ({ key, label }))} />
        <div className="search">
          <input type="search" className="input" placeholder="搜索标题、任务 ID…" aria-label="搜索派单" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
      </div>
      <div className="card">
        <QueryView q={list}>
          {(items) =>
            items.length ? (
              <ul className="dlist">
                {items.map((d) => (
                  <DispatchRow key={d.id} d={d} showStage />
                ))}
              </ul>
            ) : (
              <Empty title={q ? `没有找到包含「${q}」的派单` : f.empty}>
                {q ? (
                  <button className="btn btn-link" onClick={() => setText("")}>
                    清除搜索
                  </button>
                ) : filter === "active" || filter === "all" ? (
                  <button className="btn btn-link" onClick={() => setParam("new", "1")}>
                    新建派单
                  </button>
                ) : null}
              </Empty>
            )
          }
        </QueryView>
      </div>
      <NewDispatchDialog open={creating} onClose={() => setParam("new", null)} />
    </div>
  );
}
