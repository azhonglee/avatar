import type { DoctorCheck, DoctorReport } from "../api/types.ts";
import { Markdown } from "../components/Markdown.tsx";
import { Bar, Card, PageHeader, Pill, QueryView, Spinner, Unavailable } from "../components/ui.tsx";
import type { Tone } from "../lib/format.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

const STATUS: Record<DoctorCheck["status"], { label: string; tone: Tone; icon: string }> = {
  ok: { label: "通过", tone: "success", icon: "✓" },
  warn: { label: "注意", tone: "warn", icon: "!" },
  fail: { label: "未通过", tone: "danger", icon: "✕" },
  skip: { label: "跳过", tone: "muted", icon: "–" },
};

function Check({ c, n }: { c: DoctorCheck; n: number }) {
  const s = STATUS[c.status];
  const needsFix = c.status === "fail" || c.status === "warn";
  return (
    <li className={`check-step check-${c.status}`}>
      <span className={`check-badge badge-${s.tone}`} aria-hidden>
        {s.icon}
      </span>
      <div className="check-body">
        <div className="row-gap">
          <span className="muted small">第 {n} 步</span>
          <strong>{c.title}</strong>
          <Pill tone={s.tone}>{s.label}</Pill>
        </div>
        {c.detail && <div className="small check-detail">{c.detail}</div>}
        {c.fix && needsFix && (
          <div className="fix">
            <div className="fix-title">怎么修</div>
            <Markdown text={c.fix} />
          </div>
        )}
      </div>
    </li>
  );
}

export function SetupPage() {
  const meta = useMeta();
  const q = useQuery<DoctorReport>(meta.features.doctor ? "/api/doctor" : null, { tags: ["doctor"] });
  return (
    <div className="page">
      <PageHeader
        title="初始化向导"
        subtitle="逐项检查依赖、飞书登录、事件订阅和看板。按提示修好后点「重新检查」。"
        actions={
          meta.features.doctor ? (
            <button className="btn btn-primary" onClick={() => void q.refetch()} disabled={q.loading || q.refreshing}>
              {(q.loading || q.refreshing) && <Spinner label="检查中" />}
              重新检查
            </button>
          ) : undefined
        }
      />
      {!meta.features.doctor ? (
        <Unavailable what="体检" />
      ) : (
        <QueryView q={q} what="体检">
          {(r) => {
            const done = r.checks.filter((c) => c.status === "ok" || c.status === "skip").length;
            const fails = r.checks.filter((c) => c.status === "fail").length;
            return (
              <>
                <Card>
                  <div className="setup-summary">
                    <div className={`setup-icon ${r.ready ? "ok" : "todo"}`} aria-hidden>
                      {r.ready ? "✓" : `${done}/${r.checks.length}`}
                    </div>
                    <div className="setup-text">
                      <strong>{r.ready ? "一切就绪" : fails ? `还有 ${fails} 项没有通过` : "基本就绪，有几项需要注意"}</strong>
                      <span className="muted small">{r.ready ? "常驻进程可以正常收事件、派单和写回飞书了。" : "修好之后点右上角的「重新检查」。"}</span>
                      <Bar value={done} max={r.checks.length || 1} tone={r.ready ? "success" : "info"} label="检查通过进度" />
                    </div>
                  </div>
                </Card>
                <Card title="检查项">
                  <ol className="check-steps" aria-busy={q.refreshing}>
                    {r.checks.map((c, i) => (
                      <Check key={c.id} c={c} n={i + 1} />
                    ))}
                  </ol>
                </Card>
              </>
            );
          }}
        </QueryView>
      )}
    </div>
  );
}
