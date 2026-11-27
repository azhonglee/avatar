import type { JobView } from "../api/types.ts";
import { Card, Collapsible, Empty, PageHeader, Pill, Pre, QueryView, RelTime, Spinner } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import type { Tone } from "../lib/format.ts";
import { useQuery } from "../lib/query.ts";

const JOB_STATE: Record<string, { label: string; tone: Tone }> = {
  pending: { label: "排队中", tone: "neutral" },
  running: { label: "运行中", tone: "info" },
  done: { label: "成功", tone: "success" },
  errored: { label: "失败", tone: "danger" },
  dead: { label: "失败", tone: "danger" },
  cancelled: { label: "已取消", tone: "muted" },
};

function JobCard({ j }: { j: JobView }) {
  const cmd = useCommand();
  const key = `job.run:${j.name}`;
  const st = j.last ? (JOB_STATE[j.last.state] ?? { label: j.last.state, tone: "neutral" as Tone }) : null;
  return (
    <li className="job">
      <div className="job-head">
        <div>
          <div className="job-name">{j.name}</div>
          <div className="muted small row-gap">
            <span>
              <code>{j.cron}</code>
            </span>
            <span>执行者 {j.harness}</span>
            <span>{j.notify ? "完成后私信你" : "不私信"}</span>
          </div>
        </div>
        <button className="btn btn-sm" disabled={cmd.isPending(key)} onClick={() => void cmd.run("job.run", { name: j.name }, { key, navigate: false })}>
          {cmd.isPending(key) && <Spinner />}立即运行
        </button>
      </div>
      <dl className="kv kv-compact">
        <dt>下次运行</dt>
        <dd>{j.next_run ? <RelTime ts={j.next_run} /> : <span className="muted">无法计算（检查 cron 表达式）</span>}</dd>
        <dt>上次结果</dt>
        <dd>
          {j.last && st ? (
            <span className="row-gap">
              <Pill tone={st.tone}>{st.label}</Pill>
              <RelTime ts={j.last.updated} />
            </span>
          ) : (
            <span className="muted">还没有运行过</span>
          )}
        </dd>
      </dl>
      {j.last?.error && <Pre className="pre-danger">{j.last.error}</Pre>}
      {j.last?.result && (
        <Collapsible summary="查看上次输出">
          <Pre>{j.last.result}</Pre>
        </Collapsible>
      )}
      <Collapsible summary="提示词">
        <Pre>{j.prompt}</Pre>
      </Collapsible>
    </li>
  );
}

export function JobsPage() {
  const q = useQuery<JobView[]>("/api/jobs", { tags: ["jobs"] });
  return (
    <div className="page">
      <PageHeader title="作业" subtitle="按时间表自动运行的 agent 作业（整理知识库、晨报等）" />
      <Card>
        <QueryView q={q}>
          {(jobs) =>
            jobs.length ? (
              <ul className="job-list">
                {jobs.map((j) => (
                  <JobCard key={j.name} j={j} />
                ))}
              </ul>
            ) : (
              <Empty title="没有配置定时作业">
                在配置文件的 <code>jobs</code> 里添加，例如每天整理一次知识库。
              </Empty>
            )
          }
        </QueryView>
      </Card>
    </div>
  );
}
