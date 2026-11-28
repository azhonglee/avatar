import { Link } from "react-router-dom";
import type { Health, HealthItem } from "../api/types.ts";
import { Card, Collapsible, Empty, PageHeader, Pill, Pre, QueryView, RelTime, Spinner } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { absTime, useNow } from "../lib/format.ts";
import { useQuery } from "../lib/query.ts";

const KIND_LABEL: Record<HealthItem["kind"], string> = {
  event: "飞书事件",
  effect: "飞书写入",
  job: "作业",
  delivery: "交付",
  context: "工作上下文",
};
const KIND_HINT: Record<HealthItem["kind"], string> = {
  event: "收到的飞书事件处理失败，相关的消息/评论可能没有被识别。",
  effect: "要写回飞书的评论、移动卡片或私信没有成功。",
  job: "定时作业没有跑完。",
  delivery: "推送分支 / 创建 PR / 合并没有成功。",
  context: "工作上下文采集、快通道理解或起草失败。",
};

function refLink(it: HealthItem) {
  if (it.ref.startsWith("dispatch:"))
    return (
      <Link to={`/dispatches/${encodeURIComponent(it.ref)}`} className="small">
        查看派单
      </Link>
    );
  return null;
}

function FailedItem({ it }: { it: HealthItem }) {
  const cmd = useCommand();
  const kr = `work.retry:${it.id}`;
  const ka = `work.acknowledge:${it.id}`;
  return (
    <li className={`hitem ${it.acknowledged ? "hitem-ack" : ""}`}>
      <div className="row-between">
        <div className="hitem-main">
          <div className="row-gap">
            <Pill tone={it.acknowledged ? "muted" : "danger"}>{KIND_LABEL[it.kind] ?? it.kind}</Pill>
            <strong>{it.summary || it.ref}</strong>
          </div>
          <div className="muted small row-gap">
            <span>{KIND_HINT[it.kind]}</span>
            <span>已尝试 {it.attempts} 次</span>
            <RelTime ts={it.updated} />
            {refLink(it)}
          </div>
        </div>
        {it.isolated ? (
          <Pill tone="muted">已隔离</Pill>
        ) : !it.acknowledged ? (
          <div className="row-gap">
            <button className="btn btn-sm btn-primary" disabled={cmd.isPending(kr)} onClick={() => void cmd.run("work.retry", { id: it.id }, { key: kr, navigate: false })}>
              {cmd.isPending(kr) && <Spinner />}重试
            </button>
            <button className="btn btn-sm" disabled={cmd.isPending(ka)} onClick={() => void cmd.run("work.acknowledge", { id: it.id }, { key: ka, navigate: false })}>
              {cmd.isPending(ka) && <Spinner />}忽略
            </button>
          </div>
        ) : (
          <Pill tone="muted">已忽略</Pill>
        )}
      </div>
      {it.error && (
        <Collapsible summary="最后一次错误" defaultOpen={!it.acknowledged}>
          <Pre className="pre-danger">{it.error}</Pre>
        </Collapsible>
      )}
    </li>
  );
}

function Daemon({ h }: { h: Health }) {
  const now = useNow();
  const hb = h.daemon.last_heartbeat;
  const alive = !!hb && now - hb < 60_000;
  return (
    <Card title="常驻进程">
      <div className="health-line">
        <Pill tone={alive ? "success" : "danger"}>{alive ? "运行中" : hb ? "心跳中断" : "未运行"}</Pill>
        <span className="small">{hb ? <RelTime ts={hb} prefix="最后心跳 " /> : "从未收到心跳"}</span>
      </div>
      {h.daemon.owner && <p className="muted small">进程标识 {h.daemon.owner}</p>}
      {!alive && (
        <p className="small">
          常驻进程负责接收飞书事件、推进派单、写回飞书。在开发机上运行 <code>pa run</code> 启动（建议用 systemd / tmux 常驻）。
        </p>
      )}
    </Card>
  );
}

export function HealthPage() {
  const q = useQuery<Health>("/api/health", { tags: ["health"] });
  return (
    <div className="page">
      <PageHeader title="健康" subtitle="失败与重试中的工作、常驻进程状态、命令守卫的拦截记录" />
      <QueryView q={q}>
        {(h) => {
          const open = h.failed.filter((f) => !f.acknowledged && !f.isolated);
          const acked = h.failed.filter((f) => f.acknowledged && !f.isolated);
          const isolated = h.failed.filter((f) => !!f.isolated);
          return (
            <div className="grid-overview">
              <div className="col-main">
                <Card title={<>失败{open.length > 0 && <span className="count count-danger">{open.length}</span>}</>}>
                  {open.length ? (
                    <ul className="hlist">
                      {open.map((it) => (
                        <FailedItem key={it.id} it={it} />
                      ))}
                    </ul>
                  ) : (
                    <Empty title="最近 14 天没有未处理的失败" icon="✓" />
                  )}
                  {acked.length > 0 && (
                    <Collapsible summary={`已忽略 ${acked.length} 项`}>
                      <ul className="hlist">
                        {acked.map((it) => (
                          <FailedItem key={it.id} it={it} />
                        ))}
                      </ul>
                    </Collapsible>
                  )}
                  {isolated.length > 0 && (
                    <Collapsible summary={`已按旧主人隔离 ${isolated.length} 项`}>
                      <ul className="hlist">
                        {isolated.map((it) => (
                          <FailedItem key={it.id} it={it} />
                        ))}
                      </ul>
                    </Collapsible>
                  )}
                </Card>
                <Card title={<>重试中{h.retrying.length > 0 && <span className="count count-warn">{h.retrying.length}</span>}</>}>
                  {h.retrying.length ? (
                    <ul className="hlist">
                      {h.retrying.map((it) => (
                        <li key={it.id} className="hitem">
                          <div className="row-gap">
                            <Pill tone="warn">{KIND_LABEL[it.kind] ?? it.kind}</Pill>
                            <strong>{it.summary || it.ref}</strong>
                          </div>
                          <div className="muted small row-gap">
                            <span>已尝试 {it.attempts} 次</span>
                            {it.next_at > 0 && <RelTime ts={it.next_at} prefix="下次重试 " />}
                            {refLink(it)}
                          </div>
                          {it.error && <Pre className="pre-danger">{it.error}</Pre>}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty title="没有正在重试的工作" icon="✓" />
                  )}
                </Card>
              </div>
              <div className="col-side">
                <Daemon h={h} />
                <Card title="命令守卫">
                  <p className="muted small">执行者调用 lark-cli 等命令时由守卫按白名单放行或拦截，下面是最近 50 条。</p>
                  {h.guard.length ? (
                    <div className="table-wrap">
                      <table className="table table-compact">
                        <thead>
                          <tr>
                            <th>时间</th>
                            <th>结果</th>
                            <th>命令</th>
                          </tr>
                        </thead>
                        <tbody>
                          {h.guard.map((g, i) => {
                            const t = Date.parse(g.at);
                            return (
                              <tr key={i}>
                                <td className="nowrap">{Number.isFinite(t) ? <RelTime ts={t} /> : g.at}</td>
                                <td>
                                  <Pill tone={g.allow ? "success" : "danger"}>{g.allow ? "放行" : "拦截"}</Pill>
                                </td>
                                <td>
                                  <code className="wrap" title={Number.isFinite(t) ? absTime(t) : g.at}>
                                    {g.argv.join(" ")}
                                  </code>
                                  <div className="muted small">
                                    {g.profile}
                                    {g.reason ? ` · ${g.reason}` : ""}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <Empty title="还没有守卫记录" />
                  )}
                </Card>
              </div>
            </div>
          );
        }}
      </QueryView>
    </div>
  );
}
