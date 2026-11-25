import { useState } from "react";
import type { CommandName, DispatchDetail } from "../api/types.ts";
import { useCommand } from "../lib/command.ts";
import { useMeta } from "../lib/meta.ts";
import { ConfirmDialog, Dialog, Field, Spinner } from "./ui.tsx";

export const ACTION_LABEL: Record<CommandName, string> = {
  "dispatch.create": "新建派单",
  "dispatch.cancel": "取消派单",
  "dispatch.retry": "重试",
  "dispatch.rework": "带意见返工",
  "dispatch.switch_harness": "换执行者",
  "delivery.create_pr": "创建 PR",
  "delivery.merge_local": "合并到本地分支",
  "delivery.discard": "放弃",
  "delivery.restore": "恢复",
  "candidate.confirm": "是任务",
  "candidate.reject": "不是任务",
  "candidate.dispatch": "派给 Agent",
  "work.retry": "重试",
  "work.acknowledge": "忽略",
  "job.run": "立即运行",
  "context.refresh": "立即刷新",
  "context.item_done": "完成",
  "context.item_reopen": "重新打开",
  "context.item_snooze": "稍后提醒",
  "context.item_delegate": "交给 Agent",
  "context.feedback": "反馈",
  "context.project_mute": "静音项目",
  "context.conv_mute": "静音会话",
  "context.conflict_resolve": "确认结论",
  "context.draft_create": "起草",
  "context.draft_approve": "确认发送",
  "context.draft_discard": "丢弃草稿",
  "context.weekly_report": "起草周报",
};

const PRIMARY = new Set<string>(["delivery.create_pr", "dispatch.rework"]);
const DANGER = new Set<string>(["dispatch.cancel", "delivery.discard"]);

type ActionTarget = Pick<DispatchDetail, "id" | "summary" | "harness" | "actions" | "branch" | "repo">;

/**
 * 派单操作栏：只渲染后端给出的 actions（顺序也按后端）。
 * 有后果的操作（取消、合并、放弃）先弹确认说明后果；需要参数的（返工、换执行者、创建 PR）弹表单。
 */
export function ActionBar({ d, size }: { d: ActionTarget; size?: "sm" }) {
  const meta = useMeta();
  const cmd = useCommand();
  const [open, setOpen] = useState<CommandName | null>(null);
  const [feedback, setFeedback] = useState("");
  const [harness, setHarness] = useState("");
  const [prTitle, setPrTitle] = useState("");
  const [draft, setDraft] = useState(false);
  const [target, setTarget] = useState("");
  const [err, setErr] = useState("");

  if (!d.actions.length) return null;
  const key = (n: CommandName) => `${n}:${d.id}`;
  const busy = (n: CommandName) => cmd.isPending(key(n));
  const close = () => {
    setOpen(null);
    setErr("");
  };
  const exec = async (n: CommandName, args: Record<string, unknown>) => {
    const r = await cmd.run(n, { id: d.id, ...args } as never, { key: key(n) });
    if (r?.ok) close();
  };

  const click = (n: CommandName) => {
    switch (n) {
      case "dispatch.retry":
      case "delivery.restore":
        return void exec(n, {});
      case "dispatch.rework":
        setFeedback("");
        break;
      case "dispatch.switch_harness":
        setHarness(meta.harnesses.find((h) => h !== d.harness) ?? "");
        break;
      case "delivery.create_pr":
        setPrTitle(d.summary);
        setDraft(false);
        break;
      case "delivery.merge_local":
        setTarget("");
        break;
      default:
        if (!(n in ACTION_LABEL)) return void exec(n, {});
    }
    setOpen(n);
  };

  const others = meta.harnesses.filter((h) => h !== d.harness);
  const branch = d.branch ? <code>{d.branch}</code> : "派单分支";

  return (
    <div className={`action-bar ${size === "sm" ? "action-bar-sm" : ""}`} role="group" aria-label="派单操作">
      {d.actions.map((n) => (
        <button
          key={n}
          className={`btn ${size === "sm" ? "btn-sm" : ""} ${PRIMARY.has(n) ? "btn-primary" : ""} ${DANGER.has(n) ? "btn-danger-ghost" : ""}`}
          disabled={busy(n)}
          aria-busy={busy(n)}
          onClick={() => click(n)}
          data-action={n}
        >
          {busy(n) && <Spinner label="执行中" />}
          {ACTION_LABEL[n] ?? n}
        </button>
      ))}

      <ConfirmDialog
        open={open === "dispatch.cancel"}
        title="取消这次派单？"
        confirmLabel="取消派单"
        busy={busy("dispatch.cancel")}
        onClose={close}
        onConfirm={() => void exec("dispatch.cancel", {})}
      >
        <p>会结束正在执行的进程，这一轮不会再继续。</p>
        <p className="muted">已经产生的改动会保留在 worktree 里，之后可以「重试」或「带意见返工」。</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={open === "delivery.merge_local"}
        title="合并到本地分支？"
        confirmLabel="确认合并"
        busy={busy("delivery.merge_local")}
        onClose={close}
        onConfirm={() => void exec("delivery.merge_local", target.trim() ? { target_branch: target.trim() } : {})}
      >
        <p>
          会把 {branch} 合并进{d.repo ? <>仓库 <code>{d.repo}</code> 的</> : ""}目标分支。
          <strong>合并会直接改动你的本地仓库，不能自动撤销</strong>（需要的话可以用 git 手动回退）。
        </p>
        <p className="muted">不会推送到远端。合并完成后这次派单的 worktree 会被清理。</p>
        <Field label="目标分支（可选）" hint="留空则用仓库配置的目标分支或当前分支" htmlFor={`mt-${d.id}`}>
          <input id={`mt-${d.id}`} className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="例如 main" />
        </Field>
      </ConfirmDialog>

      <ConfirmDialog
        open={open === "delivery.discard"}
        title="放弃这次结果？"
        confirmLabel="放弃"
        busy={busy("delivery.discard")}
        onClose={close}
        onConfirm={() => void exec("delivery.discard", {})}
      >
        <p>这次派单的改动不会被采纳；如果已经创建了 PR，PR 不会被自动关闭。</p>
        <p className="muted">worktree 和 {branch} 会保留一段时间（默认 7 天），期间可以在这里点「恢复」找回；之后自动清理。</p>
      </ConfirmDialog>

      <Dialog
        open={open === "dispatch.rework"}
        title="带意见返工"
        onClose={close}
        size="lg"
        footer={
          <>
            <button className="btn" onClick={close}>
              取消
            </button>
            <button
              className="btn btn-primary"
              disabled={busy("dispatch.rework")}
              onClick={() => {
                if (!feedback.trim()) return setErr("请写下返工意见");
                void exec("dispatch.rework", { feedback: feedback.trim() });
              }}
            >
              {busy("dispatch.rework") && <Spinner label="执行中" />}
              提交并返工
            </button>
          </>
        }
      >
        <p className="muted">意见会作为下一轮的反馈交给执行者{d.harness ? <>（{d.harness}）</> : ""}，在原 worktree 基础上继续改。</p>
        <Field label="返工意见" error={err} htmlFor={`fb-${d.id}`}>
          <textarea
            id={`fb-${d.id}`}
            className="input textarea"
            rows={6}
            maxLength={5000}
            value={feedback}
            data-autofocus
            onChange={(e) => (setFeedback(e.target.value), setErr(""))}
            placeholder="例如：补上单元测试；不要改动公共接口的签名"
          />
        </Field>
      </Dialog>

      <Dialog
        open={open === "dispatch.switch_harness"}
        title="换执行者重试"
        onClose={close}
        footer={
          <>
            <button className="btn" onClick={close}>
              取消
            </button>
            <button className="btn btn-primary" disabled={!harness || busy("dispatch.switch_harness")} onClick={() => void exec("dispatch.switch_harness", { harness })}>
              {busy("dispatch.switch_harness") && <Spinner label="执行中" />}
              改由 {harness || "…"} 执行
            </button>
          </>
        }
      >
        {others.length ? (
          <Field label="新的执行者" hint={d.harness ? `当前是 ${d.harness}` : undefined} htmlFor={`hs-${d.id}`}>
            <select id={`hs-${d.id}`} className="input" value={harness} onChange={(e) => setHarness(e.target.value)} data-autofocus>
              {others.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          </Field>
        ) : (
          <p>没有其他可用的执行者。可以在设置里添加。</p>
        )}
      </Dialog>

      <Dialog
        open={open === "delivery.create_pr"}
        title="创建 PR"
        onClose={close}
        footer={
          <>
            <button className="btn" onClick={close}>
              取消
            </button>
            <button className="btn btn-primary" disabled={busy("delivery.create_pr")} onClick={() => void exec("delivery.create_pr", { title: prTitle.trim() || undefined, draft })}>
              {busy("delivery.create_pr") && <Spinner label="执行中" />}
              推送并创建
            </button>
          </>
        }
      >
        <p className="muted">会把 {branch} 推送到远端，并在{d.repo ? <>仓库 <code>{d.repo}</code> 配置的</> : "配置的"}代码平台上创建 PR / MR。</p>
        <Field label="标题" htmlFor={`pt-${d.id}`}>
          <input id={`pt-${d.id}`} className="input" value={prTitle} onChange={(e) => setPrTitle(e.target.value)} maxLength={200} data-autofocus />
        </Field>
        <label className="check">
          <input type="checkbox" checked={draft} onChange={(e) => setDraft(e.target.checked)} />
          创建为草稿（Draft）
        </label>
      </Dialog>
    </div>
  );
}
