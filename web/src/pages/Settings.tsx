import { createContext, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { errorMessage, request } from "../api/client.ts";
import type { SettingsUpdateResult, SettingsView } from "../api/types.ts";
import { Card, Empty, PageHeader, Pill, QueryView, Spinner, Unavailable } from "../components/ui.tsx";
import { useMeta } from "../lib/meta.ts";
import { invalidate, useQuery } from "../lib/query.ts";
import { useToast } from "../lib/toast.tsx";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Obj = Record<string, any>;

/** 可编辑的顶层配置段（只把改动过的段整段发回去）。 */
const EDITABLE = ["context", "roles", "dispatch", "acceptance", "budget", "notify", "schedules", "delivery"] as const;

export function getIn(o: unknown, path: string): any {
  return path.split(".").reduce<any>((v, k) => (v && typeof v === "object" ? v[k] : undefined), o);
}

export function setIn(o: Obj, path: string, value: unknown): Obj {
  const [k, ...rest] = path.split(".");
  const cur = o && typeof o === "object" ? o : {};
  if (!rest.length) {
    const n = { ...cur };
    if (value === undefined) delete n[k];
    else n[k] = value;
    return n;
  }
  return { ...cur, [k]: setIn(cur[k] ?? {}, rest.join("."), value) };
}

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v ?? {}));
const isPlainObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * 计算两份配置段的增量补丁，与后端 SettingsService 的补丁语义对齐：
 * 未变化的键省略，被删除的键写 null（如删除仓库别名 / 交付平台 / 可选字段）。
 */
export function diffPatch(before: unknown, after: unknown): unknown {
  if (JSON.stringify(before) === JSON.stringify(after)) return undefined;
  if (isPlainObj(before) && isPlainObj(after)) {
    const out: Obj = {};
    for (const k of new Set([...Object.keys(before), ...Object.keys(after)])) {
      if (!(k in after)) out[k] = null;
      else if (!(k in before)) out[k] = after[k];
      else {
        const d = diffPatch(before[k], after[k]);
        if (d !== undefined) out[k] = d;
      }
    }
    return Object.keys(out).length ? out : undefined;
  }
  return after === undefined ? null : after;
}

interface FormApi {
  draft: Obj;
  set(path: string, v: unknown): void;
  error(path: string): string | undefined;
}
const Form = createContext<FormApi>({ draft: {}, set: () => undefined, error: () => undefined });

function FieldShell({ label, hint, path, children, id }: { label: string; hint?: ReactNode; path: string; children: ReactNode; id: string }) {
  const { error } = useContext(Form);
  const e = error(path);
  return (
    <div className={`field ${e ? "field-invalid" : ""}`} data-path={path}>
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      {children}
      {e ? (
        <div className="field-error" role="alert" id={`${id}-err`}>
          {e}
        </div>
      ) : hint ? (
        <div className="field-hint">{hint}</div>
      ) : null}
    </div>
  );
}

function Text({ path, label, hint, placeholder, type = "text" }: { path: string; label: string; hint?: ReactNode; placeholder?: string; type?: string }) {
  const f = useContext(Form);
  const id = useId();
  const v = getIn(f.draft, path);
  return (
    <FieldShell label={label} hint={hint} path={path} id={id}>
      <input
        id={id}
        type={type}
        className="input"
        value={v ?? ""}
        placeholder={placeholder}
        aria-invalid={!!f.error(path)}
        aria-describedby={f.error(path) ? `${id}-err` : undefined}
        onChange={(e) => f.set(path, e.target.value)}
      />
    </FieldShell>
  );
}

function Num({ path, label, hint, min, step = 1, suffix }: { path: string; label: string; hint?: ReactNode; min?: number; step?: number; suffix?: string }) {
  const f = useContext(Form);
  const id = useId();
  const v = getIn(f.draft, path);
  return (
    <FieldShell label={label} hint={hint} path={path} id={id}>
      <div className="input-group">
        <input
          id={id}
          type="number"
          inputMode="decimal"
          className="input"
          value={v ?? ""}
          min={min}
          step={step}
          aria-invalid={!!f.error(path)}
          onChange={(e) => f.set(path, e.target.value === "" ? undefined : Number(e.target.value))}
        />
        {suffix && <span className="input-suffix">{suffix}</span>}
      </div>
    </FieldShell>
  );
}

function Select({ path, label, hint, options }: { path: string; label: string; hint?: ReactNode; options: { value: string; label: string }[] }) {
  const f = useContext(Form);
  const id = useId();
  const v = getIn(f.draft, path) ?? "";
  const opts = options.some((o) => o.value === v) ? options : [...options, { value: v, label: `${v}（未定义）` }];
  return (
    <FieldShell label={label} hint={hint} path={path} id={id}>
      <select id={id} className="input" value={v} aria-invalid={!!f.error(path)} onChange={(e) => f.set(path, e.target.value)}>
        {opts.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </FieldShell>
  );
}

function Toggle({ path, label, hint }: { path: string; label: string; hint?: string }) {
  const f = useContext(Form);
  const v = !!getIn(f.draft, path);
  const e = f.error(path);
  return (
    <div className={`toggle-row ${e ? "field-invalid" : ""}`} data-path={path}>
      <label className="switch">
        <input type="checkbox" role="switch" checked={v} onChange={(ev) => f.set(path, ev.target.checked)} />
        <span className="switch-track" aria-hidden>
          <span className="switch-thumb" />
        </span>
        <span>
          <span className="toggle-label">{label}</span>
          {hint && <span className="field-hint">{hint}</span>}
        </span>
      </label>
      {e && (
        <div className="field-error" role="alert">
          {e}
        </div>
      )}
    </div>
  );
}

function Section({ id, title, keys, hot, children, desc, dirty }: { id: string; title: string; keys: string[]; hot: Record<string, boolean>; children: ReactNode; desc?: string; dirty: boolean }) {
  const known = keys.filter((k) => k in hot);
  const allHot = known.length > 0 && known.every((k) => hot[k]);
  const anyCold = known.some((k) => hot[k] === false);
  return (
    <Card
      id={id}
      className="settings-section"
      title={
        <>
          {title}
          {dirty && (
            <span className="dirty-dot" title="有未保存的修改">
              ●<span className="sr-only">有未保存的修改</span>
            </span>
          )}
        </>
      }
      actions={anyCold ? <Pill tone="warn">保存后需重启常驻进程</Pill> : allHot ? <Pill tone="success">保存即生效</Pill> : undefined}
    >
      {desc && <p className="muted small section-desc">{desc}</p>}
      {children}
    </Card>
  );
}

interface RepoRow {
  key: number;
  alias: string;
  path: string;
  verify: string;
  provider: string;
  target_branch: string;
}

function ReposEditor({ onInvalid }: { onInvalid: (msg: string) => void }) {
  const f = useContext(Form);
  const providers = Object.keys(getIn(f.draft, "delivery.providers") ?? {});
  const seq = useRef(0);
  const [rows, setRows] = useState<RepoRow[]>(() =>
    Object.entries((getIn(f.draft, "dispatch.repos") ?? {}) as Obj).map(([alias, v]) => {
      const o = typeof v === "string" ? { path: v } : (v ?? {});
      return { key: seq.current++, alias, path: o.path ?? "", verify: o.verify ?? "", provider: o.provider ?? "", target_branch: o.target_branch ?? "" };
    }),
  );
  const write = (next: RepoRow[]) => {
    setRows(next);
    const aliases = next.map((r) => r.alias.trim());
    const dup = aliases.find((a, i) => a && aliases.indexOf(a) !== i);
    const empty = next.some((r) => !r.alias.trim() || !r.path.trim());
    onInvalid(dup ? `仓库别名「${dup}」重复了` : empty ? "每个仓库都需要填写别名和路径" : "");
    if (dup || empty) return;
    const obj: Obj = {};
    for (const r of next) {
      const v: Obj = { path: r.path.trim() };
      if (r.verify.trim()) v.verify = r.verify.trim();
      if (r.provider) v.provider = r.provider;
      if (r.target_branch.trim()) v.target_branch = r.target_branch.trim();
      obj[r.alias.trim()] = v;
    }
    f.set("dispatch.repos", obj);
  };
  const upd = (key: number, patch: Partial<RepoRow>) => write(rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  return (
    <div className="rows-editor">
      {rows.length === 0 && <Empty title="还没有配置仓库">添加后，派单时选择仓库即可在它的 git worktree 中执行，并自动运行校验命令。</Empty>}
      {rows.map((r) => {
        const base = `dispatch.repos.${r.alias.trim()}`;
        const e = (k: string) => f.error(`${base}.${k}`) ?? (k === "path" ? f.error(base) : undefined);
        return (
          <fieldset key={r.key} className="row-card">
            <legend className="sr-only">仓库 {r.alias}</legend>
            <div className="form-grid">
              <label className="field">
                <span className="field-label">别名</span>
                <input className="input" value={r.alias} onChange={(ev) => upd(r.key, { alias: ev.target.value })} placeholder="web" />
              </label>
              <label className={`field field-wide ${e("path") ? "field-invalid" : ""}`}>
                <span className="field-label">本地路径</span>
                <input className="input" value={r.path} onChange={(ev) => upd(r.key, { path: ev.target.value })} placeholder="~/code/web" />
                {e("path") && <span className="field-error">{e("path")}</span>}
              </label>
              <label className={`field field-wide ${e("verify") ? "field-invalid" : ""}`}>
                <span className="field-label">校验命令</span>
                <input className="input mono" value={r.verify} onChange={(ev) => upd(r.key, { verify: ev.target.value })} placeholder="npm test" />
                {e("verify") ? <span className="field-error">{e("verify")}</span> : <span className="field-hint">在 worktree 里运行，失败即打回返工</span>}
              </label>
              <label className={`field ${e("provider") ? "field-invalid" : ""}`}>
                <span className="field-label">代码平台</span>
                <select className="input" value={r.provider} onChange={(ev) => upd(r.key, { provider: ev.target.value })}>
                  <option value="">默认</option>
                  {providers.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                  {r.provider && !providers.includes(r.provider) && <option value={r.provider}>{r.provider}（未定义）</option>}
                </select>
                {e("provider") && <span className="field-error">{e("provider")}</span>}
              </label>
              <label className="field">
                <span className="field-label">目标分支</span>
                <input className="input" value={r.target_branch} onChange={(ev) => upd(r.key, { target_branch: ev.target.value })} placeholder="默认分支" />
              </label>
            </div>
            <button className="btn btn-sm btn-danger-ghost" onClick={() => write(rows.filter((x) => x.key !== r.key))} aria-label={`删除仓库 ${r.alias || "（未命名）"}`}>
              删除
            </button>
          </fieldset>
        );
      })}
      <button className="btn btn-sm" onClick={() => write([...rows, { key: seq.current++, alias: "", path: "", verify: "", provider: "", target_branch: "" }])}>
        ＋ 添加仓库
      </button>
    </div>
  );
}

interface ProviderRow {
  key: number;
  name: string;
  type: string;
  base_url: string;
  token_env: string;
  remote: string;
}

function ProvidersEditor({ onInvalid }: { onInvalid: (msg: string) => void }) {
  const f = useContext(Form);
  const seq = useRef(0);
  const [rows, setRows] = useState<ProviderRow[]>(() =>
    Object.entries((getIn(f.draft, "delivery.providers") ?? {}) as Obj).map(([name, v]) => ({
      key: seq.current++,
      name,
      type: v?.type ?? "github",
      base_url: v?.base_url ?? "",
      token_env: v?.token_env ?? "",
      remote: v?.remote ?? "origin",
    })),
  );
  const write = (next: ProviderRow[]) => {
    setRows(next);
    const names = next.map((r) => r.name.trim());
    const dup = names.find((a, i) => a && names.indexOf(a) !== i);
    const empty = next.some((r) => !r.name.trim());
    onInvalid(dup ? `代码平台名称「${dup}」重复了` : empty ? "每个代码平台都需要一个名称" : "");
    if (dup || empty) return;
    const obj: Obj = {};
    for (const r of next) {
      const v: Obj = { type: r.type, remote: r.remote.trim() || "origin" };
      if (r.base_url.trim()) v.base_url = r.base_url.trim();
      if (r.token_env.trim()) v.token_env = r.token_env.trim();
      obj[r.name.trim()] = v;
    }
    f.set("delivery.providers", obj);
  };
  const upd = (key: number, patch: Partial<ProviderRow>) => write(rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  return (
    <div className="rows-editor">
      {rows.length === 0 && <p className="muted small">还没有配置代码平台。不配置也可以「合并到本地分支」，但不能一键创建 PR。</p>}
      {rows.map((r) => {
        const base = `delivery.providers.${r.name.trim()}`;
        const e = (k: string) => f.error(`${base}.${k}`);
        return (
          <fieldset key={r.key} className="row-card">
            <legend className="sr-only">代码平台 {r.name}</legend>
            <div className="form-grid">
              <label className="field">
                <span className="field-label">名称</span>
                <input className="input" value={r.name} onChange={(ev) => upd(r.key, { name: ev.target.value })} placeholder="github" />
              </label>
              <label className={`field ${e("type") ? "field-invalid" : ""}`}>
                <span className="field-label">类型</span>
                <select className="input" value={r.type} onChange={(ev) => upd(r.key, { type: ev.target.value })}>
                  <option value="github">GitHub</option>
                  <option value="gitlab">GitLab</option>
                  <option value="codebase">Codebase</option>
                </select>
                {e("type") && <span className="field-error">{e("type")}</span>}
              </label>
              <label className={`field field-wide ${e("base_url") ? "field-invalid" : ""}`}>
                <span className="field-label">地址</span>
                <input className="input" value={r.base_url} onChange={(ev) => upd(r.key, { base_url: ev.target.value })} placeholder={r.type === "github" ? "https://api.github.com" : "https://gitlab.example.com"} />
                {e("base_url") && <span className="field-error">{e("base_url")}</span>}
              </label>
              <label className={`field ${e("token_env") ? "field-invalid" : ""}`}>
                <span className="field-label">令牌环境变量</span>
                <input className="input mono" value={r.token_env} onChange={(ev) => upd(r.key, { token_env: ev.target.value })} placeholder={r.type === "codebase" ? "不需要" : "GITHUB_TOKEN"} />
                {e("token_env") ? <span className="field-error">{e("token_env")}</span> : <span className="field-hint">只填变量名，不要填令牌本身</span>}
              </label>
              <label className="field">
                <span className="field-label">git remote</span>
                <input className="input" value={r.remote} onChange={(ev) => upd(r.key, { remote: ev.target.value })} />
              </label>
            </div>
            <button className="btn btn-sm btn-danger-ghost" onClick={() => write(rows.filter((x) => x.key !== r.key))} aria-label={`删除代码平台 ${r.name || "（未命名）"}`}>
              删除
            </button>
          </fieldset>
        );
      })}
      <button className="btn btn-sm" onClick={() => write([...rows, { key: seq.current++, name: "", type: "github", base_url: "", token_env: "", remote: "origin" }])}>
        ＋ 添加代码平台
      </button>
    </div>
  );
}

const NOTIFY_TYPES: { key: string; label: string; hint: string }[] = [
  { key: "candidate", label: "候选任务", hint: "识别出可能要你做的事" },
  { key: "progress", label: "派单进度", hint: "开始执行、进入验收等阶段变化" },
  { key: "result", label: "验收结果", hint: "通过 / 需介入 / 出错" },
  { key: "failure", label: "失败告警", hint: "事件或飞书写入重试耗尽、作业中断" },
  { key: "brief", label: "晨报 / 晚报", hint: "每天的分区摘要（启用工作上下文时为晨间卡 / 收尾卡）" },
  { key: "nudge", label: "实时提醒", hint: "新出现的紧急请求、风险、快到期的承诺" },
];

const SCHEDULES: { key: string; label: string; hint: string }[] = [
  { key: "capture", label: "收集候选任务", hint: "扫描消息与评论（兜底，事件长连接会实时触发）" },
  { key: "dispatch", label: "对账派单", hint: "检查看板上「派给Agent」的卡片" },
  { key: "brief_morning", label: "晨报", hint: "工作日早上" },
  { key: "brief_evening", label: "晚报", hint: "工作日傍晚" },
];

const PATH_LABEL: Record<string, string> = {
  context: "工作上下文",
  roles: "执行者",
  dispatch: "派单",
  acceptance: "验收",
  budget: "预算",
  notify: "通知",
  schedules: "时间表",
  delivery: "交付",
};

export function SettingsForm({ view, onSaved }: { view: SettingsView; onSaved: () => void }) {
  const toast = useToast();
  const [draft, setDraft] = useState<Obj>(() => clone(view.config));
  const [errors, setErrors] = useState<SettingsUpdateResult["errors"]>([]);
  const [restart, setRestart] = useState(view.restart_required);
  const [saving, setSaving] = useState(false);
  const [version, setVersion] = useState(0);
  const [invalid, setInvalid] = useState<Record<string, string>>({});
  const loc = useLocation();

  const dirty = useMemo(() => EDITABLE.filter((k) => JSON.stringify(draft[k] ?? null) !== JSON.stringify(view.config[k] ?? null)), [draft, view.config]);
  // 服务端配置变了（保存成功或别处修改）且本地没有未保存的修改：同步
  const cfgKey = JSON.stringify(view.config);
  const lastCfg = useRef(cfgKey);
  useEffect(() => {
    if (cfgKey === lastCfg.current) return;
    lastCfg.current = cfgKey;
    if (!dirty.length) {
      setDraft(clone(view.config));
      setVersion((v) => v + 1);
    }
  }, [cfgKey, dirty.length, view.config]);
  useEffect(() => setRestart((r) => r || view.restart_required), [view.restart_required]);
  useEffect(() => {
    if (loc.hash) document.getElementById(loc.hash.slice(1))?.scrollIntoView?.({ block: "start" });
  }, [loc.hash]);

  const api: FormApi = useMemo(
    () => ({
      draft,
      set: (p, v) => setDraft((d) => setIn(d, p, v)),
      error: (p) => errors.find((e) => e.path === p)?.message,
    }),
    [draft, errors],
  );

  const localErr = Object.values(invalid).filter(Boolean);
  const save = async () => {
    if (!dirty.length || localErr.length) return;
    setSaving(true);
    try {
      const patch: Obj = {};
      for (const k of dirty) {
        const d = diffPatch(view.config[k], draft[k]);
        if (d !== undefined) patch[k] = d;
      }
      const r = await request<SettingsUpdateResult>("/api/settings", { method: "PUT", body: patch, accept: [400] });
      if (r?.ok) {
        setErrors([]);
        if (r.restart_required) setRestart(true);
        toast.push("success", r.restart_required ? "已保存。部分修改需要重启常驻进程才能生效" : "已保存，已经生效");
        invalidate(["meta", "settings"]);
        onSaved();
      } else {
        const errs = r?.errors ?? [];
        setErrors(errs);
        toast.push("error", errs.length ? `有 ${errs.length} 处需要修改` : "保存失败");
      }
    } catch (e) {
      toast.push("error", errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  const discard = () => {
    setDraft(clone(view.config));
    setErrors([]);
    setInvalid({});
    setVersion((v) => v + 1);
  };

  const harnesses = Object.entries((draft.harnesses ?? {}) as Obj);
  const hNames = harnesses.map(([n]) => n);
  const hOpts = hNames.map((h) => ({ value: h, label: h }));
  const providers = Object.keys(getIn(draft, "delivery.providers") ?? {});
  const pricing = Object.entries((getIn(draft, "budget.pricing") ?? {}) as Obj);
  const hot = view.hot_reload;
  const isDirty = (...ks: string[]) => ks.some((k) => (dirty as readonly string[]).includes(k));
  const labelOf = (p: string) => {
    const [top] = p.split(".");
    return `${PATH_LABEL[top] ?? top} · ${p}`;
  };

  return (
    <Form.Provider value={api}>
      {restart && (
        <div className="banner banner-warn" role="status">
          <span className="banner-icon" aria-hidden>
            ↻
          </span>
          <div className="banner-text">
            <strong>需要重启常驻进程</strong>
            <span>
              有些修改要重启后才生效。在开发机上重启 <code>pa run</code>（例如 <code>systemctl --user restart personal-agent</code>）。
            </span>
          </div>
        </div>
      )}
      {errors.length > 0 && (
        <div className="banner banner-danger" role="alert">
          <span className="banner-icon" aria-hidden>
            !
          </span>
          <div className="banner-text">
            <strong>没有保存：有 {errors.length} 处需要修改</strong>
            <ul className="error-list">
              {errors.map((e, i) => (
                <li key={i}>
                  <code>{labelOf(e.path)}</code>：{e.message}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      <p className="muted small">
        配置文件 <code>{view.file}</code>。敏感值不会显示在这里。
      </p>

      <div className="settings" key={version}>
        <Section
          id="harness"
          title="执行者"
          keys={["roles", "dispatch"]}
          hot={hot}
          dirty={isDirty("roles") || getIn(draft, "dispatch.default_harness") !== getIn(view.config, "dispatch.default_harness")}
          desc="执行者（harness）在配置文件中定义；这里选择各角色用哪个。"
        >
          {harnesses.length ? (
            <div className="table-wrap">
              <table className="table table-compact">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>Agent / 启动命令</th>
                    <th>模型</th>
                  </tr>
                </thead>
                <tbody>
                  {harnesses.map(([name, h]) => (
                    <tr key={name}>
                      <td>
                        <strong>{name}</strong>
                      </td>
                      <td>
                        <code className="wrap">{h?.agent ?? h?.agentCommand ?? "—"}</code>
                      </td>
                      <td>{h?.model ?? <span className="muted">默认</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">没有定义执行者。</p>
          )}
          <div className="form-grid">
            <Select path="roles.brain" label="大脑" hint="分诊、私聊对话、知识库整理" options={hOpts} />
            <Select path="roles.reviewer" label="审查者" hint="派单结果的交叉审查" options={[{ value: "", label: "不审查" }, ...hOpts]} />
            <Select path="dispatch.default_harness" label="默认执行者" hint="派单没指定时用谁" options={[{ value: "", label: "同大脑" }, ...hOpts]} />
          </div>
        </Section>

        <Section id="dispatch" title="派单与仓库" keys={["dispatch"]} hot={hot} dirty={isDirty("dispatch")}>
          <div className="form-grid">
            <Num path="dispatch.max_parallel" label="最多同时执行" min={1} suffix="个" />
            <Num path="dispatch.timeout_sec" label="单步超时" min={60} suffix="秒" />
            <Num path="dispatch.fix_rounds" label="自动返工轮数" min={0} suffix="轮" hint="验收没通过时自动打回几次" />
            <Num path="dispatch.max_attempts" label="每阶段最多尝试" min={1} suffix="次" hint="含进程崩溃中断" />
          </div>
          <h3 className="group-title">仓库</h3>
          <ReposEditor key={`repos-${version}`} onInvalid={(m) => setInvalid((x) => ({ ...x, repos: m }))} />
          {invalid.repos && <div className="field-error">{invalid.repos}</div>}
        </Section>

        <Section id="acceptance" title="验收" keys={["acceptance"]} hot={hot} dirty={isDirty("acceptance")} desc="派单“完成”由验收关卡定义，而不是执行者自己说做完了。">
          <div className="form-grid">
            <Select
              path="acceptance.on_unverified"
              label="没有任何校验手段时"
              hint="没有审查者、仓库也没有校验命令"
              options={[
                { value: "needs_human", label: "进「需人工介入」" },
                { value: "review", label: "标为未验证，进「待验收」" },
              ]}
            />
            <Num path="acceptance.review_retries" label="审查故障重试" min={0} suffix="次" />
            <Num path="acceptance.review_timeout_sec" label="审查超时" min={60} suffix="秒" />
            <Num path="acceptance.verify_timeout_sec" label="校验命令超时" min={10} suffix="秒" />
          </div>
        </Section>

        <Section id="budget" title="预算" keys={["budget"]} hot={hot} dirty={isDirty("budget")} desc="0 表示不限制。超出后新的派单会暂停并通知你。">
          <div className="form-grid">
            <Num path="budget.daily_usd" label="每日预算" min={0} step={0.5} suffix="美元" />
            <Num path="budget.per_task_usd" label="单个派单上限" min={0} step={0.5} suffix="美元" />
          </div>
          {pricing.length > 0 ? (
            <div className="table-wrap">
              <table className="table table-compact">
                <caption className="muted small">单价（每百万 token，美元；在配置文件中修改）</caption>
                <thead>
                  <tr>
                    <th>执行者</th>
                    <th className="num">输入</th>
                    <th className="num">输出</th>
                  </tr>
                </thead>
                <tbody>
                  {pricing.map(([h, p]) => (
                    <tr key={h}>
                      <td>{h}</td>
                      <td className="num">{p?.input}</td>
                      <td className="num">{p?.output}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted small">没有配置单价，只记录耗时。</p>
          )}
        </Section>

        {!!view.config.context && (
          <Section id="context" title="工作上下文" keys={["context"]} hot={hot} dirty={isDirty("context")} desc="从 Meego、飞书消息、妙记、日历和飞书任务里识别你的项目、事项、知识和动态。对外可见的动作永远需要你确认。">
            <div className="toggles">
              <Toggle path="context.understand" label="理解消息内容" hint="把采集到的消息交给模型抽取事项；关闭后只采集 Meego 与飞书任务" />
              <Toggle path="context.nudge" label="实时提醒" hint="新出现的紧急请求 / 风险立刻发卡片" />
            </div>
            <h3 className="group-title">来源</h3>
            <div className="toggles">
              <Toggle path="context.sources.meego" label="Meego 待办" />
              <Toggle path="context.sources.im" label="飞书消息" hint="@我、私聊、我发言过的群" />
              <Toggle path="context.sources.minutes" label="妙记" />
              <Toggle path="context.sources.calendar" label="日历" />
              <Toggle path="context.sources.tasks" label="飞书任务" />
              <Toggle path="context.sources.docs" label="文档评论 @我" hint="需开启事件 drive.notice.comment_add_v1" />
            </div>
            <div className="form-grid">
              <Select path="context.harness" label="理解用的执行者" options={[{ value: "", label: "跟随「大脑」" }, ...Object.keys(view.config.harnesses ?? {}).map((h) => ({ value: h, label: h }))]} />
              <Select
                path="context.groups"
                label="群消息范围"
                options={[
                  { value: "spoken", label: "我发言过的群" },
                  { value: "allowlist", label: "只看白名单里的群" },
                ]}
              />
              <Num path="context.max_groups" label="最多读几个群" min={1} />
              <Num path="context.min_confidence" label="待确认阈值" min={0} step={0.05} hint="识别把握低于它的事项标为「待确认」" />
              <Num path="context.legacy_days" label="历史遗留天数" min={30} suffix="天" hint="Meego / 飞书任务超过这么久没动静视为历史遗留" />
              <Text path="context.schedule" label="采集周期" hint="cron；改后需重启" />
              <Text path="context.morning" label="晨间卡" hint="cron；改后需重启" />
              <Text path="context.evening" label="收尾卡" hint="cron；改后需重启" />
              <Text path="context.weekly" label="周报草稿" hint="cron；改后需重启" />
            </div>
            <h3 className="group-title">自主等级（只影响你自己的低风险动作）</h3>
            <div className="toggles">
              <Toggle path="context.autonomy.auto_close" label="有证据时自动关闭事项" hint="例如你已在群里回复、Meego 节点已流转" />
              <Toggle path="context.autonomy.mute_legacy" label="自动静音历史遗留项目" />
              <Toggle path="context.autonomy.create_own_todo" label="把你的承诺建成飞书任务" hint="只建给你自己" />
            </div>
            <h3 className="group-title">个人 Web 独立网关（秒级接收任意群 @我 与私聊）</h3>
            <div className="toggles">
              <Toggle path="context.personal_web.enabled" label="启用独立个人 Web 网关客户端" hint="需先独立部署并启动 feishu-gateway，并在 config.yaml 配置 gateway_socket 或回环 gateway_url 与令牌环境变量；改后需重启常驻进程" />
              <Toggle path="context.personal_web.fast_lane" label="@我 与私聊秒级快通道" hint="不等 10 分钟定时周期，立刻做单会话理解并推送提醒卡片" />
              <Toggle path="context.personal_web.pre_draft" label="高优先级请求自动预起草" hint="只生成待确认草稿，永远不会自动在群里发言" />
              <Toggle path="context.personal_web.send_replies" label="确认草稿后允许经网关发送回复" hint="仅对尚未拿到开放平台 ID 的实时消息生效，同时需网关侧开启 allow_reply 并提供独立 reply_token" />
            </div>
            <div className="form-grid">
              <Num path="context.personal_web.debounce_ms" label="连续消息合并等待" min={0} step={500} suffix="毫秒" hint="同一会话短时间连发多条消息时合并成一次理解" />
            </div>
          </Section>
        )}

        <Section id="notify" title="通知" keys={["notify"]} hot={hot} dirty={isDirty("notify")}>
          <div className="form-grid">
            <Text path="notify.quiet_start" label="免打扰开始" type="time" hint="期间的非紧急私信延后发送" />
            <Text path="notify.quiet_end" label="免打扰结束" type="time" hint="留空表示不启用免打扰" />
          </div>
          <h3 className="group-title">哪些事私信我</h3>
          <div className="toggles">
            {NOTIFY_TYPES.map((t) => (
              <Toggle key={t.key} path={`notify.types.${t.key}`} label={t.label} hint={t.hint} />
            ))}
          </div>
        </Section>

        <Section id="schedules" title="时间表" keys={["schedules"]} hot={hot} dirty={isDirty("schedules")} desc="cron 表达式（分 时 日 月 周），按你的时区。">
          <div className="form-grid">
            {SCHEDULES.map((s) => (
              <Text key={s.key} path={`schedules.${s.key}`} label={s.label} hint={s.hint} />
            ))}
          </div>
        </Section>

        <Section id="delivery" title="交付" keys={["delivery"]} hot={hot} dirty={isDirty("delivery")} desc="把派单结果变成 PR / MR、合并到本地分支或放弃。">
          <div className="form-grid">
            <Select path="delivery.default_provider" label="默认代码平台" options={[{ value: "", label: "不指定" }, ...providers.map((p) => ({ value: p, label: p }))]} />
            <Num path="delivery.discard_retention_days" label="放弃后保留" min={0} suffix="天" hint="期间可以恢复" />
          </div>
          <h3 className="group-title">代码平台</h3>
          <ProvidersEditor key={`prov-${version}`} onInvalid={(m) => setInvalid((x) => ({ ...x, providers: m }))} />
          {invalid.providers && <div className="field-error">{invalid.providers}</div>}
        </Section>
      </div>

      <div className={`savebar ${dirty.length ? "savebar-show" : ""}`} role="region" aria-label="保存设置">
        <span className="small">
          {dirty.length ? `有未保存的修改：${dirty.map((k) => PATH_LABEL[k]).join("、")}` : "没有未保存的修改"}
          {localErr.length > 0 && <span className="text-danger"> · {localErr[0]}</span>}
        </span>
        <span className="row-gap">
          <button className="btn" onClick={discard} disabled={!dirty.length || saving}>
            放弃修改
          </button>
          <button className="btn btn-primary" onClick={() => void save()} disabled={!dirty.length || saving || localErr.length > 0}>
            {saving && <Spinner label="保存中" />}
            保存
          </button>
        </span>
      </div>
    </Form.Provider>
  );
}

export function SettingsPage() {
  const meta = useMeta();
  const q = useQuery<SettingsView>(meta.features.settings ? "/api/settings" : null, { tags: ["settings"] });
  return (
    <div className="page page-settings">
      <PageHeader title="设置" subtitle="改完点保存，会先校验；能热加载的部分立即生效" />
      {!meta.features.settings ? (
        <Unavailable what="设置" />
      ) : (
        <QueryView q={q} what="设置">
          {(v) => <SettingsForm view={v} onSaved={() => void q.refetch()} />}
        </QueryView>
      )}
    </div>
  );
}
