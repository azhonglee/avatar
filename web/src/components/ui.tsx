import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ApiRequestError, errorMessage } from "../api/client.ts";
import type { QueryState } from "../lib/query.ts";
import { absTime, relTime, useNow, type Tone } from "../lib/format.ts";

export function Pill({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function RelTime({ ts, prefix }: { ts: number | null | undefined; prefix?: string }) {
  const now = useNow();
  if (!ts) return <span className="muted">—</span>;
  return (
    <time dateTime={new Date(ts).toISOString()} title={absTime(ts)}>
      {prefix}
      {relTime(ts, now)}
    </time>
  );
}

export function Spinner({ label = "加载中" }: { label?: string }) {
  return <span className="spinner" role="status" aria-label={label} />;
}

export function Loading({ label = "加载中…" }: { label?: string }) {
  return (
    <div className="state state-loading">
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function Empty({ title, children, icon = "○" }: { title: string; children?: ReactNode; icon?: string }) {
  return (
    <div className="state state-empty">
      <div className="state-icon" aria-hidden>
        {icon}
      </div>
      <div className="state-title">{title}</div>
      {children && <div className="state-body">{children}</div>}
    </div>
  );
}

export function Unavailable({ what }: { what?: string }) {
  return (
    <div className="state state-unavailable" role="note">
      <div className="state-icon" aria-hidden>
        ◌
      </div>
      <div className="state-title">{what ? `${what}未启用` : "未启用"}</div>
      <div className="state-body">这个模块在当前版本或配置中没有启用。升级到包含该模块的版本、或在配置里打开后，重启常驻进程即可使用。</div>
    </div>
  );
}

export function ErrorState({ error, onRetry, what }: { error: unknown; onRetry?: () => void; what?: string }) {
  if (error instanceof ApiRequestError && error.unavailable) return <Unavailable what={what} />;
  return (
    <div className="state state-error" role="alert">
      <div className="state-icon" aria-hidden>
        !
      </div>
      <div className="state-title">加载失败</div>
      <div className="state-body">{errorMessage(error)}</div>
      {onRetry && (
        <button className="btn" onClick={onRetry}>
          重试
        </button>
      )}
    </div>
  );
}

/** 统一处理 loading / error / 501；有数据时渲染 children（后台刷新失败时保留旧数据并提示）。 */
export function QueryView<T>({ q, what, children, loading }: { q: QueryState<T>; what?: string; children: (data: T) => ReactNode; loading?: ReactNode }) {
  if (q.data === undefined) {
    if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} what={what} />;
    return <>{loading ?? <Loading />}</>;
  }
  return (
    <>
      {q.error !== undefined && !(q.error instanceof ApiRequestError && q.error.unauthorized) ? (
        <div className="inline-warn" role="status">
          刷新失败：{errorMessage(q.error)}（显示的是上次的数据）
          <button className="btn btn-link" onClick={() => void q.refetch()}>
            重试
          </button>
        </div>
      ) : null}
      {children(q.data)}
    </>
  );
}

export function Card({ title, actions, children, className = "", id }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; id?: string }) {
  const hid = useId();
  return (
    <section className={`card ${className}`} aria-labelledby={title ? hid : undefined} id={id}>
      {(title || actions) && (
        <header className="card-head">
          {title && (
            <h2 className="card-title" id={hid}>
              {title}
            </h2>
          )}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        <h1>{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Bar({ value, max, tone, label }: { value: number; max: number; tone?: Tone; label: string }) {
  const ratio = max > 0 ? Math.min(1, value / max) : 0;
  const t = tone ?? (ratio >= 1 ? "danger" : ratio >= 0.8 ? "warn" : "info");
  return (
    <div className="bar" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={max} aria-valuenow={value}>
      <div className={`bar-fill bar-${t}`} style={{ width: `${ratio * 100}%` }} />
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** 模态对话框：Esc 关闭、焦点限制在框内、关闭后焦点回到触发按钮。 */
export function Dialog({
  open,
  title,
  onClose,
  children,
  footer,
  tone,
  size = "md",
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  tone?: "danger";
  size?: "md" | "lg";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const hid = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const first = el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        closeRef.current();
      } else if (e.key === "Tab" && el) {
        const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)];
        if (!items.length) return;
        const i = items.indexOf(document.activeElement as HTMLElement);
        if (e.shiftKey && i <= 0) {
          e.preventDefault();
          items[items.length - 1].focus();
        } else if (!e.shiftKey && i === items.length - 1) {
          e.preventDefault();
          items[0].focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.body.style.overflow = overflow;
      prev?.focus?.();
    };
  }, [open]);
  if (!open) return null;
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className={`modal modal-${size} ${tone ? `modal-${tone}` : ""}`} role="dialog" aria-modal="true" aria-labelledby={hid}>
        <header className="modal-head">
          <h2 id={hid}>{title}</h2>
          <button className="icon-btn" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

/** 不可逆/有后果的操作：说明后果，再确认。 */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  onConfirm,
  onClose,
  busy,
  danger = true,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
  danger?: boolean;
}) {
  return (
    <Dialog
      open={open}
      title={title}
      onClose={onClose}
      tone={danger ? "danger" : undefined}
      footer={
        <>
          <button className="btn" onClick={onClose} data-autofocus>
            再想想
          </button>
          <button className={`btn ${danger ? "btn-danger" : "btn-primary"}`} onClick={onConfirm} disabled={busy}>
            {busy ? <Spinner label="执行中" /> : null}
            {confirmLabel}
          </button>
        </>
      }
    >
      {children}
    </Dialog>
  );
}

export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: ReactNode; error?: string; children: ReactNode; htmlFor?: string }) {
  return (
    <div className={`field ${error ? "field-invalid" : ""}`}>
      <label className="field-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <div className="field-error" role="alert">
          {error}
        </div>
      ) : hint ? (
        <div className="field-hint">{hint}</div>
      ) : null}
    </div>
  );
}

export function Tabs<K extends string>({ value, onChange, items, label }: { value: K; onChange: (k: K) => void; items: { key: K; label: ReactNode }[]; label: string }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {items.map((it) => (
        <button
          key={it.key}
          role="tab"
          aria-selected={value === it.key}
          tabIndex={value === it.key ? 0 : -1}
          className={`tab ${value === it.key ? "tab-active" : ""}`}
          onClick={() => onChange(it.key)}
          onKeyDown={(e) => {
            const i = items.findIndex((x) => x.key === value);
            if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
              e.preventDefault();
              const n = items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
              onChange(n.key);
              const parent = (e.currentTarget as HTMLElement).parentElement;
              setTimeout(() => parent?.querySelector<HTMLElement>('[aria-selected="true"]')?.focus(), 0);
            }
          }}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}

export function Stat({ label, value, tone, sub }: { label: string; value: ReactNode; tone?: Tone; sub?: ReactNode }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Collapsible({ summary, children, defaultOpen = false }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  return (
    <details className="collapsible" open={defaultOpen}>
      <summary>{summary}</summary>
      <div className="collapsible-body">{children}</div>
    </details>
  );
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  if (!href) return null;
  return (
    <a href={href} target="_blank" rel="noreferrer noopener" className="ext-link">
      {children}
      <span aria-hidden> ↗</span>
    </a>
  );
}

export function Pre({ children, className = "" }: { children: string; className?: string }) {
  return (
    <pre className={`pre ${className}`} tabIndex={0}>
      {children}
    </pre>
  );
}
