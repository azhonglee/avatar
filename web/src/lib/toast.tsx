import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

export type ToastKind = "success" | "error" | "info";
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  action?: { label: string; href: string };
}

interface ToastApi {
  push(kind: ToastKind, message: string, action?: Toast["action"]): void;
}

const Ctx = createContext<ToastApi>({ push: () => undefined });

export function useToast(): ToastApi {
  return useContext(Ctx);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const next = useRef(1);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((t) => t.id !== id)), []);
  const push = useCallback(
    (kind: ToastKind, message: string, action?: Toast["action"]) => {
      const id = next.current++;
      setItems((xs) => [...xs.slice(-3), { id, kind, message, action }]);
      setTimeout(() => dismiss(id), kind === "error" ? 8000 : 4000);
    },
    [dismiss],
  );
  const value = useMemo(() => ({ push }), [push]);
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toasts" role="region" aria-label="通知">
        <div aria-live="polite" aria-atomic="false">
          {items.map((t) => (
            <div key={t.id} className={`toast toast-${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
              <span className="toast-icon" aria-hidden>
                {t.kind === "success" ? "✓" : t.kind === "error" ? "!" : "i"}
              </span>
              <span className="toast-msg">{t.message}</span>
              {t.action && (
                <a className="toast-action" href={t.action.href} target="_blank" rel="noreferrer">
                  {t.action.label}
                </a>
              )}
              <button className="toast-close" aria-label="关闭通知" onClick={() => dismiss(t.id)}>
                ×
              </button>
            </div>
          ))}
        </div>
      </div>
    </Ctx.Provider>
  );
}
