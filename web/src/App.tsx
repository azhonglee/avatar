import { useCallback, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ApiRequestError, api, onUnauthorized } from "./api/client.ts";
import type { Meta } from "./api/types.ts";
import { ErrorState, Loading } from "./components/ui.tsx";
import { LiveProvider, useServerEvents, type LiveState } from "./lib/events.ts";
import { MetaProvider } from "./lib/meta.ts";
import { useQuery } from "./lib/query.ts";
import { CandidatesPage } from "./pages/Candidates.tsx";
import { DispatchDetailPage } from "./pages/DispatchDetail.tsx";
import { DispatchesPage } from "./pages/Dispatches.tsx";
import { HealthPage } from "./pages/Health.tsx";
import { JobsPage } from "./pages/Jobs.tsx";
import { NeedLogin } from "./pages/NeedLogin.tsx";
import { NotFound } from "./pages/NotFound.tsx";
import { OverviewPage } from "./pages/Overview.tsx";
import { SettingsPage } from "./pages/Settings.tsx";
import { SetupPage } from "./pages/Setup.tsx";
import { UsagePage } from "./pages/Usage.tsx";

interface NavItem {
  to: string;
  label: string;
  icon: string;
  show: (m: Meta) => boolean;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "概览", icon: "◎", show: () => true, end: true },
  { to: "/dispatches", label: "派单", icon: "➤", show: () => true },
  { to: "/candidates", label: "候选任务", icon: "✦", show: (m) => m.features.candidates },
  { to: "/jobs", label: "作业", icon: "⏱", show: () => true },
  { to: "/health", label: "健康", icon: "♥", show: () => true },
  { to: "/usage", label: "花费", icon: "$", show: (m) => m.features.usage },
  { to: "/settings", label: "设置", icon: "⚙", show: (m) => m.features.settings },
  { to: "/setup", label: "初始化向导", icon: "✓", show: (m) => m.features.doctor },
];

const LIVE_LABEL: Record<LiveState, string> = {
  connecting: "正在连接实时更新…",
  open: "实时更新已连接",
  reconnecting: "实时更新断开，重连中…",
  off: "实时更新不可用",
};

function Shell({ meta, live }: { meta: Meta; live: LiveState }) {
  const [menu, setMenu] = useState(false);
  const loc = useLocation();
  useEffect(() => setMenu(false), [loc.pathname]);
  const logout = async () => {
    try {
      await api.logout();
    } finally {
      window.location.reload();
    }
  };
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        跳到主要内容
      </a>
      <header className="topbar">
        <button className="icon-btn menu-btn" aria-label={menu ? "关闭导航" : "打开导航"} aria-expanded={menu} aria-controls="sidenav" onClick={() => setMenu((v) => !v)}>
          ☰
        </button>
        <span className="brand">
          <span className="brand-mark" aria-hidden>
            A
          </span>
          Avatar
        </span>
        <span className={`live-dot live-${live}`} title={LIVE_LABEL[live]} aria-label={LIVE_LABEL[live]} role="img" />
      </header>
      <nav id="sidenav" className={`sidenav ${menu ? "sidenav-open" : ""}`} aria-label="主导航">
        <div className="sidenav-brand">
          <span className="brand-mark" aria-hidden>
            A
          </span>
          <div>
            <div className="brand-name">Avatar</div>
            <div className="brand-sub">个人 Agent 控制台</div>
          </div>
        </div>
        <ul>
          {NAV.filter((n) => n.show(meta)).map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.end} className={({ isActive }) => `nav-link ${isActive ? "nav-active" : ""}`}>
                <span className="nav-icon" aria-hidden>
                  {n.icon}
                </span>
                {n.label}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="sidenav-foot">
          <div className={`live live-${live}`}>
            <span className={`live-dot live-${live}`} aria-hidden />
            {LIVE_LABEL[live]}
          </div>
          <div className="muted small">版本 {meta.version}</div>
          <button className="btn btn-link small" onClick={() => void logout()}>
            退出登录
          </button>
        </div>
      </nav>
      {menu && <div className="nav-scrim" onClick={() => setMenu(false)} aria-hidden />}
      <main id="main" className="main" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/dispatches" element={<DispatchesPage />} />
          <Route path="/dispatches/:id" element={<DispatchDetailPage />} />
          <Route path="/candidates" element={<CandidatesPage />} />
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/health" element={<HealthPage />} />
          <Route path="/usage" element={<UsagePage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

/** 鉴权与元数据：401 → 需要登录；其余错误 → 整页错误；之后才渲染控制台。 */
export function App({ live: liveOverride }: { live?: boolean } = {}) {
  const [needLogin, setNeedLogin] = useState(false);
  useEffect(() => onUnauthorized(() => setNeedLogin(true)), []);
  const meta = useQuery<Meta>("/api/meta", { tags: ["meta"] });
  const unauthorized = needLogin || (meta.error instanceof ApiRequestError && meta.error.unauthorized);
  const onEvent = useCallback(() => undefined, []);
  const live = useServerEvents(!!meta.data && !unauthorized && liveOverride !== false, { onEvent });

  if (unauthorized) return <NeedLogin onRetry={() => (setNeedLogin(false), void meta.refetch())} />;
  if (!meta.data) {
    return (
      <div className="boot">
        {meta.error ? <ErrorState error={meta.error} onRetry={() => void meta.refetch()} /> : <Loading label="正在连接控制台…" />}
      </div>
    );
  }
  return (
    <MetaProvider value={meta.data}>
      <LiveProvider value={live}>
        <Shell meta={meta.data} live={live} />
      </LiveProvider>
    </MetaProvider>
  );
}
