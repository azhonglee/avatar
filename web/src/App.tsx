import { useCallback, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ApiRequestError, api, onUnauthorized } from "./api/client.ts";
import type { Meta } from "./api/types.ts";
import { ErrorState, Loading } from "./components/ui.tsx";
import { LiveProvider, useServerEvents, type LiveState } from "./lib/events.ts";
import { MetaProvider } from "./lib/meta.ts";
import { useQuery } from "./lib/query.ts";
import { CandidatesPage } from "./pages/Candidates.tsx";
import { DraftsPage, KnowledgePage, PeoplePage, UpdatesPage } from "./pages/ContextMisc.tsx";
import { ItemDetailPage, ItemsPage } from "./pages/Items.tsx";
import { ProjectDetailPage, ProjectsPage } from "./pages/Projects.tsx";
import { TodayPage } from "./pages/Today.tsx";
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
  /** 启用工作上下文时，派单相关的页面收进“更多” */
  more?: boolean;
}

const ctx = (m: Meta) => !!m.features.context;

const NAV: NavItem[] = [
  { to: "/", label: "今天", icon: "☀", show: ctx, end: true },
  { to: "/projects", label: "项目", icon: "◇", show: ctx },
  { to: "/items", label: "事项", icon: "☐", show: ctx },
  { to: "/knowledge", label: "知识", icon: "❖", show: ctx },
  { to: "/updates", label: "动态", icon: "~", show: ctx },
  { to: "/people", label: "人", icon: "☺", show: ctx },
  { to: "/drafts", label: "草稿", icon: "✎", show: ctx },
  { to: "/", label: "概览", icon: "◎", show: (m) => !ctx(m), end: true },
  { to: "/overview", label: "派单概览", icon: "◎", show: ctx, more: true },
  { to: "/dispatches", label: "派单", icon: "➤", show: () => true, more: true },
  { to: "/candidates", label: "候选任务", icon: "✦", show: (m) => m.features.candidates, more: true },
  { to: "/jobs", label: "作业", icon: "⏱", show: () => true, more: true },
  { to: "/health", label: "健康", icon: "♥", show: () => true, more: true },
  { to: "/usage", label: "花费", icon: "$", show: (m) => m.features.usage, more: true },
  { to: "/settings", label: "设置", icon: "⚙", show: (m) => m.features.settings, more: true },
  { to: "/setup", label: "初始化向导", icon: "✓", show: (m) => m.features.doctor, more: true },
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
            <div className="brand-sub">{ctx(meta) ? "你的工作上下文" : "个人 Agent 控制台"}</div>
          </div>
        </div>
        <ul>
          {NAV.filter((n) => n.show(meta)).map((n, i, all) => (
            <li key={`${n.to}-${n.label}`}>
              {ctx(meta) && n.more && !all[i - 1]?.more && <div className="nav-group">更多</div>}
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
          <Route path="/" element={ctx(meta) ? <TodayPage /> : <OverviewPage />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/today" element={<Navigate to="/" replace />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:id" element={<ProjectDetailPage />} />
          <Route path="/items" element={<ItemsPage />} />
          <Route path="/items/:id" element={<ItemDetailPage />} />
          <Route path="/knowledge" element={<KnowledgePage />} />
          <Route path="/updates" element={<UpdatesPage />} />
          <Route path="/people" element={<PeoplePage />} />
          <Route path="/drafts" element={<DraftsPage />} />
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
