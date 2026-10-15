import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Bell,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileArchive,
  FileSpreadsheet,
  FileText,
  Fingerprint,
  HardDrive,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Upload,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
} from "recharts";
import { AppIcon } from "./components/AppIcon";
import { Brand } from "./components/Brand";
import { PageHeader } from "./components/PageHeader";
import { RiskBadge } from "./components/RiskBadge";
import { activityTrend, demoAlerts, demoApps, demoHistory } from "./data/demo";
import { signOut as signOutAccount } from "./lib/auth";
import { supabase, supabaseConfigured } from "./lib/supabase";
import { loadCloudHistory, saveAnalysisSummary } from "./lib/cloudHistory";
import type {
  AnalysisResponse,
  AuthView,
  Page,
  ProtectedApp,
  RiskLevel,
} from "./types";
import type { User } from "@supabase/supabase-js";

const API_BASE_URL = "http://127.0.0.1:8000/api";
const MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024;

const navigation: { label: Page; icon: typeof LayoutDashboard }[] = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Installed apps", icon: Smartphone },
  { label: "Alerts", icon: Bell },
  { label: "Scan history", icon: Clock3 },
  { label: "Manual analysis", icon: FileArchive },
  { label: "Privacy settings", icon: Settings2 },
];

function App() {
  const [view, setView] = useState<AuthView>("landing");
  const [page, setPage] = useState<Page>("Overview");
  const [selectedAppId, setSelectedAppId] = useState(demoApps[0].id);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<"All risks" | RiskLevel>("All risks");
  const [categoryFilter, setCategoryFilter] = useState("All categories");
  const [alerts, setAlerts] = useState(demoAlerts);
  const [history, setHistory] = useState(demoHistory);
  const [notice, setNotice] = useState("");
  const [email, setEmail] = useState("");
  const [accountUser, setAccountUser] = useState<User | null>(null);
  const [isGuestMode, setIsGuestMode] = useState(false);
  const [cloudSyncEnabled, setCloudSyncEnabled] = useState(false);
  const [authLoading, setAuthLoading] = useState(supabaseConfigured);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authMessage, setAuthMessage] = useState("");
  const [settings, setSettings] = useState({
    localOnly: true,
    alerts: true,
    weeklySummary: false,
  });

  useEffect(() => {
    if (!supabase) return;
    let active = true;
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        if (!active) return;
        if (session) {
          setAccountUser(session.user);
          setEmail(session.user.email ?? "");
          if (event === "SIGNED_IN") {
            setIsGuestMode(false);
            setView("app");
          }
          return;
        }
        setAccountUser(null);
        setCloudSyncEnabled(false);
        if (event === "SIGNED_OUT") {
          setIsGuestMode(false);
          setView("landing");
        }
      },
    );

    void (async () => {
      try {
        const { data, error } = await supabase.auth.getSession();
        if (error) throw error;
        if (!data.session) return;
        const { data: userData, error: userError } = await supabase.auth.getUser();
        if (userError) throw userError;
        if (active && userData.user) {
          setAccountUser(userData.user);
          setEmail(userData.user.email ?? "");
          setView("app");
        }
      } catch {
        if (active) {
          setAuthError(
            "Your saved session could not be verified. Sign in again to use cloud history; local analysis remains available.",
          );
        }
      } finally {
        if (active) setAuthLoading(false);
      }
    })();

    return () => {
      active = false;
      subscription.unsubscribe();
    };
  }, []);

  const signOut = async () => {
    if (accountUser && supabase) {
      try {
        await signOutAccount(supabase);
      } catch (cause) {
        setNotice(cause instanceof Error ? cause.message : "Unable to sign out.");
        return;
      }
    }
    setView("landing");
    setPage("Overview");
    setEmail("");
    setAccountUser(null);
    setIsGuestMode(false);
    setCloudSyncEnabled(false);
    setAlerts(demoAlerts);
    setHistory(demoHistory);
    setQuery("");
    setRiskFilter("All risks");
    setCategoryFilter("All categories");
    setSettings({ localOnly: true, alerts: true, weeklySummary: false });
    setNotice("");
    setAuthError("");
    setAuthMessage("");
  };

  const authenticate = async (
    mode: "sign-in" | "create-account",
    address: string,
    password: string,
  ) => {
    if (!supabase) {
      setAuthError("Cloud authentication is not configured. Local analysis is still available.");
      return;
    }
    setAuthBusy(true);
    setAuthError("");
    setAuthMessage("");
    try {
      if (mode === "create-account") {
        const { data, error } = await supabase.auth.signUp({
          email: address.trim(),
          password,
        });
        if (error) throw error;
        if (data.session) {
          setAccountUser(data.session.user);
          setEmail(data.session.user.email ?? address.trim());
          setIsGuestMode(false);
          setView("app");
        } else {
          setAuthMessage("Account created. Check your email to confirm your address, then sign in.");
        }
      } else {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: address.trim(),
          password,
        });
        if (error) throw error;
        setAccountUser(data.user);
        setEmail(data.user.email ?? address.trim());
        setIsGuestMode(false);
        setView("app");
      }
    } catch (cause) {
      setAuthError(cause instanceof Error ? cause.message : "Authentication failed.");
    } finally {
      setAuthBusy(false);
    }
  };
  const selectedApp = demoApps.find((app) => app.id === selectedAppId) ?? demoApps[0];
  const filteredApps = useMemo(() => demoApps.filter((app) => {
    const matchesSearch = `${app.name} ${app.publisher} ${app.category}`.toLowerCase().includes(query.toLowerCase());
    const matchesRisk = riskFilter === "All risks" || app.risk === riskFilter;
    const matchesCategory = categoryFilter === "All categories" || app.category === categoryFilter;
    return matchesSearch && matchesRisk && matchesCategory;
  }), [query, riskFilter, categoryFilter]);

  const goTo = (next: Page) => {
    setPage(next);
    setView("app");
    setMobileNavOpen(false);
    setNotice("");
  };

  const openApp = (app: ProtectedApp) => {
    setSelectedAppId(app.id);
    goTo("App details");
  };

  if (view !== "app") {
    return (
      <AuthScreen
        view={view}
        setView={setView}
        email={email}
        setEmail={setEmail}
        authLoading={authLoading}
        authBusy={authBusy}
        authError={authError}
        authMessage={authMessage}
        onAuthenticate={authenticate}
        onEnter={() => {
          setAuthError("");
          setAuthMessage("");
          setIsGuestMode(true);
          setView("app");
          setPage("Overview");
        }}
      />
    );
  }

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className={`sidebar${mobileNavOpen ? " sidebar--open" : ""}`}>
        <div className="sidebar-brand"><Brand /></div>
        <div className="workspace-switcher">
          <span className="workspace-avatar">P</span>
          <span><strong>Personal space</strong><small>Local workspace</small></span>
          <ChevronDown size={15} />
        </div>
        <p className="nav-caption">SECURITY</p>
        <nav className="main-nav" aria-label="Main navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-link${page === label || (label === "Installed apps" && page === "App details") ? " nav-link--active" : ""}`}
              aria-current={page === label || (label === "Installed apps" && page === "App details") ? "page" : undefined}
              onClick={() => goTo(label)}
            >
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {label === "Alerts" && settings.alerts && alerts.some((alert) => !alert.read) && <span className="nav-count">{alerts.filter((alert) => !alert.read).length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-chip"><LockKeyhole size={15} /><span><strong>{cloudSyncEnabled ? "Cloud sync opted in" : "Local by default"}</strong><small>{cloudSyncEnabled ? "Only summaries you choose" : "Save only what you explicitly choose"}</small></span></div>
          <button className="profile-button" onClick={() => goTo("Privacy settings")}>
            <span className="profile-avatar">{accountUser ? (email.slice(0, 2).toUpperCase() || "U") : "JD"}</span><span><strong>{accountUser ? email : isGuestMode ? "Local demo" : "Demo user"}</strong><small>{accountUser ? "Signed-in account" : "Local demo session"}</small></span><ChevronRight size={15} />
          </button>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" aria-expanded={mobileNavOpen} onClick={() => setMobileNavOpen(true)}><Menu size={20} /></button>
          <div className="breadcrumb"><span>Workspace</span><ChevronRight size={14} /><strong>{page}</strong></div>
          <div className="topbar-actions">
            <span className="demo-pill"><span />{page === "Manual analysis" ? "Local analysis" : "Synthetic demo"}</span>
            <button className="icon-button top-help" aria-label="Help" onClick={() => setNotice(page === "Manual analysis" ? "Manual reports are analyzed locally by the Python policy engine. Other dashboard records remain synthetic." : "PermissionGuard's inventory is a synthetic demonstration. No device scan is running.")}><CircleHelp size={18} /></button>
          </div>
        </header>
        <div className="content-area">
          {notice && <div className="inline-notice" role="status"><Shield size={16} />{notice}<button aria-label="Dismiss notice" onClick={() => setNotice("")}><X size={15} /></button></div>}
          {page === "Overview" && <Overview onNavigate={goTo} onOpenApp={openApp} />}
          {page === "Installed apps" && (
            <AppsPage
              apps={filteredApps}
              query={query}
              setQuery={setQuery}
              riskFilter={riskFilter}
              setRiskFilter={setRiskFilter}
              categoryFilter={categoryFilter}
              setCategoryFilter={setCategoryFilter}
              selectedApp={selectedApp}
              onSelect={openApp}
              onNavigate={goTo}
            />
          )}
          {page === "App details" && <AppDetailsPage app={selectedApp} onBack={() => goTo("Installed apps")} />}
          {page === "Alerts" && <AlertsPage alerts={alerts} setAlerts={setAlerts} onOpenApp={(id) => { const app = demoApps.find((item) => item.id === id); if (app) openApp(app); }} />}
          {page === "Scan history" && <HistoryPage history={history} setHistory={setHistory} onOpenApp={(name) => { const app = demoApps.find((item) => item.name === name); if (app) openApp(app); }} cloudSyncEnabled={Boolean(accountUser && cloudSyncEnabled)} />}
          {page === "Manual analysis" && <ManualAnalysis cloudSyncEnabled={Boolean(accountUser && cloudSyncEnabled)} />}
          {page === "Privacy settings" && <PrivacyPage settings={settings} setSettings={setSettings} setNotice={setNotice} onSignOut={signOut} onAccountOptions={() => { setView("landing"); setNotice(""); }} accountUser={accountUser} cloudSyncEnabled={cloudSyncEnabled} onCloudSyncChange={setCloudSyncEnabled} />}
          <footer className="page-footer"><span>PermissionGuard <span className="footer-dot">·</span> Local-first permission insights</span><span>{page === "Manual analysis" ? "Results from the local analysis engine" : "Synthetic demonstration data"}</span></footer>
        </div>
      </main>
    </div>
  );
}

function AuthScreen({
  view,
  setView,
  email,
  setEmail,
  authLoading,
  authBusy,
  authError,
  authMessage,
  onAuthenticate,
  onEnter,
}: {
  view: AuthView;
  setView: (view: AuthView) => void;
  email: string;
  setEmail: (email: string) => void;
  authLoading: boolean;
  authBusy: boolean;
  authError: string;
  authMessage: string;
  onAuthenticate: (
    mode: "sign-in" | "create-account",
    email: string,
    password: string,
  ) => Promise<void>;
  onEnter: () => void;
}) {
  const [password, setPassword] = useState("");
  const isLanding = view === "landing";
  const isCreate = view === "create-account";
  const title = isCreate ? "A little more clarity." : "Your privacy, in focus.";

  return (
    <div className="auth-shell">
      <header className="auth-top"><Brand /><span className="auth-top-note"><LockKeyhole size={14} />Private by design</span></header>
      <div className={`auth-content${isLanding ? " auth-content--landing" : ""}`}>
        <section className="auth-copy">
          <div className="auth-orbit"><div className="orbit-ring orbit-ring--outer" /><div className="orbit-ring orbit-ring--inner" /><div className="orbit-core"><ShieldCheck size={42} strokeWidth={1.35} /></div><span className="orbit-node orbit-node--one"><Fingerprint size={19} /></span><span className="orbit-node orbit-node--two"><LockKeyhole size={18} /></span></div>
          <p className="eyebrow">UNDERSTAND WHAT APPS CAN ACCESS</p>
          <h1>{title}</h1>
          <p className="auth-lede">A clearer view of Android app permissions, with practical guidance to help you make informed choices.</p>
          <div className="auth-assurances"><span><Check size={15} />Local-first analysis</span><span><Check size={15} />No automatic changes</span><span><Check size={15} />You stay in control</span></div>
        </section>
        {isLanding ? (
          <section className="auth-card landing-card">
            <p className="eyebrow">START WITH PERMISSIONGUARD</p>
            <h2>Make permissions make sense.</h2>
            <p>Review permission declarations, understand potential concerns, and explore recommendations in one calm, private space.</p>
            <button className="button button--primary button--wide" onClick={() => setView("sign-in")}>Sign in <ArrowRight size={17} /></button>
            <button className="button button--secondary button--wide" onClick={() => setView("create-account")}>Create an account</button>
            <div className="card-divider"><span>OR</span></div>
            <button className="button button--quiet button--wide" onClick={onEnter}>Explore local demo <ArrowRight size={16} /></button>
            <small className="demo-disclaimer">Local analysis is available without an account. Cloud history is optional and requires your consent.</small>
            {authLoading && <p className="auth-status" role="status">Checking saved account session…</p>}
            {authError && <p className="analysis-error" role="alert">{authError}</p>}
          </section>
        ) : (
          <section className="auth-card">
            <button className="back-link" onClick={() => setView("landing")}><ArrowLeft size={15} /> Back</button>
            <p className="eyebrow">{isCreate ? "CREATE YOUR SPACE" : "WELCOME BACK"}</p>
            <h2>{isCreate ? "Create your account" : "Sign in"}</h2>
            <p className="auth-card-intro">Sign in with your email to optionally save scan summaries to your private cloud history. Analysis remains available locally without signing in.</p>
            {authMessage && <p className="auth-status" role="status">{authMessage}</p>}
            {authError && <p className="analysis-error" role="alert">{authError}</p>}
            <form className="auth-form" onSubmit={(event) => {
              event.preventDefault();
              void onAuthenticate(
                view === "create-account" ? "create-account" : "sign-in",
                email,
                password,
              );
            }}>
              <label>Email address<input required type="email" autoComplete="email" placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
              <label>Password<input required minLength={8} type="password" autoComplete={isCreate ? "new-password" : "current-password"} placeholder="At least 8 characters" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
              <button className="button button--primary button--wide" type="submit" disabled={authBusy || authLoading || !supabaseConfigured}>
                {authBusy ? "Please wait…" : isCreate ? "Create account" : "Sign in"} <ArrowRight size={16} />
              </button>
              {!supabaseConfigured && <small className="demo-disclaimer">Cloud sign-in is not configured. Use “Explore local demo” for local analysis.</small>}
            </form>
            <p className="switch-auth">{isCreate ? "Already have an account?" : "New to PermissionGuard?"} <button onClick={() => setView(isCreate ? "sign-in" : "create-account")}>{isCreate ? "Sign in" : "Create an account"}</button></p>
          </section>
        )}
      </div>
      <footer className="auth-footer"><span>© PermissionGuard · An independent privacy tool</span><span><LockKeyhole size={13} />Cloud history is off until you opt in</span></footer>
    </div>
  );
}

function Overview({ onNavigate, onOpenApp }: { onNavigate: (page: Page) => void; onOpenApp: (app: ProtectedApp) => void }) {
  const high = demoApps.filter((app) => app.risk === "High");
  const today = new Intl.DateTimeFormat("en", { weekday: "long", month: "long", day: "numeric" }).format(new Date()).toUpperCase();
  return (
    <>
      <div className="welcome-row"><div><p className="eyebrow">{today}</p><h1>Your security overview</h1><p className="page-description">A considered look at the permissions declared by apps in this demo.</p></div><button className="button button--secondary" onClick={() => onNavigate("Manual analysis")}><Upload size={16} /> Analyze a report</button></div>
      <div className="demo-banner"><span className="demo-banner-icon"><Activity size={17} /></span><span><strong>Exploring with synthetic data</strong><small>These sample apps and scores are illustrative. No device apps were scanned.</small></span><button onClick={() => onNavigate("Privacy settings")}>How it works <ArrowRight size={14} /></button></div>
      <div className="overview-grid">
        <section className="panel health-panel"><div className="panel-heading"><div><p className="eyebrow">SECURITY SNAPSHOT</p><h2>Room to review</h2></div><span className="health-icon"><ShieldCheck size={20} /></span></div><div className="health-score"><strong>{demoApps.length}</strong><span>apps in this sample</span></div><div className="risk-stats"><div><span className="stat-dot stat-dot--low" /><strong>{demoApps.filter((app) => app.risk === "Low").length}</strong><small>Low</small></div><div><span className="stat-dot stat-dot--medium" /><strong>{demoApps.filter((app) => app.risk === "Medium").length}</strong><small>Medium</small></div><div><span className="stat-dot stat-dot--high" /><strong>{high.length}</strong><small>High</small></div></div><div className="panel-footnote"><span className="status-indicator" />Demo inventory is not connected to your device</div></section>
        <section className="panel trend-panel"><div className="panel-heading"><div><p className="eyebrow">RECENT ACTIVITY</p><h2>Review activity</h2></div><button className="text-button" onClick={() => onNavigate("Scan history")}>View history <ArrowRight size={14} /></button></div><div className="chart-area"><ResponsiveContainer width="100%" height="100%"><AreaChart data={activityTrend} margin={{ top: 12, right: 4, left: 0, bottom: 0 }}><defs><linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#65cabb" stopOpacity={0.2} /><stop offset="100%" stopColor="#65cabb" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#202d39" vertical={false} /><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: "#82909e", fontSize: 11 }} dy={10} /><Tooltip contentStyle={{ background: "#101923", border: "1px solid #2a3946", borderRadius: 8, color: "#e4eaf0", fontSize: 12 }} /><Area type="monotone" dataKey="scans" name="Sample reviews" stroke="#69cabb" strokeWidth={2} fill="url(#activityFill)" /></AreaChart></ResponsiveContainer></div><div className="chart-caption"><span><span className="legend-dot" />Illustrative sample activity</span><span>Last 7 days</span></div></section>
      </div>
      <section className="section-block"><div className="section-heading"><div><p className="eyebrow">NEEDS A CLOSER LOOK</p><h2>Priority reviews</h2></div><button className="text-button" onClick={() => onNavigate("Installed apps")}>All apps <ArrowRight size={14} /></button></div><div className="priority-list">{high.map((app) => <button className="priority-row" key={app.id} onClick={() => onOpenApp(app)}><AppIcon app={app} /><span className="priority-copy"><strong>{app.name}</strong><small>{app.permissions.filter((permission) => permission.purposeFit === "Review").length} permissions to review · {app.category}</small></span><RiskBadge level={app.risk} score={app.score} small /><ChevronRight size={17} className="row-chevron" /></button>)}</div></section>
      <section className="section-block apps-preview"><div className="section-heading"><div><p className="eyebrow">SAMPLE INVENTORY</p><h2>Recently reviewed</h2></div><button className="text-button" onClick={() => onNavigate("Installed apps")}>Browse apps <ArrowRight size={14} /></button></div><div className="mini-app-grid">{demoApps.slice(0, 3).map((app) => <button key={app.id} className="mini-app" onClick={() => onOpenApp(app)}><AppIcon app={app} /><span><strong>{app.name}</strong><small>{app.category}</small></span><RiskBadge level={app.risk} small /></button>)}</div></section>
    </>
  );
}

function AppsPage({
  apps, query, setQuery, riskFilter, setRiskFilter, categoryFilter, setCategoryFilter, selectedApp, onSelect,
  onNavigate,
}: {
  apps: ProtectedApp[];
  query: string;
  setQuery: (value: string) => void;
  riskFilter: "All risks" | RiskLevel;
  setRiskFilter: (value: "All risks" | RiskLevel) => void;
  categoryFilter: string;
  setCategoryFilter: (value: string) => void;
  selectedApp: ProtectedApp;
  onSelect: (app: ProtectedApp) => void;
  onNavigate: (page: Page) => void;
}) {
  const categories = [...new Set(demoApps.map((app) => app.category))];
  return (
    <>
      <PageHeader eyebrow="APP INVENTORY · SYNTHETIC DATA" title="Installed apps" description="Explore sample app profiles and the permission declarations in this demonstration." action={<button className="button button--primary" onClick={() => onNavigate("Manual analysis")}><Upload size={16} /> Analyze report</button>} />
      <div className="filter-bar"><label className="search-field"><Search size={17} /><input aria-label="Search apps" placeholder="Search apps or publishers" value={query} onChange={(event) => setQuery(event.target.value)} /></label><label className="select-wrap"><span className="sr-only">Filter by risk</span><select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value as "All risks" | RiskLevel)}><option>All risks</option><option>Low</option><option>Medium</option><option>High</option></select><ChevronDown size={14} /></label><label className="select-wrap"><span className="sr-only">Filter by category</span><select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}><option>All categories</option>{categories.map((category) => <option key={category}>{category}</option>)}</select><ChevronDown size={14} /></label><span className="results-count">{apps.length} apps</span></div>
      <div className="apps-layout"><section className="panel app-table-panel"><div className="table-head"><span>APPLICATION</span><span>CATEGORY</span><span>DECLARED</span><span>RISK</span></div>{apps.map((app) => <button key={app.id} className={`app-table-row${selectedApp.id === app.id ? " app-table-row--selected" : ""}`} onClick={() => onSelect(app)}><span className="app-identity"><AppIcon app={app} /><span><strong>{app.name}</strong><small>{app.publisher}</small></span></span><span className="cell-muted">{app.category}</span><span className="cell-muted">{app.permissions.length} permissions</span><span><RiskBadge level={app.risk} score={app.score} small /></span></button>)}{apps.length === 0 && <div className="empty-state"><Search size={22} /><strong>No matching apps</strong><span>Try changing your search or filters.</span></div>}</section>
        <AppDetail app={selectedApp} compact /></div>
    </>
  );
}

function AppDetail({ app, compact = false }: { app: ProtectedApp; compact?: boolean }) {
  return (
    <section className={`panel detail-panel${compact ? " detail-panel--compact" : ""}`}>
      <div className="detail-hero"><AppIcon app={app} size="large" /><div><p className="eyebrow">APP PROFILE</p><h2>{app.name}</h2><span>{app.publisher}</span></div></div>
      <div className="detail-risk"><span>Risk overview</span><RiskBadge level={app.risk} score={app.score} /></div>
      <div className="detail-progress"><span style={{ width: `${Math.max(app.score, 5)}%` }} className={`detail-progress__fill risk-fill--${app.risk.toLowerCase()}`} /></div>
      <div className="score-explainer"><span>Score is illustrative</span><span>0 — 100</span></div>
      <div className="detail-meta"><span>Declared permissions<strong>{app.permissions.length}</strong></span><span>Last reviewed<strong>{app.lastScanned}</strong></span><span>Purpose category<strong>{app.category}</strong></span></div>
      <div className="detail-section-heading"><h3>Permission declarations</h3><span>{app.permissions.length}</span></div>
      <div className="permission-list">{app.permissions.map((permission) => <details className="permission-item" key={permission.name}><summary><span className={`permission-status permission-status--${permission.purposeFit.toLowerCase()}`} /><span className="permission-title"><strong>{permission.name}</strong><small>{permission.group}</small></span><RiskBadge level={permission.severity} small /><ChevronDown size={14} className="permission-chevron" /></summary><div className="permission-explanation"><p>{permission.explanation}</p><div><span>Purpose fit <strong>{permission.purposeFit === "Expected" ? "Expected" : "Review"}</strong></span><span>Confidence <strong>{Math.round(permission.confidence * 100)}% · illustrative</strong></span></div><p className="recommendation"><strong>Consider:</strong> {permission.recommendation}</p></div></details>)}</div>
      <div className="static-note"><Shield size={15} /><span>Declared permissions only. This does not show device grants or runtime use.</span></div>
    </section>
  );
}

function AppDetailsPage({ app, onBack }: { app: ProtectedApp; onBack: () => void }) {
  return (
    <>
      <PageHeader
        eyebrow="APP DETAILS · SYNTHETIC DATA"
        title={app.name}
        description="Review declared permissions, sample purpose-fit notes, and illustrative recommendations."
        action={<button className="button button--secondary" onClick={onBack}><ArrowLeft size={15} /> Back to apps</button>}
      />
      <div className="app-details-page">
        <AppDetail app={app} />
        <aside className="panel detail-methodology">
          <p className="eyebrow">HOW TO READ THIS</p>
          <h2>Context matters.</h2>
          <p>A permission declaration describes what an app may request access to. It does not tell us whether access was granted or used.</p>
          <div className="detail-methodology-row"><span>Declared</span><strong>Listed in the manifest</strong></div>
          <div className="detail-methodology-row"><span>Granted</span><strong>Chosen by the device user</strong></div>
          <div className="detail-methodology-row"><span>Used</span><strong>Requires runtime observation</strong></div>
          <div className="analysis-caveat"><ShieldAlert size={17} /><p><strong>Illustrative profile</strong>Scores, purpose fit, and guidance here are synthetic demonstration content, not a live engine result.</p></div>
        </aside>
      </div>
    </>
  );
}

function AlertsPage({ alerts, setAlerts, onOpenApp }: { alerts: typeof demoAlerts; setAlerts: (alerts: typeof demoAlerts) => void; onOpenApp: (id: string) => void }) {
  const [filter, setFilter] = useState<"All alerts" | RiskLevel>("All alerts");
  const filtered = alerts.filter((alert) => filter === "All alerts" || alert.severity === filter);
  const markAll = () => setAlerts(alerts.map((alert) => ({ ...alert, read: true })));
  return (
    <>
      <PageHeader eyebrow="PERMISSION REVIEW · SYNTHETIC DATA" title="Alerts" description="Permission patterns in this sample that may benefit from a closer look." action={<button className="button button--secondary" onClick={markAll}><Check size={15} /> Mark all read</button>} />
      <div className="alert-disclaimer"><ShieldAlert size={17} /><span>These are review indicators, not evidence of harmful behavior.</span></div>
      <div className="filter-bar"><label className="select-wrap"><span className="sr-only">Filter alerts by severity</span><select value={filter} onChange={(event) => setFilter(event.target.value as "All alerts" | RiskLevel)}><option>All alerts</option><option>High</option><option>Medium</option><option>Low</option></select><ChevronDown size={14} /></label><span className="results-count">{filtered.length} alerts</span></div>
      <div className="alert-list">{filtered.map((alert) => <article className={`panel alert-row${alert.read ? " alert-row--read" : ""}`} key={alert.id}><span className={`alert-marker alert-marker--${alert.severity.toLowerCase()}`}><ShieldAlert size={18} /></span><div className="alert-main"><div className="alert-title-row"><h2>{alert.title}</h2><RiskBadge level={alert.severity} small />{!alert.read && <span className="unread-dot" aria-label="Unread" />}</div><p>{alert.detail}</p><span className="alert-meta">{alert.appName}<span>·</span>{alert.time}</span><div className="alert-actions"><button className="text-button" onClick={() => onOpenApp(alert.appId)}>Review app <ArrowRight size={14} /></button><button className="text-button text-button--muted" onClick={() => setAlerts(alerts.map((item) => item.id === alert.id ? { ...item, read: true } : item))}>{alert.read ? "Read" : "Mark as read"}</button></div></div></article>)}</div>
      {filtered.length === 0 && <div className="empty-state"><Bell size={22} /><strong>All clear for this filter</strong><span>No sample alerts match your selection.</span></div>}
      <p className="method-note">Permission declarations alone cannot confirm whether an app used a permission or transmitted data.</p>
    </>
  );
}

function HistoryPage({ history, setHistory, onOpenApp, cloudSyncEnabled }: { history: typeof demoHistory; setHistory: (history: typeof demoHistory) => void; onOpenApp: (name: string) => void; cloudSyncEnabled: boolean }) {
  const [filter, setFilter] = useState<"All sources" | "Installed app" | "Manual upload">("All sources");
  const rows = history.filter((item) => filter === "All sources" || item.source === filter);
  return (
    <>
      <PageHeader eyebrow="LOCAL DEMONSTRATION" title="Scan history" description="A sample of recent reviews. These records are not saved scans." action={<button className="button button--secondary" onClick={() => setHistory(demoHistory)}><Activity size={15} /> Restore sample history</button>} />
      <div className="history-notice"><HardDrive size={16} /><span><strong>Local demo only</strong> History actions affect this browser session only. Persistence is not connected.</span></div>
      <div className="filter-bar"><label className="select-wrap"><span className="sr-only">Filter history by source</span><select value={filter} onChange={(event) => setFilter(event.target.value as typeof filter)}><option>All sources</option><option>Installed app</option><option>Manual upload</option></select><ChevronDown size={14} /></label><span className="results-count">{rows.length} entries</span></div>
      <div className="panel history-table"><div className="history-head"><span>APPLICATION</span><span>SOURCE</span><span>DATE REVIEWED</span><span>RISK</span><span /></div>{rows.map((item) => <div className="history-row" key={`${item.app}-${item.date}`}><span className="history-app"><AppIcon app={demoApps.find((app) => app.name === item.app) ?? demoApps[0]} /><strong>{item.app}</strong></span><span className="cell-muted">{item.source}</span><span className="cell-muted">{item.date}</span><span><RiskBadge level={item.risk} score={item.score} small /></span><span className="history-actions"><button className="icon-button" aria-label={`Reopen ${item.app}`} title="Open app report" onClick={() => onOpenApp(item.app)}><ArrowRight size={16} /></button><button className="icon-button icon-button--danger" aria-label={`Delete ${item.app} record`} title="Remove from demo history" onClick={() => setHistory(history.filter((entry) => entry.app !== item.app || entry.date !== item.date))}><X size={16} /></button></span></div>)}
        {rows.length === 0 && <div className="empty-state"><Clock3 size={22} /><strong>No history entries</strong><span>There are no sample records for this filter.</span></div>}</div>
      <CloudHistorySection enabled={cloudSyncEnabled} />
    </>
  );
}

function CloudHistorySection({ enabled }: { enabled: boolean }) {
  const [records, setRecords] = useState<Awaited<ReturnType<typeof loadCloudHistory>>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;
    if (!enabled) {
      setRecords([]);
      setError("");
      return () => { active = false; };
    }
    setLoading(true);
    setError("");
    void loadCloudHistory(supabase, true)
      .then((data) => { if (active) setRecords(data); })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : "Unable to load cloud history.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [enabled, refreshKey]);

  return (
    <section className="panel cloud-history">
      <div className="cloud-history-heading">
        <div><p className="eyebrow">PRIVATE ACCOUNT DATA</p><h2>Optional cloud history</h2></div>
        {enabled && <button className="button button--secondary" disabled={loading} onClick={() => setRefreshKey((key) => key + 1)}>Refresh</button>}
      </div>
      {!enabled ? <p>Cloud history is off. Enable it in Privacy settings to view summaries saved to your account. Local analysis and demo examples remain available.</p>
        : loading ? <p role="status">Loading your private scan summaries…</p>
          : error ? <p className="analysis-error" role="alert">{error}</p>
            : records.length === 0 ? <p>No summaries have been explicitly saved to your account.</p>
              : <div className="cloud-record-list">{records.map((record) => <article className="cloud-record" key={record.id}>
                <div><strong>{record.app_name || record.package_name || "Unnamed application"}</strong><small>{record.package_name || "Package name unavailable"} · {record.source_format.toUpperCase()} · {new Date(record.created_at).toLocaleString()}</small></div>
                <RiskBadge level={record.risk_band} score={record.score} small />
              </article>)}</div>}
      <small>Only summaries explicitly saved by you are sent. Original files, declared permission lists, and finding details are not stored in cloud history.</small>
    </section>
  );
}

function ManualAnalysis({ cloudSyncEnabled }: { cloudSyncEnabled: boolean }) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [purpose, setPurpose] = useState("");
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isSavingCloud, setIsSavingCloud] = useState(false);
  const [cloudMessage, setCloudMessage] = useState("");

  const acceptFile = (file?: File) => {
    if (!file) return;
    const extension = file.name.split(".").pop()?.toLowerCase();
    if (!["apk", "json", "csv"].includes(extension ?? "")) {
      setSelectedFile(null);
      setAnalysis(null);
      setError("Unsupported file. Choose an APK, JSON, or CSV report.");
      return;
    }
    if (file.size > MAX_UPLOAD_SIZE_BYTES) {
      setSelectedFile(null);
      setAnalysis(null);
      setError("File exceeds the 100 MB limit.");
      return;
    }
    setSelectedFile(file);
    setAnalysis(null);
    setError("");
    setCloudMessage("");
  };

  const analyzeFile = async () => {
    if (!selectedFile) {
      setError("Choose a report before starting analysis.");
      return;
    }
    if (purpose.length > 500) {
      setError("Purpose must not exceed 500 characters.");
      return;
    }

    setIsAnalyzing(true);
    setError("");
    setAnalysis(null);
    const form = new FormData();
    form.append("file", selectedFile);
    if (purpose.trim()) form.append("purpose", purpose.trim());
    const endpoint = selectedFile.name.toLowerCase().endsWith(".apk")
      ? "analyze/apk"
      : "analyze/report";

    try {
      const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
        method: "POST",
        body: form,
      });
      const payload = await response.json();
      if (!response.ok) {
        const detail = typeof payload.detail === "string"
          ? payload.detail
          : JSON.stringify(payload.detail ?? "The API rejected this report.");
        throw new Error(detail);
      }
      setAnalysis(payload as AnalysisResponse);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Unknown error.";
      setError(
        message === "Failed to fetch"
          ? "Could not reach the local analysis API. Start the backend at http://127.0.0.1:8000 and try again."
          : `Analysis failed: ${message}`,
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const saveToCloud = async () => {
    if (!analysis) return;
    setIsSavingCloud(true);
    setCloudMessage("");
    try {
      const outcome = await saveAnalysisSummary(supabase, cloudSyncEnabled, analysis);
      if (outcome === "saved") {
        setCloudMessage("This summary was saved to your private cloud history. No original file or permission list was uploaded.");
      } else if (outcome === "not_configured") {
        setCloudMessage("Cloud accounts are not configured. Your local analysis is still available.");
      } else {
        setCloudMessage("Enable optional cloud history in Privacy settings and confirm your choice before saving.");
      }
    } catch (cause) {
      setCloudMessage(cause instanceof Error ? cause.message : "Unable to save cloud history.");
    } finally {
      setIsSavingCloud(false);
    }
  };

  return (
    <>
      <PageHeader eyebrow="LOCAL ENGINE · REAL ANALYSIS" title="Analyze a report" description="Analyze an APK manifest or JSON/CSV permission report using the local deterministic policy engine." />
      <div className="analysis-layout"><section className="panel upload-panel"><div className="upload-panel-heading"><span className="upload-icon"><Upload size={20} /></span><div><h2>Choose a file</h2><p>APK, JSON, or CSV · up to 100 MB</p></div></div>
        <label className="drop-zone" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); acceptFile(event.dataTransfer.files[0]); }}><input type="file" accept=".apk,.json,.csv,application/json,text/csv" onChange={(event) => acceptFile(event.currentTarget.files?.[0])} /><span className="drop-icon"><FileArchive size={24} /></span><strong>{selectedFile?.name || "Drop a report here, or browse"}</strong><span>{selectedFile ? "Selected for local analysis" : "APK manifest · JSON · CSV"}</span><span className="button button--secondary">{selectedFile ? "Choose another file" : "Browse files"}</span></label>
        <label className="purpose-label">App purpose <span>Optional</span><input value={purpose} maxLength={500} onChange={(event) => setPurpose(event.target.value)} placeholder="e.g. navigation, photo editing, messaging" /></label>
        <button type="button" className="button button--primary button--wide" disabled={!selectedFile || isAnalyzing} onClick={analyzeFile}>{isAnalyzing ? <><Activity className="loading-icon" size={16} /> Analyzing locally…</> : <><Shield size={16} /> Analyze permissions</>}</button>
        <p className="local-note"><LockKeyhole size={14} /> Files are sent only to the local backend at 127.0.0.1. APKs are not installed or executed.</p>
        {error && <div className="analysis-error" role="alert">{error}</div>}
        {isAnalyzing && <p className="analysis-loading" role="status">Parsing the report and calculating policy-based findings…</p>}
      </section>
        <aside className="analysis-info"><p className="eyebrow">SUPPORTED INPUTS</p><h2>One clear report, three ways in.</h2><div className="format-row"><span><FileArchive size={17} /></span><div><strong>Android APK</strong><small>Static manifest declarations only</small></div><Check size={15} /></div><div className="format-row"><span><FileText size={17} /></span><div><strong>JSON report</strong><small>Structured permission list</small></div><Check size={15} /></div><div className="format-row"><span><FileSpreadsheet size={17} /></span><div><strong>CSV report</strong><small>One permission per row</small></div><Check size={15} /></div><div className="analysis-caveat"><ShieldAlert size={17} /><p><strong>Analysis scope</strong>APK results cover manifest declarations only; this does not determine device grants or observe runtime behavior.</p></div></aside></div>
      {analysis && <AnalysisResultView analysis={analysis} onSaveCloud={saveToCloud} canSaveCloud={cloudSyncEnabled} isSavingCloud={isSavingCloud} cloudMessage={cloudMessage} />}
    </>
  );
}

function AnalysisResultView({ analysis, onSaveCloud, canSaveCloud, isSavingCloud, cloudMessage }: { analysis: AnalysisResponse; onSaveCloud: () => void; canSaveCloud: boolean; isSavingCloud: boolean; cloudMessage: string }) {
  const { report, result } = analysis;
  return (
    <section className="panel analysis-result" aria-live="polite">
      <div className="analysis-result-heading">
        <div><p className="eyebrow">LOCAL ENGINE RESULT · SAVED REPORT #{analysis.analysis_id}</p><h2>{report.app_name || report.package_name || "Unnamed application"}</h2><p>{report.package_name || "Package name unavailable"} · {report.source_format.toUpperCase()} · policy {result.policy_version}</p></div>
        <RiskBadge level={result.risk_band} score={result.score} />
      </div>
      <div className="analysis-result-meta"><span><strong>Purpose</strong>{report.purpose || "Not provided"}</span><span><strong>Declared permissions</strong>{report.permissions.length}</span><span><strong>Findings</strong>{result.findings.length}</span></div>
      <div className="cloud-save-control">
        <button className="button button--secondary" type="button" disabled={!canSaveCloud || isSavingCloud} onClick={onSaveCloud}>
          {isSavingCloud ? "Saving summary…" : "Save summary to cloud history"}
        </button>
        <span>{cloudMessage || (canSaveCloud ? "Cloud history is enabled, but each scan must be saved with this button." : "Optional account sync is off; local analysis is unaffected.")}</span>
      </div>
      <div className="analysis-result-permissions"><strong>Declared permissions</strong>{report.permissions.length ? <ul>{report.permissions.map((permission) => <li key={permission}>{permission}</li>)}</ul> : <p>No permissions were declared in this report.</p>}</div>
      <h3>Findings</h3>
      {result.findings.length === 0 ? <p>No configured permission findings for this application.</p> : <div className="analysis-findings">{result.findings.map((finding) => <article className="analysis-finding" key={finding.finding_id}>
        <div className="analysis-finding-heading"><strong>{finding.category.replaceAll("_", " ")}</strong><span className={`finding-severity finding-severity--${finding.severity}`}>{finding.severity}</span><span className="finding-contribution">+{finding.score_contribution} points</span></div>
        {finding.permissions.length > 0 && <p className="finding-permissions">{finding.permissions.join(", ")}</p>}
        <p>{finding.explanation}</p>
        {finding.evidence.length > 0 && <ul>{finding.evidence.map((item) => <li key={item}>{item}</li>)}</ul>}
        {finding.uncertainty && <p className="finding-uncertainty">Uncertainty: {finding.uncertainty}</p>}
        <div className="finding-recommendation"><strong>Recommended action</strong><p>{finding.recommended_action}</p></div>
      </article>)}</div>}
    </section>
  );
}

function PrivacyPage({ settings, setSettings, setNotice, onSignOut, onAccountOptions, accountUser, cloudSyncEnabled, onCloudSyncChange }: { settings: { localOnly: boolean; alerts: boolean; weeklySummary: boolean }; setSettings: (settings: { localOnly: boolean; alerts: boolean; weeklySummary: boolean }) => void; setNotice: (notice: string) => void; onSignOut: () => void; onAccountOptions: () => void; accountUser: User | null; cloudSyncEnabled: boolean; onCloudSyncChange: (enabled: boolean) => void }) {
  const toggle = (key: keyof typeof settings) => setSettings({ ...settings, [key]: !settings[key] });
  return (
    <>
      <PageHeader eyebrow="YOUR DATA, YOUR CHOICE" title="Privacy settings" description="Control whether you choose to save scan summaries to your private account history." />
      <div className="privacy-layout">
        <section className="panel settings-panel">
          <div className="settings-section">
            <div className="settings-title"><span className="settings-icon"><HardDrive size={18} /></span><div><h2>Data handling</h2><p>Local analysis always works without an account.</p></div></div>
            <SettingRow title="Optional cloud history" detail={accountUser ? "When enabled, you may explicitly save a small scan summary. Files and permission lists are never synced. You will be asked again after reloading." : supabaseConfigured ? "Sign in to optionally save scan summaries. Local analysis remains available." : "Cloud accounts are not configured. Local analysis remains available."} enabled={cloudSyncEnabled} disabled={!accountUser || !supabaseConfigured} onToggle={() => onCloudSyncChange(!cloudSyncEnabled)} />
            {cloudSyncEnabled && <p className="method-note">Turning this off stops future sync and hides cloud history; existing cloud records remain in your account.</p>}
          </div>
          <div className="settings-section">
            <div className="settings-title"><span className="settings-icon settings-icon--blue"><Bell size={18} /></span><div><h2>Interface preferences</h2><p>These switches are local demo preferences only.</p></div></div>
            <SettingRow title="Permission review alerts" detail="Show a count of unread synthetic alerts in navigation." enabled={settings.alerts} onToggle={() => toggle("alerts")} />
            <SettingRow title="Weekly privacy summary" detail="A future preference for an optional local summary." enabled={settings.weeklySummary} onToggle={() => toggle("weeklySummary")} />
          </div>
          <div className="settings-section settings-section--last">
            <div className="settings-title"><span className="settings-icon"><Fingerprint size={18} /></span><div><h2>Your account</h2><p>{accountUser ? "Supabase email account" : "No account is currently signed in."}</p></div></div>
            <div className="account-row"><span>Signed-in identity</span><strong>{accountUser?.email ?? "Local demo session"}</strong></div>
            {accountUser
              ? <button className="button button--secondary" onClick={() => void onSignOut()}><LogOut size={15} /> Sign out</button>
              : <div className="account-actions">
                <button className="button button--secondary" onClick={onAccountOptions}>Sign in or create account</button>
                <button className="text-button" onClick={() => void onSignOut()}>Exit local demo</button>
              </div>}
          </div>
        </section>
        <aside className="panel privacy-summary"><span className="privacy-shield"><ShieldCheck size={24} /></span><p className="eyebrow">PRIVACY PROMISE</p><h2>Clarity without taking control.</h2><p>PermissionGuard helps explain declarations. It never silently changes app permissions or replaces Android's system controls.</p><div className="privacy-points"><span><Check size={14} />No external AI service</span><span><Check size={14} />No APK execution</span><span><Check size={14} />No background device scan</span></div><button className="text-button" onClick={() => setNotice("Declared permissions are not the same as granted permissions or runtime use.")}>Read the methodology <ArrowRight size={14} /></button></aside></div>
    </>
  );
}

function SettingRow({ title, detail, enabled, disabled = false, onToggle }: { title: string; detail: string; enabled: boolean; disabled?: boolean; onToggle: () => void }) {
  return <div className="setting-row"><span><strong>{title}</strong><small>{detail}</small></span><button className={`toggle${enabled ? " toggle--on" : ""}`} type="button" role="switch" aria-checked={enabled} aria-label={title} disabled={disabled} onClick={onToggle}><span /></button></div>;
}

export default App;
