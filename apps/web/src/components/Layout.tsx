import { useEffect, useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bell,
  ChevronRight,
  Cloud,
  Database,
  FileBarChart2,
  FileCheck2,
  FileText,
  History,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogIn,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  User,
  Wrench,
  X,
} from "lucide-react";
import {
  fetchAuthMe,
  fetchDashboardSummary,
  getStoredToken,
  setStoredToken,
} from "../lib/api";
import { ConnectorStatus } from "./Badges";
import { CommandPalette } from "./CommandPalette";

interface NavItem {
  to: string;
  label: string;
  group: string;
  icon: ReactNode;
}

interface NavGroup {
  heading: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    heading: "WORKSPACE",
    items: [
      { to: "/", label: "Overview", group: "Workspace", icon: <LayoutDashboard className="h-4 w-4 shrink-0" /> },
      { to: "/aws", label: "AWS Environment", group: "Workspace", icon: <Cloud className="h-4 w-4 shrink-0 text-[#F59E0B]" /> },
      { to: "/azure", label: "Azure Environment", group: "Workspace", icon: <Cloud className="h-4 w-4 shrink-0 text-[#38BDF8]" /> },
      { to: "/connections", label: "Cloud Connections", group: "Workspace", icon: <Cloud className="h-4 w-4 shrink-0" /> },
    ],
  },
  {
    heading: "SECURITY POSTURE",
    items: [
      { to: "/assets", label: "Asset Inventory", group: "Security Posture", icon: <Database className="h-4 w-4 shrink-0" /> },
      { to: "/findings", label: "Security Findings", group: "Security Posture", icon: <ShieldAlert className="h-4 w-4 shrink-0" /> },
      { to: "/identity", label: "Identity & Access", group: "Security Posture", icon: <KeyRound className="h-4 w-4 shrink-0" /> },
    ],
  },
  {
    heading: "DETECTION & GOVERNANCE",
    items: [
      { to: "/detections", label: "Threat Detection", group: "Detection & Governance", icon: <Shield className="h-4 w-4 shrink-0" /> },
      { to: "/compliance", label: "Compliance Centre", group: "Detection & Governance", icon: <FileCheck2 className="h-4 w-4 shrink-0" /> },
      { to: "/assessments", label: "Assessment History", group: "Detection & Governance", icon: <History className="h-4 w-4 shrink-0" /> },
    ],
  },
  {
    heading: "RESPONSE",
    items: [
      { to: "/remediations", label: "Remediation Centre", group: "Response", icon: <Wrench className="h-4 w-4 shrink-0" /> },
      { to: "/reports", label: "Reports & Evidence", group: "Response", icon: <FileBarChart2 className="h-4 w-4 shrink-0" /> },
    ],
  },
  {
    heading: "PLATFORM",
    items: [
      { to: "/settings", label: "Settings", group: "Platform", icon: <Settings className="h-4 w-4 shrink-0" /> },
      { to: "/audit", label: "Audit Logs", group: "Platform", icon: <FileText className="h-4 w-4 shrink-0" /> },
      { to: "/system", label: "System Health", group: "Platform", icon: <Activity className="h-4 w-4 shrink-0" /> },
    ],
  },
];

const FLAT_NAV = NAV_GROUPS.flatMap((g) => g.items);

export function Layout({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();

  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem("cs_sidebar_collapsed") === "true";
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const hasToken = Boolean(getStoredToken());

  const meQuery = useQuery({
    queryKey: ["layout-auth-me", hasToken],
    queryFn: fetchAuthMe,
    enabled: hasToken,
    retry: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary", "all"],
    queryFn: () => fetchDashboardSummary(),
    enabled: hasToken,
    retry: false,
  });

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setNotifOpen(false);
        setProfileOpen(false);
        setMobileOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem("cs_sidebar_collapsed", String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  const activeRoute = useMemo(() => {
    const exact = FLAT_NAV.find((n) => n.to === location.pathname);
    if (exact) return exact;
    if (location.pathname === "/login") {
      return { to: "/login", label: "Sign In", group: "Authentication" };
    }
    if (location.pathname.startsWith("/findings/")) {
      return { to: location.pathname, label: "Finding Investigation", group: "Security Posture" };
    }
    return { to: "/", label: "Security Overview", group: "Workspace" };
  }, [location.pathname]);

  const operationalAlerts = useMemo(() => {
    const items: Array<{ id: string; title: string; detail: string; to: string }> = [];
    if (summaryQuery.data) {
      if (summaryQuery.data.connections.error > 0) {
        items.push({
          id: "conn-err",
          title: `${summaryQuery.data.connections.error} connector(s) failing preflight`,
          detail: "Review IAM / Azure Identity permissions in Cloud Connections.",
          to: "/connections",
        });
      }
      if (summaryQuery.data.findings.by_severity.critical > 0) {
        items.push({
          id: "crit-find",
          title: `${summaryQuery.data.findings.by_severity.critical} open critical finding(s)`,
          detail: "Prioritize triage in Security Findings.",
          to: "/findings",
        });
      }
      if (summaryQuery.data.detections.critical > 0) {
        items.push({
          id: "crit-det",
          title: `${summaryQuery.data.detections.critical} critical detection event(s)`,
          detail: "Inspect correlated cloud events in Threat Detection.",
          to: "/detections",
        });
      }
    }
    return items;
  }, [summaryQuery.data]);

  const lastSyncedLabel = useMemo(() => {
    if (!summaryQuery.dataUpdatedAt) return "Not synced";
    return new Date(summaryQuery.dataUpdatedAt).toISOString().slice(11, 19) + " UTC";
  }, [summaryQuery.dataUpdatedAt]);

  const handleSignOut = () => {
    setStoredToken("");
    setProfileOpen(false);
    void queryClient.clear();
    navigate("/login");
  };

  if (location.pathname === "/login") {
    return (
      <div className="min-h-screen bg-[#080D14] text-[#F1F5F9]">
        <div className="mx-auto max-w-6xl px-6 py-8">{children}</div>
      </div>
    );
  }

  const renderSidebarInner = (isCollapsed: boolean, isMobile = false) => (
    <div className="flex h-full flex-col bg-[#0C121B]">
      {/* Brand header */}
      <div
        className={`flex h-14 items-center border-b border-[#243142] ${
          isCollapsed ? "justify-center px-2" : "justify-between px-4"
        }`}
      >
        <NavLink
          to="/"
          onClick={() => setMobileOpen(false)}
          className="flex items-center gap-2.5 overflow-hidden"
          title="CloudSentinel — Security Intelligence Workspace"
        >
          <img
            src="/cloudsentinel-icon.png"
            alt="CloudSentinel"
            className="h-8 w-8 shrink-0 object-contain"
          />
          {!isCollapsed && (
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold tracking-tight text-[#F1F5F9]">
                CloudSentinel
              </div>
              <div className="truncate font-mono text-[10px] text-[#64748B]">
                Security Intelligence
              </div>
            </div>
          )}
        </NavLink>
        {isMobile ? (
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation menu"
            className="rounded-[8px] p-1 text-[#A0AEC0] hover:bg-[#172131] hover:text-[#F1F5F9]"
          >
            <X className="h-4 w-4" />
          </button>
        ) : (
          !isCollapsed && (
            <button
              type="button"
              onClick={toggleCollapsed}
              aria-label="Collapse sidebar"
              title="Collapse sidebar"
              className="rounded-[8px] p-1 text-[#64748B] hover:bg-[#172131] hover:text-[#F1F5F9]"
            >
              <PanelLeftClose className="h-4 w-4" />
            </button>
          )
        )}
      </div>

      {/* Expand button when collapsed */}
      {isCollapsed && !isMobile && (
        <div className="flex justify-center border-b border-[#243142] py-2">
          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label="Expand sidebar"
            title="Expand sidebar"
            className="rounded-[8px] p-1.5 text-[#64748B] hover:bg-[#172131] hover:text-[#F1F5F9]"
          >
            <PanelLeftOpen className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Grouped nav links */}
      <nav
        aria-label="Primary Navigation"
        className="flex-1 overflow-y-auto px-2.5 py-4 space-y-5"
      >
        {NAV_GROUPS.map((group) => (
          <div key={group.heading}>
            {!isCollapsed && (
              <div className="px-2.5 pb-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-[#64748B]">
                {group.heading}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  title={isCollapsed ? item.label : undefined}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    [
                      "relative flex items-center rounded-[8px] text-[13px] font-medium transition-colors",
                      isCollapsed ? "justify-center p-2.5" : "gap-2.5 px-2.5 py-2",
                      isActive
                        ? "bg-[#172131] text-[#F1F5F9]"
                        : "text-[#A0AEC0] hover:bg-[#1C293A]/70 hover:text-[#F1F5F9]",
                    ].join(" ")
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span
                          aria-hidden="true"
                          className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-[#00D6A0]"
                        />
                      )}
                      {item.icon}
                      {!isCollapsed && <span className="truncate">{item.label}</span>}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Sidebar operational footer */}
      <div className="border-t border-[#243142] p-3 space-y-2">
        {isCollapsed ? (
          <div className="flex flex-col items-center gap-2">
            <span
              title="Read-Only Security Default"
              className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-[#243142] bg-[#111925] text-[#00D6A0]"
            >
              <Lock className="h-3.5 w-3.5" />
            </span>
          </div>
        ) : (
          <>
            <div className="rounded-[8px] border border-[#243142] bg-[#111925] p-2.5 space-y-1.5">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-[#F1F5F9]">
                <Lock className="h-3.5 w-3.5 text-[#00D6A0]" />
                <span>Read-Only Default</span>
              </div>
              {summaryQuery.data ? (
                <ConnectorStatus
                  healthy={summaryQuery.data.connections.healthy}
                  total={summaryQuery.data.connections.total}
                />
              ) : (
                <span className="block text-[11px] text-[#64748B]">Sign in for connector status</span>
              )}
            </div>
            {meQuery.data && (
              <div className="flex items-center gap-2 rounded-[8px] px-2 py-1 text-[11px]">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-[#243142] bg-[#172131] font-mono text-[10px] font-semibold text-[#00D6A0]">
                  {meQuery.data.email.slice(0, 2).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-[#F1F5F9]">{meQuery.data.email}</div>
                  <div className="truncate font-mono text-[10px] uppercase text-[#64748B]">
                    {meQuery.data.role.replace(/_/g, " ")}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden bg-[#080D14] text-[#F1F5F9]">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-[8px] focus:bg-[#00D6A0] focus:px-3 focus:py-2 focus:text-xs focus:font-semibold focus:text-[#080D14]"
      >
        Skip to main content
      </a>

      {/* Desktop Collapsible Sidebar (Fixed Viewport Height, Independent Scroll) */}
      <aside
        className={`hidden h-screen shrink-0 border-r border-[#243142] transition-[width] duration-200 lg:block ${
          collapsed ? "w-[72px]" : "w-[256px]"
        }`}
      >
        {renderSidebarInner(collapsed)}
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div className="h-full w-[264px] border-r border-[#243142]">
            {renderSidebarInner(false, true)}
          </div>
          <div
            className="flex-1 bg-black/70"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
        </div>
      )}

      {/* Main Column */}
      <div className="flex h-screen min-w-0 flex-1 flex-col">
        {/* Persistent Top Navigation Bar */}
        <header className="relative z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-[#243142] bg-[#080D14]/95 px-4 backdrop-blur-sm sm:px-6">
          {/* Left: Mobile trigger + Breadcrumbs */}
          <div className="flex min-w-0 items-center gap-2.5">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
              className="rounded-[8px] border border-[#243142] bg-[#111925] p-1.5 text-[#A0AEC0] hover:text-[#F1F5F9] lg:hidden"
            >
              <Menu className="h-4 w-4" />
            </button>

            <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-xs">
              <span className="hidden text-[#64748B] sm:inline">{activeRoute.group}</span>
              <ChevronRight className="hidden h-3.5 w-3.5 text-[#64748B] sm:inline" />
              <span className="truncate font-semibold text-[#F1F5F9]">{activeRoute.label}</span>
            </nav>
          </div>

          {/* Center: Global Search / Command Palette Trigger */}
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="hidden max-w-sm flex-1 items-center justify-between rounded-[8px] border border-[#243142] bg-[#111925] px-3 py-1.5 text-xs text-[#64748B] transition-colors hover:border-[#00D6A0]/40 hover:text-[#A0AEC0] md:flex"
          >
            <span className="flex items-center gap-2">
              <Search className="h-3.5 w-3.5" />
              <span>Search workspace or jump to view...</span>
            </span>
            <kbd className="rounded border border-[#243142] bg-[#0C121B] px-1.5 py-0.5 font-mono text-[10px] text-[#A0AEC0]">
              Ctrl K
            </kbd>
          </button>

          {/* Right: Mobile Search, Data freshness, Notifications, Tenant, User Menu */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open command palette"
              className="rounded-[8px] border border-[#243142] bg-[#111925] p-2 text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9] md:hidden"
            >
              <Search className="h-3.5 w-3.5" />
            </button>

            {/* Data freshness */}
            <button
              type="button"
              onClick={() => void queryClient.invalidateQueries()}
              title="Refresh active workspace data"
              className="hidden items-center gap-1.5 rounded-[8px] border border-[#243142] bg-[#111925] px-2.5 py-1.5 font-mono text-[11px] text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9] xl:inline-flex"
            >
              <RefreshCw className="h-3 w-3 text-[#00D6A0]" />
              <span>{lastSyncedLabel}</span>
            </button>

            {/* Notifications popover (strictly real backend state) */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setNotifOpen((p) => !p);
                  setProfileOpen(false);
                }}
                aria-label="Operational notifications"
                className="relative rounded-[8px] border border-[#243142] bg-[#111925] p-2 text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9]"
              >
                <Bell className="h-3.5 w-3.5" />
                {operationalAlerts.length > 0 && (
                  <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-[#F43F5E]" />
                )}
              </button>
              {notifOpen && (
                <>
                  <div
                    className="fixed inset-0 z-20"
                    onClick={() => setNotifOpen(false)}
                    aria-hidden="true"
                  />
                  <div className="absolute right-0 z-30 mt-2 w-80 rounded-[12px] border border-[#243142] bg-[#111925] p-3 shadow-2xl">
                    <div className="flex items-center justify-between border-b border-[#243142] pb-2 text-xs font-semibold text-[#F1F5F9]">
                      <span>Operational Status</span>
                      <span className="font-mono text-[10px] text-[#64748B]">Backend-Verified</span>
                    </div>
                    <div className="mt-2 space-y-2">
                      {operationalAlerts.length === 0 ? (
                        <p className="py-3 text-center text-xs text-[#64748B]">
                          No active critical posture alerts.
                        </p>
                      ) : (
                        operationalAlerts.map((al) => (
                          <button
                            key={al.id}
                            type="button"
                            onClick={() => {
                              setNotifOpen(false);
                              navigate(al.to);
                            }}
                            className="w-full rounded-[8px] border border-[#243142] bg-[#172131] p-2.5 text-left text-xs hover:bg-[#1C293A]"
                          >
                            <div className="font-semibold text-[#F1F5F9]">{al.title}</div>
                            <div className="mt-0.5 text-[11px] text-[#A0AEC0]">{al.detail}</div>
                          </button>
                        ))
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Tenant badge */}
            {meQuery.data && (
              <span
                title={`Verified Tenant ID: ${meQuery.data.tenant_id}`}
                className="hidden rounded-[8px] border border-[#243142] bg-[#111925] px-2.5 py-1.5 font-mono text-[11px] text-[#A0AEC0] lg:inline-flex"
              >
                tenant:{meQuery.data.tenant_id.slice(0, 8)}
              </span>
            )}

            {/* User Profile Menu */}
            {meQuery.data ? (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => {
                    setProfileOpen((p) => !p);
                    setNotifOpen(false);
                  }}
                  aria-label="User profile menu"
                  className="inline-flex items-center gap-2 rounded-[8px] border border-[#243142] bg-[#111925] px-2.5 py-1.5 text-xs text-[#F1F5F9] hover:bg-[#1C293A]"
                >
                  <User className="h-3.5 w-3.5 text-[#00D6A0]" />
                  <span className="hidden max-w-[140px] truncate sm:inline">
                    {meQuery.data.email}
                  </span>
                </button>
                {profileOpen && (
                  <>
                    <div
                      className="fixed inset-0 z-20"
                      onClick={() => setProfileOpen(false)}
                      aria-hidden="true"
                    />
                    <div className="absolute right-0 z-30 mt-2 w-60 rounded-[12px] border border-[#243142] bg-[#111925] p-2 shadow-2xl text-xs">
                      <div className="border-b border-[#243142] px-2.5 py-2">
                        <div className="truncate font-semibold text-[#F1F5F9]">
                          {meQuery.data.email}
                        </div>
                        <div className="mt-0.5 font-mono text-[10px] uppercase text-[#00D6A0]">
                          {meQuery.data.role.replace(/_/g, " ")}
                        </div>
                      </div>
                      <div className="mt-1 space-y-0.5">
                        <button
                          type="button"
                          onClick={() => {
                            setProfileOpen(false);
                            navigate("/settings");
                          }}
                          className="flex w-full items-center gap-2 rounded-[8px] px-2.5 py-2 text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9]"
                        >
                          <Settings className="h-3.5 w-3.5" />
                          <span>Tenant Settings</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleSignOut}
                          className="flex w-full items-center gap-2 rounded-[8px] px-2.5 py-2 text-[#F43F5E] hover:bg-[#F43F5E]/10"
                        >
                          <LogOut className="h-3.5 w-3.5" />
                          <span>Sign Out</span>
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <NavLink
                to="/login"
                className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3 py-1.5 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25"
              >
                <LogIn className="h-3.5 w-3.5" />
                <span>Sign In</span>
              </NavLink>
            )}
          </div>
        </header>

        {/* Main Workspace Canvas (Independently Scrollable) */}
        <main id="main-content" className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
