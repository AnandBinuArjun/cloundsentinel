import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Lock, Search, ShieldCheck } from "lucide-react";
import { fetchAuditEvents, fetchAuthMe } from "../lib/api";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function AuditLogsPage() {
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["audit-events"],
    queryFn: fetchAuditEvents,
    retry: false,
  });

  const items = query.data?.items ?? [];
  const roles = useMemo(
    () => Array.from(new Set(items.map((e) => e.actor_role))).sort(),
    [items]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((ev) => {
      if (roleFilter && ev.actor_role !== roleFilter) return false;
      if (!q) return true;
      return (
        ev.action.toLowerCase().includes(q) ||
        ev.resource_type.toLowerCase().includes(q) ||
        ev.resource_id.toLowerCase().includes(q) ||
        ev.request_id.toLowerCase().includes(q)
      );
    });
  }, [items, search, roleFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Append-Only Accountability"
        title="Audit Logs"
        description="Tenant-scoped immutable security audit trail recording connector validations, assessments, finding dispositions, report exports, and remediation approvals."
      />

      <div className="flex flex-wrap items-center gap-2.5 rounded-[12px] border border-[#243142] bg-[#111925] p-3.5">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
          <input
            placeholder="Search action, resource ID, or request ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] py-2 pl-9 pr-3 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
          />
        </div>
        <select
          aria-label="Filter actor role"
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Roles</option>
          {roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>

      <Panel
        title={`Audit Events (${filtered.length})`}
        subtitle="Click any row to inspect structured event metadata"
        noPadding
      >
        {query.isPending && (
          <div className="p-5">
            <LoadingState label="Loading immutable audit trail..." />
          </div>
        )}
        {query.isError && (
          <div className="p-5">
            <ErrorBanner message={query.error.message} />
          </div>
        )}
        {query.data && filtered.length === 0 && (
          <div className="p-5">
            <EmptyState
              title="No Audit Events Found"
              description="Security-relevant actions performed inside this tenant will appear here automatically."
            />
          </div>
        )}
        {query.data && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#243142] bg-[#0C121B] text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                <tr>
                  <th className="px-5 py-3">Timestamp (UTC)</th>
                  <th className="px-3 py-3">Action</th>
                  <th className="px-3 py-3">Actor Role</th>
                  <th className="px-3 py-3">Resource</th>
                  <th className="px-5 py-3">Request ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#243142]">
                {filtered.map((ev) => {
                  const isOpen = expandedId === ev.id;
                  return (
                    <Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : ev.id)}
                        className="cursor-pointer transition-colors hover:bg-[#1C293A]/60"
                      >
                        <td className="px-5 py-2.5 font-mono text-[11px] text-[#A0AEC0]">
                          {ev.created_at.slice(0, 19).replace("T", " ")}Z
                        </td>
                        <td className="px-3 py-2.5 font-mono font-semibold text-[#00D6A0]">
                          {ev.action}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[#F1F5F9]">
                          {ev.actor_role}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-[#A0AEC0]">
                          {ev.resource_type}:{ev.resource_id}
                        </td>
                        <td className="px-5 py-2.5 font-mono text-[11px] text-[#64748B]">
                          {ev.request_id}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[#080D14]">
                          <td colSpan={5} className="px-5 py-3">
                            <pre className="overflow-x-auto rounded-[8px] border border-[#243142] bg-[#111925] p-3 font-mono text-[11px] text-[#A0AEC0]">
                              {JSON.stringify(ev.details, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

export function SettingsPage() {
  const query = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Server-Verified Session Context"
        title="Settings & Access Context"
        description="OIDC identity, active tenant isolation boundary, and RBAC permission grants resolved strictly from backend persistence."
      />

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel title="Active Security Context" className="lg:col-span-2">
          {query.isPending && <LoadingState label="Loading verified OIDC session..." />}
          {query.isError && <ErrorBanner message={query.error.message} />}
          {query.data && (
            <div className="space-y-6 text-xs">
              <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5">
                  <dt className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                    Email
                  </dt>
                  <dd className="mt-1 font-mono text-[#F1F5F9]">{query.data.email}</dd>
                </div>
                <div className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5">
                  <dt className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                    OIDC Subject
                  </dt>
                  <dd className="mt-1 font-mono text-[#F1F5F9]">{query.data.subject}</dd>
                </div>
                <div className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5">
                  <dt className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                    Verified Tenant ID
                  </dt>
                  <dd className="mt-1 font-mono text-[#00D6A0]">{query.data.tenant_id}</dd>
                </div>
                <div className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5">
                  <dt className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                    Assigned RBAC Role
                  </dt>
                  <dd className="mt-1 font-mono uppercase text-[#F1F5F9]">
                    {query.data.role.replace(/_/g, " ")}
                  </dd>
                </div>
              </dl>

              <div>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#A0AEC0]">
                  Granted RBAC Permissions ({query.data.permissions.length})
                </h3>
                <div className="mt-2.5 flex flex-wrap gap-2">
                  {query.data.permissions.map((perm) => (
                    <span
                      key={perm}
                      className="rounded-md border border-[#00D6A0]/30 bg-[#00D6A0]/10 px-2.5 py-1 font-mono text-[11px] text-[#00D6A0]"
                    >
                      {perm}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Panel>

        <Panel title="Platform Security Invariants" subtitle="Enforced server-side">
          <ul className="space-y-3 text-xs text-[#A0AEC0]">
            <li className="flex items-start gap-2.5">
              <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Default read-only cloud assessment boundary</span>
            </li>
            <li className="flex items-start gap-2.5">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Tenant isolation enforced by server-verified membership + PostgreSQL RLS</span>
            </li>
            <li className="flex items-start gap-2.5">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Zero cloud secrets persisted in browser storage or frontend bundles</span>
            </li>
            <li className="flex items-start gap-2.5">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Separation of duties required on all remediation approvals</span>
            </li>
          </ul>
        </Panel>
      </div>
    </div>
  );
}
