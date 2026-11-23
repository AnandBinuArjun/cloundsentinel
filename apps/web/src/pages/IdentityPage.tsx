import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Cloud, KeyRound, ShieldAlert, Users } from "lucide-react";
import { fetchIdentityAnalysis } from "../lib/api";
import { DataSourceBadge, ProviderBadge, SeverityBadge } from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function IdentityPage() {
  const [providerFilter, setProviderFilter] = useState("");
  const [expandedEvidence, setExpandedEvidence] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["identity-analysis"],
    queryFn: fetchIdentityAnalysis,
    retry: false,
  });

  const reports = query.data?.reports ?? [];
  const filteredReports = useMemo(
    () =>
      providerFilter
        ? reports.filter((r) => r.provider.toLowerCase() === providerFilter)
        : reports,
    [reports, providerFilter]
  );

  const totalPrincipals = reports.reduce((acc, r) => acc + r.principals_reviewed, 0);
  const totalFindings = reports.reduce((acc, r) => acc + r.findings.length, 0);
  const criticalHigh = reports.reduce(
    (acc, r) =>
      acc +
      r.findings.filter(
        (f) => f.severity.toLowerCase() === "critical" || f.severity.toLowerCase() === "high"
      ).length,
    0
  );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Least-Privilege Entitlement Review"
        title="Identity & Access Security"
        description="AWS IAM privilege, MFA, and trust-policy review alongside Microsoft Azure RBAC & Service Principal exposure analysis. Every report explicitly documents effective-permission limitations."
        actions={
          <select
            aria-label="Filter cloud provider"
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
            className="rounded-[8px] border border-[#243142] bg-[#0C121B] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
          >
            <option value="">All Clouds</option>
            <option value="aws">AWS IAM</option>
            <option value="azure">Azure Entra / RBAC</option>
          </select>
        }
      />

      <section aria-label="Identity Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Environments Analyzed"
          value={reports.length}
          subtitle="AWS & Azure scopes"
          icon={Cloud}
          accent="accent"
        />
        <MetricCard
          label="Principals Reviewed"
          value={totalPrincipals}
          subtitle="Users, roles & service principals"
          icon={Users}
          accent="info"
        />
        <MetricCard
          label="Identity Risks"
          value={totalFindings}
          subtitle="Privilege & trust findings"
          icon={KeyRound}
          accent={totalFindings > 0 ? "warning" : "success"}
        />
        <MetricCard
          label="Critical & High"
          value={criticalHigh}
          subtitle="Priority privilege reductions"
          icon={ShieldAlert}
          accent={criticalHigh > 0 ? "critical" : "success"}
        />
      </section>

      {query.isPending && <LoadingState label="Analyzing IAM and Azure RBAC entitlements..." />}
      {query.isError && <ErrorBanner message={query.error.message} />}
      {query.data && filteredReports.length === 0 && (
        <EmptyState
          title="No Identity Reports Available"
          description="Register an AWS or Azure connector to run identity and access posture analysis."
        />
      )}
      {query.data &&
        filteredReports.map((report) => (
          <Panel
            key={report.connection_id}
            title={report.connection_name}
            subtitle={`Scope: ${report.account_ref} · Principals Reviewed: ${report.principals_reviewed}`}
            action={
              <div className="flex items-center gap-2">
                <ProviderBadge provider={report.provider} />
                <DataSourceBadge source={report.data_source} />
              </div>
            }
          >
            <div className="space-y-4">
              <div className="rounded-[10px] border border-[#F59E0B]/35 bg-[#F59E0B]/10 p-3.5 text-xs text-[#F1F5F9] space-y-1.5">
                <div className="flex items-center gap-1.5 font-semibold text-[#F59E0B]">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Explicit Analysis Limitations</span>
                </div>
                <ul className="list-disc pl-5 space-y-0.5 text-[11px] text-[#A0AEC0]">
                  {report.limitations.map((lim) => (
                    <li key={lim}>{lim}</li>
                  ))}
                </ul>
              </div>

              {report.findings.length === 0 ? (
                <p className="text-xs text-[#A0AEC0]">
                  No high-risk identity patterns detected in this scope.
                </p>
              ) : (
                <div className="grid gap-3.5 md:grid-cols-2">
                  {report.findings.map((item, idx) => {
                    const key = `${report.connection_id}-${item.principal_id}-${idx}`;
                    const isExpanded = expandedEvidence === key;
                    return (
                      <div
                        key={key}
                        className="rounded-[12px] border border-[#243142] bg-[#172131]/65 p-4 text-xs space-y-2.5"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2 font-mono font-semibold text-[#F1F5F9] break-all">
                            <KeyRound className="h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
                            <span>{item.principal_id}</span>
                          </div>
                          <SeverityBadge severity={item.severity} />
                        </div>
                        <div className="text-[#A0AEC0]">
                          Risk Category:{" "}
                          <span className="font-mono text-[#F1F5F9]">{item.risk_category}</span>{" "}
                          · Principal:{" "}
                          <span className="font-mono text-[#F1F5F9]">{item.principal_type}</span>
                        </div>
                        <div className="rounded-[8px] border border-[#243142] bg-[#080D14] p-2.5 text-[#00D6A0]/90">
                          {item.recommendation}
                        </div>
                        <button
                          type="button"
                          onClick={() => setExpandedEvidence(isExpanded ? null : key)}
                          className="font-mono text-[11px] text-[#A0AEC0] hover:text-[#00D6A0]"
                        >
                          {isExpanded ? "Hide evidence payload ▲" : "Inspect evidence payload ▼"}
                        </button>
                        {isExpanded && (
                          <pre className="overflow-x-auto rounded-[8px] border border-[#243142] bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                            {JSON.stringify(item.evidence, null, 2)}
                          </pre>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </Panel>
        ))}
    </div>
  );
}
