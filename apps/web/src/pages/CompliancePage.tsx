import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, ClipboardCheck, ShieldAlert } from "lucide-react";
import { fetchCompliance } from "../lib/api";
import { StatusBadge } from "../components/Badges";
import { ComplianceProgress } from "../components/ComplianceProgress";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState("all");
  const [statusFilter, setStatusFilter] = useState("");

  const query = useQuery({
    queryKey: ["compliance"],
    queryFn: fetchCompliance,
    retry: false,
  });

  const frameworks = query.data?.frameworks ?? [];

  const totals = useMemo(() => {
    return frameworks.reduce(
      (acc, fw) => ({
        controls: acc.controls + fw.summary.total_controls,
        passed: acc.passed + fw.summary.passed,
        failed: acc.failed + fw.summary.failed,
        na: acc.na + fw.summary.not_assessed_or_error,
      }),
      { controls: 0, passed: 0, failed: 0, na: 0 }
    );
  }, [frameworks]);

  const visibleFrameworks = useMemo(
    () =>
      selectedFramework === "all"
        ? frameworks
        : frameworks.filter((fw) => fw.id === selectedFramework),
    [frameworks, selectedFramework]
  );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Version-Controlled Governance Mappings"
        title="Compliance Centre"
        description="Automated technical control posture across CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, and ISO/IEC 27001:2022 with explicit coverage limitations."
      />

      {query.isPending && <LoadingState label="Evaluating compliance mappings..." />}
      {query.isError && <ErrorBanner message={query.error.message} />}

      {query.data && (
        <>
          <div className="flex items-start gap-2.5 rounded-[12px] border border-[#F59E0B]/35 bg-[#F59E0B]/10 p-4 text-xs text-[#F1F5F9]">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#F59E0B]" />
            <span className="leading-relaxed text-[#A0AEC0]">
              <strong className="text-[#F59E0B]">Non-Certification Notice:</strong>{" "}
              {query.data.disclaimer}
            </span>
          </div>

          <section aria-label="Compliance Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Frameworks Mapped"
              value={frameworks.length}
              subtitle={`${totals.controls} technical controls`}
              icon={ClipboardCheck}
              accent="accent"
            />
            <MetricCard
              label="Controls Passed"
              value={totals.passed}
              subtitle="Verified via cloud rules"
              icon={CheckCircle2}
              accent="success"
            />
            <MetricCard
              label="Controls Failed"
              value={totals.failed}
              subtitle="Linked to open findings"
              icon={ShieldAlert}
              accent={totals.failed > 0 ? "critical" : "success"}
            />
            <MetricCard
              label="Not Assessed / Error"
              value={totals.na}
              subtitle="Never coerced to PASS"
              icon={AlertTriangle}
              accent="neutral"
            />
          </section>

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-[12px] border border-[#243142] bg-[#111925] p-3.5">
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => setSelectedFramework("all")}
                className={`rounded-[8px] px-3 py-1.5 text-xs font-medium transition-colors ${
                  selectedFramework === "all"
                    ? "border border-[#00D6A0]/40 bg-[#00D6A0]/15 text-[#00D6A0]"
                    : "border border-[#243142] bg-[#080D14] text-[#A0AEC0] hover:text-[#F1F5F9]"
                }`}
              >
                All Frameworks ({frameworks.length})
              </button>
              {frameworks.map((fw) => (
                <button
                  key={fw.id}
                  type="button"
                  onClick={() => setSelectedFramework(fw.id)}
                  className={`rounded-[8px] px-3 py-1.5 text-xs font-medium transition-colors ${
                    selectedFramework === fw.id
                      ? "border border-[#00D6A0]/40 bg-[#00D6A0]/15 text-[#00D6A0]"
                      : "border border-[#243142] bg-[#080D14] text-[#A0AEC0] hover:text-[#F1F5F9]"
                  }`}
                >
                  {fw.name}
                </button>
              ))}
            </div>

            <select
              aria-label="Filter control status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-1.5 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            >
              <option value="">All Control Statuses</option>
              <option value="fail">Failed Only</option>
              <option value="pass">Passed Only</option>
              <option value="not_assessed">Not Assessed</option>
            </select>
          </div>

          <div className="space-y-5">
            {visibleFrameworks.map((fw) => {
              const filteredControls = statusFilter
                ? fw.controls.filter((c) => c.status.toLowerCase() === statusFilter)
                : fw.controls;

              return (
                <Panel
                  key={fw.id}
                  title={`${fw.name} v${fw.version}`}
                  subtitle={fw.description}
                >
                  <div className="mb-5 rounded-[10px] border border-[#243142] bg-[#0C121B] p-4 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="font-medium text-[#A0AEC0]">Technical Control Coverage</span>
                      <div className="flex items-center gap-3 font-mono text-[11px] tabular-nums">
                        <span className="text-[#10B981]">Pass {fw.summary.passed}</span>
                        <span className="text-[#F43F5E]">Fail {fw.summary.failed}</span>
                        <span className="text-[#64748B]">
                          N/A {fw.summary.not_assessed_or_error}
                        </span>
                        <span className="rounded-md border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-2 py-0.5 font-semibold text-[#00D6A0]">
                          {fw.summary.technical_pass_rate_pct === null
                            ? "N/A"
                            : `${fw.summary.technical_pass_rate_pct}%`}
                        </span>
                      </div>
                    </div>
                    <ComplianceProgress
                      passed={fw.summary.passed}
                      failed={fw.summary.failed}
                      notAssessedOrError={fw.summary.not_assessed_or_error}
                      total={fw.summary.total_controls}
                    />
                  </div>

                  {filteredControls.length === 0 ? (
                    <EmptyState
                      title="No Matching Controls"
                      description="No controls in this framework match the active status filter."
                    />
                  ) : (
                    <div className="space-y-2.5">
                      {filteredControls.map((ctrl) => (
                        <div
                          key={ctrl.control_id}
                          className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5 text-xs space-y-1.5"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-semibold text-[#F1F5F9]">
                              <span className="mr-2 font-mono text-[#00D6A0]">
                                {ctrl.control_id}
                              </span>
                              {ctrl.title}
                            </span>
                            <StatusBadge status={ctrl.status} />
                          </div>
                          <div className="text-[#A0AEC0]">
                            Rules:{" "}
                            <span className="font-mono text-[#F1F5F9]">
                              {ctrl.related_rules.join(", ")}
                            </span>{" "}
                            · Coverage:{" "}
                            <span className="font-mono text-[#A0AEC0]">
                              {ctrl.coverage_status}
                            </span>
                          </div>
                          <div className="text-[11px] text-[#64748B]">
                            <strong className="text-[#A0AEC0]">Limitation:</strong>{" "}
                            {ctrl.limitations}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
