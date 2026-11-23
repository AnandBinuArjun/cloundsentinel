import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Clock, Lock, Play, ShieldCheck, Wrench, X } from "lucide-react";
import {
  approveRemediation,
  executeRemediation,
  fetchAuthMe,
  fetchRemediations,
} from "../lib/api";
import { ProviderBadge, StatusBadge } from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

const STAGES = ["previewed", "approved", "executed_unverified", "verified"] as const;

function StageStepper({ stage }: { stage: string }) {
  const normalized = stage === "pending_approval" ? "previewed" : stage;
  const idx = STAGES.indexOf(normalized as (typeof STAGES)[number]);
  const isTerminalFail = ["rejected", "failed", "cancelled", "rollback_required"].includes(stage);
  return (
    <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-wider">
      {STAGES.map((s, i) => {
        const active = idx >= i && !isTerminalFail;
        const label = s === "executed_unverified" ? "executed (unverified)" : s;
        return (
          <div key={s} className="flex items-center gap-1.5">
            <span
              className={`rounded-md border px-2 py-0.5 ${
                active
                  ? "border-[#00D6A0]/35 bg-[#00D6A0]/15 text-[#00D6A0]"
                  : "border-[#243142] bg-[#080D14] text-[#64748B]"
              }`}
            >
              {i + 1}. {label}
            </span>
            {i < STAGES.length - 1 && <span className="text-[#64748B]">→</span>}
          </div>
        );
      })}
    </div>
  );
}

export function RemediationPage() {
  const qc = useQueryClient();
  const [stageFilter, setStageFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const query = useQuery({
    queryKey: ["remediations"],
    queryFn: fetchRemediations,
    retry: false,
  });

  const canApprove = Boolean(
    authQuery.data?.permissions.includes("remediations:approve")
  );
  const canExecute = Boolean(
    authQuery.data?.permissions.includes("remediations:execute")
  );

  const approveMut = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approved" | "rejected" }) =>
      approveRemediation(id, decision, `Reviewed and ${decision} via Remediation Centre.`),
    onSuccess: (item) => {
      setNotice({
        ok: true,
        text: `Remediation ${item.id} transitioned to ${item.stage}.`,
      });
      void qc.invalidateQueries({ queryKey: ["remediations"] });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (e: Error) => setNotice({ ok: false, text: `Approval blocked: ${e.message}` }),
  });

  const executeMut = useMutation({
    mutationFn: executeRemediation,
    onSuccess: (item) => {
      setNotice({
        ok: true,
        text: `Remediation ${item.id} completed in ${item.execution_mode} mode.`,
      });
      void qc.invalidateQueries({ queryKey: ["remediations"] });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (e: Error) => setNotice({ ok: false, text: `Execution blocked: ${e.message}` }),
  });

  const items = query.data?.items ?? [];
  const filtered = useMemo(
    () =>
      stageFilter
        ? items.filter((r) => r.stage.toLowerCase() === stageFilter)
        : items,
    [items, stageFilter]
  );

  const previewedCount = items.filter((r) => r.stage === "previewed" || r.stage === "pending_approval").length;
  const approvedCount = items.filter((r) => r.stage === "approved").length;
  const verifiedCount = items.filter((r) => r.stage === "verified").length;
  const simulatedCount = items.filter((r) => r.stage === "executed_unverified").length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Approval-Gated Response Engine"
        title="Remediation Centre"
        description="Preview-first workflow enforcing impact analysis, rollback guidance, human approval with separation of duties (proposer cannot self-approve), and dry-run simulation that never marks findings resolved without live reassessment proof."
        actions={
          <select
            aria-label="Filter stage"
            value={stageFilter}
            onChange={(e) => setStageFilter(e.target.value)}
            className="rounded-[8px] border border-[#243142] bg-[#0C121B] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
          >
            <option value="">All Stages</option>
            <option value="previewed">Awaiting Approval</option>
            <option value="approved">Approved (Ready)</option>
            <option value="executed_unverified">Executed (Unverified / Dry-Run)</option>
            <option value="verified">Verified (Reassessed PASS)</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
            <option value="rejected">Rejected</option>
          </select>
        }
      />

      <section aria-label="Remediation KPIs" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Proposals"
          value={items.length}
          subtitle={`${simulatedCount} dry-run simulated`}
          icon={Wrench}
          accent="accent"
        />
        <MetricCard
          label="Awaiting Approval"
          value={previewedCount}
          subtitle="Requires peer admin sign-off"
          icon={Clock}
          accent={previewedCount > 0 ? "warning" : "neutral"}
        />
        <MetricCard
          label="Approved"
          value={approvedCount}
          subtitle="Ready for dry-run verify"
          icon={Check}
          accent="info"
        />
        <MetricCard
          label="Verified & Audited"
          value={verifiedCount}
          subtitle="Evidence recorded"
          icon={ShieldCheck}
          accent="success"
        />
      </section>

      <div className="flex items-center gap-2.5 rounded-[12px] border border-[#00D6A0]/30 bg-[#00D6A0]/10 px-4 py-3 text-xs text-[#F1F5F9]">
        <Lock className="h-4 w-4 shrink-0 text-[#00D6A0]" />
        <span className="text-[#A0AEC0]">
          <strong className="text-[#F1F5F9]">Separation of Duties Active:</strong> A Security
          Analyst proposes the dry-run remediation preview; a different Tenant Administrator must
          approve before execution.
        </span>
      </div>

      {notice && (
        <div
          role="status"
          className={`flex items-center justify-between gap-2 rounded-[12px] border px-4 py-3 text-xs ${
            notice.ok
              ? "border-[#10B981]/35 bg-[#10B981]/10 text-[#F1F5F9]"
              : "border-[#F43F5E]/35 bg-[#F43F5E]/10 text-[#F1F5F9]"
          }`}
        >
          <span>{notice.text}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            Dismiss
          </button>
        </div>
      )}

      <Panel title={`Remediation Queue (${filtered.length})`}>
        {query.isPending && <LoadingState label="Loading remediation queue..." />}
        {query.isError && <ErrorBanner message={query.error.message} />}
        {query.data && filtered.length === 0 && (
          <EmptyState
            title="No Remediation Previews Queued"
            description="Open any Security Finding and click 'Preview Remediation' to generate an impact analysis and rollback plan."
          />
        )}
        {query.data && filtered.length > 0 && (
          <div className="space-y-4">
            {filtered.map((rem) => {
              const isExpanded = expandedId === rem.id;
              return (
                <div
                  key={rem.id}
                  className="rounded-[12px] border border-[#243142] bg-[#172131]/65 p-4 text-xs space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold text-[#00D6A0]">
                        {rem.action_type}
                      </span>
                      <ProviderBadge provider={rem.provider} />
                      <StatusBadge status={rem.stage} />
                      <span className="rounded-md border border-[#243142] bg-[#080D14] px-2 py-0.5 font-mono text-[10px] text-[#A0AEC0]">
                        mode: {rem.execution_mode}
                      </span>
                    </div>
                    <StageStepper stage={rem.stage} />
                  </div>

                  <div className="font-mono text-[11px] text-[#64748B] break-all">
                    Resource: <span className="text-[#F1F5F9]">{rem.resource_id}</span>
                  </div>

                  <div className="rounded-[10px] border border-[#243142] bg-[#080D14] p-3 text-[#A0AEC0]">
                    <strong className="text-[#F1F5F9]">Rollback Guidance:</strong>{" "}
                    {rem.rollback_guidance}
                  </div>

                  <div>
                    <button
                      type="button"
                      onClick={() => setExpandedId(isExpanded ? null : rem.id)}
                      className="font-mono text-[11px] text-[#A0AEC0] hover:text-[#00D6A0]"
                    >
                      {isExpanded
                        ? "Hide proposal & impact analysis ▲"
                        : "Inspect proposal & impact analysis ▼"}
                    </button>
                    {isExpanded && (
                      <div className="mt-2.5 grid gap-3 sm:grid-cols-2">
                        <div>
                          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-[#00D6A0]">
                            Proposed Change Plan
                          </div>
                          <pre className="overflow-x-auto rounded-[8px] border border-[#243142] bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                            {JSON.stringify(rem.proposal, null, 2)}
                          </pre>
                        </div>
                        <div>
                          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-[#F59E0B]">
                            Impact Analysis
                          </div>
                          <pre className="overflow-x-auto rounded-[8px] border border-[#243142] bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                            {JSON.stringify(rem.impact_analysis, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#243142] pt-3">
                    {rem.stage === "previewed" && (
                      <>
                        <button
                          type="button"
                          disabled={approveMut.isPending || (authQuery.data && !canApprove)}
                          onClick={() =>
                            approveMut.mutate({ id: rem.id, decision: "approved" })
                          }
                          className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3 py-1.5 font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
                        >
                          <Check className="h-3.5 w-3.5" /> Approve
                        </button>
                        <button
                          type="button"
                          disabled={approveMut.isPending || (authQuery.data && !canApprove)}
                          onClick={() =>
                            approveMut.mutate({ id: rem.id, decision: "rejected" })
                          }
                          className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#F43F5E]/35 bg-[#F43F5E]/12 px-3 py-1.5 font-semibold text-[#F43F5E] hover:bg-[#F43F5E]/20 disabled:cursor-not-allowed disabled:opacity-45"
                        >
                          <X className="h-3.5 w-3.5" /> Reject
                        </button>
                      </>
                    )}
                    {rem.stage === "approved" && (
                      <button
                        type="button"
                        disabled={executeMut.isPending || (authQuery.data && !canExecute)}
                        onClick={() => executeMut.mutate(rem.id)}
                        className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3.5 py-1.5 font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
                      >
                        <Play className="h-3.5 w-3.5" /> Execute Dry-Run Simulation
                      </button>
                    )}
                    {rem.stage === "executed_unverified" && (
                      <span className="inline-flex items-center gap-1.5 font-semibold text-[#38BDF8]">
                        <Clock className="h-4 w-4" /> Dry-Run Simulated · Finding Remains Open Until Reassessed
                      </span>
                    )}
                    {rem.stage === "verified" && (
                      <span className="inline-flex items-center gap-1.5 font-semibold text-[#10B981]">
                        <ShieldCheck className="h-4 w-4" /> Verified by Reassessment &amp; Audited
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}
