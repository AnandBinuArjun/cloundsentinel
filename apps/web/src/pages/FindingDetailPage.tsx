import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, CheckCircle2, Clock, Wrench } from "lucide-react";
import {
  fetchAuthMe,
  fetchFindingDetail,
  previewRemediation,
  updateFindingStatus,
} from "../lib/api";
import {
  DataSourceBadge,
  ProviderBadge,
  RiskScoreBar,
  SeverityBadge,
  StatusBadge,
} from "../components/Badges";
import { ErrorBanner, LoadingState, Panel } from "../components/UI";

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const query = useQuery({
    queryKey: ["finding-detail", id],
    queryFn: () => fetchFindingDetail(id),
    enabled: Boolean(id),
    retry: false,
  });

  const [newStatus, setNewStatus] = useState("risk_accepted");
  const [justification, setJustification] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const canPreviewRemediation = Boolean(
    authQuery.data?.permissions.includes("remediations:preview")
  );
  const canUpdateFinding = Boolean(
    authQuery.data?.permissions.includes("findings:write")
  );

  const updateMut = useMutation({
    mutationFn: () => updateFindingStatus(id, newStatus, justification),
    onSuccess: () => {
      setJustification("");
      setMessage({
        ok: true,
        text: "Finding disposition updated and logged to immutable audit trail.",
      });
      void qc.invalidateQueries({ queryKey: ["finding-detail", id] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (e: Error) => setMessage({ ok: false, text: `Error: ${e.message}` }),
  });

  const previewMut = useMutation({
    mutationFn: () => previewRemediation(id),
    onSuccess: () => navigate("/remediations"),
    onError: (e: Error) =>
      setMessage({ ok: false, text: `Remediation preview error: ${e.message}` }),
  });

  if (query.isPending) return <LoadingState label="Loading finding evidence & history..." />;
  if (query.isError) return <ErrorBanner message={query.error.message} />;

  const { finding, evidence, history } = query.data;

  const handleDisposition = (e: FormEvent) => {
    e.preventDefault();
    updateMut.mutate();
  };

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/findings"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-[#A0AEC0] hover:text-[#00D6A0]"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Security Findings</span>
        </Link>
      </div>

      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-[#243142] pb-5">
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-2 py-0.5 font-mono text-xs font-semibold text-[#00D6A0]">
              {finding.rule_id} v{finding.rule_version}
            </span>
            <ProviderBadge provider={finding.provider} />
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            <DataSourceBadge source={finding.data_source} />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#F1F5F9]">
            {finding.title}
          </h1>
          <p className="font-mono text-xs text-[#A0AEC0] break-all">{finding.resource_id}</p>
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-[#64748B]">
            <span>Account: {finding.account_ref}</span>
            <span>·</span>
            <span>Region: {finding.region}</span>
            <span>·</span>
            <span>Confidence: {finding.confidence}</span>
          </div>
        </div>

        <div className="flex flex-col items-end gap-3">
          <div className="flex items-center gap-3 rounded-[10px] border border-[#243142] bg-[#111925] px-3.5 py-2">
            <span className="text-[11px] uppercase tracking-wider text-[#64748B]">
              Risk Score
            </span>
            <RiskScoreBar score={finding.risk_score} />
          </div>
          <button
            type="button"
            disabled={previewMut.isPending || (authQuery.data && !canPreviewRemediation)}
            title={
              authQuery.data && !canPreviewRemediation
                ? "Requires remediations:preview permission"
                : "Generate dry-run remediation proposal"
            }
            onClick={() => previewMut.mutate()}
            className="inline-flex items-center gap-2 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-4 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <Wrench className="h-3.5 w-3.5" />
            <span>
              {previewMut.isPending
                ? "Generating Dry-Run..."
                : "Preview Safe Remediation (Dry-Run)"}
            </span>
          </button>
        </div>
      </header>

      {message && (
        <div
          role="status"
          className={`flex items-center gap-2 rounded-[12px] border px-4 py-3 text-xs ${
            message.ok
              ? "border-[#10B981]/35 bg-[#10B981]/10 text-[#F1F5F9]"
              : "border-[#F43F5E]/35 bg-[#F43F5E]/10 text-[#F1F5F9]"
          }`}
        >
          <CheckCircle2
            className={`h-4 w-4 shrink-0 ${message.ok ? "text-[#10B981]" : "text-[#F43F5E]"}`}
          />
          <span>{message.text}</span>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Risk Breakdown & Remediation Guidance"
          subtitle="Transparent internal scoring model (0–100)"
        >
          <div className="space-y-4">
            <p className="text-xs leading-relaxed text-[#A0AEC0]">{finding.description}</p>
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[#00D6A0]">
                Recommended Remediation
              </div>
              <p className="mt-1.5 rounded-[10px] border border-[#243142] bg-[#172131] p-3.5 text-xs leading-relaxed text-[#F1F5F9]">
                {finding.remediation_guidance}
              </p>
            </div>
            {finding.framework_mappings.length > 0 && (
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                  Mapped Compliance Controls
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {finding.framework_mappings.map((fw) => (
                    <span
                      key={fw}
                      className="rounded-md border border-[#243142] bg-[#172131] px-2 py-0.5 font-mono text-[11px] text-[#A0AEC0]"
                    >
                      {fw}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                Risk Factor Breakdown
              </div>
              <pre className="overflow-x-auto rounded-[8px] border border-[#243142] bg-[#080D14] p-3 font-mono text-[11px] text-[#A0AEC0]">
                {JSON.stringify(finding.risk_explanation, null, 2)}
              </pre>
            </div>
            {finding.limitations && (
              <div className="flex items-start gap-2 rounded-[10px] border border-[#F59E0B]/35 bg-[#F59E0B]/10 p-3 text-xs text-[#F59E0B]">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  <strong>Analysis Limitation:</strong> {finding.limitations}
                </span>
              </div>
            )}
          </div>
        </Panel>

        <Panel
          title="Reproducible Evidence Snapshots"
          subtitle="Redacted expected vs. observed configuration"
        >
          <div className="space-y-3">
            {evidence.length === 0 ? (
              <p className="text-xs text-[#64748B]">No evidence records attached.</p>
            ) : (
              evidence.slice(0, 2).map((ev) => (
                <div
                  key={ev.id}
                  className="space-y-3 rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5"
                >
                  <div className="flex flex-wrap justify-between gap-2 font-mono text-[11px] text-[#A0AEC0]">
                    <span className="text-[#00D6A0]">{ev.source}</span>
                    <span className="text-[#64748B]">{ev.collected_at}</span>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[#10B981]">
                        Expected Secure Config
                      </div>
                      <pre className="overflow-x-auto rounded-[8px] border border-[#10B981]/25 bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                        {JSON.stringify(ev.expected_config, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[#F43F5E]">
                        Observed Config
                      </div>
                      <pre className="overflow-x-auto rounded-[8px] border border-[#F43F5E]/25 bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                        {JSON.stringify(ev.observed_config, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Risk Acceptance & Disposition Workflow"
          subtitle="All transitions require documented justification and are written to audit logs"
        >
          <form onSubmit={handleDisposition} className="space-y-3">
            <select
              aria-label="New status"
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            >
              <option value="risk_accepted">Risk Accepted</option>
              <option value="false_positive">False Positive</option>
              <option value="resolved">Resolved</option>
              <option value="open">Re-Open</option>
            </select>
            <textarea
              required
              minLength={5}
              rows={3}
              placeholder="Document justification (stored immutably in finding_history & audit_events)..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
            />
            <button
              type="submit"
              disabled={updateMut.isPending || (authQuery.data && !canUpdateFinding)}
              className="rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-4 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
            >
              {updateMut.isPending ? "Recording..." : "Record Disposition"}
            </button>
          </form>
        </Panel>

        <Panel title="Lifecycle History" subtitle="Immutable state transitions for this finding">
          {history.length === 0 ? (
            <p className="text-xs text-[#64748B]">No lifecycle transitions recorded yet.</p>
          ) : (
            <div className="space-y-2.5">
              {history.map((h) => (
                <div
                  key={h.id}
                  className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3 text-xs"
                >
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="font-semibold text-[#F1F5F9]">
                      {h.previous_status} →{" "}
                      <span className="text-[#00D6A0]">{h.new_status}</span>
                    </span>
                    <span className="inline-flex items-center gap-1 text-[#64748B]">
                      <Clock className="h-3 w-3" />
                      {h.created_at.slice(0, 19).replace("T", " ")}Z
                    </span>
                  </div>
                  {h.justification && (
                    <p className="mt-1.5 text-[#A0AEC0]">{h.justification}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
