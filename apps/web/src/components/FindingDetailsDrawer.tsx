import { useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, ExternalLink, Wrench, X } from "lucide-react";
import { fetchFindingDetail, previewRemediation } from "../lib/api";
import {
  DataSourceBadge,
  ProviderBadge,
  RiskScoreBar,
  SeverityBadge,
  StatusBadge,
} from "./Badges";
import { ErrorBanner, LoadingState } from "./UI";

export function FindingDetailsDrawer({
  findingId,
  canPreviewRemediation,
  onClose,
}: {
  findingId: string | null;
  canPreviewRemediation: boolean;
  onClose: () => void;
}) {
  const navigate = useNavigate();

  const query = useQuery({
    queryKey: ["finding-drawer-detail", findingId],
    queryFn: () => fetchFindingDetail(findingId ?? ""),
    enabled: Boolean(findingId),
    retry: false,
  });

  const previewMut = useMutation({
    mutationFn: () => previewRemediation(findingId ?? ""),
    onSuccess: () => {
      onClose();
      navigate("/remediations");
    },
  });

  useEffect(() => {
    if (!findingId) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [findingId, onClose]);

  if (!findingId) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/65"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Finding Investigation Drawer"
        onClick={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-2xl flex-col border-l border-[#243142] bg-[#0C121B] shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-[#243142] bg-[#111925] px-5 py-4">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-[#00D6A0]">
              Finding Investigation &amp; Evidence
            </p>
            <h2 className="mt-0.5 text-sm font-semibold text-[#F1F5F9]">
              {query.data ? `${query.data.finding.rule_id} — ${query.data.finding.title}` : "Loading..."}
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <Link
              to={`/findings/${findingId}`}
              onClick={onClose}
              className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-1.5 text-xs font-medium text-[#A0AEC0] hover:text-[#F1F5F9]"
            >
              <span>Full Page</span>
              <ExternalLink className="h-3 w-3" />
            </Link>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close finding drawer"
              className="rounded-[8px] border border-[#243142] bg-[#172131] p-1.5 text-[#A0AEC0] hover:text-[#F1F5F9]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {query.isPending && <LoadingState label="Fetching finding evidence..." />}
          {query.isError && <ErrorBanner message={query.error.message} />}
          {query.data && (
            <>
              {/* Metadata bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-[12px] border border-[#243142] bg-[#111925] p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={query.data.finding.severity} />
                  <ProviderBadge provider={query.data.finding.provider} />
                  <StatusBadge status={query.data.finding.status} />
                  <DataSourceBadge source={query.data.finding.data_source} />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wider text-[#64748B]">Risk</span>
                  <RiskScoreBar score={query.data.finding.risk_score} />
                </div>
              </div>

              {/* Executive summary & resource */}
              <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-4 space-y-3 text-xs">
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                    Technical Description
                  </div>
                  <p className="mt-1 leading-relaxed text-[#F1F5F9]">
                    {query.data.finding.description}
                  </p>
                </div>
                <div className="grid gap-3 border-t border-[#243142] pt-3 sm:grid-cols-2">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                      Affected Resource
                    </div>
                    <div className="mt-0.5 break-all font-mono text-[11px] text-[#F1F5F9]">
                      {query.data.finding.resource_id}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                      Account / Region / Rule Version
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-[#A0AEC0]">
                      {query.data.finding.account_ref} · {query.data.finding.region} · v
                      {query.data.finding.rule_version}
                    </div>
                  </div>
                </div>
              </div>

              {/* Expected vs Observed Evidence */}
              <div className="space-y-2.5">
                <div className="text-xs font-semibold text-[#F1F5F9]">
                  Reproducible Evidence ({query.data.evidence.length})
                </div>
                {query.data.evidence.length === 0 ? (
                  <p className="text-xs text-[#64748B]">No evidence snapshots recorded.</p>
                ) : (
                  query.data.evidence.slice(0, 1).map((ev) => (
                    <div
                      key={ev.id}
                      className="grid gap-3 rounded-[12px] border border-[#243142] bg-[#111925] p-4 sm:grid-cols-2"
                    >
                      <div>
                        <div className="mb-1.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#10B981]">
                          Expected Secure Config
                        </div>
                        <pre className="overflow-x-auto rounded-[8px] border border-[#10B981]/20 bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                          {JSON.stringify(ev.expected_config, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="mb-1.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F43F5E]">
                          Observed Config
                        </div>
                        <pre className="overflow-x-auto rounded-[8px] border border-[#F43F5E]/20 bg-[#080D14] p-2.5 font-mono text-[11px] text-[#A0AEC0]">
                          {JSON.stringify(ev.observed_config, null, 2)}
                        </pre>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Compliance & Remediation Guidance */}
              <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-4 space-y-3 text-xs">
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-[#00D6A0]">
                    Recommended Remediation
                  </div>
                  <p className="mt-1 leading-relaxed text-[#F1F5F9]">
                    {query.data.finding.remediation_guidance}
                  </p>
                </div>
                {query.data.finding.framework_mappings.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {query.data.finding.framework_mappings.map((ctrl) => (
                      <span
                        key={ctrl}
                        className="rounded-md border border-[#243142] bg-[#172131] px-2 py-0.5 font-mono text-[10px] text-[#A0AEC0]"
                      >
                        {ctrl}
                      </span>
                    ))}
                  </div>
                )}
                {query.data.finding.limitations && (
                  <div className="flex items-start gap-2 rounded-[8px] border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-2.5 text-[11px] text-[#F59E0B]">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>{query.data.finding.limitations}</span>
                  </div>
                )}
              </div>

              {/* Action footer */}
              {previewMut.isError && (
                <ErrorBanner
                  message={`Remediation preview failed: ${
                    previewMut.error instanceof Error
                      ? previewMut.error.message
                      : "Unexpected error"
                  }`}
                />
              )}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#243142] pt-4">
                <p className="text-[11px] text-[#64748B]">
                  Remediation preview is dry-run only; human approval required before execution.
                </p>
                <button
                  type="button"
                  disabled={!canPreviewRemediation || previewMut.isPending}
                  title={
                    canPreviewRemediation
                      ? "Generate dry-run remediation proposal"
                      : "Requires remediations:preview permission"
                  }
                  onClick={() => previewMut.mutate()}
                  className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3.5 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
                >
                  <Wrench className="h-3.5 w-3.5" />
                  <span>{previewMut.isPending ? "Generating..." : "Preview Remediation"}</span>
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
