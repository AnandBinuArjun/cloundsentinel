import { useState } from "react";
import { Download, FileCheck2, FileText, Shield } from "lucide-react";
import { downloadReport } from "../lib/api";
import { PageHeader, Panel } from "../components/UI";

const REPORT_TYPES = [
  {
    value: "posture",
    label: "Cloud Posture Report",
    desc: "Executive summary of open findings, assets & risk distribution",
  },
  {
    value: "assessment",
    label: "Assessment History Report",
    desc: "Pass/Fail/Not-Assessed execution log with partial collection status",
  },
  {
    value: "vulnerability",
    label: "Misconfiguration & Risk Report",
    desc: "Full rule findings ranked by transparent 0–100 risk score",
  },
  {
    value: "identity",
    label: "Identity Risk Report",
    desc: "IAM & Azure RBAC entitlement exposure and explicit limitations",
  },
  {
    value: "compliance",
    label: "Compliance Mapping Report",
    desc: "CIS AWS/Azure, NIST CSF 2.0 & ISO 27001 technical control status",
  },
  {
    value: "remediation",
    label: "Remediation Report",
    desc: "Dry-run proposals, peer approvals, and verification evidence",
  },
  {
    value: "threat_detection",
    label: "Threat Detection Report",
    desc: "Correlated CloudTrail & Azure Activity Log rules mapped to ATT&CK",
  },
];

export function ReportsPage() {
  const [reportType, setReportType] = useState("posture");
  const [format, setFormat] = useState<"json" | "csv" | "pdf">("pdf");
  const [provider, setProvider] = useState("");
  const [redact, setRedact] = useState(true);
  const [statusMsg, setStatusMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const handleExport = async () => {
    setBusy(true);
    setStatusMsg(null);
    try {
      const blob = await downloadReport({
        reportType,
        format,
        provider: provider || undefined,
        redact,
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `cloudsentinel-${reportType}.${format}`;
      link.click();
      URL.revokeObjectURL(url);
      setStatusMsg({
        ok: true,
        text: `Exported cloudsentinel-${reportType}.${format} (${blob.size} bytes).`,
      });
    } catch (e) {
      setStatusMsg({
        ok: false,
        text: e instanceof Error ? e.message : "Export failed.",
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Audit-Ready Evidence Exports"
        title="Reports & Evidence"
        description="Generate JSON, CSV, or PDF posture, compliance, identity, remediation, and threat detection reports with optional pre-share redaction."
      />

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel
          title="Configure Report Export"
          subtitle="Every export is recorded in the tenant immutable audit log"
          className="lg:col-span-2"
        >
          <div className="space-y-5">
            <div>
              <span className="block text-xs font-medium text-[#A0AEC0]">
                Select Report Package
              </span>
              <div className="mt-2 grid gap-2.5 sm:grid-cols-2">
                {REPORT_TYPES.map((rt) => {
                  const selected = reportType === rt.value;
                  return (
                    <button
                      key={rt.value}
                      type="button"
                      onClick={() => setReportType(rt.value)}
                      className={`flex items-start gap-2.5 rounded-[10px] border p-3 text-left transition-colors ${
                        selected
                          ? "border-[#00D6A0]/50 bg-[#00D6A0]/10"
                          : "border-[#243142] bg-[#172131]/55 hover:border-[#2E3F55]"
                      }`}
                    >
                      <FileText
                        className={`mt-0.5 h-4 w-4 shrink-0 ${
                          selected ? "text-[#00D6A0]" : "text-[#64748B]"
                        }`}
                      />
                      <div>
                        <div className="text-xs font-semibold text-[#F1F5F9]">
                          {rt.label}
                        </div>
                        <div className="mt-0.5 text-[11px] leading-snug text-[#64748B]">
                          {rt.desc}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid gap-3.5 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="report-format"
                  className="block text-xs font-medium text-[#A0AEC0]"
                >
                  Export Format
                </label>
                <select
                  id="report-format"
                  value={format}
                  onChange={(e) => setFormat(e.target.value as "json" | "csv" | "pdf")}
                  className="mt-1.5 w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
                >
                  <option value="pdf">PDF Document</option>
                  <option value="csv">CSV Spreadsheet</option>
                  <option value="json">Structured JSON</option>
                </select>
              </div>
              <div>
                <label
                  htmlFor="report-provider"
                  className="block text-xs font-medium text-[#A0AEC0]"
                >
                  Cloud Scope
                </label>
                <select
                  id="report-provider"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="mt-1.5 w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
                >
                  <option value="">AWS + Azure</option>
                  <option value="aws">AWS Only</option>
                  <option value="azure">Azure Only</option>
                </select>
              </div>
            </div>

            <label className="flex items-start gap-2.5 rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5 text-xs text-[#A0AEC0]">
              <input
                type="checkbox"
                checked={redact}
                onChange={(e) => setRedact(e.target.checked)}
                className="mt-0.5 rounded border-[#243142]"
              />
              <span>
                <strong className="text-[#F1F5F9]">External-Sharing Redaction</strong>
                <span className="block text-[11px] text-[#64748B]">
                  Masks 12-digit AWS account IDs, tenant/subscription UUIDs, and IPv4 addresses
                  prior to download.
                </span>
              </span>
            </label>

            {statusMsg && (
              <div
                role="status"
                className={`flex items-center gap-2 rounded-[10px] border px-3.5 py-2.5 text-xs ${
                  statusMsg.ok
                    ? "border-[#10B981]/35 bg-[#10B981]/10 text-[#10B981]"
                    : "border-[#F43F5E]/35 bg-[#F43F5E]/10 text-[#F43F5E]"
                }`}
              >
                <FileCheck2 className="h-4 w-4 shrink-0" />
                <span>{statusMsg.text}</span>
              </div>
            )}

            <button
              type="button"
              onClick={handleExport}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-4 py-2.5 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:opacity-50"
            >
              <Download className="h-4 w-4" />
              <span>{busy ? "Generating Report..." : "Generate & Download Report"}</span>
            </button>
          </div>
        </Panel>

        <Panel title="Report Provenance" subtitle="Embedded in every generated artifact">
          <ul className="space-y-3 text-xs text-[#A0AEC0]">
            <li className="flex items-start gap-2.5">
              <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>UTC generation timestamp &amp; active tenant scope</span>
            </li>
            <li className="flex items-start gap-2.5">
              <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Collection status, record count &amp; coverage disclaimers</span>
            </li>
            <li className="flex items-start gap-2.5">
              <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Deterministic rule IDs, severity &amp; remediation state</span>
            </li>
            <li className="flex items-start gap-2.5">
              <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#00D6A0]" />
              <span>Explicit live vs. synthetic fixture provenance tags</span>
            </li>
          </ul>
        </Panel>
      </div>
    </div>
  );
}
