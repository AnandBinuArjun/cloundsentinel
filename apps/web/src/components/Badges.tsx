export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  const styles: Record<string, string> = {
    critical: "bg-[#F43F5E]/12 text-[#F43F5E] border-[#F43F5E]/30",
    high: "bg-[#F97316]/12 text-[#F97316] border-[#F97316]/30",
    medium: "bg-[#F59E0B]/12 text-[#F59E0B] border-[#F59E0B]/30",
    low: "bg-[#38BDF8]/12 text-[#38BDF8] border-[#38BDF8]/30",
  };
  const dotColors: Record<string, string> = {
    critical: "bg-[#F43F5E]",
    high: "bg-[#F97316]",
    medium: "bg-[#F59E0B]",
    low: "bg-[#38BDF8]",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${
        styles[key] ?? "bg-[#94A3B8]/12 text-[#94A3B8] border-[#94A3B8]/30"
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dotColors[key] ?? "bg-[#94A3B8]"}`} />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const cls =
    normalized === "pass" ||
    normalized === "healthy" ||
    normalized === "resolved" ||
    normalized === "verified" ||
    normalized === "completed" ||
    normalized === "collected" ||
    normalized === "approved"
      ? "bg-[#10B981]/12 text-[#10B981] border-[#10B981]/30"
      : normalized === "fail" ||
          normalized === "error" ||
          normalized === "open" ||
          normalized === "rejected" ||
          normalized === "true_positive"
        ? "bg-[#F43F5E]/12 text-[#F43F5E] border-[#F43F5E]/30"
        : normalized === "not_assessed"
          ? "bg-[#94A3B8]/12 text-[#94A3B8] border-[#94A3B8]/30"
          : "bg-[#F59E0B]/12 text-[#F59E0B] border-[#F59E0B]/30";
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize ${cls}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function ProviderBadge({ provider }: { provider: string }) {
  const isAws = provider.toLowerCase() === "aws";
  return (
    <span
      className={
        isAws
          ? "inline-flex items-center gap-1.5 rounded-md border border-[#F59E0B]/30 bg-[#F59E0B]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F59E0B]"
          : "inline-flex items-center gap-1.5 rounded-md border border-[#38BDF8]/30 bg-[#38BDF8]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#38BDF8]"
      }
    >
      <span className={`h-1.5 w-1.5 rounded-full ${isAws ? "bg-[#F59E0B]" : "bg-[#38BDF8]"}`} />
      {isAws ? "AWS" : "Azure"}
    </span>
  );
}

export type ProvenanceKind =
  | "live"
  | "synthetic_fixture"
  | "partial"
  | "stale"
  | "not_assessed"
  | "error";

export function DataSourceBadge({ source }: { source: string }) {
  const key = source.toLowerCase();
  if (key === "synthetic_fixture" || key === "synthetic") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F59E0B]">
        <span className="h-1.5 w-1.5 rounded-full bg-[#F59E0B]" />
        SYNTHETIC
      </span>
    );
  }
  if (key === "partial" || key === "completed_with_warnings") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#F97316]/35 bg-[#F97316]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F97316]">
        PARTIAL
      </span>
    );
  }
  if (key === "stale") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F59E0B]">
        STALE
      </span>
    );
  }
  if (key === "not_assessed") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#94A3B8]/30 bg-[#94A3B8]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#94A3B8]">
        NOT ASSESSED
      </span>
    );
  }
  if (key === "error") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#F43F5E]/35 bg-[#F43F5E]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#F43F5E]">
        ERROR
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-[#10B981]/35 bg-[#10B981]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#10B981]">
      <span className="h-1.5 w-1.5 rounded-full bg-[#10B981]" />
      LIVE
    </span>
  );
}

export function ConnectorStatus({
  healthy,
  total,
}: {
  healthy: number;
  total: number;
}) {
  const allOk = total > 0 && healthy === total;
  const none = total === 0;
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[#A0AEC0]">
      <span
        className={`h-2 w-2 rounded-full ${
          none ? "bg-[#64748B]" : allOk ? "bg-[#10B981]" : "bg-[#F59E0B]"
        }`}
      />
      <span className="tabular-nums">
        {none ? "No connectors" : `${healthy}/${total} connectors healthy`}
      </span>
    </span>
  );
}

export function RiskScoreBar({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score));
  const barColor =
    clamped >= 80
      ? "bg-[#F43F5E]"
      : clamped >= 60
        ? "bg-[#F97316]"
        : clamped >= 35
          ? "bg-[#F59E0B]"
          : "bg-[#38BDF8]";
  const textColor =
    clamped >= 80
      ? "text-[#F43F5E]"
      : clamped >= 60
        ? "text-[#F97316]"
        : clamped >= 35
          ? "text-[#F59E0B]"
          : "text-[#38BDF8]";

  return (
    <div className="flex items-center gap-2">
      <span className={`w-7 font-mono text-xs font-semibold tabular-nums ${textColor}`}>
        {score.toFixed(0)}
      </span>
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-[#1C293A]">
        <div className={`h-full rounded-full ${barColor}`} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}

export { RiskScoreBar as RiskIndicator };
