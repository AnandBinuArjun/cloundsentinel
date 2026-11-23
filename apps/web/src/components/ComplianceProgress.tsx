interface ComplianceProgressProps {
  passed: number;
  failed: number;
  notAssessedOrError: number;
  total: number;
}

export function ComplianceProgress({
  passed,
  failed,
  notAssessedOrError,
  total,
}: ComplianceProgressProps) {
  const safeTotal = Math.max(total, 1);
  const passPct = (passed / safeTotal) * 100;
  const failPct = (failed / safeTotal) * 100;
  const naPct = (notAssessedOrError / safeTotal) * 100;

  return (
    <div
      className="flex h-2 w-full overflow-hidden rounded-full bg-[#1C293A]"
      role="img"
      aria-label={`Passed ${passed}, Failed ${failed}, Not assessed or error ${notAssessedOrError} of ${total} controls`}
    >
      {passPct > 0 && <div className="h-full bg-[#10B981]" style={{ width: `${passPct}%` }} />}
      {failPct > 0 && <div className="h-full bg-[#F43F5E]" style={{ width: `${failPct}%` }} />}
      {naPct > 0 && <div className="h-full bg-[#64748B]/60" style={{ width: `${naPct}%` }} />}
    </div>
  );
}
