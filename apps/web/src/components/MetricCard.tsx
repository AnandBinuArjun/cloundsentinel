import { isValidElement, type ComponentType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";

type IconProp = ReactNode | ComponentType<{ className?: string }>;

export type MetricAccent =
  | "default"
  | "neutral"
  | "accent"
  | "critical"
  | "high"
  | "warning"
  | "success"
  | "info";

interface MetricCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  subtitle?: string;
  icon: IconProp;
  to?: string;
  accent?: MetricAccent;
  updatedAt?: string;
}

const ACCENT_ICON_CLS: Record<MetricAccent, string> = {
  default: "border-[#243142] bg-[#172131] text-[#A0AEC0]",
  neutral: "border-[#243142] bg-[#172131] text-[#A0AEC0]",
  accent: "border-[#00D6A0]/30 bg-[#00D6A0]/10 text-[#00D6A0]",
  critical: "border-[#F43F5E]/30 bg-[#F43F5E]/10 text-[#F43F5E]",
  high: "border-[#F97316]/30 bg-[#F97316]/10 text-[#F97316]",
  warning: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B]",
  success: "border-[#10B981]/30 bg-[#10B981]/10 text-[#10B981]",
  info: "border-[#38BDF8]/30 bg-[#38BDF8]/10 text-[#38BDF8]",
};

function renderIcon(icon: IconProp): ReactNode {
  if (isValidElement(icon) || typeof icon === "string" || typeof icon === "number" || icon == null) {
    return icon;
  }
  const IconComp = icon as ComponentType<{ className?: string }>;
  return <IconComp className="h-3.5 w-3.5" />;
}

export function MetricCard({
  label,
  value,
  sublabel,
  subtitle,
  icon,
  to,
  accent = "default",
  updatedAt,
}: MetricCardProps) {
  const caption = sublabel ?? subtitle ?? "";
  const content = (
    <>
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs font-medium text-[#A0AEC0]">{label}</span>
        <span
          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-[8px] border ${ACCENT_ICON_CLS[accent]}`}
        >
          {renderIcon(icon)}
        </span>
      </div>

      <div className="mt-3 flex items-baseline justify-between gap-2">
        <span className="font-mono text-2xl font-semibold tracking-tight text-[#F1F5F9] tabular-nums">
          {value}
        </span>
        {to && (
          <ArrowUpRight className="h-3.5 w-3.5 text-[#64748B] opacity-0 transition-opacity group-hover:text-[#00D6A0] group-hover:opacity-100" />
        )}
      </div>

      <div className="mt-2 flex items-center justify-between gap-2 text-[11px] text-[#64748B]">
        <span className="truncate">{caption}</span>
        {updatedAt && <span className="shrink-0 font-mono text-[10px]">{updatedAt}</span>}
      </div>
    </>
  );

  if (to) {
    return (
      <Link
        to={to}
        className="group flex flex-col justify-between rounded-[12px] border border-[#243142] bg-[#111925] p-4 transition-colors hover:border-[#00D6A0]/45 hover:bg-[#172131]/80"
      >
        {content}
      </Link>
    );
  }

  return (
    <div className="flex flex-col justify-between rounded-[12px] border border-[#243142] bg-[#111925] p-4">
      {content}
    </div>
  );
}
