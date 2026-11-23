import type { ReactNode } from "react";
import { AlertCircle, Inbox } from "lucide-react";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-4 border-b border-[#243142] pb-5 lg:flex-row lg:items-end lg:justify-between">
      <div>
        {eyebrow && (
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-[#00D6A0]">
            {eyebrow}
          </p>
        )}
        <h1 className="mt-1 text-2xl font-semibold tracking-tight text-[#F1F5F9]">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm leading-relaxed text-[#A0AEC0]">{description}</p>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
  noPadding = false,
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  noPadding?: boolean;
}) {
  return (
    <section
      className={`rounded-[12px] border border-[#243142] bg-[#111925] shadow-[0_1px_2px_rgba(0,0,0,0.35)] ${className}`}
    >
      {(title || action) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#243142] px-5 py-3.5">
          <div>
            {title && <h2 className="text-sm font-semibold text-[#F1F5F9]">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-[#64748B]">{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      <div className={noPadding ? "" : "p-5"}>{children}</div>
    </section>
  );
}

export function LoadingState({ label = "Loading security telemetry..." }: { label?: string }) {
  return (
    <div aria-live="polite" className="space-y-4 py-4">
      <div className="flex items-center gap-2 text-xs text-[#A0AEC0]">
        <span className="h-2 w-2 animate-pulse rounded-full bg-[#00D6A0]" />
        <span>{label}</span>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div className="h-24 animate-pulse rounded-[12px] border border-[#243142] bg-[#172131]" />
        <div className="h-24 animate-pulse rounded-[12px] border border-[#243142] bg-[#172131]" />
        <div className="h-24 animate-pulse rounded-[12px] border border-[#243142] bg-[#172131]" />
      </div>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-[12px] border border-[#F43F5E]/35 bg-[#F43F5E]/10 p-4 text-sm text-[#F1F5F9]"
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#F43F5E]" />
      <div className="leading-relaxed text-xs sm:text-sm">{message}</div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-[12px] border border-dashed border-[#243142] bg-[#0C121B] px-6 py-10 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#243142] bg-[#172131] text-[#64748B]">
        <Inbox className="h-4 w-4" />
      </div>
      <h3 className="mt-3 text-sm font-semibold text-[#F1F5F9]">{title}</h3>
      <p className="mt-1 max-w-md text-xs leading-relaxed text-[#A0AEC0]">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
