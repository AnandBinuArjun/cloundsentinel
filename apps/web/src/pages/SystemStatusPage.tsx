import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
  XCircle,
} from "lucide-react";
import { fetchHealth, fetchReadiness, fetchSystemInfo } from "../lib/api";
import { PageHeader, Panel } from "../components/UI";

export function SystemStatusPage() {
  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    retry: false,
  });

  const readinessQuery = useQuery({
    queryKey: ["readiness"],
    queryFn: fetchReadiness,
    retry: false,
  });

  const systemInfoQuery = useQuery({
    queryKey: ["system-info"],
    queryFn: fetchSystemInfo,
    retry: false,
  });

  const isRefreshing =
    healthQuery.isFetching ||
    readinessQuery.isFetching ||
    systemInfoQuery.isFetching;

  const handleRefresh = () => {
    void healthQuery.refetch();
    void readinessQuery.refetch();
    void systemInfoQuery.refetch();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={systemInfoQuery.data?.current_milestone ?? "CloudSentinel Control Plane"}
        title="Control Plane Status"
        description="Live operational telemetry from FastAPI /health, /ready (real PostgreSQL & Redis probes), and /api/v1/system/info."
        actions={
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="inline-flex items-center gap-2 rounded-[8px] border border-[#243142] bg-[#172131] px-3.5 py-2 text-xs font-semibold text-[#F1F5F9] hover:border-[#00D6A0]/40 hover:text-[#00D6A0] disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
            <span>{isRefreshing ? "Checking..." : "Re-check Now"}</span>
          </button>
        }
      />

      <section aria-label="Operational Probes" className="grid gap-5 md:grid-cols-2">
        <Panel
          title="API Liveness (GET /health)"
          action={
            healthQuery.isPending ? (
              <span className="text-xs text-[#A0AEC0]">Loading...</span>
            ) : healthQuery.isError ? (
              <span className="inline-flex items-center gap-1 rounded-md border border-[#F43F5E]/35 bg-[#F43F5E]/12 px-2 py-0.5 text-xs font-medium text-[#F43F5E]">
                <XCircle className="h-3.5 w-3.5" /> Unreachable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-md border border-[#10B981]/35 bg-[#10B981]/12 px-2 py-0.5 text-xs font-medium text-[#10B981]">
                <CheckCircle2 className="h-3.5 w-3.5" /> Healthy
              </span>
            )
          }
        >
          <div className="text-sm">
            {healthQuery.isPending && (
              <p className="text-xs text-[#A0AEC0]">Querying API liveness endpoint...</p>
            )}
            {healthQuery.isError && (
              <p role="alert" className="text-xs text-[#F43F5E]">
                Unable to reach API: {healthQuery.error.message}
              </p>
            )}
            {healthQuery.data && (
              <dl className="grid grid-cols-2 gap-y-2.5 text-xs">
                <dt className="flex items-center gap-1.5 text-[#A0AEC0]">
                  <Server className="h-3.5 w-3.5" /> Service
                </dt>
                <dd className="font-mono text-[#F1F5F9]">{healthQuery.data.service}</dd>
                <dt className="text-[#A0AEC0]">Version</dt>
                <dd className="font-mono text-[#F1F5F9]">{healthQuery.data.version}</dd>
                <dt className="text-[#A0AEC0]">Environment</dt>
                <dd className="font-mono text-[#F1F5F9]">{healthQuery.data.environment}</dd>
                <dt className="text-[#A0AEC0]">Checked (UTC)</dt>
                <dd className="font-mono text-[#F1F5F9]">{healthQuery.data.timestamp}</dd>
              </dl>
            )}
          </div>
        </Panel>

        <Panel
          title="Backing Dependencies (GET /ready)"
          action={
            readinessQuery.isPending ? (
              <span className="text-xs text-[#A0AEC0]">Probing...</span>
            ) : readinessQuery.isError ? (
              <span className="inline-flex items-center gap-1 rounded-md border border-[#F43F5E]/35 bg-[#F43F5E]/12 px-2 py-0.5 text-xs font-medium text-[#F43F5E]">
                <XCircle className="h-3.5 w-3.5" /> Error
              </span>
            ) : readinessQuery.data?.data.status === "ready" ? (
              <span className="inline-flex items-center gap-1 rounded-md border border-[#10B981]/35 bg-[#10B981]/12 px-2 py-0.5 text-xs font-medium text-[#10B981]">
                <CheckCircle2 className="h-3.5 w-3.5" /> Ready (200)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-md border border-[#F59E0B]/35 bg-[#F59E0B]/12 px-2 py-0.5 text-xs font-medium text-[#F59E0B]">
                <AlertTriangle className="h-3.5 w-3.5" /> Degraded (503)
              </span>
            )
          }
        >
          <div className="space-y-2.5 text-sm">
            {readinessQuery.isPending && (
              <p className="flex items-center gap-1.5 text-xs text-[#A0AEC0]">
                <Clock className="h-3.5 w-3.5" /> Probing PostgreSQL and Redis...
              </p>
            )}
            {readinessQuery.isError && (
              <p role="alert" className="text-xs text-[#F43F5E]">
                Unable to query readiness: {readinessQuery.error.message}
              </p>
            )}
            {readinessQuery.data &&
              Object.entries(readinessQuery.data.data.dependencies).map(([name, dep]) => (
                <div
                  key={name}
                  className="flex items-start justify-between rounded-[10px] border border-[#243142] bg-[#172131]/65 px-3.5 py-2.5 text-xs"
                >
                  <div>
                    <div className="font-mono font-semibold text-[#F1F5F9]">{name}</div>
                    {dep.detail && <div className="mt-0.5 text-[#F59E0B]">{dep.detail}</div>}
                  </div>
                  <div className="text-right">
                    <span
                      className={
                        dep.status === "up"
                          ? "font-semibold uppercase text-[#10B981]"
                          : "font-semibold uppercase text-[#F43F5E]"
                      }
                    >
                      {dep.status}
                    </span>
                    <div className="font-mono text-[#A0AEC0] tabular-nums">
                      {dep.latency_ms} ms
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </Panel>
      </section>

      <Panel
        title="Platform Capabilities Matrix (Reported by Backend)"
        subtitle="Reflects implemented backend modules from /api/v1/system/info"
      >
        {systemInfoQuery.isPending && (
          <p className="text-xs text-[#A0AEC0]">Loading capability metadata...</p>
        )}
        {systemInfoQuery.isError && (
          <p role="alert" className="text-xs text-[#F43F5E]">
            Could not load system info: {systemInfoQuery.error.message}
          </p>
        )}
        {systemInfoQuery.data && (
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {Object.entries(systemInfoQuery.data.capabilities).map(([key, enabled]) => (
              <div
                key={key}
                className="flex items-center justify-between rounded-[10px] border border-[#243142] bg-[#172131]/65 px-3.5 py-2.5 text-xs"
              >
                <span className="font-mono text-[#F1F5F9]">{key}</span>
                <span
                  className={
                    enabled
                      ? "rounded-md border border-[#10B981]/35 bg-[#10B981]/12 px-2 py-0.5 font-semibold text-[#10B981]"
                      : "rounded-md border border-[#243142] bg-[#080D14] px-2 py-0.5 font-medium text-[#64748B]"
                  }
                >
                  {enabled ? "Active" : "Planned"}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
