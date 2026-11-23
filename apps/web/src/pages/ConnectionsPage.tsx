import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Cloud,
  Lock,
  Play,
  Plus,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import {
  createConnection,
  fetchAuthMe,
  fetchConnections,
  triggerAssessment,
  validateConnection,
} from "../lib/api";
import { DataSourceBadge, ProviderBadge, StatusBadge } from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function ConnectionsPage() {
  const qc = useQueryClient();
  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });
  const query = useQuery({
    queryKey: ["connections"],
    queryFn: () => fetchConnections(),
    retry: false,
  });

  const [name, setName] = useState("");
  const [provider, setProvider] = useState<"aws" | "azure">("aws");
  const [accountId, setAccountId] = useState("123456789012");
  const [roleArn, setRoleArn] = useState(
    "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole"
  );
  const [azureTenantId, setAzureTenantId] = useState("");
  const [regionsInput, setRegionsInput] = useState("us-east-1");
  const [dataSource, setDataSource] = useState<"live" | "synthetic_fixture">(
    "synthetic_fixture"
  );
  const [feedback, setFeedback] = useState<{ kind: "ok" | "err"; text: string } | null>(
    null
  );

  const canManageConnections = Boolean(
    authQuery.data?.permissions.includes("connections:write")
  );
  const canRunAssessment = Boolean(
    authQuery.data?.permissions.includes("assessments:run")
  );

  const createMut = useMutation({
    mutationFn: createConnection,
    onSuccess: () => {
      setName("");
      setFeedback({
        kind: "ok",
        text: "Connector registered. Run Preflight Validation to verify read-only permissions.",
      });
      void qc.invalidateQueries({ queryKey: ["connections"] });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (e: Error) => setFeedback({ kind: "err", text: e.message }),
  });

  const validateMut = useMutation({
    mutationFn: validateConnection,
    onSuccess: () => {
      setFeedback({
        kind: "ok",
        text: "Identity and read-only permission preflight validation completed.",
      });
      void qc.invalidateQueries({ queryKey: ["connections"] });
    },
    onError: (e: Error) =>
      setFeedback({ kind: "err", text: `Validation error: ${e.message}` }),
  });

  const assessMut = useMutation({
    mutationFn: triggerAssessment,
    onSuccess: (run) => {
      setFeedback({
        kind: "ok",
        text: `Assessment completed (${run.provider.toUpperCase()}): ${run.checks_passed} PASS, ${run.checks_failed} FAIL, ${run.assets_discovered} assets discovered.`,
      });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
      void qc.invalidateQueries({ queryKey: ["assessments"] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
      void qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (e: Error) =>
      setFeedback({ kind: "err", text: `Assessment error: ${e.message}` }),
  });

  const switchProvider = (next: "aws" | "azure") => {
    setProvider(next);
    setAccountId(
      next === "aws" ? "123456789012" : "00000000-1111-2222-3333-444444444444"
    );
    setRegionsInput(next === "aws" ? "us-east-1" : "eastus");
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const regions = regionsInput
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);
    createMut.mutate({
      name,
      provider,
      auth_mode: provider === "aws" ? "sts_assume_role" : "managed_identity",
      account_or_subscription_id: accountId,
      role_arn: provider === "aws" ? roleArn : null,
      azure_tenant_id: provider === "azure" && azureTenantId ? azureTenantId : null,
      regions: regions.length > 0 ? regions : [provider === "aws" ? "us-east-1" : "eastus"],
      data_source: dataSource,
    });
  };

  const items = query.data?.items ?? [];
  const healthyCount = items.filter((c) => c.status.toLowerCase() === "healthy").length;
  const awsCount = items.filter((c) => c.provider.toLowerCase() === "aws").length;
  const azureCount = items.filter((c) => c.provider.toLowerCase() === "azure").length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Least-Privilege Cloud Onboarding"
        title="Cloud Connections"
        description="Connect AWS accounts via cross-account STS AssumeRole + ExternalId and Microsoft Azure subscriptions via Managed or Workload Identity. Root keys and Global Administrator roles are prohibited."
      />

      <section aria-label="Connector KPIs" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Connectors"
          value={items.length}
          subtitle={`${healthyCount} healthy`}
          icon={Cloud}
          accent="accent"
        />
        <MetricCard
          label="AWS Accounts"
          value={awsCount}
          subtitle="STS AssumeRole read-only"
          icon={ShieldCheck}
          accent="warning"
          to="/aws"
        />
        <MetricCard
          label="Azure Subscriptions"
          value={azureCount}
          subtitle="Managed / Workload Identity"
          icon={ShieldCheck}
          accent="info"
          to="/azure"
        />
        <MetricCard
          label="Credential Storage"
          value="Zero Keys"
          subtitle="Identity metadata only"
          icon={Lock}
          accent="success"
        />
      </section>

      {feedback && (
        <div
          role="status"
          className={`flex items-center justify-between gap-2 rounded-[12px] border px-4 py-3 text-xs ${
            feedback.kind === "ok"
              ? "border-[#10B981]/35 bg-[#10B981]/10 text-[#F1F5F9]"
              : "border-[#F43F5E]/35 bg-[#F43F5E]/10 text-[#F1F5F9]"
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.kind === "ok" ? (
              <ShieldCheck className="h-4 w-4 shrink-0 text-[#10B981]" />
            ) : (
              <XCircle className="h-4 w-4 shrink-0 text-[#F43F5E]" />
            )}
            <span>{feedback.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            Dismiss
          </button>
        </div>
      )}

      <Panel
        title="Register New Cloud Connector"
        subtitle="Only non-secret identity metadata (Role ARN, Subscription UUID, regions) is stored"
        action={
          <div className="inline-flex rounded-[8px] border border-[#243142] bg-[#080D14] p-0.5 text-xs">
            <button
              type="button"
              onClick={() => switchProvider("aws")}
              className={`rounded-[6px] px-3 py-1 font-medium transition-colors ${
                provider === "aws"
                  ? "bg-[#172131] text-[#F59E0B]"
                  : "text-[#A0AEC0] hover:text-[#F1F5F9]"
              }`}
            >
              AWS (STS)
            </button>
            <button
              type="button"
              onClick={() => switchProvider("azure")}
              className={`rounded-[6px] px-3 py-1 font-medium transition-colors ${
                provider === "azure"
                  ? "bg-[#172131] text-[#38BDF8]"
                  : "text-[#A0AEC0] hover:text-[#F1F5F9]"
              }`}
            >
              Azure (Managed ID)
            </button>
          </div>
        }
      >
        <div className="mb-4 rounded-[10px] border border-[#243142] bg-[#0C121B] p-3.5 text-xs text-[#A0AEC0]">
          <div className="flex items-center gap-2 font-semibold text-[#F1F5F9]">
            <Lock className="h-3.5 w-3.5 text-[#00D6A0]" />
            <span>
              {provider === "aws"
                ? "AWS Read-Only Permission Manifest"
                : "Azure Read-Only Permission Manifest"}
            </span>
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-[#64748B]">
            {provider === "aws"
              ? "Attach cloud_connectors/aws/iam_readonly_policy.json with an ExternalId trust condition. Static IAM access keys and root credentials are blocked."
              : "Assign Azure Reader + Security Reader scoped to the target subscription (see cloud_connectors/azure/reader_role_manifest.json). Global Administrator is prohibited."}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="grid gap-3.5 md:grid-cols-3">
          <div>
            <label
              htmlFor="conn-name"
              className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
            >
              Connection Name
            </label>
            <input
              id="conn-name"
              required
              placeholder={
                provider === "aws"
                  ? "e.g. AWS Production Account"
                  : "e.g. Azure Production Subscription"
              }
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
            />
          </div>

          <div>
            <label
              htmlFor="conn-scope"
              className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
            >
              {provider === "aws"
                ? "AWS Account ID (12 digits)"
                : "Azure Subscription UUID"}
            </label>
            <input
              id="conn-scope"
              required
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            />
          </div>

          <div>
            <label
              htmlFor="conn-mode"
              className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
            >
              Data Mode
            </label>
            <select
              id="conn-mode"
              aria-label="Data Source Mode"
              value={dataSource}
              onChange={(e) =>
                setDataSource(e.target.value as "live" | "synthetic_fixture")
              }
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            >
              <option value="live">Live Cloud API</option>
              <option value="synthetic_fixture">Synthetic Demo Fixture</option>
            </select>
          </div>

          {provider === "aws" ? (
            <div>
              <label
                htmlFor="conn-role"
                className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
              >
                IAM Read-Only Role ARN
              </label>
              <input
                id="conn-role"
                required
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
              />
            </div>
          ) : (
            <div>
              <label
                htmlFor="conn-az-tenant"
                className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
              >
                Azure Tenant ID (Optional)
              </label>
              <input
                id="conn-az-tenant"
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={azureTenantId}
                onChange={(e) => setAzureTenantId(e.target.value)}
                className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
              />
            </div>
          )}

          <div>
            <label
              htmlFor="conn-regions"
              className="mb-1 block text-[11px] font-medium text-[#A0AEC0]"
            >
              Target Regions (comma-separated)
            </label>
            <input
              id="conn-regions"
              value={regionsInput}
              onChange={(e) => setRegionsInput(e.target.value)}
              className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={createMut.isPending || (authQuery.data && !canManageConnections)}
              title={
                authQuery.data && !canManageConnections
                  ? "Requires connections:write permission"
                  : "Register read-only cloud connector"
              }
              className="inline-flex w-full items-center justify-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-4 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
            >
              <Plus className="h-4 w-4" />
              <span>{createMut.isPending ? "Registering..." : "Register Connector"}</span>
            </button>
          </div>
        </form>
      </Panel>

      <Panel
        title={`Configured Cloud Environments (${items.length})`}
        subtitle="Validate read-only permissions and trigger deterministic posture assessments"
      >
        {query.isPending && <LoadingState label="Loading registered connectors..." />}
        {query.isError && <ErrorBanner message={query.error.message} />}
        {query.data && items.length === 0 && (
          <EmptyState
            title="No Cloud Connections Registered"
            description="Use the onboarding form above to connect an AWS account or Azure subscription."
          />
        )}
        {query.data && items.length > 0 && (
          <div className="grid gap-3.5">
            {items.map((conn) => (
              <div
                key={conn.id}
                className="flex flex-wrap items-center justify-between gap-4 rounded-[12px] border border-[#243142] bg-[#172131]/65 p-4 transition-colors hover:border-[#2E3F55]"
              >
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-[#F1F5F9]">
                      {conn.name}
                    </span>
                    <ProviderBadge provider={conn.provider} />
                    <StatusBadge status={conn.status} />
                    <DataSourceBadge source={conn.data_source} />
                  </div>
                  <div className="font-mono text-xs text-[#A0AEC0]">
                    Scope:{" "}
                    <span className="text-[#F1F5F9]">
                      {conn.account_or_subscription_id}
                    </span>{" "}
                    · Auth: <span className="text-[#F1F5F9]">{conn.auth_mode}</span> ·
                    Regions:{" "}
                    <span className="text-[#F1F5F9]">{conn.regions.join(", ")}</span>
                  </div>
                  <div className="font-mono text-[11px] text-[#64748B]">
                    {conn.last_validated_at
                      ? `Last validated: ${conn.last_validated_at.slice(0, 19).replace("T", " ")}Z`
                      : "Not validated yet"}
                    {conn.role_arn ? ` · ${conn.role_arn}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={validateMut.isPending}
                    onClick={() => validateMut.mutate(conn.id)}
                    className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#243142] bg-[#0C121B] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] hover:border-[#00D6A0]/40 hover:text-[#00D6A0] disabled:opacity-50"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 text-[#10B981]" />
                    <span>Preflight Validate</span>
                  </button>
                  <button
                    type="button"
                    disabled={assessMut.isPending || (authQuery.data && !canRunAssessment)}
                    onClick={() => assessMut.mutate(conn.id)}
                    className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3 py-1.5 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    <Play className="h-3.5 w-3.5" />
                    <span>Run Assessment</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
