import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cloud, Layers, RotateCcw, Search, Server, Tag, X } from "lucide-react";
import { fetchAssets, type AssetItem } from "../lib/api";
import { DataSourceBadge, ProviderBadge, StatusBadge } from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

function AssetDetailDrawer({
  asset,
  onClose,
}: {
  asset: AssetItem | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!asset) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [asset, onClose]);

  if (!asset) return null;

  const tagEntries = Object.entries(asset.tags ?? {});

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/65" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Asset Inspection Drawer"
        onClick={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-xl flex-col border-l border-[#243142] bg-[#0C121B] shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-[#243142] bg-[#111925] px-5 py-4">
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-[#00D6A0]">
              Normalized Cloud Resource
            </p>
            <h2 className="mt-0.5 truncate text-sm font-semibold text-[#F1F5F9]">
              {asset.resource_name}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close asset drawer"
            className="rounded-[8px] border border-[#243142] bg-[#172131] p-1.5 text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
          <div className="flex flex-wrap items-center gap-2 rounded-[12px] border border-[#243142] bg-[#111925] p-4">
            <ProviderBadge provider={asset.provider} />
            <StatusBadge status={asset.collection_status} />
            <DataSourceBadge source={asset.data_source} />
          </div>

          <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-4 space-y-3">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                Canonical Resource ID
              </div>
              <div className="mt-1 break-all font-mono text-[11px] text-[#F1F5F9]">
                {asset.resource_id}
              </div>
            </div>
            <div className="grid gap-3 border-t border-[#243142] pt-3 sm:grid-cols-2">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                  Resource Type
                </div>
                <div className="mt-0.5 font-mono text-[#F1F5F9]">{asset.resource_type}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                  Account / Subscription
                </div>
                <div className="mt-0.5 font-mono text-[#F1F5F9]">{asset.account_ref}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                  Region
                </div>
                <div className="mt-0.5 font-mono text-[#A0AEC0]">{asset.region}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-[#64748B]">
                  Last Observed (UTC)
                </div>
                <div className="mt-0.5 font-mono text-[#A0AEC0]">
                  {asset.last_observed_at.slice(0, 19).replace("T", " ")}Z
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-4 space-y-2.5">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#A0AEC0]">
              <Tag className="h-3.5 w-3.5 text-[#00D6A0]" />
              <span>Resource Tags ({tagEntries.length})</span>
            </div>
            {tagEntries.length === 0 ? (
              <p className="text-[11px] text-[#64748B]">
                No tags reported by cloud provider for this asset.
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {tagEntries.map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded-md border border-[#243142] bg-[#080D14] px-2 py-1 font-mono text-[11px] text-[#A0AEC0]"
                  >
                    <span className="text-[#00D6A0]">{k}</span>={String(v)}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export function AssetsPage() {
  const [provider, setProvider] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [search, setSearch] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<AssetItem | null>(null);

  const query = useQuery({
    queryKey: ["assets", provider, search],
    queryFn: () =>
      fetchAssets({ provider: provider || undefined, search: search || undefined }),
    retry: false,
  });

  const items = query.data?.items ?? [];

  const resourceTypes = useMemo(() => {
    return Array.from(new Set(items.map((a) => a.resource_type))).sort();
  }, [items]);

  const filtered = useMemo(() => {
    if (!resourceType) return items;
    return items.filter((a) => a.resource_type === resourceType);
  }, [items, resourceType]);

  const awsCount = items.filter((a) => a.provider.toLowerCase() === "aws").length;
  const azureCount = items.filter((a) => a.provider.toLowerCase() === "azure").length;
  const hasFilters = Boolean(provider || resourceType || search);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Multi-Cloud Resource Catalogue"
        title="Asset Inventory"
        description="Discovered AWS and Microsoft Azure resources normalized with canonical identifiers, regions, tags, provenance, and observation timestamps."
      />

      <section aria-label="Inventory Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Assets"
          value={query.data?.total ?? 0}
          subtitle="Across connected scopes"
          icon={Server}
          accent="accent"
        />
        <MetricCard
          label="AWS Resources"
          value={awsCount}
          subtitle="In current view"
          icon={Cloud}
          accent="warning"
          to="/aws"
        />
        <MetricCard
          label="Azure Resources"
          value={azureCount}
          subtitle="In current view"
          icon={Cloud}
          accent="info"
          to="/azure"
        />
        <MetricCard
          label="Resource Types"
          value={resourceTypes.length}
          subtitle="Normalized cloud schemas"
          icon={Layers}
          accent="neutral"
        />
      </section>

      <div className="flex flex-wrap items-center gap-2.5 rounded-[12px] border border-[#243142] bg-[#111925] p-3.5">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
          <input
            placeholder="Search resource name or ARN / Azure Resource ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] py-2 pl-9 pr-3 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
          />
        </div>
        <select
          aria-label="Filter provider"
          value={provider}
          onChange={(e) => {
            setProvider(e.target.value);
            setResourceType("");
          }}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
        </select>
        <select
          aria-label="Filter resource type"
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Resource Types</option>
          {resourceTypes.map((rt) => (
            <option key={rt} value={rt}>
              {rt}
            </option>
          ))}
        </select>
        {hasFilters && (
          <button
            type="button"
            onClick={() => {
              setProvider("");
              setResourceType("");
              setSearch("");
            }}
            className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-2 text-xs text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset</span>
          </button>
        )}
      </div>

      <Panel
        title={`Discovered Assets (${filtered.length})`}
        subtitle="Click any asset row to inspect canonical metadata and resource tags"
        noPadding
      >
        {query.isPending && (
          <div className="p-5">
            <LoadingState label="Loading cloud asset inventory..." />
          </div>
        )}
        {query.isError && (
          <div className="p-5">
            <ErrorBanner message={query.error.message} />
          </div>
        )}
        {query.data && filtered.length === 0 && (
          <div className="p-5">
            <EmptyState
              title="No Assets Discovered"
              description="No resources match your search criteria, or no assessments have been run yet."
            />
          </div>
        )}
        {query.data && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#243142] bg-[#0C121B] text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                <tr>
                  <th className="px-5 py-3">Resource</th>
                  <th className="px-3 py-3">Cloud</th>
                  <th className="px-3 py-3">Type</th>
                  <th className="px-3 py-3">Region</th>
                  <th className="px-3 py-3">Status</th>
                  <th className="px-5 py-3">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#243142]">
                {filtered.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAsset(a)}
                    className="cursor-pointer transition-colors hover:bg-[#1C293A]/60"
                  >
                    <td className="px-5 py-3">
                      <div className="font-semibold text-[#F1F5F9]">{a.resource_name}</div>
                      <div className="mt-0.5 max-w-md truncate font-mono text-[11px] text-[#64748B]">
                        {a.resource_id}
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <ProviderBadge provider={a.provider} />
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#A0AEC0]">
                      {a.resource_type}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#A0AEC0]">
                      {a.region}
                    </td>
                    <td className="px-3 py-3">
                      <StatusBadge status={a.collection_status} />
                    </td>
                    <td className="px-5 py-3">
                      <DataSourceBadge source={a.data_source} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <AssetDetailDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
    </div>
  );
}
