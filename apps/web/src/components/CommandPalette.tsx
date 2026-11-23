import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Command, Search } from "lucide-react";

interface PaletteItem {
  id: string;
  label: string;
  group: string;
  path: string;
  keywords: string;
}

const PALETTE_ITEMS: PaletteItem[] = [
  { id: "overview", label: "Security Overview", group: "Workspace", path: "/", keywords: "dashboard home kpi posture" },
  { id: "aws", label: "AWS Environment", group: "Workspace", path: "/aws", keywords: "amazon s3 ec2 iam cloudtrail" },
  { id: "azure", label: "Azure Environment", group: "Workspace", path: "/azure", keywords: "microsoft subscription nsg keyvault" },
  { id: "connections", label: "Cloud Connections", group: "Workspace", path: "/connections", keywords: "connectors onboard sts managed identity" },
  { id: "assets", label: "Asset Inventory", group: "Security Posture", path: "/assets", keywords: "resources catalogue inventory" },
  { id: "findings", label: "Security Findings", group: "Security Posture", path: "/findings", keywords: "misconfigurations vulnerabilities alerts" },
  { id: "identity", label: "Identity & Access", group: "Security Posture", path: "/identity", keywords: "iam rbac mfa privilege" },
  { id: "detections", label: "Threat Detection", group: "Detection & Governance", path: "/detections", keywords: "mitre attack cloudtrail activity log" },
  { id: "compliance", label: "Compliance Centre", group: "Detection & Governance", path: "/compliance", keywords: "cis nist iso 27001 controls" },
  { id: "assessments", label: "Assessment History", group: "Detection & Governance", path: "/assessments", keywords: "scans runs history" },
  { id: "remediations", label: "Remediation Centre", group: "Response", path: "/remediations", keywords: "approve preview fix rollback" },
  { id: "reports", label: "Reports & Evidence", group: "Response", path: "/reports", keywords: "export pdf csv json redaction" },
  { id: "settings", label: "Tenant Settings", group: "Platform", path: "/settings", keywords: "oidc role permissions profile" },
  { id: "audit", label: "Audit Logs", group: "Platform", path: "/audit", keywords: "events immutable trail" },
  { id: "system", label: "System Health", group: "Platform", path: "/system", keywords: "health ready postgres redis" },
];

export function CommandPalette({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return PALETTE_ITEMS;
    return PALETTE_ITEMS.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.group.toLowerCase().includes(q) ||
        item.keywords.includes(q)
    );
  }, [query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((prev) => (filtered.length ? (prev + 1) % filtered.length : 0));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex((prev) =>
          filtered.length ? (prev - 1 + filtered.length) % filtered.length : 0
        );
      } else if (e.key === "Enter" && filtered[activeIndex]) {
        e.preventDefault();
        navigate(filtered[activeIndex].path);
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, filtered, activeIndex, navigate, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 px-4 pt-[12vh]"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command Palette"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg overflow-hidden rounded-[12px] border border-[#243142] bg-[#111925] shadow-2xl"
      >
        <div className="flex items-center gap-2.5 border-b border-[#243142] px-4 py-3">
          <Search className="h-4 w-4 shrink-0 text-[#64748B]" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            placeholder="Jump to workspace, module, or security view..."
            className="w-full bg-transparent text-sm text-[#F1F5F9] placeholder:text-[#64748B] focus:outline-none"
          />
          <kbd className="rounded border border-[#243142] bg-[#0C121B] px-1.5 py-0.5 font-mono text-[10px] text-[#64748B]">
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <p className="px-3 py-6 text-center text-xs text-[#64748B]">
              No matching workspace views.
            </p>
          ) : (
            filtered.map((item, idx) => (
              <button
                key={item.id}
                type="button"
                onMouseEnter={() => setActiveIndex(idx)}
                onClick={() => {
                  navigate(item.path);
                  onClose();
                }}
                className={`flex w-full items-center justify-between rounded-[8px] px-3 py-2 text-left text-xs transition-colors ${
                  idx === activeIndex
                    ? "bg-[#1C293A] text-[#F1F5F9]"
                    : "text-[#A0AEC0] hover:bg-[#172131]"
                }`}
              >
                <div>
                  <span className="font-medium">{item.label}</span>
                  <span className="ml-2 font-mono text-[10px] text-[#64748B]">{item.group}</span>
                </div>
                <ArrowRight
                  className={`h-3.5 w-3.5 ${
                    idx === activeIndex ? "text-[#00D6A0]" : "text-transparent"
                  }`}
                />
              </button>
            ))
          )}
        </div>

        <div className="flex items-center justify-between border-t border-[#243142] bg-[#0C121B] px-4 py-2 text-[11px] text-[#64748B]">
          <span className="inline-flex items-center gap-1">
            <Command className="h-3 w-3 text-[#00D6A0]" /> CloudSentinel Command Palette
          </span>
          <span className="font-mono">↑↓ navigate · ↵ open</span>
        </div>
      </div>
    </div>
  );
}
