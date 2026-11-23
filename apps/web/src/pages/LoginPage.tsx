import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, KeyRound, Lock, Play, ShieldCheck, Terminal } from "lucide-react";
import {
  DEMO_ADMIN_TOKEN,
  DEMO_ANALYST_TOKEN,
  fetchAuthMe,
  setStoredToken,
} from "../lib/api";

export function LoginPage() {
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      setStoredToken(token);
      await fetchAuthMe();
      navigate("/");
    } catch (err) {
      setStoredToken("");
      setError(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchDemo = async (demoToken: string) => {
    setError(null);
    setLoading(true);
    try {
      setStoredToken(demoToken);
      await fetchAuthMe();
      navigate("/");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-[80vh] items-center justify-center py-6">
      <div className="w-full max-w-md space-y-5">
        <div className="flex flex-col items-center text-center">
          <img
            src="/cloudsentinel-logo.png"
            alt="CloudSentinel — Hybrid Cloud Security Platform"
            className="h-32 w-auto object-contain"
          />
          <h1 className="mt-3 text-xl font-semibold tracking-tight text-[#F1F5F9]">
            CloudSentinel Sign In
          </h1>
          <p className="mt-1 text-xs text-[#A0AEC0]">
            Security Intelligence Workspace · AWS &amp; Microsoft Azure
          </p>
        </div>

        <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-6 shadow-[0_8px_32px_rgba(0,0,0,0.45)] space-y-5">
          {/* 1-Click Synthetic Demo Sandbox (Works on Vercel & Local Preview without hardcoded secrets) */}
          <div className="rounded-[10px] border border-[#00D6A0]/35 bg-[#0C121B] p-4 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-[#F1F5F9]">
                <ShieldCheck className="h-4 w-4 text-[#00D6A0]" />
                <span>Interactive Demo Sandbox</span>
              </div>
              <span className="rounded-md border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-[#F59E0B]">
                SYNTHETIC FIXTURE
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-[#A0AEC0]">
              Explore all 16 workspace views immediately using explicitly labeled synthetic AWS &amp;
              Azure demo fixtures (<code>data_source=&quot;synthetic_fixture&quot;</code>).
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              <button
                type="button"
                disabled={loading}
                onClick={() => void handleLaunchDemo(DEMO_ADMIN_TOKEN)}
                className="inline-flex items-center justify-center gap-1.5 rounded-[8px] border border-[#00D6A0]/45 bg-[#00D6A0]/15 px-3 py-2 text-xs font-semibold text-[#00D6A0] transition-colors hover:bg-[#00D6A0]/25 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5" />
                <span>Demo Tenant Admin</span>
              </button>
              <button
                type="button"
                disabled={loading}
                onClick={() => void handleLaunchDemo(DEMO_ANALYST_TOKEN)}
                className="inline-flex items-center justify-center gap-1.5 rounded-[8px] border border-[#243142] bg-[#172131] px-3 py-2 text-xs font-medium text-[#F1F5F9] transition-colors hover:border-[#00D6A0]/40 hover:text-[#00D6A0] disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 text-[#38BDF8]" />
                <span>Demo Security Analyst</span>
              </button>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 border-t border-[#243142] pt-4">
            <div>
              <label htmlFor="oidc-token" className="block text-xs font-semibold text-[#F1F5F9]">
                OIDC Access Token (JWT)
              </label>
              <p className="mt-1 text-[11px] leading-relaxed text-[#A0AEC0]">
                Connect to a live FastAPI control plane using an OIDC JWKS or local dev JWT.
              </p>
              <textarea
                id="oidc-token"
                rows={3}
                required
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste your Bearer JWT (eyJhbGciOi...)"
                className="mt-2 w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 font-mono text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
              />
            </div>

            {error && (
              <p
                role="alert"
                className="rounded-[8px] border border-[#F43F5E]/35 bg-[#F43F5E]/10 px-3 py-2 text-xs text-[#F43F5E]"
              >
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-[8px] border border-[#243142] bg-[#172131] px-4 py-2.5 text-xs font-semibold text-[#F1F5F9] transition-colors hover:border-[#00D6A0]/40 hover:text-[#00D6A0] disabled:opacity-50"
            >
              <KeyRound className="h-3.5 w-3.5" />
              <span>{loading ? "Verifying Session..." : "Authenticate with OIDC JWT"}</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </form>

          <div className="border-t border-[#243142] pt-4 text-[11px] text-[#A0AEC0] space-y-2">
            <div className="flex items-center gap-1.5 font-medium text-[#F1F5F9]">
              <Terminal className="h-3.5 w-3.5 text-[#00D6A0]" />
              <span>Local FastAPI Seeder</span>
            </div>
            <code className="block rounded-[8px] border border-[#243142] bg-[#080D14] px-2.5 py-1.5 font-mono text-[11px] text-[#00D6A0]">
              python database/seeds/seed_demo_fixtures.py
            </code>
          </div>
        </div>

        <div className="flex items-center justify-between px-1 text-[11px] text-[#64748B]">
          <span className="inline-flex items-center gap-1.5">
            <Lock className="h-3 w-3 text-[#00D6A0]" />
            Zero cloud credentials stored in browser
          </span>
          <Link to="/system" className="text-[#A0AEC0] hover:text-[#00D6A0]">
            System Health →
          </Link>
        </div>
      </div>
    </div>
  );
}
