import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, KeyRound, Lock, Terminal } from "lucide-react";
import { fetchAuthMe, setStoredToken } from "../lib/api";

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

        <div className="rounded-[12px] border border-[#243142] bg-[#111925] p-6 shadow-[0_8px_32px_rgba(0,0,0,0.45)]">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="oidc-token" className="block text-xs font-semibold text-[#F1F5F9]">
                OIDC Access Token (JWT)
              </label>
              <p className="mt-1 text-[11px] leading-relaxed text-[#A0AEC0]">
                Verified server-side against OIDC JWKS or local dev signing key. Tenant scope and
                RBAC role are resolved strictly from your membership record.
              </p>
              <textarea
                id="oidc-token"
                rows={4}
                required
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste your Bearer JWT (eyJhbGciOi...)"
                className="mt-2.5 w-full rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2.5 font-mono text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
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
              className="flex w-full items-center justify-center gap-2 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-4 py-2.5 text-sm font-semibold text-[#00D6A0] transition-colors hover:bg-[#00D6A0]/25 disabled:opacity-50"
            >
              <KeyRound className="h-4 w-4" />
              <span>{loading ? "Verifying Session..." : "Authenticate Session"}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          <div className="mt-5 border-t border-[#243142] pt-4 text-[11px] text-[#A0AEC0] space-y-2">
            <div className="flex items-center gap-1.5 font-medium text-[#F1F5F9]">
              <Terminal className="h-3.5 w-3.5 text-[#00D6A0]" />
              <span>Local Development Quick Seed</span>
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
