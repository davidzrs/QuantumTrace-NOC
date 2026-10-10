import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, ScrollRestoration } from "react-router";
import { api } from "../lib/api";

export function Shell() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0 });

  return (
    <div className="min-h-dvh">
      <header className="border-b border-rule">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-8">
          <Link to="/" className="flex items-center gap-2.5 font-bold tracking-tight">
            <Wordmark />
            QuantumTrace
          </Link>
          <p className="flex items-center gap-2 text-sm text-ink-muted" aria-live="polite">
            <span
              aria-hidden
              className={`size-2 rounded-full ${
                health.isSuccess ? "bg-safe" : health.isError ? "bg-critical" : "bg-rule-strong"
              }`}
            />
            {health.isSuccess
              ? `Scanner v${health.data.version} online`
              : health.isError
                ? "Scanner unreachable"
                : "Connecting to scanner"}
          </p>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 pt-10 pb-24 sm:px-8 sm:pt-14">
        <Outlet />
      </main>
      <ScrollRestoration />
    </div>
  );
}

function Wordmark() {
  // A miniature debt strip: two Shor ticks, one Grover, one resilient.
  return (
    <svg width="20" height="16" viewBox="0 0 20 16" aria-hidden>
      <rect x="0" y="0" width="3" height="16" fill="var(--qt-critical)" />
      <rect x="5" y="0" width="3" height="16" fill="var(--qt-critical)" />
      <rect x="10" y="5" width="3" height="11" fill="var(--qt-medium)" />
      <rect x="15" y="10" width="3" height="6" fill="var(--qt-safe)" />
    </svg>
  );
}
