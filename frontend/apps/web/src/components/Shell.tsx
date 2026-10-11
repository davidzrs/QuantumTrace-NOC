import { Link, NavLink, Outlet, ScrollRestoration, useMatch } from "react-router";
import { useAccount } from "../lib/account";
import { readHistory } from "../lib/history";
import { ApiStatus } from "./ApiStatus";

const navClass = ({ isActive }: { isActive: boolean }) =>
  `px-3 py-2 text-sm font-medium no-underline ${
    isActive ? "text-ink shadow-[inset_0_-2px_0_var(--qt-ink)]" : "rounded-md text-ink-muted hover:bg-raise hover:text-ink"
  }`;

export function Shell() {
  // Optional sign-in: a link only, hidden when this deployment has no Firebase config.
  const account = useAccount();
  const onReport = useMatch("/scans/:scanId");
  // "Report" opens the report in view, else the latest scan run in this browser.
  const reportId = onReport?.params.scanId ?? readHistory()[0];

  return (
    <div className="flex min-h-dvh flex-col">
      <header className="sticky top-0 z-30 border-b border-rule bg-ground/85 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center gap-x-7 gap-y-2 px-4 py-1.5 sm:px-8">
          <Link to="/" className="flex items-center gap-2.5 text-base font-bold tracking-[-0.01em] text-ink no-underline">
            <Wordmark />
            <span className="font-display">QuantumTrace</span>
          </Link>
          <nav aria-label="Main" className="flex flex-auto flex-wrap gap-0.5">
            <NavLink to="/" end className={navClass}>
              Scan
            </NavLink>
            {reportId ? (
              <NavLink to={`/scans/${reportId}`} className={navClass}>
                Report
              </NavLink>
            ) : (
              <span className="px-3 py-2 text-sm font-medium text-ink-ghost" title="Run a scan to see its report">
                Report
              </span>
            )}
          </nav>
          <ApiStatus />
          {account.status !== "off" && (
            <NavLink to="/account" className={navClass}>
              {account.status === "signed-in" ? account.username : "Account"}
            </NavLink>
          )}
        </div>
      </header>
      <div className="flex-1">
        <Outlet />
      </div>
      <footer className="mx-auto w-full max-w-[1240px] px-4 pb-8 sm:px-8">
        <div className="flex flex-wrap justify-between gap-3 border-t border-rule pt-5 text-[13px] text-ink-faint">
          <span>Maps to NIST FIPS 203, 204 and 205 · exports CycloneDX 1.6</span>
          <span>JunctionX Lisbon 2026 · Inspiring Solutions</span>
        </div>
      </footer>
      <ScrollRestoration />
    </div>
  );
}

function Wordmark() {
  // A miniature debt strip: two Shor ticks, one Grover, one resilient.
  return (
    <svg width="22" height="18" viewBox="0 0 22 18" aria-hidden>
      <rect x="0" y="0" width="3" height="18" fill="var(--qt-critical)" />
      <rect x="6" y="0" width="3" height="18" fill="var(--qt-critical)" />
      <rect x="12" y="6" width="3" height="12" fill="var(--qt-medium)" />
      <rect x="18" y="11" width="3" height="7" fill="var(--qt-safe)" />
    </svg>
  );
}
