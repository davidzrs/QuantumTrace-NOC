import { QuantumTraceError, type ScanResult } from "@quantumtrace/sdk";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useId, useState, type ReactNode } from "react";
import { api } from "../lib/api";
import { siteLabel, siteTarget } from "../lib/site";
import { GitHubIcon } from "./BrandIcons";

interface Props {
  /** True while an upload scan runs: one scan at a time. */
  disabled: boolean;
  onScanned: (result: ScanResult) => void;
}

/**
 * Scan a public GitHub repository by link. The API downloads the commit itself, so nothing is
 * uploaded from this browser and the repository doesn't have to be cloned first.
 */
export function RepoScan(props: Props) {
  return (
    <LinkScan
      {...props}
      icon={<GitHubIcon size={20} />}
      title="Or scan a GitHub repository"
      hint="Paste a link to a public repository, or to a branch, tag or folder in it. The scanner downloads that commit from GitHub, so nothing is uploaded from here."
      placeholder="https://github.com/owner/repo"
      action="Scan repository"
      doing={(link) => (
        <>
          Downloading <span className="font-mono text-sm text-ink">{link}</span> from GitHub and scanning it
        </>
      )}
      invalid="That isn’t a link the scanner understands. Paste one such as https://github.com/owner/repo."
      run={(link) => api.scanGithub(link)}
    />
  );
}

/**
 * Check a live website by link, the way the browser extension checks the tab it's on: the API
 * connects to it and classifies what the handshake agrees on.
 */
export function SiteScan(props: Props) {
  return (
    <LinkScan
      {...props}
      icon={<GlobeIcon size={20} />}
      title="Or scan a website"
      hint="Paste a link or a domain. The scanner connects to the site the way a browser does and rates what it agrees on: TLS version, key exchange (classical or post-quantum), cipher and certificate key."
      placeholder="https://example.com"
      action="Scan website"
      check={(link) => {
        const target = siteTarget(link);
        return "problem" in target ? target.problem : null;
      }}
      doing={(link) => {
        const target = siteTarget(link);
        return (
          <>
            Connecting to <span className="font-mono text-sm text-ink">{"host" in target ? siteLabel(target) : link}</span>{" "}
            and reading its handshake
          </>
        );
      }}
      invalid="That isn’t a website the scanner can check. Paste one such as https://example.com."
      run={(link) => {
        const target = siteTarget(link);
        if ("problem" in target) throw new Error(target.problem);
        return api.probeTls(target.host, target.port);
      }}
    />
  );
}

/** One card: a link in, a scan out. The repository and website cards differ only in their words. */
function LinkScan({
  disabled,
  onScanned,
  icon,
  title,
  hint,
  placeholder,
  action,
  doing,
  invalid,
  check,
  run,
}: Props & {
  icon: ReactNode;
  title: string;
  hint: string;
  placeholder: string;
  action: string;
  /** What's happening while it runs, given the link. */
  doing: (link: string) => ReactNode;
  /** Shown when the API rejects the link's shape (422). */
  invalid: string;
  /** Why the link can't be sent, checked here before any request; null when it can. */
  check?: (link: string) => string | null;
  run: (link: string) => Promise<ScanResult>;
}) {
  const [url, setUrl] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const inputId = useId();
  const hintId = useId();
  const scan = useMutation({ mutationFn: run, onSuccess: onScanned });
  const link = url.trim();
  const message = problem ?? (scan.error && !scan.isPending ? explain(scan.error, invalid) : null);

  return (
    <form
      className="flex flex-col gap-3 rounded-xl border border-rule bg-surface p-5 sm:px-6"
      aria-busy={scan.isPending}
      onSubmit={(e) => {
        e.preventDefault();
        if (!link || scan.isPending) return;
        const reason = check?.(link) ?? null;
        setProblem(reason);
        if (!reason) scan.mutate(link);
      }}
    >
      <div className="grid gap-1">
        <label htmlFor={inputId} className="flex items-center gap-2.5 font-display text-lg font-[650] tracking-[-0.01em]">
          {icon}
          {title}
        </label>
        <p id={hintId} className="max-w-[78ch] text-sm text-ink-muted">
          {hint}
        </p>
      </div>
      {/* At the card's foot, so the inputs of cards side by side line up whatever their hint's length. */}
      <div className="mt-auto flex flex-wrap gap-3">
        <input
          id={inputId}
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          aria-describedby={hintId}
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setProblem(null);
          }}
          placeholder={placeholder}
          disabled={scan.isPending}
          className="min-h-[38px] min-w-0 flex-[1_1_240px] rounded-lg border border-rule-strong bg-transparent px-3.5 font-mono text-sm outline-none placeholder:text-ink-faint focus:border-ink disabled:opacity-60"
        />
        <button type="submit" className="btn btn-primary min-w-[150px]" disabled={disabled || scan.isPending || !link}>
          {scan.isPending ? "Scanning…" : action}
        </button>
      </div>
      {scan.isPending && <Progress>{doing(link)}</Progress>}
      {message && (
        <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
          {message}
        </p>
      )}
    </form>
  );
}

function Progress({ children }: { children: ReactNode }) {
  const [started] = useState(() => Date.now());
  const [now, setNow] = useState(started);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(timer);
  }, []);
  return (
    <p aria-live="polite" className="flex items-center gap-2.5 text-[15px] text-ink-muted">
      <span aria-hidden className="qt-live size-2 rounded-full bg-ink" />
      <span className="min-w-0 truncate">{children}</span>
      <span className="font-mono text-[13px] text-ink-faint">{((now - started) / 1000).toFixed(1)} s</span>
    </p>
  );
}

function explain(error: Error, invalid: string): string {
  // The API's messages already say what failed and what to do next.
  if (error instanceof QuantumTraceError && typeof error.detail === "string") return error.detail;
  if (error instanceof QuantumTraceError && error.status === 422) return invalid;
  return `The scan didn’t run: ${error.message}. Check that the scanner is online and try again.`;
}

/** A website: the globe, drawn in ink like the rest of the interface. */
function GlobeIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden className="shrink-0">
      <circle cx="12" cy="12" r="9.25" />
      <path d="M2.75 12h18.5" />
      <path d="M12 2.75c2.5 2.55 3.75 5.63 3.75 9.25S14.5 18.7 12 21.25C9.5 18.7 8.25 15.62 8.25 12S9.5 5.3 12 2.75Z" />
    </svg>
  );
}
