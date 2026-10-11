import { QuantumTraceError, type ScanResult } from "@quantumtrace/sdk";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useId, useState } from "react";
import { api } from "../lib/api";
import { GitHubIcon } from "./BrandIcons";

/**
 * Scan a public GitHub repository by link. The API downloads the commit itself, so nothing is
 * uploaded from this browser and the repository doesn't have to be cloned first.
 */
export function RepoScan({
  disabled,
  onScanned,
}: {
  /** True while an upload scan runs: one scan at a time. */
  disabled: boolean;
  onScanned: (result: ScanResult) => void;
}) {
  const [url, setUrl] = useState("");
  const inputId = useId();
  const hintId = useId();
  const scan = useMutation({ mutationFn: (link: string) => api.scanGithub(link), onSuccess: onScanned });
  const link = url.trim();

  return (
    <form
      className="grid gap-3 rounded-xl border border-rule bg-surface p-5 sm:px-6"
      aria-busy={scan.isPending}
      onSubmit={(e) => {
        e.preventDefault();
        if (link && !scan.isPending) scan.mutate(link);
      }}
    >
      <div className="grid gap-1">
        <label htmlFor={inputId} className="flex items-center gap-2.5 font-display text-lg font-[650] tracking-[-0.01em]">
          <GitHubIcon size={20} />
          Or scan a GitHub repository
        </label>
        <p id={hintId} className="max-w-[78ch] text-sm text-ink-muted">
          Paste a link to a public repository, or to a branch, tag or folder in it. The scanner downloads
          that commit from GitHub, so nothing is uploaded from here.
        </p>
      </div>
      <div className="flex flex-wrap gap-3">
        <input
          id={inputId}
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          aria-describedby={hintId}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={scan.isPending}
          className="min-h-[38px] min-w-0 flex-[1_1_320px] rounded-lg border border-rule-strong bg-transparent px-3.5 font-mono text-sm outline-none placeholder:text-ink-faint focus:border-ink disabled:opacity-60"
        />
        <button type="submit" className="btn btn-primary min-w-[170px]" disabled={disabled || scan.isPending || !link}>
          {scan.isPending ? "Scanning…" : "Scan repository"}
        </button>
      </div>
      {scan.isPending && <Progress link={link} />}
      {scan.error && !scan.isPending && (
        <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
          {explain(scan.error)}
        </p>
      )}
    </form>
  );
}

function Progress({ link }: { link: string }) {
  const [started] = useState(() => Date.now());
  const [now, setNow] = useState(started);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(timer);
  }, []);
  return (
    <p aria-live="polite" className="flex items-center gap-2.5 text-[15px] text-ink-muted">
      <span aria-hidden className="qt-live size-2 rounded-full bg-ink" />
      <span className="min-w-0 truncate">
        Downloading <span className="font-mono text-sm text-ink">{link}</span> from GitHub and scanning it
      </span>
      <span className="font-mono text-[13px] text-ink-faint">{((now - started) / 1000).toFixed(1)} s</span>
    </p>
  );
}

function explain(error: Error): string {
  // The API's messages already say what failed and what to do next.
  if (error instanceof QuantumTraceError && typeof error.detail === "string") return error.detail;
  if (error instanceof QuantumTraceError && error.status === 422)
    return "That isn’t a link the scanner understands. Paste one such as https://github.com/owner/repo.";
  return `The scan didn’t run: ${error.message}. Check that the scanner is online and try again.`;
}
