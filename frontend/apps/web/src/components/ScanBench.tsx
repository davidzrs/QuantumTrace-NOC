import type { ScanResult } from "@quantumtrace/sdk";
import { Fragment, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ACCEPTED_FILES,
  formatBytes,
  fromDrop,
  fromInput,
  kindOf,
  MAX_FILES,
  mergePicked,
  planIntake,
  type Intake,
  type Kind,
  type Picked,
} from "../lib/intake";
import { plural, type Source } from "../lib/format";

const MB = 1024 * 1024;
const FILES_SHOWN = 8;
const EXTS_SHOWN = 4;

const KIND_LABEL: Record<Kind, string> = {
  cloud: "Cloud posture",
  code: "Source code",
  capture: "Network capture",
  archive: "Zip archive",
};

/** What is being scanned right now, and its result once the scanner answers. */
export type RunningScan = { started: number; items: Picked[]; result?: ScanResult; finished?: number };

/**
 * Where a scan starts: drop or choose folders, files and zips (in any mix, over several picks),
 * review what will be sent, then scan. Only files a scanner reads leave the browser.
 *
 * `limitMb` is the most a scan may hold. When the API unpacks gzip, files are compressed
 * before upload, so this is the unpacked size rather than the bytes sent.
 */
export function ScanBench({
  limitMb,
  running,
  onScan,
  children,
}: {
  limitMb: number | undefined;
  running: RunningScan | null;
  onScan: (items: Picked[]) => void;
  /** Shown under the drop zone, e.g. why the last scan failed. */
  children?: ReactNode;
}) {
  const [dragging, setDragging] = useState(false);
  const [reading, setReading] = useState(false);
  const [staged, setStaged] = useState<{ picked: Picked[]; skippedDirs: string[] } | null>(null);
  const filesInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const busy = running !== null;

  // Each pick adds to the scan: a folder, then a zip, then a capture all go up together.
  const stage = (picked: Picked[], skippedDirs: string[] = []) => {
    if (!picked.length && !skippedDirs.length) return;
    setStaged((prev) => ({
      picked: mergePicked(prev?.picked ?? [], picked),
      skippedDirs: [...new Set([...(prev?.skippedDirs ?? []), ...skippedDirs])],
    }));
  };
  const remove = (path: string) =>
    setStaged((prev) => {
      const picked = prev?.picked.filter((p) => p.path !== path) ?? [];
      return picked.length ? { picked, skippedDirs: prev?.skippedDirs ?? [] } : null;
    });
  const plan = useMemo(() => (staged ? planIntake(staged.picked, staged.skippedDirs) : null), [staged]);
  const blocker = plan && blockerFor(plan, limitMb);
  const n = plan?.send.length ?? 0;
  const ready = plan !== null && !blocker;

  return (
    <section
      id="upload"
      aria-labelledby={titleId}
      aria-busy={busy || reading}
      className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-4"
      onDragOver={(e) => {
        e.preventDefault();
        if (!busy) setDragging(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (busy) return;
        setReading(true);
        fromDrop(e.dataTransfer)
          .then(({ picked, skippedDirs }) => stage(picked, skippedDirs))
          .finally(() => setReading(false));
      }}
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="grid gap-1.5">
          <h2 id={titleId} className="font-display text-[24px] leading-tight font-bold tracking-[-0.02em]">
            Upload what you want to scan
          </h2>
          <p className="max-w-[70ch] text-ink-muted">
            Cloud exports, source code, dependency manifests, server configs, certificates, Java builds
            and packet captures, in any mix. Only the files a scanner reads leave this browser, and
            nothing is kept but the report.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary min-w-[180px]"
          disabled={busy || !ready}
          onClick={() => plan && onScan(plan.send)}
        >
          {running?.result
            ? "Opening the report…"
            : running
              ? `Scanning ${plural(running.items.length, "file")}…`
              : ready
                ? `Scan ${plural(n, "file")}`
                : "Add files to scan"}
        </button>
      </div>

      {running ? (
        <ScanProgress running={running} />
      ) : (
        <>
          {/* Two explicit pickers rather than a clickable zone with small links: a near miss on
              "a folder" used to open the file picker instead. The zone itself only takes drops. */}
          <div
            className={`flex flex-col items-center justify-center gap-3 rounded-[14px] border-[1.5px] border-dashed px-6 text-center transition-colors ${
              plan ? "min-h-[150px] py-6" : "min-h-[220px] py-8"
            } ${dragging ? "border-ink bg-raise" : "border-rule-strong bg-surface"}`}
          >
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--qt-ink-muted)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M12 15V3" />
              <path d="m7 8 5-5 5 5" />
              <path d="M20 15v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-4" />
            </svg>
            <p className="font-display text-xl font-[650] tracking-[-0.01em]">
              {reading
                ? "Reading the folder…"
                : dragging
                  ? "Drop to add them to the scan"
                  : plan
                    ? "Drop more files, folders or zips here, or add them"
                    : "Drop files, folders or a zipped folder here, or pick them"}
            </p>
            <div className="flex flex-wrap justify-center gap-3 pt-1">
              <button
                type="button"
                className="btn min-h-12 min-w-[184px] bg-raise px-5 text-[15px]"
                disabled={reading}
                onClick={() => filesInput.current?.click()}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
                  <path d="M14 3v5h5" />
                </svg>
                {plan ? "Add files" : "Choose files"}
              </button>
              <button
                type="button"
                className="btn min-h-12 min-w-[184px] bg-raise px-5 text-[15px]"
                disabled={reading}
                onClick={() => folderInput.current?.click()}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                </svg>
                {plan ? "Add a folder" : "Choose a folder"}
              </button>
            </div>
            {/* Reference, not a call to action: folded under one quiet line so the pickers stay the
                thing to look at. The paragraph above already names the kinds of input. */}
            <details className="group w-full max-w-[560px] text-xs text-ink-faint">
              <summary className="mx-auto flex w-fit cursor-pointer list-none items-center gap-1.5 rounded-md px-2 py-1 hover:text-ink-muted [&::-webkit-details-marker]:hidden">
                Which files are read
                <svg width="10" height="10" viewBox="0 0 12 12" aria-hidden className="transition-transform group-open:rotate-180">
                  <path d="m2 4 4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" />
                </svg>
              </summary>
              <dl className="mt-3 grid grid-cols-[max-content_minmax(0,1fr)] text-left">
                {ACCEPTED_FILES.map((g, i) => (
                  <Fragment key={g.label}>
                    <dt className={`py-1.5 pr-6 ${i ? "border-t border-rule" : ""}`}>{g.label}</dt>
                    <dd className={`py-1.5 font-mono text-[11.5px] leading-[18px] ${i ? "border-t border-rule" : ""}`}>
                      {g.files.join("  ")}
                    </dd>
                  </Fragment>
                ))}
              </dl>
              <p className="mt-3 border-t border-rule pt-3 text-left leading-relaxed">
                Everything else stays behind, including <span className="font-mono">node_modules</span>,{" "}
                <span className="font-mono">.git</span>, virtualenvs and build output. Go executables have
                no extension: zip them to include them.
              </p>
            </details>
          </div>
          {plan && (
            <Manifest plan={plan} limitMb={limitMb} blocker={blocker} onRemove={remove} onReset={() => setStaged(null)} />
          )}
        </>
      )}

      {children}

      <input
        ref={filesInput}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          if (e.target.files?.length) stage(fromInput(e.target.files));
          e.target.value = "";
        }}
      />
      <input
        ref={folderInput}
        type="file"
        hidden
        {...({ webkitdirectory: "" } as object)}
        onChange={(e) => {
          if (e.target.files?.length) stage(fromInput(e.target.files));
          e.target.value = "";
        }}
      />
    </section>
  );
}

function blockerFor(plan: Intake, limitMb: number | undefined): string | null {
  if (!plan.send.length)
    return "Nothing here is something QuantumTrace reads. It scans .py, .java and .go source, AWS .json exports, .pcap captures and .zip archives.";
  if (plan.send.length > MAX_FILES)
    return `That is ${plan.send.length} files and a scan takes up to ${MAX_FILES}. Zip the folder and add the .zip instead, or pick a subfolder.`;
  if (limitMb && plan.bytes > limitMb * MB)
    return `These files add up to ${formatBytes(plan.bytes)} and this scanner takes up to ${limitMb} MB per scan. Pick a subfolder, or run QuantumTrace locally for bigger codebases.`;
  return null;
}

function Manifest({
  plan,
  limitMb,
  blocker,
  onRemove,
  onReset,
}: {
  plan: Intake;
  limitMb: number | undefined;
  blocker: string | null;
  onRemove: (path: string) => void;
  onReset: () => void;
}) {
  const [all, setAll] = useState(false);
  const { skipped } = plan;
  const shown = all ? plan.send : plan.send.slice(0, FILES_SHOWN);
  const share = limitMb ? Math.min(1, plan.bytes / (limitMb * MB)) : 0;
  const exts = skipped.byExt.slice(0, EXTS_SHOWN).map(([ext, n]) => `${n} ${ext}`);
  const moreTypes = skipped.byExt.length - EXTS_SHOWN;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-3 text-sm text-ink-muted">
        <span className="tabular-nums">
          {plural(plan.send.length, "file")} to scan from{" "}
          <span className="font-mono text-ink">{plan.roots.slice(0, 3).join(", ")}</span>
          {plan.roots.length > 3 && ` and ${plan.roots.length - 3} more`}, {formatBytes(plan.bytes)}
          {limitMb ? ` of ${limitMb} MB` : ""}
          {skipped.total > 0 && ` · ${skipped.total} left out`}
        </span>
        <button type="button" onClick={onReset} className="link min-h-11 font-semibold text-ink-muted">
          Clear all
        </button>
      </div>
      {limitMb ? (
        <div className="h-1 overflow-hidden rounded-sm bg-rule" aria-hidden>
          <div className={`h-full ${share >= 1 ? "bg-critical" : "bg-ink"}`} style={{ width: `${share * 100}%` }} />
        </div>
      ) : null}
      {plan.send.length > 0 && (
        <ul className="border-t border-rule" aria-label="Files to scan">
          {shown.map((p) => {
            const kind = kindOf(p.path);
            return (
              <li
                key={p.path}
                className="grid grid-cols-[minmax(0,1fr)_auto_auto_44px] items-center gap-4 border-b border-rule py-1.5 pl-1 text-sm"
              >
                <span className="truncate font-mono text-[13px]" title={p.path}>{p.path}</span>
                <span className="whitespace-nowrap text-ink-soft max-sm:hidden">{kind ? KIND_LABEL[kind] : ""}</span>
                <span className="whitespace-nowrap font-mono text-xs text-ink-faint">{formatBytes(p.file.size)}</span>
                <button
                  type="button"
                  aria-label={`Remove ${p.path}`}
                  onClick={() => onRemove(p.path)}
                  className="grid size-11 place-items-center rounded-lg text-ink-muted hover:bg-raise hover:text-ink"
                >
                  <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden>
                    <path d="M2 2l10 10M12 2 2 12" stroke="currentColor" strokeWidth="1.6" />
                  </svg>
                </button>
              </li>
            );
          })}
        </ul>
      )}
      {plan.send.length > FILES_SHOWN && (
        <button
          type="button"
          aria-expanded={all}
          onClick={() => setAll((a) => !a)}
          className="link justify-self-start text-sm font-semibold"
        >
          {all ? "Show fewer" : `Show all ${plan.send.length} files`}
        </button>
      )}
      {skipped.total > 0 && (
        <p className="max-w-[80ch] text-sm leading-relaxed text-ink-faint">
          Left out {plural(skipped.total, "file")} no scanner reads
          {exts.length > 0 && <>: {exts.join(", ")}{moreTypes > 0 && ` and ${plural(moreTypes, "more type")}`}</>}.
          {skipped.oversized > 0 && ` ${plural(skipped.oversized, "source file")} over 2 MB.`}
          {skipped.dirs.length > 0 && (
            <> Skipped <span className="font-mono">{skipped.dirs.join(", ")}</span>.</>
          )}
        </p>
      )}
      {blocker && (
        <p role="alert" className="max-w-[80ch] border-l-2 border-critical pl-4">
          {blocker}
        </p>
      )}
    </div>
  );
}

const PROGRESS_LANES: { kind: Kind; title: string; source?: Source }[] = [
  { kind: "cloud", title: "Cloud posture", source: "cloud" },
  { kind: "code", title: "Source code", source: "code" },
  { kind: "capture", title: "Network capture", source: "network" },
  { kind: "archive", title: "Zip archives" },
];

/**
 * The scan runs as one request, so there is no per-file progress to report: each scanner shows
 * what it was given and a sweep while the server works. The report opens when it finishes.
 */
function ScanProgress({ running }: { running: RunningScan }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(timer);
  }, []);
  const { result } = running;
  const elapsed = `${(((running.finished ?? now) - running.started) / 1000).toFixed(1)} s`;
  const found = (source: Source | undefined) =>
    result && source ? result.findings.filter((f) => f.asset.evidence.source_type === source).length : 0;

  const lanes = PROGRESS_LANES.map((l) => {
    const files = running.items.filter((p) => kindOf(p.path) === l.kind);
    return { ...l, files: files.map((p) => p.path.slice(p.path.lastIndexOf("/") + 1)) };
  }).filter((l) => l.kind !== "archive" || l.files.length > 0);

  return (
    <div className="qt-fade grid gap-5">
      <p aria-live="polite" className="flex items-center gap-2.5 text-[15px] text-ink-muted">
        <span aria-hidden className={`size-2 rounded-full ${result ? "bg-safe" : "qt-live bg-ink"}`} />
        <span>
          {result
            ? `Scanned ${plural(running.items.length, "file")}, ${plural(result.findings.length, "finding")}. Opening the report…`
            : `Scanning ${plural(running.items.length, "uploaded file")}`}
        </span>
        <span className="font-mono text-[13px] text-ink-faint">{elapsed}</span>
      </p>
      <div className="grid gap-5 [grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr))]">
        {lanes.map((l) => {
          const idle = l.files.length === 0;
          return (
            <article
              key={l.kind}
              onMouseMove={(e) => {
                const r = e.currentTarget.getBoundingClientRect();
                e.currentTarget.style.setProperty("--x", `${e.clientX - r.left}px`);
                e.currentTarget.style.setProperty("--y", `${e.clientY - r.top}px`);
              }}
              className={`group relative grid min-w-0 gap-4 overflow-hidden rounded-xl border border-rule bg-surface p-5 transition-colors hover:border-rule-strong ${
                idle ? "opacity-45" : ""
              }`}
            >
              <span
                aria-hidden
                className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
                style={{
                  backgroundColor: "rgba(232,235,239,.035)",
                  backgroundImage: "radial-gradient(rgba(232,235,239,.32) 1px, transparent 1.6px)",
                  backgroundSize: "9px 9px",
                  maskImage: "radial-gradient(260px circle at var(--x) var(--y), #000, transparent 80%)",
                  WebkitMaskImage: "radial-gradient(260px circle at var(--x) var(--y), #000, transparent 80%)",
                }}
              />
              <div className="relative flex items-baseline justify-between gap-3">
                <h3 className="font-display text-lg font-[650] tracking-[-0.01em]">{l.title}</h3>
                <span className="text-sm whitespace-nowrap text-ink-muted">
                  {idle
                    ? "Nothing uploaded"
                    : result && l.source
                      ? plural(found(l.source), "finding")
                      : result
                        ? "Unpacked"
                        : plural(l.files.length, "file")}
                </span>
              </div>
              <div className="relative h-1 overflow-hidden rounded-sm bg-rule" aria-hidden>
                {!idle && (result ? <div className="qt-fill h-full bg-ink" /> : <div className="qt-sweep h-full w-2/5 bg-ink" />)}
              </div>
              <p className="relative truncate font-mono text-xs text-ink-faint" title={l.files.join(", ")}>
                {idle
                  ? l.kind === "capture"
                    ? "Upload a .pcap to see negotiated sessions"
                    : "Waiting"
                  : `${l.files.slice(0, 3).join(", ")}${l.files.length > 3 ? `, +${l.files.length - 3}` : ""}`}
              </p>
            </article>
          );
        })}
      </div>
      <p className="text-sm text-ink-faint">
        The report opens as soon as the scanner finishes. Large codebases and captures can take a minute.
      </p>
    </div>
  );
}
