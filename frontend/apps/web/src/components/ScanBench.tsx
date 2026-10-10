import { useId, useRef, useState } from "react";
import {
  formatBytes,
  fromDrop,
  fromInput,
  KINDS,
  MAX_FILES,
  planIntake,
  type Intake,
  type Picked,
} from "../lib/intake";

const MB = 1024 * 1024;
const EXTS_SHOWN = 4;

/**
 * Where a scan starts: drop or choose a folder, files or a zip, review what will be sent,
 * then scan. Only files a scanner reads leave the browser.
 */
export function ScanBench({
  limitMb,
  busy,
  onScan,
}: {
  limitMb: number | undefined;
  busy: boolean;
  onScan: (items: Picked[]) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const [reading, setReading] = useState(false);
  const [plan, setPlan] = useState<Intake | null>(null);
  const filesInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const titleId = useId();

  const stage = (picked: Picked[], skippedDirs: string[] = []) => {
    if (picked.length || skippedDirs.length) setPlan(planIntake(picked, skippedDirs));
  };

  const blocker = plan && blockerFor(plan, limitMb);
  const n = plan?.send.length ?? 0;

  return (
    <div
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
      aria-busy={busy || reading}
      aria-labelledby={titleId}
      className={`grid grid-cols-[minmax(0,1fr)] border transition-colors ${
        dragging
          ? "border-ink bg-surface"
          : plan
            ? "border-rule-strong bg-surface"
            : "border-dashed border-rule-strong"
      }`}
    >
      {!plan || dragging ? (
        <div className="grid gap-x-12 gap-y-8 px-5 py-10 sm:px-10 sm:py-12 md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] md:items-center">
          <div className="grid justify-items-start gap-5">
            <div className="grid gap-2">
              <p id={titleId} className="text-xl font-semibold">
                {reading
                  ? "Reading the folder…"
                  : dragging
                    ? "Drop to review what gets scanned"
                    : "Drop a folder, files or a .zip here"}
              </p>
              <p className="max-w-[58ch] text-ink-muted">
                Point it at a whole codebase: only the files a scanner reads are uploaded, and you
                see the list before anything leaves this browser. Nothing is kept except the report.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || reading}
                onClick={() => folderInput.current?.click()}
                className="bg-ink px-4 py-2.5 font-semibold text-ground hover:opacity-90 disabled:opacity-50"
              >
                Choose a folder
              </button>
              <button
                type="button"
                disabled={busy || reading}
                onClick={() => filesInput.current?.click()}
                className="border border-rule-strong px-4 py-2.5 font-semibold hover:border-ink disabled:opacity-50"
              >
                Choose files
              </button>
            </div>
          </div>
          <dl className="grid gap-3 border-l border-rule pl-6 text-sm max-md:hidden">
            <div>
              <dt className="font-semibold">Uploaded</dt>
              <dd className="mt-0.5 font-mono text-xs text-ink-muted">.py .java .go .json .pcap .pcapng .zip</dd>
            </div>
            <div>
              <dt className="font-semibold">Left behind</dt>
              <dd className="mt-0.5 text-ink-muted">
                Everything else, plus <span className="font-mono text-xs">node_modules</span>,{" "}
                <span className="font-mono text-xs">.git</span>, virtualenvs and build output
              </dd>
            </div>
          </dl>
        </div>
      ) : (
        <Manifest
          plan={plan}
          titleId={titleId}
          limitMb={limitMb}
          blocker={blocker}
          busy={busy}
          onScan={() => onScan(plan.send)}
          onReset={() => setPlan(null)}
          scanLabel={busy ? `Scanning ${n} ${n === 1 ? "file" : "files"}…` : `Scan ${n} ${n === 1 ? "file" : "files"}`}
        />
      )}
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
    </div>
  );
}

function blockerFor(plan: Intake, limitMb: number | undefined): string | null {
  if (!plan.send.length)
    return "Nothing here is something QuantumTrace reads. It scans .py, .java and .go source, AWS .json exports, .pcap captures and .zip archives.";
  if (plan.send.length > MAX_FILES)
    return `That is ${plan.send.length} files and a scan takes up to ${MAX_FILES}. Zip the folder and drop the .zip, or pick a subfolder.`;
  if (limitMb && plan.bytes > limitMb * MB)
    return `These files add up to ${formatBytes(plan.bytes)} and this scanner takes up to ${limitMb} MB per scan. Pick a subfolder, or run QuantumTrace locally for bigger codebases.`;
  return null;
}

function Manifest({
  plan,
  titleId,
  limitMb,
  blocker,
  busy,
  scanLabel,
  onScan,
  onReset,
}: {
  plan: Intake;
  titleId: string;
  limitMb: number | undefined;
  blocker: string | null;
  busy: boolean;
  scanLabel: string;
  onScan: () => void;
  onReset: () => void;
}) {
  const { skipped } = plan;
  const share = limitMb ? Math.min(1, plan.bytes / (limitMb * MB)) : 0;
  const exts = skipped.byExt.slice(0, EXTS_SHOWN).map(([ext, n]) => `${n} ${ext}`);
  const moreTypes = skipped.byExt.length - EXTS_SHOWN;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-6 px-5 py-6 sm:px-8 sm:py-8">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h3 id={titleId} className="min-w-0 text-xl font-semibold">
          <span className="font-mono text-lg break-all">{plan.roots.slice(0, 3).join(", ")}</span>
          {plan.roots.length > 3 && <span className="text-ink-muted"> and {plan.roots.length - 3} more</span>}
        </h3>
        <p className="text-ink-muted tabular-nums">
          {plan.send.length} {plan.send.length === 1 ? "file" : "files"} to scan, {formatBytes(plan.bytes)}
          {limitMb ? ` of ${limitMb} MB` : ""}
        </p>
      </div>

      {limitMb ? (
        <div className="-mt-3 h-1 bg-rule" aria-hidden>
          <div className={`h-full ${share >= 1 ? "bg-critical" : "bg-ink"}`} style={{ width: `${share * 100}%` }} />
        </div>
      ) : null}

      <table className="w-full text-left">
        <caption className="sr-only">Files that will be scanned, by kind</caption>
        <tbody>
          {KINDS.map((k) => {
            const count = plan.counts[k.id];
            return (
              <tr key={k.id} className={`border-b border-rule ${count ? "" : "text-ink-faint"}`}>
                <th scope="row" className="py-2 pr-4 font-semibold">{k.label}</th>
                <td className="w-16 py-2 pr-4 text-right font-semibold tabular-nums">{count}</td>
                <td className="py-2 text-sm text-ink-muted">{k.hint}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {skipped.total > 0 && (
        <p className="max-w-[72ch] text-sm leading-relaxed text-ink-muted">
          Left out {skipped.total} {skipped.total === 1 ? "file" : "files"} no scanner reads
          {exts.length > 0 && <>: {exts.join(", ")}{moreTypes > 0 && ` and ${moreTypes} more ${moreTypes === 1 ? "type" : "types"}`}</>}.
          {skipped.oversized > 0 && ` ${skipped.oversized} source ${skipped.oversized === 1 ? "file is" : "files are"} over 2 MB.`}
          {skipped.dirs.length > 0 && (
            <> Skipped <span className="font-mono">{skipped.dirs.join(", ")}</span>.</>
          )}
        </p>
      )}

      {blocker && (
        <p role="alert" className="max-w-[72ch] border-l-2 border-critical pl-4">
          {blocker}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {!blocker && (
          <button
            type="button"
            onClick={onScan}
            disabled={busy}
            className="bg-ink px-5 py-2.5 font-semibold text-ground hover:opacity-90 disabled:opacity-60"
          >
            {scanLabel}
          </button>
        )}
        <button
          type="button"
          onClick={onReset}
          disabled={busy}
          className="border border-rule-strong px-4 py-2.5 font-semibold hover:border-ink disabled:opacity-50"
        >
          Choose something else
        </button>
        {!busy && <p className="text-sm text-ink-faint">Or drop another folder here.</p>}
      </div>
    </div>
  );
}
