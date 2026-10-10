import { QuantumTraceError, type FixSuggestion } from "@quantumtrace/sdk";
import { useState } from "react";
import { diffLines } from "../lib/diff";

const ROW: Record<string, { mark: string; style?: React.CSSProperties }> = {
  same: { mark: " " },
  del: { mark: "−", style: { background: "var(--qt-critical-wash)", boxShadow: "inset 3px 0 var(--qt-critical)" } },
  add: { mark: "+", style: { background: "var(--qt-safe-wash)", boxShadow: "inset 3px 0 var(--qt-safe)" } },
};

/** What the API said went wrong, in words a person can act on. */
export function fixError(e: unknown): string {
  if (e instanceof QuantumTraceError && typeof e.detail === "string") return e.detail;
  return "Couldn’t get a fix from the API. Check it is running and try again.";
}

/** An AI-written rewrite of a code snippet, shown as a diff against the scanned lines. */
export function FixPanel({ fix }: { fix: FixSuggestion }) {
  const [copied, setCopied] = useState(false);
  const lines = diffLines(fix.original_snippet, fix.fixed_snippet, fix.snippet_start_line);

  const copy = () => {
    void navigator.clipboard.writeText(fix.fixed_snippet).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <section aria-label="Suggested fix" className="qt-fade grid min-w-0 gap-3 border-t border-rule pt-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
        <span className="text-[17px] font-[650]">{fix.summary}</span>
        {fix.changed && (
          <button type="button" className="btn" onClick={copy}>
            {copied ? "Copied" : "Copy fix"}
          </button>
        )}
      </div>
      {fix.changed ? (
        <pre className="code-block">
          <code className="grid min-w-max">
            {lines.map((l, i) => (
              <span key={i} className={`block ${l.op === "same" ? "text-ink-soft" : "text-ink"}`} style={ROW[l.op]!.style}>
                <span className="inline-block w-11 pr-4 text-right text-ink-ghost tabular-nums select-none" aria-hidden>
                  {l.before ?? ""}
                </span>
                <span className="inline-block w-4 text-ink-muted select-none" aria-hidden>
                  {ROW[l.op]!.mark}
                </span>
                {l.op !== "same" && <span className="sr-only">{l.op === "add" ? "Added: " : "Removed: "}</span>}
                <span className="pr-6 whitespace-pre">{l.text || " "}</span>
              </span>
            ))}
          </code>
        </pre>
      ) : (
        <p className="m-0 text-[14px] text-ink-soft">These lines stay as they are. The fix is elsewhere in the file.</p>
      )}
      <p className="m-0 max-w-[75ch] text-[14px] leading-[1.55] text-ink-soft">{fix.explanation}</p>
      {fix.caveats.length > 0 && (
        <div className="grid gap-1">
          <span className="text-[13px] text-ink-muted">{fix.changed ? "Also change" : "Change instead"}</span>
          <ul className="m-0 grid gap-1 pl-5 text-[14px] leading-[1.5] text-ink-soft">
            {fix.caveats.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
      <span className="text-[12.5px] text-ink-faint">
        Written by {fix.model} from the snippet. Review it before applying.
      </span>
    </section>
  );
}
