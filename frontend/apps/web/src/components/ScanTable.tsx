import type { ScanSummary } from "@quantumtrace/sdk";
import { Link } from "react-router";
import { formatWhen } from "../lib/format";
import { TIER } from "../lib/tiers";

/** A list of past scans, newest first: the home page's history and the account page's. */
export function ScanTable({
  scans,
  onDelete,
  deleting = false,
}: {
  scans: ScanSummary[];
  /** Without it, the table has no Delete column. */
  onDelete?: (id: string) => void;
  deleting?: boolean;
}) {
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[720px] border-collapse text-left">
        <thead className="text-[13px] text-ink-muted">
          <tr className="border-b border-rule-strong">
            <th className="py-2.5 pr-4 font-medium">Ran</th>
            <th className="py-2.5 pr-4 font-medium">Scanned</th>
            <th className="py-2.5 pr-4 font-medium">Shape</th>
            <th className="py-2.5 pr-4 text-right font-medium">Findings</th>
            <th className="py-2.5 pr-4 text-right font-medium">Critical</th>
            <th className="py-2.5 pr-4 text-right font-medium">Risk score</th>
            {onDelete && <th className="w-px py-2.5"><span className="sr-only">Delete</span></th>}
          </tr>
        </thead>
        <tbody className="text-[15px]">
          {scans.map((s) => (
            <tr key={s.id} className="border-b border-rule">
              <td className="py-3.5 pr-4 whitespace-nowrap">
                <Link to={`/scans/${s.id}`} className="link font-semibold">
                  {formatWhen(s.created_at)}
                </Link>
              </td>
              <td className="max-w-[22rem] truncate py-3.5 pr-4 font-mono text-[13px] text-ink-muted" title={s.targets.join(", ")}>
                {s.targets.join(", ")}
              </td>
              <td className="py-3.5 pr-4"><Shape scan={s} /></td>
              <td className="py-3.5 pr-4 text-right tabular-nums">{s.findings}</td>
              <td className="py-3.5 pr-4 text-right text-critical tabular-nums">{s.score.counts.critical}</td>
              <td className="py-3.5 pr-4 text-right whitespace-nowrap tabular-nums">
                <strong>{s.score.value.toFixed(1)}</strong> <span className="text-ink-muted">{s.score.grade}</span>
              </td>
              {onDelete && (
                <td className="py-2 text-right">
                  <button
                    type="button"
                    onClick={() => onDelete(s.id)}
                    disabled={deleting}
                    aria-label={`Delete the scan from ${formatWhen(s.created_at)}`}
                    className="min-h-11 rounded-lg px-3 text-sm font-semibold text-ink-muted hover:bg-raise hover:text-critical disabled:opacity-50"
                  >
                    Delete
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Shape({ scan }: { scan: ScanSummary }) {
  const c = scan.score.counts;
  const parts = (["critical", "medium", "unknown", "safe"] as const).filter((t) => c[t] > 0);
  return (
    <span
      className="flex h-3.5 w-40 gap-0.5"
      role="img"
      aria-label={parts.map((t) => `${c[t]} ${TIER[t].label.toLowerCase()}`).join(", ") || "No findings"}
    >
      {parts.map((t) => (
        <span key={t} className="rounded-xs" style={{ flex: c[t], background: TIER[t].color }} />
      ))}
    </span>
  );
}
