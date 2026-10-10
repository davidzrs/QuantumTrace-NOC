import type { RiskTier, ScanResult } from "@quantumtrace/sdk";
import { DebtStrip, TIER_META, TIER_ORDER, TierGlyph } from "@quantumtrace/ui";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { FindingsTable } from "../components/FindingsTable";
import { api } from "../lib/api";
import { downloadJson, formatDate } from "../lib/format";
import { migrationPriorities } from "../lib/priorities";

export function Report() {
  const { scanId = "" } = useParams();
  const scan = useQuery({ queryKey: ["scan", scanId], queryFn: () => api.getScan(scanId) });
  const [tier, setTier] = useState<RiskTier | undefined>();

  if (scan.isPending) return <p className="text-ink-muted">Loading report…</p>;
  if (scan.isError)
    return (
      <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
        <h1 className="text-2xl font-bold">This report isn’t available</h1>
        <p className="max-w-[60ch] text-ink-muted">
          Reports are held in memory, so they disappear when the API restarts. Run the scan again
          to get a fresh one.
        </p>
        <Link to="/" className="font-semibold underline underline-offset-4">Start a new scan</Link>
      </div>
    );

  return <ReportBody result={scan.data} tier={tier} onTierChange={setTier} />;
}

function ReportBody({
  result,
  tier,
  onTierChange,
}: {
  result: ScanResult;
  tier: RiskTier | undefined;
  onTierChange: (t: RiskTier | undefined) => void;
}) {
  const { findings, score } = result;
  const total = findings.length;
  const priorities = migrationPriorities(findings);

  const exportCbom = async () =>
    downloadJson(`quantumtrace-cbom-${result.id.slice(0, 8)}.cdx.json`, await api.getCbom(result.id));

  return (
    <article className="grid grid-cols-[minmax(0,1fr)] gap-14">
      <header className="grid grid-cols-[minmax(0,1fr)] gap-6">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 text-sm text-ink-muted">
          <p>
            <Link to="/" className="underline decoration-rule-strong underline-offset-4 hover:text-ink">
              All scans
            </Link>
            <span className="mx-2" aria-hidden>/</span>
            Scanned <span className="font-mono text-ink">{result.targets.join(", ")}</span> on{" "}
            {formatDate(result.created_at)}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => downloadJson(`quantumtrace-report-${result.id.slice(0, 8)}.json`, result)}
              className="border border-rule-strong px-3 py-1.5 font-semibold text-ink hover:border-ink"
            >
              Download report
            </button>
            <button
              type="button"
              onClick={() => void exportCbom()}
              className="bg-ink px-3 py-1.5 font-semibold text-ground hover:opacity-90"
            >
              Export CBOM
            </button>
          </div>
        </div>

        {total === 0 ? (
          <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
            <h1 className="text-3xl font-extrabold tracking-tight">No cryptography found.</h1>
            <p className="max-w-[60ch] text-ink-muted">
              None of the scanners recognised anything in these files. QuantumTrace reads AWS
              posture exports (JSON), Python, Java and Go source, and .pcap/.pcapng captures.
            </p>
          </div>
        ) : (
          <>
            <h1 className="max-w-[22ch] text-4xl leading-[1.08] font-extrabold tracking-[-0.025em] text-balance sm:text-[3.5rem]">
              {score.counts.critical === 0
                ? `None of these ${total} assets is breakable by Shor’s algorithm.`
                : `${score.counts.critical} of ${total} cryptographic assets break under Shor’s algorithm.`}
            </h1>
            <p className="max-w-[64ch] text-lg leading-relaxed text-ink-muted">
              {score.counts.medium > 0 && `${score.counts.medium} more are weakened by Grover’s algorithm. `}
              Quantum risk score{" "}
              <strong className="text-ink">{score.value}</strong> out of 100, grade{" "}
              <strong className="text-ink">{score.grade}</strong>. Taller ticks are internet-facing:
              traffic there can be recorded today and decrypted later.
            </p>
            <div className="qt-strip-reveal">
              <DebtStrip
                findings={findings}
                focus={tier}
                onSelectTier={(t) => onTierChange(tier === t ? undefined : t)}
                height={72}
              />
            </div>
            <ul className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
              {TIER_ORDER.filter((t) => score.counts[t] > 0).map((t) => (
                <li key={t} className="flex items-center gap-2">
                  <TierGlyph tier={t} />
                  <span className="font-semibold tabular-nums">{score.counts[t]}</span>
                  <span className="text-ink-muted">{lowerFirst(TIER_META[t].threat)}</span>
                </li>
              ))}
            </ul>
          </>
        )}
        {result.errors.length > 0 && (
          <div role="alert" className="border-l-2 border-critical pl-4 text-sm">
            <p className="font-semibold">Some inputs couldn’t be scanned</p>
            <ul className="mt-1 font-mono text-ink-muted">
              {result.errors.map((e) => <li key={e}>{e}</li>)}
            </ul>
          </div>
        )}
      </header>

      {result.limitations.length > 0 && (
        <section aria-labelledby="blind-spots" className="grid grid-cols-[minmax(0,1fr)] gap-3">
          <h2 id="blind-spots" className="text-xl font-bold">What this scan couldn’t see</h2>
          <ul className="grid max-w-[72ch] gap-2 border-l-2 border-rule-strong pl-4 text-ink-muted">
            {result.limitations.map((n) => (
              <li key={n.message}>{n.message}</li>
            ))}
          </ul>
        </section>
      )}

      {priorities.length > 0 && (
        <section aria-labelledby="migrate" className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <h2 id="migrate" className="text-xl font-bold">Migrate these first</h2>
          <p className="-mt-2 max-w-[64ch] text-ink-muted">
            Ranked by what is already broken, then by internet exposure, then by how often it appears.
          </p>
          <ol className="divide-y divide-rule border-y border-rule">
            {priorities.map((p, i) => (
              <li key={p.ruleId} className="grid gap-1 py-4 sm:grid-cols-[2rem_12rem_1fr_auto] sm:items-baseline sm:gap-6">
                <span className="text-sm text-ink-faint tabular-nums">{i + 1}</span>
                <span className="text-lg font-bold">{p.name}</span>
                <span className="max-w-[60ch]">
                  {p.replacement ? <>Replace with {p.replacement}</> : "No drop-in replacement; redesign required"}
                  {p.nistReference && <span className="block text-sm text-ink-muted">{p.nistReference}</span>}
                </span>
                <span className="text-sm whitespace-nowrap text-ink-muted tabular-nums">
                  {p.count} {p.count === 1 ? "place" : "places"}
                  {p.internetFacing > 0 && <>, {p.internetFacing} internet-facing</>}
                </span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {total > 0 && (
        <section aria-labelledby="inventory" className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <h2 id="inventory" className="text-xl font-bold">Full inventory</h2>
          <FindingsTable findings={findings} tier={tier} onTierChange={onTierChange} />
        </section>
      )}
    </article>
  );
}

const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
