import type { RiskTier, ScanResult } from "@quantumtrace/sdk";
import { DebtStrip, TIER_META, TIER_ORDER, TierGlyph } from "@quantumtrace/ui";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { FindingsTable } from "../components/FindingsTable";
import { api } from "../lib/api";
import { downloadJson, formatDate } from "../lib/format";
import { codeHotspots, commonDir, type Hotspot } from "../lib/hotspots";
import { migrationPriorities } from "../lib/priorities";

export function Report() {
  const { scanId = "" } = useParams();
  const scan = useQuery({ queryKey: ["scan", scanId], queryFn: () => api.getScan(scanId) });
  const [tier, setTier] = useState<RiskTier | undefined>();
  const [query, setQuery] = useState("");

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

  return (
    <ReportBody result={scan.data} tier={tier} onTierChange={setTier} query={query} onQueryChange={setQuery} />
  );
}

function ReportBody({
  result,
  tier,
  onTierChange,
  query,
  onQueryChange,
}: {
  result: ScanResult;
  tier: RiskTier | undefined;
  onTierChange: (t: RiskTier | undefined) => void;
  query: string;
  onQueryChange: (q: string) => void;
}) {
  const { findings, score } = result;
  const total = findings.length;
  const priorities = migrationPriorities(findings);
  const hotspots = useMemo(() => codeHotspots(findings), [findings]);
  const sections = [
    { id: "summary", label: "Summary", show: true },
    { id: "blind-spots", label: "Blind spots", show: result.limitations.length > 0 },
    { id: "migrate", label: "Migrate first", show: priorities.length > 0 },
    { id: "files", label: "Files", show: hotspots.length > 1 },
    { id: "inventory", label: "Inventory", show: total > 0 },
  ].filter((x) => x.show);
  const active = useActiveSection(sections.map((x) => x.id));

  const showFile = (path: string) => {
    onTierChange(undefined);
    onQueryChange(path);
    document.getElementById("inventory")?.scrollIntoView({ behavior: smoothScroll() });
  };

  const exportCbom = async () =>
    downloadJson(`quantumtrace-cbom-${result.id.slice(0, 8)}.cdx.json`, await api.getCbom(result.id));

  return (
    <article className="grid grid-cols-[minmax(0,1fr)] gap-14">
      <nav
        aria-label="Report sections"
        className="sticky top-0 z-10 -mx-4 -mb-6 flex items-center justify-between gap-4 border-b border-rule bg-ground/95 px-4 py-2 backdrop-blur-sm sm:-mx-8 sm:px-8"
      >
        <ul className="flex min-w-0 gap-1 overflow-x-auto text-sm [scrollbar-width:none]">
          {sections.map((x) => (
            <li key={x.id}>
              <a
                href={`#${x.id}`}
                aria-current={active === x.id ? "location" : undefined}
                className={`block px-2 py-1.5 font-semibold whitespace-nowrap ${
                  active === x.id ? "text-ink shadow-[inset_0_-2px_var(--qt-ink)]" : "text-ink-muted hover:text-ink"
                }`}
              >
                {x.label}
              </a>
            </li>
          ))}
        </ul>
        <div className="flex shrink-0 gap-2 text-sm">
          <button
            type="button"
            onClick={() => downloadJson(`quantumtrace-report-${result.id.slice(0, 8)}.json`, result)}
            className="border border-rule-strong px-3 py-1.5 font-semibold text-ink hover:border-ink max-sm:hidden"
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
      </nav>

      <header id="summary" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-6">
        <p className="text-sm text-ink-muted">
          <Link to="/" className="underline decoration-rule-strong underline-offset-4 hover:text-ink">
            All scans
          </Link>
          <span className="mx-2" aria-hidden>/</span>
          Scanned <span className="font-mono text-ink">{result.targets.join(", ")}</span> on{" "}
          {formatDate(result.created_at)}
        </p>

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
        <section id="blind-spots" aria-labelledby="blind-spots-title" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-3">
          <h2 id="blind-spots-title" className="text-xl font-bold">What this scan couldn’t see</h2>
          <ul className="grid max-w-[72ch] gap-2 border-l-2 border-rule-strong pl-4 text-ink-muted">
            {result.limitations.map((n) => (
              <li key={n.message}>{n.message}</li>
            ))}
          </ul>
        </section>
      )}

      {priorities.length > 0 && (
        <section id="migrate" aria-labelledby="migrate-title" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-4">
          <h2 id="migrate-title" className="text-xl font-bold">Migrate these first</h2>
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

      {hotspots.length > 1 && <FileHotspots hotspots={hotspots} onSelect={showFile} />}

      {total > 0 && (
        <section id="inventory" aria-labelledby="inventory-title" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-4">
          <h2 id="inventory-title" className="text-xl font-bold">Full inventory</h2>
          <FindingsTable
            findings={findings}
            tier={tier}
            onTierChange={onTierChange}
            query={query}
            onQueryChange={onQueryChange}
          />
        </section>
      )}
    </article>
  );
}

const HOTSPOTS_SHOWN = 8;
const TICKS_SHOWN = 24;

function FileHotspots({ hotspots, onSelect }: { hotspots: Hotspot[]; onSelect: (path: string) => void }) {
  const [all, setAll] = useState(false);
  const shown = all ? hotspots : hotspots.slice(0, HOTSPOTS_SHOWN);
  const base = commonDir(hotspots.map((h) => h.path));
  return (
    <section id="files" aria-labelledby="files-title" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-4">
      <h2 id="files-title" className="text-xl font-bold">Files to fix first</h2>
      <p className="-mt-2 max-w-[64ch] text-ink-muted">
        {hotspots.length} source files{base && <> in <span className="font-mono text-ink">{base}</span></>} use
        cryptography. Ranked by calls Shor’s algorithm breaks, then
        by calls Grover’s weakens. Pick a file to see its findings.
      </p>
      <ol className="divide-y divide-rule border-y border-rule">
        {shown.map((h) => {
          const rel = h.path.slice(base.length);
          const slash = rel.lastIndexOf("/");
          return (
            <li key={h.path}>
              <button
                type="button"
                onClick={() => onSelect(h.path)}
                className="grid w-full gap-x-6 gap-y-1.5 py-3 text-left hover:bg-surface sm:grid-cols-[minmax(0,1fr)_8rem_minmax(0,10rem)] sm:items-center"
              >
                <span className="min-w-0 truncate font-mono text-sm" title={h.path}>
                  <span className="text-ink-muted">{rel.slice(0, slash + 1)}</span>
                  <span className="font-medium">{rel.slice(slash + 1)}</span>
                </span>
                <span className="flex gap-4 text-sm tabular-nums">
                  {(["critical", "medium"] as const).map((t) =>
                    h.counts[t] ? (
                      <span key={t} className="flex items-center gap-1.5" title={TIER_META[t].threat}>
                        <TierGlyph tier={t} />
                        {h.counts[t]} <span className="sr-only">{TIER_META[t].label}</span>
                      </span>
                    ) : null,
                  )}
                  {!h.counts.critical && !h.counts.medium && <span className="text-ink-muted">{h.total} resilient or unclassified</span>}
                </span>
                <span className="flex h-4 items-stretch gap-0.5 max-sm:hidden" aria-hidden>
                  {h.ticks.slice(0, TICKS_SHOWN).map((t, i) => (
                    <span key={i} className="w-1.5" style={{ background: TIER_META[t].color }} />
                  ))}
                  {h.ticks.length > TICKS_SHOWN && (
                    <span className="self-center pl-1 text-xs text-ink-muted">+{h.ticks.length - TICKS_SHOWN}</span>
                  )}
                </span>
              </button>
            </li>
          );
        })}
      </ol>
      {hotspots.length > shown.length && (
        <button
          type="button"
          onClick={() => setAll(true)}
          className="justify-self-start font-semibold underline decoration-rule-strong underline-offset-4 hover:decoration-ink"
        >
          Show all {hotspots.length} files
        </button>
      )}
    </section>
  );
}

/** The section the reader is in: the last one whose top has passed under the section bar. */
function useActiveSection(ids: string[]): string | undefined {
  const [active, setActive] = useState<string | undefined>(ids[0]);
  const key = ids.join(",");
  useEffect(() => {
    const list = key.split(",");
    let frame = 0;
    const update = () => {
      frame = 0;
      const atEnd = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
      const passed = list.filter((id) => (document.getElementById(id)?.getBoundingClientRect().top ?? Infinity) <= 96);
      setActive(atEnd ? list[list.length - 1] : (passed[passed.length - 1] ?? list[0]));
    };
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      cancelAnimationFrame(frame);
    };
  }, [key]);
  return active;
}

const smoothScroll = (): ScrollBehavior =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";

const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
