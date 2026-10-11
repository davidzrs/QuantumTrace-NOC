import type { RiskScore, RiskTier, ScanResult } from "@quantumtrace/sdk";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { ExposurePanels } from "../components/ExposurePanels";
import { FindingsTable } from "../components/FindingsTable";
import { TickStrip } from "../components/TickStrip";
import { api } from "../lib/api";
import { downloadJson, formatWhen, noteSource, plural, SOURCE_LABEL, SOURCES, type Source } from "../lib/format";
import { exportPdf } from "../lib/pdf";
import { heroSub, tally } from "../lib/summary";

export function Report() {
  const { scanId = "" } = useParams();
  const scan = useQuery({ queryKey: ["scan", scanId], queryFn: () => api.getScan(scanId) });

  if (scan.isPending)
    return (
      <main className="mx-auto max-w-[1240px] px-4 pt-9 pb-24 sm:px-8">
        <p className="qt-live text-ink-muted">Loading report…</p>
      </main>
    );
  if (scan.isError)
    return (
      <main className="mx-auto grid max-w-[1240px] gap-4 px-4 pt-16 pb-24 sm:px-8">
        <h1 className="font-display text-3xl font-bold tracking-[-0.02em]">This report isn’t available</h1>
        <p className="max-w-[60ch] text-ink-muted">
          Reports expire, and a scanner without storage forgets them when it restarts. Run the scan
          again to get a fresh one.
        </p>
        <div>
          <Link to="/#upload" className="btn btn-primary">Start a new scan</Link>
        </div>
      </main>
    );

  return <ReportBody key={scan.data.id} result={scan.data} />;
}

function ReportBody({ result }: { result: ScanResult }) {
  const [source, setSource] = useState<Source | undefined>();
  const [tier, setTier] = useState<RiskTier | undefined>();
  // The list's own source filter, picked on the debt strip; the switch above scopes the whole report.
  const [listSource, setListSource] = useState<Source | undefined>();
  const [query, setQuery] = useState("");
  const all = result.findings;
  // Stable between renders: the findings table keeps its page until the list itself changes.
  const findings = useMemo(
    () => (source ? all.filter((f) => f.asset.evidence.source_type === source) : all),
    [all, source],
  );
  const bySource = (s: Source) => all.filter((f) => f.asset.evidence.source_type === s).length;
  const total = findings.length;
  const counts = tally(findings);
  const c = counts.c;
  const notes = result.limitations.filter((n) => !source || (noteSource(n.scanner) ?? source) === source);
  const noCapture = bySource("network") === 0;

  const pickSource = (s: Source | undefined) => {
    setSource(s);
    setListSource(undefined);
  };
  const showFile = (path: string) => {
    pickSource(undefined);
    setTier(undefined);
    setQuery(path);
    document.getElementById("fixes")?.scrollIntoView({ behavior: smoothScroll() });
  };
  const exportCbom = async () =>
    downloadJson(`quantumtrace-cbom-${result.id.slice(0, 8)}.cdx.json`, await api.getCbom(result.id));
  // Always the whole scan, whichever source is picked above.
  const pdf = useMutation({ mutationFn: () => exportPdf(result, `${window.location.origin}/scans/${result.id}`) });

  return (
    <main className="mx-auto grid max-w-[1240px] grid-cols-[minmax(0,1fr)] gap-10 px-4 pt-5 pb-20 sm:px-8">
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5">
        <div className="grid gap-3">
          <p className="flex min-w-0 flex-wrap items-center gap-2 text-[13px] text-ink-muted">
            <Link to="/#history" className="link text-ink-muted">All scans</Link>
            <span aria-hidden>/</span>
            <span>{formatWhen(result.created_at)}</span>
            <span aria-hidden>·</span>
            <span className="truncate font-mono text-xs" title={result.targets.join(", ")}>
              {result.targets.join(", ")}
            </span>
          </p>
          <div className="flex flex-wrap items-center justify-between gap-3">
            {all.length > 0 ? (
              <div role="group" aria-label="Show findings from" className="seg">
                <button type="button" className="seg-btn" aria-pressed={!source} onClick={() => pickSource(undefined)}>
                  All sources<span className="font-mono text-xs opacity-75">{all.length}</span>
                </button>
                {SOURCES.map((s) => {
                  const n = bySource(s);
                  return (
                    <button
                      key={s}
                      type="button"
                      className="seg-btn"
                      aria-pressed={source === s}
                      disabled={n === 0}
                      title={n === 0 ? `No ${SOURCE_LABEL[s].toLowerCase()} in this scan` : undefined}
                      onClick={() => pickSource(s)}
                    >
                      {SOURCE_LABEL[s]}
                      <span className="font-mono text-xs opacity-75">{n || "–"}</span>
                    </button>
                  );
                })}
              </div>
            ) : (
              <span />
            )}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="btn"
                onClick={() => downloadJson(`quantumtrace-report-${result.id.slice(0, 8)}.json`, result)}
              >
                Download report
              </button>
              <button type="button" className="btn" onClick={() => pdf.mutate()} disabled={pdf.isPending}>
                {pdf.isPending ? "Exporting…" : "Export PDF"}
              </button>
              <button type="button" className="btn btn-primary" onClick={() => void exportCbom()}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M12 3v12" />
                  <path d="m7 10 5 5 5-5" />
                  <path d="M5 21h14" />
                </svg>
                Export CBOM
              </button>
            </div>
          </div>
          {pdf.isError && (
            <p role="alert" className="justify-self-end border-l-2 border-critical pl-4 text-sm">
              Couldn’t make the PDF. Check your connection, then try again.
            </p>
          )}
        </div>

        <section aria-labelledby="hero" className="flex flex-wrap items-end gap-x-12 gap-y-5">
          <div className="grid min-w-0 flex-[2_1_560px] gap-3">
            {all.length === 0 ? (
              <>
                <h1 id="hero" className="font-display text-[clamp(30px,3.4vw,46px)] leading-[1.05] font-[750] tracking-[-0.035em]">
                  No cryptography found.
                </h1>
                <p className="max-w-[64ch] text-base leading-[1.55] text-ink-muted">
                  None of the scanners recognised anything in these files. QuantumTrace reads AWS posture
                  exports (JSON), Python, Java and Go source, and .pcap or .pcapng captures.
                </p>
              </>
            ) : (
              <>
                <h1
                  id="hero"
                  className="max-w-[22ch] font-display text-[clamp(30px,3.2vw,44px)] leading-[1.05] font-[750] tracking-[-0.035em] text-balance"
                >
                  {c === 0 ? (
                    `None of these ${plural(total, "asset")} is breakable by Shor’s algorithm.`
                  ) : (
                    <>
                      <span className="text-critical">{c}</span> of {total} cryptographic assets are critical.
                    </>
                  )}
                </h1>
                <p className="qt-fade max-w-[72ch] text-base leading-[1.5] text-pretty text-ink-muted">
                  {heroSub(counts)}
                </p>
              </>
            )}
          </div>
          {all.length > 0 && (
            // The API scores each source on its own. Reports stored before it did fall back to
            // the whole scan's score, and say so.
            <ScorePanel
              score={(source && result.score_by_source[source]) || result.score}
              scope={
                !source ? "All sources" : result.score_by_source[source] ? `${SOURCE_LABEL[source]} only` : "Whole scan, all sources"
              }
            />
          )}
        </section>

        {result.errors.length > 0 && (
          <div role="alert" className="border-l-2 border-critical pl-4 text-sm">
            <p className="font-semibold">Some inputs couldn’t be scanned</p>
            <ul className="mt-1 font-mono text-ink-muted">
              {result.errors.map((e) => <li key={e}>{e}</li>)}
            </ul>
          </div>
        )}

        {total > 0 && (
          <TickStrip
            key={source ?? "all"}
            findings={findings}
            focus={tier}
            focusSource={listSource}
            onSelect={(t, s) => {
              const same = tier === t && listSource === s; // clicking the selection again clears it
              setTier(same ? undefined : t);
              setListSource(same ? undefined : s);
            }}
          />
        )}
      </div>

      {total > 0 && (
        <section id="fixes" aria-labelledby="fixes-title" className="qt-fade scroll-mt-16">
          <FindingsTable
            scanId={result.id}
            findings={findings}
            tier={tier}
            onTierChange={setTier}
            source={listSource}
            onSourceChange={setListSource}
            query={query}
            onQueryChange={setQuery}
          />
        </section>
      )}

      {total > 0 && <ExposurePanels all={all} findings={findings} source={source} onSelectFile={showFile} />}

      {(notes.length > 0 || (noCapture && all.length > 0 && source !== "code")) && (
        <BlindSpots notes={notes} noCapture={noCapture && all.length > 0 && source !== "code"} />
      )}
    </main>
  );
}

function ScorePanel({ score, scope }: { score: RiskScore; scope: string }) {
  const grades = ["A", "B", "C", "D", "F"];
  const at = Math.min(100, Math.max(0, score.value));
  return (
    <div className="panel qt-fade flex-[1_1_320px] gap-2.5 px-5 py-4">
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-semibold">Quantum risk score</span>
        <span className="text-[13px] text-ink-faint">{scope}</span>
      </div>
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div className="flex items-baseline gap-2.5">
          <span className="font-display text-[44px] leading-none font-[750] tracking-[-0.03em]">{score.value.toFixed(1)}</span>
          <span className="text-sm whitespace-nowrap text-ink-muted">
            of 100 · grade <strong className="text-lg text-ink">{score.grade}</strong>
          </span>
        </div>
        <div className="relative min-w-[150px] flex-1 pt-2.5" role="img" aria-label={`Score ${score.value.toFixed(1)} sits in grade ${score.grade}`}>
          <div className="absolute top-0 h-[24px] w-0.5 -translate-x-px bg-ink transition-[left] duration-300 ease-out" style={{ left: `${at}%` }} />
          <div className="grid grid-cols-5 gap-[3px]">
            {grades.map((g) => (
              <span key={g} className="h-2 rounded-xs" style={{ background: g === score.grade ? "var(--qt-ink-muted)" : "var(--qt-rule-strong)" }} />
            ))}
          </div>
          <div className="mt-1.5 grid grid-cols-5 gap-[3px] font-mono text-[11px]">
            {grades.map((g) => (
              <span key={g} style={{ color: g === score.grade ? "var(--qt-ink)" : "var(--qt-ink-faint)" }}>{g}</span>
            ))}
          </div>
        </div>
      </div>
      <p className="text-xs text-ink-faint">0 is quantum-ready, 100 is every asset broken and exposed.</p>
    </div>
  );
}

function BlindSpots({ notes, noCapture }: { notes: ScanResult["limitations"]; noCapture: boolean }) {
  // The list scrolls inside the height of the explanation beside it, instead of trailing on.
  const list = useRef<HTMLUListElement>(null);
  const [overflows, setOverflows] = useState(false);
  useEffect(() => {
    const el = list.current;
    if (!el) return;
    // Observing starts with one callback, so this also re-measures when a source tab swaps the notes.
    const observer = new ResizeObserver(() => setOverflows(el.scrollHeight > el.clientHeight + 1));
    observer.observe(el);
    return () => observer.disconnect();
  }, [notes, noCapture]);
  const total = notes.length + (noCapture ? 1 : 0);
  const bySource = SOURCES.map((s) => ({ s, n: notes.filter((n) => noteSource(n.scanner) === s).length })).filter((x) => x.n > 0);
  const general = notes.filter((n) => !noteSource(n.scanner)).length;

  return (
    <section aria-labelledby="blind-title" className="grid gap-x-12 gap-y-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      <div className="grid content-start gap-3 lg:min-h-[220px]">
        <h2 id="blind-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
          What this scan couldn’t see
        </h2>
        <p className="text-ink-muted">
          Stated so nobody mistakes silence for safety. These also travel in the CBOM metadata.
        </p>
        <dl className="mt-1 grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-2 border-t border-rule pt-3 text-sm">
          {bySource.map(({ s, n }) => (
            <Fragment key={s}>
              <dt className="text-ink-muted">{SOURCE_LABEL[s]}</dt>
              <dd className="tabular-nums">{plural(n, "blind spot")}</dd>
            </Fragment>
          ))}
          {general > 0 && (
            <>
              <dt className="text-ink-muted">Whole scan</dt>
              <dd className="tabular-nums">{plural(general, "blind spot")}</dd>
            </>
          )}
          {noCapture && (
            <>
              <dt className="text-ink-muted">Network capture</dt>
              <dd>Not in this scan</dd>
            </>
          )}
        </dl>
        {overflows && <p className="text-[13px] text-ink-faint">Scroll the list for all {total}.</p>}
      </div>
      <div className="relative">
        <ul
          ref={list}
          tabIndex={overflows ? 0 : undefined}
          aria-label="Blind spots"
          className="grid max-h-[420px] content-start gap-2.5 overflow-y-auto lg:absolute lg:inset-0 lg:max-h-none"
        >
          {notes.map((n) => (
            <BlindSpot key={n.message}>{n.message}</BlindSpot>
          ))}
          {noCapture && (
            <BlindSpot>
              No packet capture in this scan, so nothing here shows what clients actually negotiate or how
              much traffic is already being recorded with these keys. That is the harvest-now,
              decrypt-later exposure, and only the wire can measure it.{" "}
              <Link to="/#upload" className="link">Add a packet capture</Link>
            </BlindSpot>
          )}
        </ul>
      </div>
    </section>
  );
}

function BlindSpot({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex gap-3 rounded-[10px] border border-rule bg-surface px-4 py-3.5 text-sm leading-normal">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--qt-ink-muted)" strokeWidth="1.8" strokeLinecap="round" aria-hidden className="mt-[3px] flex-none">
        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
        <path d="M4 4l16 16" />
      </svg>
      <span>{children}</span>
    </li>
  );
}

const smoothScroll = (): ScrollBehavior =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
