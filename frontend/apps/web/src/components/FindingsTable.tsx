import type { CryptoLibrary, Finding, RiskTier } from "@quantumtrace/sdk";
import { TierGlyph } from "@quantumtrace/ui";
import { useQuery } from "@tanstack/react-query";
import { Fragment, useDeferredValue, useEffect, useId, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { FixPanel, fixError } from "./FixPanel";
import { findComponent } from "../lib/cbom";
import { FIX_BY, fixRows, type FixBy, type FixRow } from "../lib/fix";
import {
  algorithmLabel,
  confidenceLabel,
  downloadJson,
  EXPOSURE_LABEL,
  evidenceLabel,
  observationLabel,
  observationNote,
  runtimeNote,
  placeLabel,
  plural,
  SOURCE_LABEL,
  standards,
  usageLabel,
  variantLabel,
  type Evidence,
  type Source,
} from "../lib/format";
import { TIER, TIERS } from "../lib/tiers";

const PAGE = 8;
const PLACES_SHOWN = 12;
const SESSIONS_SHOWN = 40;

const FIX_TAG: Record<FixBy, React.CSSProperties> = {
  now: { background: "var(--qt-critical)", color: "var(--qt-ground)" },
  "before-2030": { border: "1px solid var(--qt-critical)", color: "var(--qt-critical)" },
  harden: { border: "1px solid var(--qt-medium)", color: "var(--qt-medium)" },
  review: { border: "1px solid var(--qt-rule-strong)", color: "var(--qt-ink-muted)" },
  none: { border: "1px solid var(--qt-rule-strong)", color: "var(--qt-ink-faint)" },
};

const TH = "h-9 py-2 pr-4 font-medium shadow-[inset_0_-1px_0_var(--qt-rule-strong)]";
const ICON_BTN =
  "grid size-9 place-items-center rounded-lg text-ink-muted hover:bg-raise hover:text-ink disabled:cursor-not-allowed disabled:text-ink-ghost disabled:hover:bg-transparent";

/**
 * Every finding, grouped where identical and ordered by when to fix it. The list pages instead
 * of scrolling, so the panels below stay in reach, and a row opens a side panel with where it
 * is, what threatens it, what replaces it, and its CBOM component.
 */
export function FindingsTable({
  scanId,
  findings,
  tier,
  onTierChange,
  source,
  onSourceChange,
  libraries = [],
  query,
  onQueryChange: setQuery,
}: {
  scanId: string;
  findings: Finding[];
  tier: RiskTier | undefined;
  onTierChange: (tier: RiskTier | undefined) => void;
  /** Only this source's findings (picked on the debt strip). */
  source: Source | undefined;
  onSourceChange: (source: Source | undefined) => void;
  /** The scan's cryptographic libraries, to name the one behind a finding. */
  libraries?: CryptoLibrary[];
  query: string;
  onQueryChange: (query: string) => void;
}) {
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [grouped, setGrouped] = useState(true);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());

  const scoped = useMemo(
    () => (source ? findings.filter((f) => f.asset.evidence.source_type === source) : findings),
    [findings, source],
  );
  const rows = useMemo(() => {
    const matching = scoped
      .filter((f) => !tier || f.classification.tier === tier)
      .filter((f) => {
        if (!deferredQuery) return true;
        const haystack = [
          algorithmLabel(f),
          f.classification.name,
          f.asset.variant ?? "",
          f.asset.observed,
          f.asset.usage ?? "",
          usageLabel(f.asset.usage),
          placeLabel(f),
          f.asset.evidence.location,
          ...Object.values(f.asset.evidence.context ?? {}),
          ...f.asset.flags,
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(deferredQuery);
      });
    return fixRows(matching, grouped);
  }, [scoped, tier, deferredQuery, grouped]);
  const findingCount = rows.reduce((n, r) => n + r.members.length, 0);
  const count = (t: RiskTier) => scoped.filter((f) => f.classification.tier === t).length;

  // A page belongs to one list of rows: a new source, tier, search or grouping starts from the first.
  const [paging, setPaging] = useState({ page: 0, rows });
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const page = paging.rows === rows ? Math.min(paging.page, pages - 1) : 0;
  const visible = rows.slice(page * PAGE, (page + 1) * PAGE);
  const table = useRef<HTMLDivElement>(null);
  const turn = (to: number) => {
    setPaging({ page: to, rows });
    // Pages differ in height: bring the column heads back if the reader scrolled past them.
    const el = table.current;
    if (el && el.getBoundingClientRect().top < 64) el.scrollIntoView({ block: "start" });
  };

  const openIndex = openKey === null ? -1 : rows.findIndex((r) => r.key === openKey);
  const openRow = rows[openIndex];
  const step = (to: number) => {
    const next = rows[to];
    if (!next) return;
    setOpenKey(next.key);
    setPaging({ page: Math.floor(to / PAGE), rows }); // the table follows the panel
  };
  // Closing the panel puts focus back on the row it last showed.
  const buttons = useRef(new Map<string, HTMLButtonElement>());
  const lastOpen = useRef<string | null>(null);
  useEffect(() => {
    if (openKey !== null) lastOpen.current = openKey;
    else if (lastOpen.current !== null) {
      buttons.current.get(lastOpen.current)?.focus();
      lastOpen.current = null;
    }
  }, [openKey]);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="grid gap-1">
          <h2 id="fixes-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
            What to fix, in order
          </h2>
          <p className="text-ink-muted">
            Broken today first. Then what Shor’s algorithm will break once quantum computers are big
            enough: NIST deprecates it in 2030 and disallows it in 2035. Then Grover hardening.
          </p>
        </div>
        <span className="text-sm text-ink-muted tabular-nums" aria-live="polite">
          {grouped ? `${plural(rows.length, "row")} · ${plural(findingCount, "finding")}` : plural(findingCount, "finding")}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div role="group" aria-label="Filter by tier" className="flex flex-wrap gap-1.5">
          <button type="button" className="chip" aria-pressed={!tier} onClick={() => onTierChange(undefined)}>
            All<span className="opacity-70">{scoped.length}</span>
          </button>
          {TIERS.filter((t) => count(t) > 0).map((t) => (
            <button
              key={t}
              type="button"
              className="chip"
              aria-pressed={tier === t}
              onClick={() => onTierChange(tier === t ? undefined : t)}
            >
              {TIER[t].label}
              <span className="opacity-70">{count(t)}</span>
            </button>
          ))}
          {source && (
            <button
              type="button"
              className="chip"
              aria-pressed
              aria-label={`Showing ${SOURCE_LABEL[source].toLowerCase()} only. Show every source`}
              onClick={() => onSourceChange(undefined)}
            >
              {SOURCE_LABEL[source]} only
              <span aria-hidden>×</span>
            </button>
          )}
        </div>
        <label className="flex min-h-9 max-w-[380px] flex-[1_1_260px] items-center gap-2.5 rounded-lg border border-rule-strong px-3.5 focus-within:border-ink">
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden className="shrink-0 text-ink-faint">
            <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="m11 11 4 4" stroke="currentColor" strokeWidth="1.6" />
          </svg>
          <span className="sr-only">Search findings</span>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Algorithm, alias, file, ARN, flag"
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-ink-faint"
          />
        </label>
        <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-ink-muted">
          <input
            type="checkbox"
            checked={grouped}
            onChange={(e) => setGrouped(e.target.checked)}
            className="size-4 accent-[var(--qt-ink)]"
          />
          Group identical findings
        </label>
        {pages > 1 && (
          // The same page turn as below the table, in reach without scrolling down to it.
          <div role="group" aria-label="Pages" className="ml-auto flex items-center gap-1">
            <button type="button" className={ICON_BTN} aria-label="Previous page" disabled={page === 0} onClick={() => turn(page - 1)}>
              <Chevron dir="left" />
            </button>
            <button type="button" className={ICON_BTN} aria-label="Next page" disabled={page === pages - 1} onClick={() => turn(page + 1)}>
              <Chevron dir="right" />
            </button>
          </div>
        )}
      </div>

      <div ref={table} className="scroll-mt-16 overflow-x-auto border-b border-rule">
        <table className="w-full border-collapse text-left sm:min-w-[600px] md:min-w-[960px]">
          <thead className="text-[13px] text-ink-muted">
            <tr>
              <th className={`${TH} w-[110px] pl-3 whitespace-nowrap`}>Risk</th>
              <th className={TH}>Algorithm</th>
              <th className={`${TH} hidden md:table-cell`}>Used for</th>
              <th className={`${TH} hidden sm:table-cell`}>Where</th>
              <th className={`${TH} hidden md:table-cell`}>Exposure</th>
              <th className={`${TH} whitespace-nowrap`}>Fix by</th>
              <th className={`${TH} w-12`}><span className="sr-only">Details</span></th>
            </tr>
          </thead>
          <tbody className="text-sm">
            {visible.map((row) => (
              <Row
                key={row.key}
                row={row}
                selected={row.key === openKey}
                onOpen={() => setOpenKey(row.key)}
                buttonRef={(el) => {
                  if (el) buttons.current.set(row.key, el);
                  else buttons.current.delete(row.key);
                }}
              />
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <p className="py-8 text-ink-muted">No findings match. Clear the search or pick another tier.</p>
        )}
      </div>

      {pages > 1 && (
        <nav aria-label="Pages of findings" className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-ink-muted tabular-nums">
            {page * PAGE + 1}–{page * PAGE + visible.length} of {rows.length} {grouped ? "rows" : "findings"}
          </p>
          <div className="flex items-center gap-2">
            <button type="button" className="btn btn-sm" disabled={page === 0} onClick={() => turn(page - 1)}>
              <Chevron dir="left" />
              Previous
            </button>
            <span className="min-w-[88px] text-center text-sm text-ink-muted tabular-nums">
              Page {page + 1} of {pages}
            </span>
            <button type="button" className="btn btn-sm" disabled={page === pages - 1} onClick={() => turn(page + 1)}>
              Next
              <Chevron dir="right" />
            </button>
          </div>
        </nav>
      )}

      {openRow && (
        <FindingPanel
          row={openRow}
          index={openIndex}
          total={rows.length}
          scanId={scanId}
          libraries={libraries}
          onStep={step}
          onClose={() => setOpenKey(null)}
        />
      )}
    </div>
  );
}

function Chevron({ dir }: { dir: "left" | "right" }) {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden>
      <path d={dir === "left" ? "m8 2-4 4 4 4" : "m4 2 4 4-4 4"} fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

function rowFlags(row: FixRow): string[] {
  const f = row.lead;
  return [
    row.fixBy === "harden" && f.classification.classically_broken ? "broken today" : "",
    ...f.asset.flags.map((x) => x.replace(/-/g, " ")),
  ].filter(Boolean);
}

function Row({
  row,
  selected,
  onOpen,
  buttonRef,
}: {
  row: FixRow;
  selected: boolean;
  onOpen: () => void;
  buttonRef: (el: HTMLButtonElement | null) => void;
}) {
  const { lead: f, members } = row;
  const tier = TIER[f.classification.tier];
  const family = variantLabel(f);
  const flags = rowFlags(row);
  const cell = "border-b border-rule py-2.5 pr-4 align-top";

  return (
    <tr onClick={onOpen} className={`cursor-pointer transition-colors hover:bg-surface ${selected ? "bg-surface" : ""}`}>
      <td className={`${cell} pl-3`}>
        <span className="inline-flex items-center gap-2 font-semibold whitespace-nowrap" style={{ color: tier.color }} title={tier.threat}>
          <TierGlyph tier={f.classification.tier} />
          {tier.label}
        </span>
      </td>
      <td className={cell}>
        <span className="grid gap-0.5">
          <span className="font-semibold">{algorithmLabel(f)}</span>
          {family && <span className="font-mono text-xs text-ink-muted">{family}</span>}
          {flags.length > 0 && <span className="font-mono text-[11px] text-medium">{flags.join(" · ")}</span>}
          {f.classification.hndl && <span className="text-xs text-ink-muted">Exposed to harvest-now, decrypt-later</span>}
          {f.asset.confidence !== "high" && (
            <span className="text-xs text-ink-faint" title={confidenceLabel(f.asset.confidence)}>
              {f.asset.confidence === "medium" ? "inferred" : "uncertain"}
            </span>
          )}
        </span>
      </td>
      <td className={`${cell} hidden text-ink-soft md:table-cell`}>{usageLabel(f.asset.usage)}</td>
      <td className={`${cell} hidden max-w-[300px] sm:table-cell`} title={members.length === 1 ? evidenceLabel(f.asset.evidence) : undefined}>
        <span className="grid gap-0.5">
          {members.length > 1 && <span className="font-semibold tabular-nums">{members.length} places</span>}
          <span className="truncate font-mono text-xs text-ink-muted">
            {members.slice(0, 3).map(placeLabel).join(", ")}
            {members.length > 3 && ", …"}
          </span>
          {row.sessions > members.length && (
            <span className="text-xs text-ink-muted tabular-nums">{row.sessions} {repeatNoun(f, row.sessions)}</span>
          )}
        </span>
      </td>
      <td className={`${cell} hidden whitespace-nowrap md:table-cell`}>{EXPOSURE_LABEL[f.asset.exposure] ?? f.asset.exposure}</td>
      <td className={cell}>
        <span className="tag" style={FIX_TAG[row.fixBy]}>{FIX_BY[row.fixBy].label}</span>
      </td>
      <td className={`${cell} py-2 pr-2 text-right`}>
        <button
          ref={buttonRef}
          type="button"
          aria-haspopup="dialog"
          aria-label={`Open details for ${algorithmLabel(f)} at ${
            members.length === 1 ? placeLabel(f) : `${members.length} places`
          }`}
          onClick={(e) => {
            e.stopPropagation();
            onOpen();
          }}
          className="grid size-8 place-items-center rounded-lg text-ink-muted hover:bg-raise hover:text-ink"
        >
          <Chevron dir="right" />
        </button>
      </td>
    </tr>
  );
}

type Tab = "details" | "cbom" | "fix";

/** A code finding with lines to send: what "Fix with AI" can rewrite. */
const hasSnippet = (f: Finding) => f.asset.evidence.source_type === "code" && !!f.asset.evidence.snippet;

/**
 * One row in a modal side panel with a single scroll of its own. The arrows (or the arrow keys)
 * step through the rows in table order without closing it.
 */
function FindingPanel({
  row,
  index,
  total,
  scanId,
  libraries,
  onStep,
  onClose,
}: {
  row: FixRow;
  index: number;
  total: number;
  scanId: string;
  libraries: CryptoLibrary[];
  onStep: (to: number) => void;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const pressedBackdrop = useRef(false);
  const [tab, setTab] = useState<Tab>("details");
  // Offered wherever the row has code to rewrite (the tab says so when the API has AI fixes off).
  // Stepping to a row without code falls back to the details.
  const fixable = row.members.some(hasSnippet);
  const shown: Tab = tab === "fix" && !fixable ? "details" : tab;
  useEffect(() => {
    const d = dialog.current;
    if (d && !d.open) {
      d.showModal();
      d.focus(); // the panel itself, not its first button: no focus ring after a tap
    }
  }, []);

  const { lead: f } = row;
  const tier = TIER[f.classification.tier];
  const family = variantLabel(f);
  const flags = rowFlags(row);

  return (
    <dialog
      ref={dialog}
      tabIndex={-1}
      aria-labelledby="finding-title"
      onCancel={(e) => {
        e.preventDefault(); // Escape: let React unmount it
        onClose();
      }}
      // A click that starts and ends on the backdrop closes; a text selection dragged out of it doesn't.
      onMouseDown={(e) => {
        pressedBackdrop.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        if (pressedBackdrop.current && e.target === e.currentTarget) onClose();
      }}
      onKeyDown={(e) => {
        if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
        if (e.target instanceof Element && e.target.closest("input, select, textarea")) return;
        if (e.key === "ArrowLeft" && index > 0) onStep(index - 1);
        if (e.key === "ArrowRight" && index < total - 1) onStep(index + 1);
      }}
      className="fixed inset-y-0 right-0 left-auto h-full max-h-full w-full max-w-full overflow-hidden border-l border-rule-strong bg-ground p-0 text-ink outline-none backdrop:bg-[rgba(4,6,9,0.72)] sm:w-[min(780px,92vw)]"
    >
      <div className="flex h-full flex-col">
        <header className="grid gap-4 border-b border-rule px-5 pt-3 pb-4 sm:px-7">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-2 font-semibold whitespace-nowrap" style={{ color: tier.color }} title={tier.threat}>
                <TierGlyph tier={f.classification.tier} />
                {tier.label}
              </span>
              <span className="tag" style={FIX_TAG[row.fixBy]}>{FIX_BY[row.fixBy].label}</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                className={ICON_BTN}
                aria-label="Previous finding"
                title="Previous finding (←)"
                disabled={index === 0}
                onClick={() => onStep(index - 1)}
              >
                <Chevron dir="left" />
              </button>
              <span className="px-1 text-[13px] text-ink-muted tabular-nums">
                {index + 1} of {total}
              </span>
              <button
                type="button"
                className={ICON_BTN}
                aria-label="Next finding"
                title="Next finding (→)"
                disabled={index === total - 1}
                onClick={() => onStep(index + 1)}
              >
                <Chevron dir="right" />
              </button>
              <button type="button" className={`${ICON_BTN} ml-2`} aria-label="Close" title="Close (Esc)" onClick={onClose}>
                <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden>
                  <path d="m2 2 10 10M12 2 2 12" fill="none" stroke="currentColor" strokeWidth="1.6" />
                </svg>
              </button>
            </div>
          </div>
          <div className="grid gap-1">
            <h2 id="finding-title" className="font-display text-[26px] leading-tight font-bold tracking-[-0.02em]">
              {algorithmLabel(f)}
            </h2>
            {family && <span className="font-mono text-[13px] text-ink-muted">{family}</span>}
            {flags.length > 0 && <span className="font-mono text-xs text-medium">{flags.join(" · ")}</span>}
            {f.classification.hndl && <span className="text-sm text-ink-muted">Exposed to harvest-now, decrypt-later</span>}
            <span className="text-sm text-ink-muted">
              {usageLabel(f.asset.usage)} · {placesNote(row)}
            </span>
          </div>
          {/* One group of views; the AI fix stands apart from the other two so it reads as the action. */}
          <div role="group" aria-label="Show" className="flex flex-wrap items-center gap-2.5">
            <div className="seg">
              <button type="button" className="seg-btn" aria-pressed={shown === "details"} onClick={() => setTab("details")}>
                Details
              </button>
              <button type="button" className="seg-btn" aria-pressed={shown === "cbom"} onClick={() => setTab("cbom")}>
                CBOM component
              </button>
            </div>
            {fixable && (
              <button
                type="button"
                className="btn btn-ai min-h-[42px] rounded-[10px]"
                aria-pressed={shown === "fix"}
                onClick={() => setTab("fix")}
              >
                <SparkleIcon solid={shown === "fix"} />
                <span className={shown === "fix" ? undefined : "ai-text"}>{AI_LABEL}</span>
              </button>
            )}
          </div>
        </header>
        <PanelBody key={row.key} row={row} tab={shown} scanId={scanId} libraries={libraries} />
      </div>
    </dialog>
  );
}

/** The panel's scrolling part. Keyed by row, so stepping resets the place and the scroll. */
function PanelBody({
  row,
  tab,
  scanId,
  libraries,
}: {
  row: FixRow;
  tab: Tab;
  scanId: string;
  libraries: CryptoLibrary[];
}) {
  const [pick, setPick] = useState(0);
  const place = row.members[Math.min(pick, row.members.length - 1)] ?? row.lead;
  return (
    // Keyed by tab too: each tab opens at its top.
    <div key={tab} className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 pt-5 pb-10 sm:px-7">
      {tab === "details" ? (
        <FindingDetail row={row} place={place} onPick={setPick} libraries={libraries} />
      ) : tab === "cbom" ? (
        <CbomComponent key={place.id} scanId={scanId} row={row} place={place} onPick={setPick} />
      ) : (
        <FixWithAi scanId={scanId} row={row} place={place} onPick={setPick} />
      )}
    </div>
  );
}

const LANGUAGE: Record<string, string> = { go: "Go", java: "Java", py: "Python" };

/** Network repeats are sessions; in code and cloud they are further lines or keys. */
function repeatNoun(f: Finding, n: number): string {
  const noun = f.asset.evidence.source_type === "network" ? "session" : "occurrence";
  return n === 1 ? noun : `${noun}s`;
}

function placesNote(row: FixRow): string {
  const { lead: f, members } = row;
  if (members.length === 1) {
    if (row.sessions <= 1) return "One place";
    return f.asset.evidence.source_type === "network" ? `${row.sessions} sessions to one server` : `${row.sessions} lines in one file`;
  }
  const usage = usageLabel(f.asset.usage).toLowerCase();
  const code = members.every((m) => m.asset.evidence.source_type === "code");
  const langs = [...new Set(members.map((m) => LANGUAGE[m.asset.evidence.location.split(".").pop() ?? ""]).filter(Boolean))];
  const across = code && langs.length > 1 ? `, across ${langs.slice(0, -1).join(", ")} and ${langs.at(-1)}` : "";
  const sessions = row.sessions > members.length ? `, ${row.sessions} ${repeatNoun(f, row.sessions)}` : "";
  return `Same ${usage} in ${members.length} ${code ? "files" : "places"}${across}${sessions}`;
}

function FindingDetail({
  row,
  place,
  onPick,
  libraries,
}: {
  row: FixRow;
  place: Finding;
  onPick: (index: number) => void;
  libraries: CryptoLibrary[];
}) {
  const [allPlaces, setAllPlaces] = useState(false);
  const { lead: f, members } = row;
  const c = f.classification;
  const tier = TIER[c.tier];
  const shownPlaces = allPlaces ? members : members.slice(0, PLACES_SHOWN);
  const refs = standards(c);
  const library = libraries.find((l) => l.id === place.asset.library);

  return (
    <div className="grid gap-7">
      <div className="grid min-w-0 gap-2.5">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
          <span className="font-semibold">Where it is</span>
          <span className="text-[13px] text-ink-muted">{placesNote(row)}</span>
        </div>
        {members.length > 1 && (
          <div role="group" aria-label="Places" className="flex flex-wrap gap-1.5">
            {shownPlaces.map((m, k) => (
              <button
                key={m.id}
                type="button"
                aria-pressed={place.id === m.id}
                onClick={() => onPick(k)}
                className={`min-h-9 rounded-lg border px-3 font-mono text-[12.5px] ${
                  place.id === m.id ? "border-ink bg-raise text-ink" : "border-rule text-ink-muted hover:border-rule-strong hover:text-ink"
                }`}
              >
                {placeLabel(m)}
              </button>
            ))}
            {members.length > PLACES_SHOWN && (
              <button
                type="button"
                aria-expanded={allPlaces}
                onClick={() => setAllPlaces((a) => !a)}
                className="link min-h-9 px-2 text-sm font-semibold"
              >
                {allPlaces ? "Show fewer" : `Show all ${members.length}`}
              </button>
            )}
          </div>
        )}
        <EvidenceView key={place.id} finding={place} />
      </div>

      <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
        <Fact
          label="Main threat"
          value={threatLabel(f)}
          sub={threatNote(f)}
          color={c.tier === "critical" || c.classically_broken ? tier.color : undefined}
        />
        <Fact label="Strength" value={strengthLabel(f)} sub={strengthNote(f)} />
        <Fact label="Exposure" value={EXPOSURE_LABEL[f.asset.exposure] ?? f.asset.exposure} sub={exposureNote(f)} />
        <Fact label="Evidence" value={observationLabel(f.asset.observation)} sub={observationNote(f.asset.observation)} />
      </div>

      <dl className="-mt-3 flex flex-wrap gap-x-8 gap-y-2 text-[13px]">
        <div className="flex min-w-0 gap-2">
          <dt className="text-ink-muted">Observed</dt>
          <dd className="font-mono break-all text-ink-soft">{place.asset.observed}</dd>
        </div>
        {runtimeNote(place.asset.evidence.execution) && (
          <div className="flex min-w-0 gap-2">
            <dt className="text-ink-muted">At runtime</dt>
            <dd className="text-ink-soft">{runtimeNote(place.asset.evidence.execution)}</dd>
          </div>
        )}
        {c.oid && (
          <div className="flex gap-2">
            <dt className="text-ink-muted">OID</dt>
            <dd className="font-mono text-ink-soft">{c.oid}</dd>
          </div>
        )}
        {library && (
          <div className="flex min-w-0 gap-2" title={library.note ?? undefined}>
            <dt className="text-ink-muted">Library</dt>
            <dd className="font-mono text-ink-soft">
              {library.name}
              {library.version ? ` ${library.version}` : ""}
            </dd>
          </div>
        )}
      </dl>

      <div className="grid gap-x-10 gap-y-6 border-t border-rule pt-5 sm:grid-cols-[minmax(0,1fr)_minmax(0,15rem)]">
        <div className="grid min-w-0 content-start gap-1.5">
          <span className="text-[13px] text-ink-muted">Replace with</span>
          <span className="text-[19px] leading-snug font-[650]">
            {c.replacement ?? (c.tier === "safe" ? "Nothing, this holds up" : "No drop-in replacement; redesign required")}
          </span>
          {refs.length > 0 && (
            <span className="mt-0.5 flex flex-wrap gap-1.5">
              {refs.map((r) => (
                <span
                  key={r.text}
                  className="rounded border px-2 py-[3px] font-mono text-xs"
                  style={r.pqc ? { borderColor: "var(--qt-safe)", color: "var(--qt-safe)" } : { borderColor: "var(--qt-rule-strong)", color: "var(--qt-ink-muted)" }}
                >
                  {r.text}
                </span>
              ))}
            </span>
          )}
        </div>
        <ConfidenceMeter level={place.asset.confidence} />
      </div>
    </div>
  );
}

type ConfidenceLevel = Finding["asset"]["confidence"];

const CONFIDENCE: Record<ConfidenceLevel, { label: string; bars: number; note: string }> = {
  high: { label: "High", bars: 3, note: "Read directly from the input." },
  medium: { label: "Medium", bars: 2, note: "Inferred, e.g. a key size taken from elsewhere in the file." },
  low: { label: "Low", bars: 1, note: "The input can’t confirm it, e.g. a random number that may not be a secret. Check it by hand." },
};

/** How sure the scanner is of this place: three bars in ink, never a risk colour. */
function ConfidenceMeter({ level }: { level: ConfidenceLevel }) {
  const c = CONFIDENCE[level];
  return (
    <div className="grid min-w-0 content-start gap-1.5">
      <span className="text-[13px] text-ink-muted">Confidence</span>
      <span className="flex items-center gap-2.5">
        <span aria-hidden className="flex items-end gap-[3px]">
          {[1, 2, 3].map((i) => (
            <span
              key={i}
              className="w-[5px] rounded-[1px]"
              style={{ height: 5 + i * 4, background: i <= c.bars ? "var(--qt-ink)" : "var(--qt-rule-strong)" }}
            />
          ))}
        </span>
        <span className="text-[19px] leading-snug font-[650]">{c.label}</span>
      </span>
      <span className="text-[13px] leading-[1.45] text-ink-muted">{c.note}</span>
    </div>
  );
}

function Fact({ label, value, sub, color }: { label: string; value: string; sub: string; color?: string }) {
  return (
    <div className="grid min-w-0 content-start gap-1">
      <span className="text-[13px] text-ink-muted">{label}</span>
      <span className="text-[17px] font-[650]" style={color ? { color } : undefined}>{value}</span>
      {sub && <span className="text-[13px] leading-[1.45] text-ink-muted">{sub}</span>}
    </div>
  );
}

const EXPOSURE_NOTE: Record<string, string> = {
  internet: "Traffic can be recorded today and decrypted later.",
  internal: "Inside the network, still readable from any compromised host.",
  unknown: "This input has no network context.",
};

function exposureNote(f: Finding): string {
  if (f.asset.exposure === "unknown" && f.asset.evidence.source_type === "network") {
    return "The capture doesn’t show whether this server faces the internet.";
  }
  // a signature or a symmetric cipher can't be harvested now and read later, only reached
  if (f.asset.exposure === "internet" && !f.classification.hndl) return "Reachable from the internet.";
  return EXPOSURE_NOTE[f.asset.exposure] ?? "";
}

/** What weighs most: an attack that works today beats a quantum one that needs a future machine. */
function threatLabel(f: Finding): string {
  const c = f.classification;
  if (c.classically_broken) return "Broken today";
  if (c.threat === "shor") return "Shor’s algorithm";
  if (c.threat === "grover") return "Grover’s algorithm";
  if (c.threat === "none") return "None known";
  return "Not classified";
}

/** The rule's reason; for what is broken today, also the quantum threat behind it when unsaid. */
function threatNote(f: Finding): string {
  const c = f.classification;
  if (!c.classically_broken) return c.rationale;
  const later =
    c.threat === "shor" && !c.rationale.includes("Shor")
      ? "Shor’s algorithm breaks it as well."
      : c.threat === "grover" && !c.rationale.includes("Grover")
        ? "Grover’s algorithm weakens it further."
        : "";
  return [c.rationale, later].filter(Boolean).join(" ");
}

function strengthLabel(f: Finding): string {
  const c = f.classification;
  if (f.asset.key_size) return `${f.asset.key_size}-bit`;
  if (c.classical_security_bits != null) return `${c.classical_security_bits}-bit classical`;
  return "Not stated";
}

function strengthNote(f: Finding): string {
  const c = f.classification;
  const parts = [
    f.asset.key_size && c.classical_security_bits != null ? `${c.classical_security_bits}-bit security today.` : "",
    c.nist_quantum_level != null
      ? c.nist_quantum_level === 0
        ? "No quantum security."
        : `NIST PQC category ${c.nist_quantum_level}.`
      : "",
  ];
  return parts.filter(Boolean).join(" ");
}

/** The flagged source with its neighbours, or the cloud or network context it was read from. */
function EvidenceView({ finding: f }: { finding: Finding }) {
  const e = f.asset.evidence;
  const [allSessions, setAllSessions] = useState(false);
  if (e.snippet) return <SnippetList finding={f} />;
  const context = Object.entries(e.context ?? {}).filter(([, v]) => v);
  const more = f.asset.more_evidence;
  const shown = allSessions ? more : more.slice(0, SESSIONS_SHOWN);
  return (
    <figure className="m-0 grid min-w-0 gap-1.5">
      <figcaption className="font-mono text-xs break-all text-ink-muted">{evidenceLabel(e)}</figcaption>
      {context.length > 0 && (
        <dl className="code-block grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 px-4">
          {context.map(([k, v]) => (
            <Fragment key={k}>
              <dt className="text-ink-faint">{k.replace(/_/g, " ")}</dt>
              <dd className="break-all text-ink-soft">{v}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {more.length > 0 && (
        <div className="grid gap-1 pt-2">
          <span className="text-[13px] text-ink-muted">Also seen in {plural(more.length, "more place")}</span>
          <ul className="grid gap-0.5 font-mono text-xs break-all text-ink-muted">
            {shown.map((m, i) => (
              <li key={i}>{evidenceLabel(m)}</li>
            ))}
          </ul>
          {more.length > SESSIONS_SHOWN && (
            <button
              type="button"
              aria-expanded={allSessions}
              onClick={() => setAllSessions((a) => !a)}
              className="link justify-self-start text-sm font-semibold"
            >
              {allSessions ? "Show fewer" : `Show all ${more.length}`}
            </button>
          )}
        </div>
      )}
    </figure>
  );
}

const SNIPPETS_SHOWN = 3;

/** One snippet per line the asset was seen on in this file (repeats are in `more_evidence`). */
function SnippetList({ finding: f }: { finding: Finding }) {
  const [all, setAll] = useState(false);
  const places = [f.asset.evidence, ...f.asset.more_evidence];
  const shown = all ? places : places.slice(0, SNIPPETS_SHOWN);
  if (places.length === 1) return <CodeSnippet finding={f} evidence={f.asset.evidence} />;
  return (
    <div className="grid min-w-0 gap-3">
      <span className="text-[13px] text-ink-muted">Seen on {places.length} lines</span>
      {shown.map((e, i) => (
        <CodeSnippet key={i} finding={f} evidence={e} />
      ))}
      {places.length > SNIPPETS_SHOWN && (
        <button type="button" aria-expanded={all} onClick={() => setAll((a) => !a)} className="link justify-self-start text-sm font-semibold">
          {all ? "Show fewer" : `Show all ${places.length}`}
        </button>
      )}
    </div>
  );
}

function CodeSnippet({ finding: f, evidence: e }: { finding: Finding; evidence: Evidence }) {
  if (!e.snippet) return null;
  const meta = TIER[f.classification.tier];
  const first = e.snippet_start_line ?? e.line ?? 1;
  const lines = e.snippet.split("\n");
  // Scans of a GitHub repository link each line to that commit on GitHub.
  const source = e.context?.source_url;
  return (
    <figure className="m-0 grid min-w-0 gap-1.5">
      <figcaption className="font-mono text-xs break-all text-ink-muted">
        {source?.startsWith("https://github.com/") ? (
          <a href={source} target="_blank" rel="noreferrer" className="link text-ink-muted">
            {evidenceLabel(e)}
            <span className="sr-only"> (opens on GitHub)</span>
          </a>
        ) : (
          evidenceLabel(e)
        )}
      </figcaption>
      <pre className="code-block">
        <code className="grid min-w-max">
          {lines.map((text, i) => {
            const n = first + i;
            const hit = n === e.line;
            return (
              <span
                key={n}
                className={`block ${hit ? "font-medium text-white" : "text-ink-soft"}`}
                style={hit ? { background: meta.wash, boxShadow: `inset 3px 0 ${meta.color}` } : undefined}
              >
                <span className="inline-block w-11 pr-4 text-right text-ink-ghost tabular-nums select-none" aria-hidden>
                  {n}
                </span>
                <span className="pr-6 whitespace-pre">
                  {hit && <span className="sr-only">Flagged line {n}: </span>}
                  {hit ? <MarkedLine text={text} match={e.end_column != null ? f.asset.observed : null} color={meta.color} /> : text || " "}
                </span>
              </span>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}

/** The flagged line with the matched call underlined (snippets are dedented, so find it by text). */
function MarkedLine({ text, match, color }: { text: string; match: string | null; color: string }) {
  const at = match ? text.indexOf(match) : -1;
  if (!match || at < 0) return <>{text || " "}</>;
  return (
    <>
      {text.slice(0, at)}
      <span style={{ textDecoration: `underline 2px ${color}`, textUnderlineOffset: "3px" }}>{match}</span>
      {text.slice(at + match.length)}
    </>
  );
}

/** Which of a row's places a tab shows, when the row has more than one. */
function PlaceSelect({ row, place, onPick }: { row: FixRow; place: Finding; onPick: (index: number) => void }) {
  if (row.members.length < 2) return null;
  return (
    <label className="flex min-w-0 flex-wrap items-center gap-2 text-sm text-ink-muted">
      For
      <select
        value={place.id}
        onChange={(e) => onPick(row.members.findIndex((m) => m.id === e.target.value))}
        className="min-h-9 max-w-full min-w-0 rounded-lg border border-rule-strong bg-surface px-2 font-mono text-[12.5px] text-ink"
      >
        {row.members.map((m) => (
          <option key={m.id} value={m.id}>{placeLabel(m)}</option>
        ))}
      </select>
    </label>
  );
}

const AI_LABEL = "Fix code with AI";

/** Two sparkles in the AI gradient, or plain white on a solid gradient button. */
function SparkleIcon({ size = 15, solid = false }: { size?: number; solid?: boolean }) {
  const id = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="flex-none">
      {!solid && (
        <defs>
          <linearGradient id={id} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" stopColor="#4796e3" />
            <stop offset="0.55" stopColor="#9177c7" />
            <stop offset="1" stopColor="#ca6673" />
          </linearGradient>
        </defs>
      )}
      <g fill={solid ? "currentColor" : `url(#${id})`}>
        <path d="M10 5.5c.75 4.6 3.9 7.75 8.5 8.5-4.6.75-7.75 3.9-8.5 8.5-.75-4.6-3.9-7.75-8.5-8.5 4.6-.75 7.75-3.9 8.5-8.5Z" />
        <path d="M18.5 1.5c.3 1.9 1.6 3.2 3.5 3.5-1.9.3-3.2 1.6-3.5 3.5-.3-1.9-1.6-3.2-3.5-3.5 1.9-.3 3.2-1.6 3.5-3.5Z" />
      </g>
    </svg>
  );
}

/** "Fix code with AI": the API sends this place's snippet to its model and returns a rewrite as a diff. */
function FixWithAi({
  scanId,
  row,
  place,
  onPick,
}: {
  scanId: string;
  row: FixRow;
  place: Finding;
  onPick: (index: number) => void;
}) {
  // A query run on demand rather than a mutation: each place keeps its fix while the reader
  // switches tabs or steps through rows, so coming back doesn't ask the model again.
  const fix = useQuery({
    queryKey: ["fix", scanId, place.id],
    queryFn: () => api.suggestFix(scanId, place.id),
    enabled: false,
    retry: false,
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0, staleTime: 60_000 });
  const aiOn = health.data?.ai_fix === true;
  const canSend = hasSnippet(place);

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-0.5">
          <span className="font-semibold">Suggested fix</span>
          <span className="text-[13px] text-ink-muted">The API sends these lines to its AI model and shows the rewrite as a diff.</span>
        </div>
        {canSend && !fix.data && (
          <button type="button" className="btn btn-ai-solid" disabled={!aiOn || fix.isFetching} onClick={() => void fix.refetch()}>
            <SparkleIcon solid />
            {fix.isFetching ? "Writing a fix…" : AI_LABEL}
          </button>
        )}
      </div>
      <PlaceSelect row={row} place={place} onPick={onPick} />
      {health.isSuccess && !aiOn && (
        <p className="m-0 text-sm text-ink-muted">
          AI fixes are off on this API. Set <span className="font-mono text-ink-soft">GEMINI_API_KEY</span> where the API
          runs to turn them on.
        </p>
      )}
      {!canSend ? (
        <p className="text-sm text-ink-muted">This place has no code snippet to send, so there is nothing to rewrite. Pick another place.</p>
      ) : fix.data ? (
        <FixPanel fix={fix.data} />
      ) : (
        <>
          {fix.isError && !fix.isFetching && (
            <p role="alert" className="m-0 text-sm" style={{ color: "var(--qt-critical)" }}>{fixError(fix.error)}</p>
          )}
          <CodeSnippet finding={place} evidence={place.asset.evidence} />
        </>
      )}
    </div>
  );
}

function CbomComponent({
  scanId,
  row,
  place,
  onPick,
}: {
  scanId: string;
  row: FixRow;
  place: Finding;
  onPick: (index: number) => void;
}) {
  const [copied, setCopied] = useState(false);
  const cbom = useQuery({ queryKey: ["cbom", scanId], queryFn: () => api.getCbom(scanId), staleTime: Infinity });
  const component = findComponent(cbom.data, place);
  const json = component ? JSON.stringify(component, null, 2) : "";
  // A CycloneDX document of its own: the scan's CBOM header with only this component. It drops
  // the serial number, which names the full CBOM.
  const download = () => {
    if (!cbom.data || !component) return;
    const doc: Record<string, unknown> = { ...cbom.data, components: [component] };
    delete doc.serialNumber;
    const ref = String((component as { "bom-ref"?: unknown })["bom-ref"] ?? "component").replace(/[^a-z0-9]+/gi, "-");
    downloadJson(`quantumtrace-cbom-${scanId.slice(0, 8)}-${ref}.cdx.json`, doc);
  };

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-0.5">
          <span className="font-semibold">CycloneDX 1.6 component</span>
          <span className="text-[13px] text-ink-muted">One occurrence per place, mapped to NIST.</span>
        </div>
        {component !== undefined && (
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn btn-sm btn-primary" onClick={download}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M12 3v12" />
                <path d="m7 10 5 5 5-5" />
                <path d="M5 21h14" />
              </svg>
              Download CBOM
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                void navigator.clipboard?.writeText(json).then(() => setCopied(true));
              }}
            >
              {copied ? "Copied" : "Copy JSON"}
            </button>
          </div>
        )}
      </div>
      <PlaceSelect row={row} place={place} onPick={onPick} />
      {cbom.isPending ? (
        <p className="qt-live text-sm text-ink-muted">Building the CBOM…</p>
      ) : cbom.isError ? (
        <p role="alert" className="text-sm">The CBOM didn’t load: {cbom.error.message}. Try again in a moment.</p>
      ) : !component ? (
        <p className="text-sm text-ink-muted">This finding isn’t in the CBOM for this scan.</p>
      ) : (
        <pre className="code-block">
          <code className="block px-4 whitespace-pre text-ink-soft">{json}</code>
        </pre>
      )}
    </div>
  );
}
