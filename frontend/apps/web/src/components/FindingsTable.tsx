import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { TierGlyph } from "@quantumtrace/ui";
import { useQuery } from "@tanstack/react-query";
import { Fragment, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { FIX_BY, fixRows, type FixBy, type FixRow } from "../lib/fix";
import {
  algorithmLabel,
  confidenceLabel,
  downloadJson,
  EXPOSURE_LABEL,
  evidenceLabel,
  observationLabel,
  placeLabel,
  plural,
  standards,
  usageLabel,
  variantLabel,
  type Evidence,
} from "../lib/format";
import { TIER, TIERS } from "../lib/tiers";

const PAGE = 40;
const PLACES_SHOWN = 12;
const SESSIONS_SHOWN = 40;

const FIX_TAG: Record<FixBy, React.CSSProperties> = {
  now: { background: "var(--qt-critical)", color: "var(--qt-ground)" },
  "before-2030": { border: "1px solid var(--qt-critical)", color: "var(--qt-critical)" },
  harden: { border: "1px solid var(--qt-medium)", color: "var(--qt-medium)" },
  review: { border: "1px solid var(--qt-rule-strong)", color: "var(--qt-ink-muted)" },
  none: { border: "1px solid var(--qt-rule-strong)", color: "var(--qt-ink-faint)" },
};

/** Column heads stay put while the list scrolls under them. */
const TH = "sticky top-0 z-[2] h-9 bg-ground py-2 pr-4 font-medium shadow-[inset_0_-1px_0_var(--qt-rule-strong)]";

/**
 * Every finding, grouped where identical and ordered by when to fix it. A row opens to show
 * where it is, what threatens it, what replaces it, and its CBOM component.
 */
export function FindingsTable({
  scanId,
  findings,
  tier,
  onTierChange,
  query,
  onQueryChange: setQuery,
}: {
  scanId: string;
  findings: Finding[];
  tier: RiskTier | undefined;
  onTierChange: (tier: RiskTier | undefined) => void;
  query: string;
  onQueryChange: (query: string) => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [limit, setLimit] = useState(PAGE);
  const [grouped, setGrouped] = useState(true);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());
  // The list scrolls inside a fixed height so the panels below stay in reach; a new filter
  // starts it from the top again.
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 });
  }, [findings, tier, deferredQuery, grouped]);

  const rows = useMemo(() => {
    const matching = findings
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
  }, [findings, tier, deferredQuery, grouped]);
  const visible = rows.slice(0, limit);
  const findingCount = rows.reduce((n, r) => n + r.members.length, 0);
  const count = (t: RiskTier) => findings.filter((f) => f.classification.tier === t).length;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="grid gap-1">
          <h2 id="fixes-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
            What to fix, in order
          </h2>
          <p className="text-ink-muted">
            Already broken first, then what Shor’s algorithm breaks before 2030, then Grover hardening.
          </p>
        </div>
        <span className="text-sm text-ink-muted tabular-nums" aria-live="polite">
          {grouped ? `${plural(rows.length, "row")} · ${plural(findingCount, "finding")}` : plural(findingCount, "finding")}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div role="group" aria-label="Filter by tier" className="flex flex-wrap gap-1.5">
          <button type="button" className="chip" aria-pressed={!tier} onClick={() => onTierChange(undefined)}>
            All<span className="opacity-70">{findings.length}</span>
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
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(null);
            }}
            placeholder="Algorithm, alias, file, ARN, flag"
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-ink-faint"
          />
        </label>
        <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-ink-muted">
          <input
            type="checkbox"
            checked={grouped}
            onChange={(e) => {
              setGrouped(e.target.checked);
              setLimit(PAGE);
              setOpen(null);
            }}
            className="size-4 accent-[var(--qt-ink)]"
          />
          Group identical findings
        </label>
      </div>

      <div ref={scroller} className="relative max-h-[min(600px,72vh)] overflow-auto border-b border-rule">
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
            {visible.map((row) => {
              const expanded = open === row.key;
              const toggle = () => setOpen(expanded ? null : row.key);
              return (
                <Fragment key={row.key}>
                  <Row row={row} expanded={expanded} onToggle={toggle} />
                  {expanded && (
                    <tr>
                      <td colSpan={7} className="p-0">
                        <FindingDetail row={row} scanId={scanId} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {rows.length > visible.length && (
          <div className="flex flex-wrap items-center gap-4 py-4">
            <button type="button" onClick={() => setLimit((l) => l + PAGE)} className="btn">
              Show {Math.min(PAGE, rows.length - visible.length)} more
            </button>
            <p className="text-sm text-ink-muted tabular-nums">
              Showing {visible.length} of {rows.length} {grouped ? "rows" : "findings"}
            </p>
          </div>
        )}
        {rows.length === 0 && (
          <p className="py-8 text-ink-muted">No findings match. Clear the search or pick another tier.</p>
        )}
      </div>
    </div>
  );
}

function Row({ row, expanded, onToggle }: { row: FixRow; expanded: boolean; onToggle: () => void }) {
  const { lead: f, members } = row;
  const tier = TIER[f.classification.tier];
  const family = variantLabel(f);
  const flags = [
    row.fixBy === "harden" && f.classification.classically_broken ? "broken today" : "",
    ...f.asset.flags.map((x) => x.replace(/-/g, " ")),
  ].filter(Boolean);
  // An open row pins under the column heads, so its collapse button stays in reach while the
  // details scroll past.
  const cell = `py-2.5 pr-4 align-top ${
    expanded
      ? "sticky top-9 z-[1] bg-surface shadow-[inset_0_-1px_0_var(--qt-rule)]"
      : "border-b border-rule"
  }`;

  return (
    <tr onClick={onToggle} className={`cursor-pointer transition-colors ${expanded ? "bg-surface" : "hover:bg-surface"}`}>
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
            <span className="text-xs text-ink-muted tabular-nums">{row.sessions} sessions</span>
          )}
        </span>
      </td>
      <td className={`${cell} hidden whitespace-nowrap md:table-cell`}>{EXPOSURE_LABEL[f.asset.exposure] ?? f.asset.exposure}</td>
      <td className={cell}>
        <span className="tag" style={FIX_TAG[row.fixBy]}>{FIX_BY[row.fixBy].label}</span>
      </td>
      <td className={`${cell} py-2 pr-2 text-right`}>
        <button
          type="button"
          aria-expanded={expanded}
          aria-label={`${expanded ? "Hide" : "Show"} details for ${algorithmLabel(f)} at ${
            members.length === 1 ? placeLabel(f) : `${members.length} places`
          }`}
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          className="grid size-8 place-items-center rounded-lg text-ink-muted hover:bg-raise hover:text-ink"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden className={`transition-transform ${expanded ? "rotate-180" : ""}`}>
            <path d="m2 4 4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" />
          </svg>
        </button>
      </td>
    </tr>
  );
}

const LANGUAGE: Record<string, string> = { go: "Go", java: "Java", py: "Python" };

function placesNote(row: FixRow): string {
  const { lead: f, members } = row;
  if (members.length === 1) {
    return row.sessions > 1 ? `${row.sessions} sessions to one server` : "One place";
  }
  const usage = usageLabel(f.asset.usage).toLowerCase();
  const code = members.every((m) => m.asset.evidence.source_type === "code");
  const langs = [...new Set(members.map((m) => LANGUAGE[m.asset.evidence.location.split(".").pop() ?? ""]).filter(Boolean))];
  const across = code && langs.length > 1 ? `, across ${langs.slice(0, -1).join(", ")} and ${langs.at(-1)}` : "";
  const sessions = row.sessions > members.length ? `, ${row.sessions} sessions` : "";
  return `Same ${usage} in ${members.length} ${code ? "files" : "places"}${across}${sessions}`;
}

function FindingDetail({ row, scanId }: { row: FixRow; scanId: string }) {
  const [pick, setPick] = useState(0);
  const [allPlaces, setAllPlaces] = useState(false);
  const [cbomOpen, setCbomOpen] = useState(false);
  const { lead: f, members } = row;
  const c = f.classification;
  const tier = TIER[c.tier];
  const place = members[Math.min(pick, members.length - 1)] ?? f;
  const shownPlaces = allPlaces ? members : members.slice(0, PLACES_SHOWN);
  const refs = standards(c);

  return (
    <div className="qt-fade grid gap-7 border-b border-rule-strong bg-surface px-4 pt-5 pb-8 sm:pr-6 lg:pl-[122px]">
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
                onClick={() => setPick(k)}
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

      <div className="grid gap-x-8 gap-y-5 [grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr))]">
        <Fact label="Quantum threat" value={threatLabel(f)} sub={c.rationale} color={c.tier === "critical" ? tier.color : undefined} />
        <Fact label="Strength" value={strengthLabel(f)} sub={strengthNote(f)} />
        <Fact label="Exposure" value={EXPOSURE_LABEL[f.asset.exposure] ?? f.asset.exposure} sub={exposureNote(f)} />
        <Fact label="Evidence" value={observationLabel(f.asset.observation)} sub={confidenceLabel(f.asset.confidence)} />
      </div>

      <dl className="-mt-3 flex flex-wrap gap-x-8 gap-y-2 text-[13px]">
        <div className="flex min-w-0 gap-2">
          <dt className="text-ink-muted">Observed</dt>
          <dd className="font-mono break-all text-ink-soft">{place.asset.observed}</dd>
        </div>
        {c.oid && (
          <div className="flex gap-2">
            <dt className="text-ink-muted">OID</dt>
            <dd className="font-mono text-ink-soft">{c.oid}</dd>
          </div>
        )}
      </dl>

      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-4 border-t border-rule pt-5">
        <div className="grid min-w-0 flex-[1_1_360px] gap-1.5">
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
        <button type="button" className="btn" aria-expanded={cbomOpen} onClick={() => setCbomOpen((o) => !o)}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2" />
            <path d="M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2" />
          </svg>
          {cbomOpen ? "Hide CBOM" : "View CBOM component"}
        </button>
      </div>

      {cbomOpen && <CbomComponent scanId={scanId} finding={place} />}
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
  return EXPOSURE_NOTE[f.asset.exposure] ?? "";
}

function threatLabel(f: Finding): string {
  const c = f.classification;
  if (c.threat === "shor") return "Shor’s algorithm";
  if (c.threat === "grover") return "Grover’s algorithm";
  if (c.threat === "none") return c.classically_broken ? "Not needed" : "None known";
  return "Not classified";
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
    c.classically_broken ? "Broken without a quantum computer." : "",
  ];
  return parts.filter(Boolean).join(" ");
}

/** The flagged source with its neighbours, or the cloud or network context it was read from. */
function EvidenceView({ finding: f }: { finding: Finding }) {
  const e = f.asset.evidence;
  const [allSessions, setAllSessions] = useState(false);
  if (e.snippet) return <CodeSnippet finding={f} />;
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

function CodeSnippet({ finding: f }: { finding: Finding }) {
  const e = f.asset.evidence;
  if (!e.snippet) return null;
  const meta = TIER[f.classification.tier];
  const first = e.snippet_start_line ?? e.line ?? 1;
  const lines = e.snippet.split("\n");
  const also = e.context?.also_lines?.split(",").filter(Boolean) ?? [];
  return (
    <figure className="m-0 grid min-w-0 gap-1.5">
      <figcaption className="font-mono text-xs break-all text-ink-muted">
        {evidenceLabel(e)}
        {also.length > 0 && <span className="font-sans"> · also on line{also.length > 1 ? "s" : ""} {also.join(", ")}</span>}
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
                  {text || " "}
                </span>
              </span>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}

/** Where the CBOM records a piece of evidence (see cbom/cyclonedx.py). */
function occurrenceAt(e: Evidence): string {
  const ctx = e.context ?? {};
  if (ctx.json_path) return `${e.location}#${ctx.json_path}`;
  if (ctx.packet) return `${e.location}/packet-${ctx.packet}`;
  return e.location;
}

type CbomOccurrence = { location?: unknown; line?: unknown };
type CbomEntry = { evidence?: { occurrences?: CbomOccurrence[] } };

function findComponent(cbom: Record<string, unknown> | undefined, e: Evidence): unknown {
  const components = Array.isArray(cbom?.components) ? (cbom.components as CbomEntry[]) : [];
  const at = occurrenceAt(e);
  return components.find((c) =>
    c.evidence?.occurrences?.some((o) => o.location === at && (o.line ?? null) === (e.line ?? null)),
  );
}

function CbomComponent({ scanId, finding }: { scanId: string; finding: Finding }) {
  const [copied, setCopied] = useState(false);
  const cbom = useQuery({ queryKey: ["cbom", scanId], queryFn: () => api.getCbom(scanId), staleTime: Infinity });
  const component = findComponent(cbom.data, finding.asset.evidence);
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
    <div className="qt-fade grid gap-3 rounded-xl border border-rule-strong bg-ground p-[18px]">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="font-semibold">CBOM component</span>
        <span className="text-xs text-ink-faint">CycloneDX 1.6 · one occurrence per place, mapped to NIST</span>
      </div>
      {cbom.isPending ? (
        <p className="qt-live text-sm text-ink-muted">Building the CBOM…</p>
      ) : cbom.isError ? (
        <p role="alert" className="text-sm">The CBOM didn’t load: {cbom.error.message}. Try again in a moment.</p>
      ) : !component ? (
        <p className="text-sm text-ink-muted">This finding isn’t in the CBOM for this scan.</p>
      ) : (
        <>
          <pre className="code-block max-h-[420px] overflow-auto">
            <code className="block px-4 whitespace-pre text-ink-soft">{json}</code>
          </pre>
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
        </>
      )}
    </div>
  );
}
