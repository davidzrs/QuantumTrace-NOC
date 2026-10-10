import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { TIER_META, TIER_ORDER, TierBadge } from "@quantumtrace/ui";
import { Fragment, useDeferredValue, useMemo, useState } from "react";
import {
  algorithmLabel,
  confidenceLabel,
  observationLabel,
  placeLabel,
  usageLabel,
  variantLabel,
} from "../lib/format";

const PAGE = 100;
const SOURCES = [
  { id: "cloud", label: "Cloud" },
  { id: "code", label: "Code" },
  { id: "network", label: "Network" },
] as const;
type SourceId = (typeof SOURCES)[number]["id"];

const EXPOSURE_LABEL: Record<string, string> = {
  internet: "Internet",
  internal: "Internal",
  unknown: "Not known",
};

interface Row {
  key: string;
  lead: Finding;
  members: Finding[];
}

/** Identical crypto in several places (same tier, rule, variant, usage, flags, exposure). */
function groupKey(f: Finding): string {
  const a = f.asset;
  return [f.classification.tier, f.classification.rule_id, a.variant ?? "", a.usage ?? "",
    [...a.flags].sort().join("+"), a.exposure, a.evidence.source_type].join("|");
}

const sessions = (f: Finding) => 1 + f.asset.more_evidence.length;

export function FindingsTable({
  findings,
  tier,
  onTierChange,
  query,
  onQueryChange: setQuery,
}: {
  findings: Finding[];
  tier: RiskTier | undefined;
  onTierChange: (tier: RiskTier | undefined) => void;
  query: string;
  onQueryChange: (query: string) => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [source, setSource] = useState<SourceId | undefined>();
  const [limit, setLimit] = useState(PAGE);
  const [grouped, setGrouped] = useState(true);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());
  const sourceCounts = useMemo(() => {
    const counts: Partial<Record<SourceId, number>> = {};
    for (const f of findings) counts[f.asset.evidence.source_type] = (counts[f.asset.evidence.source_type] ?? 0) + 1;
    return counts;
  }, [findings]);

  const rows = useMemo(() => {
    const order = (f: Finding) => TIER_ORDER.indexOf(f.classification.tier);
    return findings
      .filter((f) => !tier || f.classification.tier === tier)
      .filter((f) => !source || f.asset.evidence.source_type === source)
      .filter((f) => {
        if (!deferredQuery) return true;
        const haystack = [
          algorithmLabel(f),
          f.asset.variant ?? "",
          f.asset.observed,
          f.asset.usage,
          placeLabel(f),
          f.asset.evidence.location,
          ...f.asset.flags,
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(deferredQuery);
      })
      .sort((a, b) => order(a) - order(b) || Number(b.asset.exposure === "internet") - Number(a.asset.exposure === "internet"));
  }, [findings, tier, source, deferredQuery]);

  const groups = useMemo<Row[]>(() => {
    if (!grouped) return rows.map((f) => ({ key: f.id, lead: f, members: [f] }));
    const byKey = new Map<string, Row>();
    for (const f of rows) {
      const k = groupKey(f);
      const row = byKey.get(k);
      if (row) row.members.push(f);
      else byKey.set(k, { key: k, lead: f, members: [f] });
    }
    return [...byKey.values()];
  }, [rows, grouped]);
  const visible = groups.slice(0, limit);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <fieldset className="flex flex-wrap gap-1" aria-label="Filter by tier">
          <FilterChip active={!tier} onClick={() => onTierChange(undefined)}>
            All {findings.length}
          </FilterChip>
          {TIER_ORDER.map((t) => {
            const n = findings.filter((f) => f.classification.tier === t).length;
            return n ? (
              <FilterChip key={t} active={tier === t} onClick={() => onTierChange(tier === t ? undefined : t)}>
                {TIER_META[t].label} {n}
              </FilterChip>
            ) : null;
          })}
        </fieldset>
        {Object.keys(sourceCounts).length > 1 && (
          <fieldset className="flex flex-wrap gap-1" aria-label="Filter by source">
            {SOURCES.filter((s) => sourceCounts[s.id]).map((s) => (
              <FilterChip
                key={s.id}
                active={source === s.id}
                onClick={() => {
                  setSource(source === s.id ? undefined : s.id);
                  setLimit(PAGE);
                }}
              >
                {s.label} {sourceCounts[s.id]}
              </FilterChip>
            ))}
          </fieldset>
        )}
        <label className="flex items-center gap-2 text-sm font-semibold text-ink-muted">
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
        <label className="flex min-w-[14rem] flex-1 items-center gap-2 border-b border-rule-strong focus-within:border-ink sm:max-w-xs">
          <span className="sr-only">Search findings</span>
          <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden className="text-ink-faint">
            <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="m11 11 4 4" stroke="currentColor" strokeWidth="1.6" />
          </svg>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Algorithm, file, key alias, ARN, flag"
            className="w-full bg-transparent py-1.5 outline-none placeholder:text-ink-faint"
          />
        </label>
      </div>

      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[46rem] text-left">
          <thead className="text-sm text-ink-muted">
            <tr className="border-b border-rule-strong">
              <th className="w-36 py-2 pr-4 font-medium">Risk</th>
              <th className="py-2 pr-4 font-medium">Algorithm</th>
              <th className="py-2 pr-4 font-medium">Used for</th>
              <th className="py-2 pr-4 font-medium">Where</th>
              <th className="py-2 pr-2 font-medium">Exposure</th>
              <th className="w-8 py-2"><span className="sr-only">Details</span></th>
            </tr>
          </thead>
          <tbody>
            {visible.map(({ key, lead: f, members }) => {
              const expanded = open === key;
              const totalSessions = members.reduce((n, m) => n + sessions(m), 0);
              return (
                <Fragment key={key}>
                  <tr
                    className={`border-b border-rule align-top ${expanded ? "bg-surface" : "hover:bg-surface"}`}
                  >
                    <td className="py-2.5 pr-4"><TierBadge tier={f.classification.tier} /></td>
                    <td className="py-2.5 pr-4">
                      <span className="font-semibold whitespace-nowrap">{algorithmLabel(f)}</span>
                      {variantLabel(f) && (
                        <span className="block font-mono text-xs text-ink-muted">{variantLabel(f)}</span>
                      )}
                      {f.asset.confidence !== "high" && (
                        <span className="block text-xs text-ink-faint" title={confidenceLabel(f.asset.confidence)}>
                          {f.asset.confidence === "medium" ? "inferred" : "uncertain"}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 pr-4">{usageLabel(f.asset.usage)}</td>
                    <td className="max-w-[20rem] py-2.5 pr-4" title={f.asset.evidence.location}>
                      {members.length === 1 ? (
                        <span className="block truncate">{placeLabel(f)}</span>
                      ) : (
                        <>
                          <span className="block font-semibold tabular-nums">{members.length} places</span>
                          <span className="block truncate text-xs text-ink-muted">
                            {members.slice(0, 3).map(placeLabel).join(", ")}
                            {members.length > 3 && ", …"}
                          </span>
                        </>
                      )}
                      {totalSessions > members.length && (
                        <span className="block text-xs text-ink-muted tabular-nums">
                          {totalSessions} sessions
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 pr-2 whitespace-nowrap">{EXPOSURE_LABEL[f.asset.exposure] ?? f.asset.exposure}</td>
                    <td className="py-1.5 text-right">
                      <button
                        type="button"
                        aria-expanded={expanded}
                        aria-label={`${expanded ? "Hide" : "Show"} details for ${algorithmLabel(f)} at ${
                          members.length === 1 ? placeLabel(f) : `${members.length} places`
                        }`}
                        onClick={() => setOpen(expanded ? null : key)}
                        className="grid size-7 place-items-center text-ink-muted hover:text-ink"
                      >
                        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden className={`transition-transform ${expanded ? "rotate-180" : ""}`}>
                          <path d="m2 4 4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" />
                        </svg>
                      </button>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="border-b border-rule bg-surface">
                      <td colSpan={6} className="px-0 pt-1 pb-5">
                        <FindingDetail finding={f} members={members} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {groups.length > visible.length && (
          <div className="flex flex-wrap items-center gap-4 pt-4">
            <button
              type="button"
              onClick={() => setLimit((l) => l + PAGE)}
              className="border border-ink px-4 py-2 font-semibold hover:bg-ink hover:text-ground"
            >
              Show {Math.min(PAGE, groups.length - visible.length)} more
            </button>
            <p className="text-sm text-ink-muted tabular-nums">
              Showing {visible.length} of {groups.length} {grouped ? "groups" : "findings"}
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

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`px-3 py-1 text-sm font-semibold tabular-nums ${
        active ? "bg-ink text-ground" : "text-ink-muted hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

const PLACES_SHOWN = 40;

function FindingDetail({ finding: f, members }: { finding: Finding; members: Finding[] }) {
  const c = f.classification;
  const single = members.length === 1;
  // Code places carry their own snippet and caption, so they replace the plain location list.
  const allCode = members.every((m) => m.asset.evidence.snippet);
  // The snippet caption already lists repeat lines.
  const context = Object.entries(f.asset.evidence.context ?? {}).filter(
    ([k, v]) => v && !(k === "also_lines" && f.asset.evidence.snippet),
  );
  return (
    <div className="grid gap-6 pl-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] sm:pl-36">
      <div className="grid content-start gap-3">
        <p className="max-w-[60ch] leading-relaxed">{c.rationale}</p>
        {c.replacement && (
          <p>
            <span className="text-ink-muted">Migrate to </span>
            <strong>{c.replacement}</strong>
          </p>
        )}
        {c.nist_reference && <p className="text-sm text-ink-muted">{c.nist_reference}</p>}
        {f.asset.flags.length > 0 && (
          <ul className="flex flex-wrap gap-1.5" aria-label="Flags">
            {f.asset.flags.map((flag) => (
              <li key={flag} className="border border-rule-strong px-2 py-0.5 text-sm">{flag.replace(/-/g, " ")}</li>
            ))}
          </ul>
        )}
      </div>
      <dl className="grid content-start grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
        <dt className="text-ink-muted">How we know</dt>
        <dd>{observationLabel(f.asset.observation)}</dd>
        <dt className="text-ink-muted">Confidence</dt>
        <dd>{confidenceLabel(f.asset.confidence)}</dd>
        <dt className="text-ink-muted">Observed</dt>
        <dd className="font-mono break-all">{f.asset.observed}</dd>
        {c.oid && (
          <>
            <dt className="text-ink-muted">OID</dt>
            <dd className="font-mono">{c.oid}</dd>
          </>
        )}
        {(c.classical_security_bits != null || c.nist_quantum_level != null) && (
          <>
            <dt className="text-ink-muted">Strength</dt>
            <dd>
              {c.classical_security_bits != null && <>{c.classical_security_bits}-bit classical. </>}
              {c.nist_quantum_level != null &&
                (c.nist_quantum_level === 0 ? "No quantum security." : `NIST PQC category ${c.nist_quantum_level}.`)}
            </dd>
          </>
        )}
        {single && (
          <>
            <dt className="text-ink-muted">Source</dt>
            <dd className="font-mono break-all">{f.asset.evidence.location}</dd>
            {context.map(([k, v]) => (
              <Fragment key={k}>
                <dt className="text-ink-muted">{k.replace(/_/g, " ")}</dt>
                <dd className="font-mono break-all">{v}</dd>
              </Fragment>
            ))}
            {f.asset.more_evidence.length > 0 && (
              <>
                <dt className="text-ink-muted">Also seen</dt>
                <dd>
                  <EvidenceList locations={f.asset.more_evidence.map((e) => evidenceLabel(e))} />
                </dd>
              </>
            )}
          </>
        )}
      </dl>
      {single && f.asset.evidence.snippet && <CodeSnippet finding={f} />}
      {!single && allCode && <SnippetList members={members} />}
      {!single && !allCode && (
        <div className="grid gap-2 sm:col-span-2">
          <h3 className="text-sm font-semibold">Seen in {members.length} places</h3>
          <EvidenceList
            locations={members.map((m) => {
              const n = sessions(m);
              return `${placeLabel(m)}${n > 1 ? ` (${n} sessions)` : ""}  ${evidenceLabel(m.asset.evidence)}`;
            })}
          />
        </div>
      )}
    </div>
  );
}

const SNIPPETS_SHOWN = 3;

function SnippetList({ members }: { members: Finding[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? members : members.slice(0, SNIPPETS_SHOWN);
  return (
    <div className="grid gap-4 sm:col-span-2">
      <h3 className="text-sm font-semibold">Seen in {members.length} places</h3>
      {shown.map((m) => (
        <CodeSnippet key={m.id} finding={m} />
      ))}
      {members.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="justify-self-start text-sm font-semibold underline underline-offset-4">
          Show all {members.length} places
        </button>
      )}
    </div>
  );
}

/** The flagged source line with its neighbours, line-numbered, the hit marked in the tier colour. */
function CodeSnippet({ finding: f }: { finding: Finding }) {
  const e = f.asset.evidence;
  if (!e.snippet) return null;
  const meta = TIER_META[f.classification.tier];
  const first = e.snippet_start_line ?? e.line ?? 1;
  const lines = e.snippet.split("\n");
  const also = e.context?.also_lines?.split(",").filter(Boolean) ?? [];
  return (
    <figure className="grid min-w-0 gap-1.5 sm:col-span-2">
      <figcaption className="text-sm text-ink-muted">
        <span className="font-mono break-all">{evidenceLabel(e)}</span>
        {also.length > 0 && (
          <> · also on line{also.length > 1 ? "s" : ""} <span className="tabular-nums">{also.join(", ")}</span></>
        )}
      </figcaption>
      <pre className="overflow-x-auto border border-rule bg-ground py-2 font-mono text-xs leading-relaxed [tab-size:4]">
        <code className="grid min-w-max">
          {lines.map((text, i) => {
            const n = first + i;
            const hit = n === e.line;
            return (
              <span
                key={n}
                className="grid grid-cols-[3.5rem_minmax(0,1fr)]"
                style={hit ? { background: meta.wash, boxShadow: `inset 3px 0 ${meta.color}` } : undefined}
              >
                <span className="pr-4 text-right text-ink-faint tabular-nums select-none" aria-hidden>{n}</span>
                <span className={`pr-4 whitespace-pre ${hit ? "font-semibold" : ""}`}>
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

function evidenceLabel(e: Finding["asset"]["evidence"]): string {
  const ctx = e.context ?? {};
  if (ctx.json_path) return `${e.location}#${ctx.json_path}`;
  if (ctx.packet) return `${e.location} (packet ${ctx.packet})`;
  return e.line ? `${e.location}:${e.line}` : e.location;
}

function EvidenceList({ locations }: { locations: string[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? locations : locations.slice(0, PLACES_SHOWN);
  return (
    <div className="grid gap-1">
      <ul className="grid gap-0.5 font-mono text-xs break-all text-ink-muted">
        {shown.map((l, i) => (
          <li key={i}>{l}</li>
        ))}
      </ul>
      {locations.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="justify-self-start text-sm font-semibold underline underline-offset-4">
          Show all {locations.length}
        </button>
      )}
    </div>
  );
}
