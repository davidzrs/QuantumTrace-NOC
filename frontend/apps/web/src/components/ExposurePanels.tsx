import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { TierGlyph } from "@quantumtrace/ui";
import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router";
import { observationLabel, SOURCE_LABEL, SOURCES, type Source } from "../lib/format";
import { codeHotspots, commonDir } from "../lib/hotspots";
import { TIER, TIERS } from "../lib/tiers";

const UPLOAD_HINT: Record<Source, string> = {
  cloud: "Upload AWS .json exports",
  code: "Upload source or a .zip",
  network: "Upload a .pcap",
};

/** Proof strength, strongest first, as shades of ink. */
const OBSERVATIONS: { id: Finding["asset"]["observation"]; shade: string }[] = [
  { id: "negotiated", shade: "#e8ebef" },
  { id: "executed", shade: "#d9dee4" },
  { id: "in-code", shade: "#c9d0d8" },
  { id: "configured", shade: "#9aa5b1" },
  { id: "offered", shade: "#6b7685" },
  { id: "permitted", shade: "#4a5563" },
];

const EXPOSURES: [Finding["asset"]["exposure"], string][] = [
  ["internet", "Internet"],
  ["internal", "Internal"],
  ["unknown", "Not known"],
];

export function ExposurePanels({
  all,
  findings,
  source,
  onSelectFile,
}: {
  /** Every finding in the scan, for the per-source comparison. */
  all: Finding[];
  /** Findings in the chosen source. */
  findings: Finding[];
  source: Source | undefined;
  onSelectFile: (path: string) => void;
}) {
  const hotspots = useMemo(() => codeHotspots(findings), [findings]);
  return (
    <section aria-labelledby="exposure-title" className="grid gap-4">
      <h2 id="exposure-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
        Where the exposure lives
      </h2>
      {/* Four panels sit two by two and three sit in a row, so none is left alone on a line. */}
      <div className={`grid gap-5 ${hotspots.length > 1 ? "md:grid-cols-2" : "lg:grid-cols-3"}`}>
        <BySource findings={all} source={source} />
        <ByExposure findings={findings} />
        <HowWeKnow findings={findings} />
        {hotspots.length > 1 && <Files hotspots={hotspots} onSelect={onSelectFile} />}
      </div>
    </section>
  );
}

function Caption({ title, note }: { title: string; note: string }) {
  return (
    <figcaption className="flex justify-between gap-3">
      <span className="font-semibold">{title}</span>
      <span className="text-[13px] text-ink-faint">{note}</span>
    </figcaption>
  );
}

const tierCount = (fs: Finding[], t: RiskTier) => fs.filter((f) => f.classification.tier === t).length;

function BySource({ findings, source }: { findings: Finding[]; source: Source | undefined }) {
  const rows = SOURCES.map((s) => ({ s, items: findings.filter((f) => f.asset.evidence.source_type === s) }));
  const present = rows.filter((r) => r.items.length > 0);
  const absent = rows.filter((r) => r.items.length === 0);
  const max = Math.max(1, ...present.map((r) => r.items.length));
  return (
    <figure className="panel">
      <Caption title="By source" note="findings" />
      <div className="grid gap-[18px]">
        {present.map(({ s, items }) => {
          const tiers = TIERS.filter((t) => tierCount(items, t) > 0);
          return (
            <div key={s} className="grid gap-2 transition-opacity duration-200" style={{ opacity: !source || source === s ? 1 : 0.3 }}>
              <div className="flex justify-between text-sm">
                <span>{SOURCE_LABEL[s]}</span>
                <span className="font-mono text-[13px]">{items.length}</span>
              </div>
              <div
                className="flex h-3.5 gap-0.5"
                style={{ width: `${(items.length / max) * 100}%` }}
                role="img"
                aria-label={`${SOURCE_LABEL[s]}: ${tiers.map((t) => `${tierCount(items, t)} ${TIER[t].label.toLowerCase()}`).join(", ")}`}
              >
                {tiers.map((t) => (
                  <span key={t} className="rounded-xs" style={{ flex: tierCount(items, t), background: TIER[t].color }} />
                ))}
              </div>
              <div className="flex flex-wrap gap-x-3.5 font-mono text-xs text-ink-muted">
                {tiers.map((t) => (
                  <span key={t}>
                    {tierCount(items, t)} {TIER[t].label.toLowerCase()}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
        {absent.map(({ s }) => (
          <div key={s} className="flex items-center justify-between gap-3 border-t border-rule pt-3.5 text-sm text-ink-faint">
            <span>{SOURCE_LABEL[s]} not in this scan</span>
            <Link to="/#upload" className="link">{UPLOAD_HINT[s]}</Link>
          </div>
        ))}
      </div>
    </figure>
  );
}

function ByExposure({ findings }: { findings: Finding[] }) {
  const tiers = TIERS.filter((t) => t !== "unknown" || tierCount(findings, t) > 0);
  const n = (x: string, t: RiskTier) => findings.filter((f) => f.asset.exposure === x && f.classification.tier === t).length;
  const max = Math.max(1, ...EXPOSURES.flatMap(([x]) => tiers.map((t) => n(x, t))));
  const unknownCount = findings.filter((f) => f.asset.exposure === "unknown").length;
  return (
    <figure className="panel">
      <Caption title="By exposure" note="findings per tier" />
      <table className="-m-1 border-separate border-spacing-1 tabular-nums">
        <thead>
          <tr>
            <th className="pr-2 pb-1 text-left text-[13px] font-medium text-ink-muted">
              <span className="sr-only">Exposure</span>
            </th>
            {tiers.map((t) => (
              <th key={t} className="pb-1 text-[13px] font-medium" style={{ color: TIER[t].color }}>
                {TIER[t].label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {EXPOSURES.map(([x, label]) => (
            <tr key={x}>
              <th scope="row" className="pr-2 text-left text-sm font-medium">{label}</th>
              {tiers.map((t) => {
                const v = n(x, t);
                const alpha = v ? 0.12 + 0.43 * (v / max) : 0;
                return (
                  <td
                    key={t}
                    className="h-11 rounded-md text-center font-mono text-sm"
                    style={{
                      background: v ? `rgba(${TIER[t].rgb},${alpha.toFixed(2)})` : "var(--qt-raise)",
                      color: v ? "var(--qt-ink)" : "var(--qt-ink-ghost)",
                    }}
                  >
                    {v}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {unknownCount > 0 && (
        <p className="text-[13px] leading-[1.45] text-ink-faint">
          Not known covers code, KMS keys and servers the input can’t place inside or outside the network.
        </p>
      )}
    </figure>
  );
}

function HowWeKnow({ findings }: { findings: Finding[] }) {
  const kinds = OBSERVATIONS.map((o) => ({ ...o, n: findings.filter((f) => f.asset.observation === o.id).length })).filter(
    (o) => o.n > 0,
  );
  const conf = (c: string) => findings.filter((f) => f.asset.confidence === c).length;
  const [high, medium, low] = [conf("high"), conf("medium"), conf("low")];
  return (
    <figure className="panel">
      <Caption title="How we know" note="evidence type" />
      <div className="grid gap-3.5">
        <div
          className="flex h-3.5 gap-0.5"
          role="img"
          aria-label={kinds.map((k) => `${k.n} ${observationLabel(k.id).toLowerCase()}`).join(", ")}
        >
          {kinds.map((k) => (
            <span key={k.id} className="rounded-xs" style={{ flex: k.n, background: k.shade }} />
          ))}
        </div>
        <dl className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2.5 text-sm">
          {kinds.map((k) => (
            <Fragment key={k.id}>
              <dt className="flex items-center gap-3">
                <span aria-hidden className="size-2.5 shrink-0 rounded-xs" style={{ background: k.shade }} />
                {observationLabel(k.id)}
              </dt>
              <dd className="font-mono text-[13px]">{k.n}</dd>
            </Fragment>
          ))}
        </dl>
        <p className="border-t border-rule pt-3.5 text-[13px] leading-[1.45] text-ink-muted">
          <strong className="font-semibold text-ink">{high} read directly</strong>
          {medium > 0 && `, ${medium} inferred (key sizes taken from elsewhere in the file, hand-rolled code)`}
          {low > 0 && `, ${low} from incomplete input`}.
        </p>
      </div>
    </figure>
  );
}

const FILES_SHOWN = 6;

function Files({ hotspots, onSelect }: { hotspots: ReturnType<typeof codeHotspots>; onSelect: (path: string) => void }) {
  const [all, setAll] = useState(false);
  const shown = all ? hotspots : hotspots.slice(0, FILES_SHOWN);
  const base = commonDir(hotspots.map((h) => h.path));
  return (
    <figure className="panel">
      <Caption title="Files to fix first" note={`${hotspots.length} source files`} />
      <ol className="grid">
        {shown.map((h) => {
          const rel = h.path.slice(base.length);
          const slash = rel.lastIndexOf("/");
          return (
            <li key={h.path} className="border-b border-rule last:border-b-0">
              <button
                type="button"
                onClick={() => onSelect(h.path)}
                className="flex min-h-10 w-full items-center justify-between gap-4 text-left hover:text-ink"
              >
                <span className="min-w-0 truncate font-mono text-[13px]" title={h.path}>
                  <span className="text-ink-faint">{rel.slice(0, slash + 1)}</span>
                  {rel.slice(slash + 1)}
                </span>
                <span className="flex shrink-0 gap-3 text-[13px] tabular-nums">
                  {(["critical", "medium"] as const).map((t) =>
                    h.counts[t] ? (
                      <span key={t} className="flex items-center gap-1.5" title={TIER[t].threat}>
                        <TierGlyph tier={t} />
                        {h.counts[t]}
                        <span className="sr-only">{TIER[t].label}</span>
                      </span>
                    ) : null,
                  )}
                  {!h.counts.critical && !h.counts.medium && <span className="text-ink-faint">{h.total} safe or unclassified</span>}
                </span>
              </button>
            </li>
          );
        })}
      </ol>
      {hotspots.length > FILES_SHOWN && (
        <button type="button" aria-expanded={all} onClick={() => setAll((a) => !a)} className="link self-start text-sm font-semibold">
          {all ? "Show fewer" : `Show all ${hotspots.length} files`}
        </button>
      )}
    </figure>
  );
}
