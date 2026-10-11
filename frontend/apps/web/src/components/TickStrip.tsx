import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { SOURCE_SHORT, SOURCES, type Source } from "../lib/format";
import { placeLabels, type Placement } from "../lib/labels";
import { TIER, TIERS } from "../lib/tiers";

/** When each tier starts rising, so the strip reads left to right: Shor, Grover, the rest. */
const DELAY: Record<RiskTier, number> = { critical: 0, medium: 280, unknown: 400, safe: 500 };

/**
 * The debt strip: one tick per finding, grouped by tier, so the reader sees the shape of the
 * inventory before any number. Hovering a tier splits it by source; clicking a tier, or one of
 * its sources, filters the list.
 */
export function TickStrip({
  findings,
  focus,
  focusSource,
  onSelect,
}: {
  findings: Finding[];
  focus: RiskTier | undefined;
  focusSource: Source | undefined;
  onSelect: (tier: RiskTier, source: Source | undefined) => void;
}) {
  const [hover, setHover] = useState<RiskTier | null>(null);
  const [hoverSource, setHoverSource] = useState<Source | null>(null);
  const groups = TIERS.map((tier) => {
    const items = findings.filter((f) => f.classification.tier === tier);
    const subs = SOURCES.map((source) => ({
      source,
      items: items.filter((f) => f.asset.evidence.source_type === source),
    })).filter((s) => s.items.length > 0);
    return { tier, n: items.length, subs };
  }).filter((g) => g.n > 0);
  // Large inventories (hundreds of network sessions) drop the gutters so every tick still fits.
  const gap = findings.length > 240 ? 0 : findings.length > 100 ? 1 : 2;
  const dimmed = (t: RiskTier) => (focus !== undefined && focus !== t) || (hover !== null && hover !== t);
  // The source a tier singles out: the one under the pointer, else the one the list is filtered to.
  const active = (t: RiskTier): Source | undefined =>
    hover === t && hoverSource ? hoverSource : focusSource && (focus === undefined || focus === t) ? focusSource : undefined;
  // A tier splits into its sources while hovered, or while the list is filtered to one of them.
  const open = (t: RiskTier) => hover === t || (focusSource !== undefined && (focus === undefined || focus === t));

  // Labels for the hovered tier, else the selected one; measured before paint, placed over their segments.
  const hovered = groups.find((g) => g.tier === hover) ?? (focusSource && focus ? groups.find((g) => g.tier === focus) : undefined);
  const lane = useRef<HTMLDivElement>(null);
  const segments = useRef(new Map<string, HTMLSpanElement>()); // "tier:source"
  const labels = useRef(new Map<Source, HTMLSpanElement>());
  const [placed, setPlaced] = useState<{ tier: RiskTier; at: Placement[] } | null>(null);
  useLayoutEffect(() => {
    if (!hovered) {
      if (placed) setPlaced(null);
      return;
    }
    if (placed?.tier === hovered.tier || !lane.current) return;
    const box = lane.current.getBoundingClientRect();
    const width = (el: Element | null | undefined) => el?.getBoundingClientRect().width ?? 0;
    const boxes = hovered.subs.map((s) => {
      const seg = segments.current.get(`${hovered.tier}:${s.source}`)?.getBoundingClientRect();
      const part = (name: string) => width(labels.current.get(s.source)?.querySelector(`[data-part="${name}"]`));
      return {
        segLeft: (seg?.left ?? 0) - box.left,
        segWidth: seg?.width ?? 0,
        name: part("name"),
        sep: part("sep"),
        num: part("num"),
      };
    });
    setPlaced({ tier: hovered.tier, at: placeLabels(boxes, box.width) });
  }, [hovered, placed]);
  useEffect(() => {
    const remeasure = () => setPlaced(null); // a new width moves the segments
    window.addEventListener("resize", remeasure);
    return () => window.removeEventListener("resize", remeasure);
  }, []);

  return (
    <section aria-label="Findings by risk tier, one tick per finding" className="grid grid-cols-[minmax(0,1fr)] gap-2.5">
      <div className="grid gap-1.5" onMouseLeave={() => setHover(null)}>
        {/* Hover labels: centred over their source's ticks, the count on a line of its own when
            the segment is too narrow for both, nudged apart rather than cut (lib/labels.ts). */}
        <div ref={lane} aria-hidden className="relative h-7">
          {hovered?.subs.map((s, k) => {
            const at = placed?.tier === hovered.tier ? placed.at[k] : undefined;
            const lit = active(hovered.tier);
            return (
              <span
                key={s.source}
                ref={(el) => {
                  if (el) labels.current.set(s.source, el);
                  else labels.current.delete(s.source);
                }}
                className={`absolute bottom-0 text-center text-[11px] leading-[14px] whitespace-nowrap ${
                  lit === undefined ? "text-ink-muted" : lit === s.source ? "text-ink" : "text-ink-faint"
                }`}
                style={{ left: at?.left ?? 0, visibility: at ? undefined : "hidden" }}
              >
                <span data-part="name">{SOURCE_SHORT[s.source]}</span>
                {at?.twoLine ? <br /> : <span data-part="sep"> · </span>}
                <span data-part="num">{s.items.length}</span>
              </span>
            );
          })}
        </div>
        <div className="flex h-11 gap-3">
          {groups.map((g) => {
            const meta = TIER[g.tier];
            const lit = active(g.tier);
            let i = 0;
            return (
              <button
                key={g.tier}
                type="button"
                aria-pressed={focus === g.tier}
                aria-label={`${g.n} ${meta.label} findings, ${meta.threat.toLowerCase()}`}
                onClick={(e) => {
                  // On a source's ticks the click picks that source too; between sources, or from the
                  // keyboard, it picks the whole tier.
                  const on = e.target instanceof Element ? e.target.closest<HTMLElement>("[data-source]") : null;
                  onSelect(g.tier, on?.dataset.source as Source | undefined);
                }}
                onMouseEnter={() => setHover(g.tier)}
                onFocus={() => setHover(g.tier)}
                onBlur={() => setHover(null)}
                className="flex h-full min-w-2.5 basis-0 cursor-pointer items-stretch p-0 transition-opacity duration-200"
                style={{ flexGrow: g.n, opacity: dimmed(g.tier) ? 0.25 : 1, gap: open(g.tier) ? 10 : gap }}
              >
                {g.subs.map((s) => (
                  <span
                    key={s.source}
                    ref={(el) => {
                      const key = `${g.tier}:${s.source}`;
                      if (el) segments.current.set(key, el);
                      else segments.current.delete(key);
                    }}
                    data-source={s.source}
                    onPointerEnter={() => setHoverSource(s.source)}
                    onPointerLeave={() => setHoverSource(null)}
                    className="relative flex min-w-1.5 basis-0 items-stretch transition-opacity duration-200"
                    style={{ flexGrow: s.items.length, gap, opacity: lit !== undefined && lit !== s.source ? 0.4 : 1 }}
                  >
                    {lit === s.source && (
                      // a light laid over the singled-out source
                      <span aria-hidden className="pointer-events-none absolute -inset-[3px] z-[1] rounded-[3px] border border-ink/50 bg-ink/15" />
                    )}
                    {s.items.map((f) => {
                      const k = i++;
                      return (
                        <span
                          key={f.id}
                          className="qt-tick min-w-0 flex-[1_1_0] rounded-[1px]"
                          style={{
                            background: meta.color,
                            // without gutters, alternate tone so individual findings stay countable
                            opacity: gap === 0 && k % 2 === 1 ? 0.72 : 1,
                            animationDelay: `${Math.min(k * 6, 420) + DELAY[g.tier]}ms`,
                          }}
                        />
                      );
                    })}
                  </span>
                ))}
              </button>
            );
          })}
        </div>
      </div>
      <div className="flex gap-3">
        {groups.map((g) => (
          <div
            key={g.tier}
            className="flex min-w-2.5 basis-0 flex-col gap-0.5 border-t border-rule-strong pt-2 transition-opacity duration-200"
            style={{ flexGrow: g.n, opacity: dimmed(g.tier) ? 0.25 : 1 }}
          >
            <span className="flex flex-wrap items-center gap-x-2 font-semibold" style={{ color: TIER[g.tier].color }}>
              <span className="font-mono font-medium">{g.n}</span>
              {TIER[g.tier].label}
            </span>
            <span className="truncate text-xs text-ink-muted">{TIER[g.tier].threat}</span>
          </div>
        ))}
      </div>
      <p className="text-xs text-ink-faint">Hover a tier to split it by source. Click a tier, or one of its sources, to filter the list below.</p>
    </section>
  );
}
