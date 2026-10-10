import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { useState } from "react";
import { SOURCE_LABEL, SOURCES } from "../lib/format";
import { TIER, TIERS } from "../lib/tiers";

/** When each tier starts rising, so the strip reads left to right: Shor, Grover, the rest. */
const DELAY: Record<RiskTier, number> = { critical: 0, medium: 280, unknown: 400, safe: 500 };

/**
 * The debt strip: one tick per finding, grouped by tier, so the reader sees the shape of the
 * inventory before any number. Hovering a tier splits it by source; clicking filters the list.
 */
export function TickStrip({
  findings,
  focus,
  onSelectTier,
}: {
  findings: Finding[];
  focus: RiskTier | undefined;
  onSelectTier: (tier: RiskTier) => void;
}) {
  const [hover, setHover] = useState<RiskTier | null>(null);
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

  return (
    <section aria-label="Findings by risk tier, one tick per finding" className="grid grid-cols-[minmax(0,1fr)] gap-2.5">
      <div className="flex h-16 gap-3" onMouseLeave={() => setHover(null)}>
        {groups.map((g) => {
          const meta = TIER[g.tier];
          const open = hover === g.tier;
          let i = 0;
          return (
            <button
              key={g.tier}
              type="button"
              aria-pressed={focus === g.tier}
              aria-label={`${g.n} ${meta.label} findings, ${meta.threat.toLowerCase()}`}
              onClick={() => onSelectTier(g.tier)}
              onMouseEnter={() => setHover(g.tier)}
              onFocus={() => setHover(g.tier)}
              onBlur={() => setHover(null)}
              className="flex h-full min-w-2.5 basis-0 cursor-pointer items-stretch p-0 transition-[opacity,gap] duration-200"
              style={{ flexGrow: g.n, opacity: dimmed(g.tier) ? 0.25 : 1, gap: open ? 10 : gap }}
            >
              {g.subs.map((s) => (
                <span key={s.source} className="flex min-w-1.5 basis-0 flex-col gap-1.5" style={{ flexGrow: s.items.length }}>
                  <span
                    className="h-3.5 truncate text-left text-[11px] leading-[14px] text-ink-muted transition-opacity duration-200"
                    style={{ opacity: open ? 1 : 0 }}
                  >
                    {SOURCE_LABEL[s.source]} · {s.items.length}
                  </span>
                  <span className="flex flex-1 items-stretch" style={{ gap }}>
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
                </span>
              ))}
            </button>
          );
        })}
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
      <p className="text-xs text-ink-faint">Hover a tier to split it by source. Click it to filter the list below.</p>
    </section>
  );
}
