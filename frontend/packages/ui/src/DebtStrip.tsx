import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { TIER_META, TIER_ORDER } from "./tiers";

export interface DebtStripProps {
  findings: Finding[];
  /** Highlight a tier (others fade); undefined shows all at full strength. */
  focus?: RiskTier;
  onSelectTier?: (tier: RiskTier) => void;
  height?: number;
}

/**
 * Cryptographic debt strip: one tick per finding, grouped by tier, so the reader sees the
 * shape of the inventory before reading any number. Each group is a button when
 * onSelectTier is provided.
 */
export function DebtStrip({ findings, focus, onSelectTier, height = 56 }: DebtStripProps) {
  const groups = TIER_ORDER.map((tier) => ({
    tier,
    // internet-facing first, so each tier reads as a step: exposed, then contained
    items: findings
      .filter((f) => f.classification.tier === tier)
      .sort((a, b) => Number(b.asset.exposure === "internet") - Number(a.asset.exposure === "internet")),
  })).filter((g) => g.items.length > 0);

  if (findings.length === 0) return null;
  // Large inventories (hundreds of network sessions) drop the gutters so every tick still fits.
  const tickGap = findings.length > 240 ? 0 : findings.length > 100 ? 1 : 2;

  return (
    <div
      role="group"
      aria-label="Findings by risk tier"
      style={{ display: "flex", gap: 6, width: "100%", height }}
    >
      {groups.map(({ tier, items }) => {
        const meta = TIER_META[tier];
        const dimmed = focus !== undefined && focus !== tier;
        const ticks = (
          <span
            aria-hidden
            style={{
              display: "flex",
              gap: tickGap,
              width: "100%",
              height: "100%",
              opacity: dimmed ? 0.22 : 1,
              transition: "opacity 160ms ease",
            }}
          >
            {items.map((f, i) => (
              <span
                key={f.id}
                style={{
                  flex: "1 1 0",
                  minWidth: 0,
                  background: meta.color,
                  // without gutters, alternate tone so individual findings stay countable
                  opacity: tickGap === 0 && i % 2 === 1 ? 0.72 : 1,
                  // shorter ticks for internal / unknown exposure: internet-facing stands taller
                  marginTop: f.asset.exposure === "internet" ? 0 : height * 0.28,
                }}
              />
            ))}
          </span>
        );
        const label = `${items.length} ${meta.label.toLowerCase()}: ${meta.threat}`;
        return onSelectTier ? (
          <button
            key={tier}
            type="button"
            aria-label={label}
            aria-pressed={focus === tier}
            onClick={() => onSelectTier(tier)}
            className="qt-strip-group"
            style={{ flex: `${items.length} 1 0`, minWidth: 8, padding: 0, border: 0, background: "none", cursor: "pointer" }}
          >
            {ticks}
          </button>
        ) : (
          <span key={tier} title={label} style={{ flex: `${items.length} 1 0`, minWidth: 8 }}>
            {ticks}
          </span>
        );
      })}
    </div>
  );
}
