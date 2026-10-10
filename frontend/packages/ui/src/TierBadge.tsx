import type { RiskTier } from "@quantumtrace/sdk";
import { TIER_META } from "./tiers";

/** Tier label with a shape cue (not colour alone) for accessibility. */
export function TierBadge({ tier }: { tier: RiskTier }) {
  const meta = TIER_META[tier];
  return (
    <span
      title={meta.threat}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.4em",
        color: meta.color,
        fontWeight: 600,
        whiteSpace: "nowrap",
      }}
    >
      <TierGlyph tier={tier} />
      {meta.label}
    </span>
  );
}

export function TierGlyph({ tier, size = 9 }: { tier: RiskTier; size?: number }) {
  const color = TIER_META[tier].color;
  const common = { width: size, height: size, viewBox: "0 0 10 10", "aria-hidden": true } as const;
  switch (tier) {
    case "critical": // solid diamond
      return (
        <svg {...common}>
          <path d="M5 0 10 5 5 10 0 5Z" fill={color} />
        </svg>
      );
    case "medium": // half-filled square
      return (
        <svg {...common}>
          <rect x="0.75" y="0.75" width="8.5" height="8.5" fill="none" stroke={color} strokeWidth="1.5" />
          <rect x="0" y="5" width="10" height="5" fill={color} />
        </svg>
      );
    case "safe": // ring
      return (
        <svg {...common}>
          <circle cx="5" cy="5" r="4.1" fill="none" stroke={color} strokeWidth="1.8" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <path d="M1 5h8" stroke={color} strokeWidth="2" />
        </svg>
      );
  }
}
