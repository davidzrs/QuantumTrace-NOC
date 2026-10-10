import type { RiskTier } from "@quantumtrace/sdk";

export const TIER_ORDER: RiskTier[] = ["critical", "medium", "unknown", "safe"];

export const TIER_META: Record<RiskTier, { label: string; threat: string; color: string; wash: string }> = {
  critical: {
    label: "Critical",
    threat: "Broken by Shor's algorithm",
    color: "var(--qt-critical)",
    wash: "var(--qt-critical-wash)",
  },
  medium: {
    label: "Weakened",
    threat: "Security halved by Grover's algorithm",
    color: "var(--qt-medium)",
    wash: "var(--qt-medium-wash)",
  },
  safe: {
    label: "Resilient",
    threat: "Holds up against known quantum attacks",
    color: "var(--qt-safe)",
    wash: "var(--qt-safe-wash)",
  },
  unknown: {
    label: "Unclassified",
    threat: "No rule matches this algorithm yet",
    color: "var(--qt-unknown)",
    wash: "var(--qt-unknown-wash)",
  },
};
