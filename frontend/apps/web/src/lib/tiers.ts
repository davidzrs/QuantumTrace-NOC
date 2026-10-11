import type { RiskTier } from "@quantumtrace/sdk";

/** How the web app names and colours each tier. Tiers themselves always come from the engine. */
export const TIER: Record<RiskTier, { label: string; threat: string; color: string; wash: string; rgb: string }> = {
  critical: {
    label: "Critical",
    threat: "Breakable by Shor",
    color: "var(--qt-critical)",
    wash: "var(--qt-critical-wash)",
    rgb: "255,93,82",
  },
  medium: {
    label: "Medium",
    threat: "Grover-weakened or legacy",
    color: "var(--qt-medium)",
    wash: "var(--qt-medium-wash)",
    rgb: "242,180,65",
  },
  unknown: {
    label: "Unclassified",
    threat: "No rule matches yet",
    color: "var(--qt-unknown)",
    wash: "var(--qt-unknown-wash)",
    rgb: "154,165,177",
  },
  safe: {
    label: "Safe",
    threat: "Quantum-resistant",
    color: "var(--qt-safe)",
    wash: "var(--qt-safe-wash)",
    rgb: "67,209,177",
  },
};

export const TIERS: RiskTier[] = ["critical", "medium", "unknown", "safe"];
