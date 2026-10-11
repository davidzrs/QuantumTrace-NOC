import type { Finding } from "@quantumtrace/sdk";
import { TIERS } from "./tiers";

/**
 * When a finding needs fixing, from the engine's tier and classically-broken flag: anything a
 * classical computer already breaks among the Shor-exposed comes first, then the rest of Shor
 * by NIST IR 8547's dates, then Grover hardening. Ordering only: tiers come from the engine.
 */
export type FixBy = "now" | "before-2030" | "before-2035" | "harden" | "review" | "none";

export const FIX_BY: Record<FixBy, { rank: number; label: string }> = {
  now: { rank: 0, label: "Fix now" },
  "before-2030": { rank: 1, label: "Before 2030" },
  "before-2035": { rank: 2, label: "Before 2035" },
  harden: { rank: 3, label: "Harden" },
  review: { rank: 4, label: "Review" },
  none: { rank: 5, label: "No action" },
};

/** Flags that ask for a look even when the algorithm itself holds up (rules/algorithms.yaml). */
const REVIEW_FLAGS = new Set(["hand-rolled-crypto"]);

/**
 * NIST IR 8547 deprecates 112-bit Shor-exposed keys (RSA-2048, DH-2048) after 2030 and disallows
 * every size after 2035. A key of unknown size gets the earlier date.
 */
export function fixBy(f: Finding): FixBy {
  const c = f.classification;
  switch (c.tier) {
    case "critical":
      if (c.classically_broken) return "now";
      return c.classical_security_bits != null && c.classical_security_bits >= 128 ? "before-2035" : "before-2030";
    case "medium":
      return "harden";
    case "unknown":
      return "review";
    default:
      return f.asset.flags.some((x) => REVIEW_FLAGS.has(x)) ? "review" : "none";
  }
}

export interface FixRow {
  key: string;
  lead: Finding;
  members: Finding[];
  fixBy: FixBy;
  /** Sessions or repeat places across members (network evidence repeats per session). */
  sessions: number;
}

/** Identical crypto in several places (same tier, rule, variant, usage, flags, exposure, source). */
export function groupKey(f: Finding): string {
  const a = f.asset;
  return [f.classification.tier, f.classification.rule_id, a.variant ?? "", a.usage ?? "",
    [...a.flags].sort().join("+"), a.exposure, a.evidence.source_type].join("|");
}

const sessions = (f: Finding) => 1 + f.asset.more_evidence.length;

/**
 * Rows for the fix list, most urgent first: by when to fix, then already broken, then exposed to
 * harvest-now, decrypt-later (a key exchange or encryption recorded today is read later), then
 * internet-facing, then how many places.
 */
export function fixRows(findings: Finding[], grouped = true): FixRow[] {
  const byKey = new Map<string, FixRow>();
  for (const f of findings) {
    const k = grouped ? groupKey(f) : f.id;
    const row = byKey.get(k);
    if (row) {
      row.members.push(f);
      row.sessions += sessions(f);
    } else {
      byKey.set(k, { key: k, lead: f, members: [f], fixBy: fixBy(f), sessions: sessions(f) });
    }
  }
  const tierRank = (r: FixRow) => TIERS.indexOf(r.lead.classification.tier);
  return [...byKey.values()].sort(
    (a, b) =>
      FIX_BY[a.fixBy].rank - FIX_BY[b.fixBy].rank ||
      Number(b.lead.classification.classically_broken) - Number(a.lead.classification.classically_broken) ||
      Number(b.lead.classification.hndl) - Number(a.lead.classification.hndl) ||
      Number(b.lead.asset.exposure === "internet") - Number(a.lead.asset.exposure === "internet") ||
      b.members.length - a.members.length ||
      tierRank(a) - tierRank(b) ||
      a.key.localeCompare(b.key),
  );
}
