import type { Classification, Finding } from "@quantumtrace/sdk";
import { TIERS } from "./tiers";

/**
 * When a finding needs fixing, from the engine's tier and classically-broken flag: anything a
 * classical computer already breaks among the Shor-exposed comes first, then the rest of Shor
 * (NIST deprecates it by 2030), then Grover hardening. Ordering only: tiers come from the engine.
 */
export type FixBy = "now" | "before-2030" | "harden" | "review" | "none";

export const FIX_BY: Record<FixBy, { rank: number; label: string }> = {
  now: { rank: 0, label: "Fix now" },
  "before-2030": { rank: 1, label: "Before 2030" },
  harden: { rank: 2, label: "Harden" },
  review: { rank: 3, label: "Review" },
  none: { rank: 4, label: "No action" },
};

export function fixBy(c: Classification): FixBy {
  switch (c.tier) {
    case "critical":
      return c.classically_broken ? "now" : "before-2030";
    case "medium":
      return "harden";
    case "unknown":
      return "review";
    default:
      return "none";
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
      byKey.set(k, { key: k, lead: f, members: [f], fixBy: fixBy(f.classification), sessions: sessions(f) });
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
