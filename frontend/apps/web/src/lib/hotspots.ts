import type { Finding, RiskTier } from "@quantumtrace/sdk";

export interface Hotspot {
  path: string;
  counts: Record<RiskTier, number>;
  total: number;
  /** One tier per occurrence, worst first: drawn as a row of ticks. */
  ticks: RiskTier[];
}

const RANK: Record<RiskTier, number> = { critical: 0, medium: 1, unknown: 2, safe: 3 };

/**
 * Source files ranked by how much quantum-vulnerable crypto they hold: Shor-broken
 * occurrences first, then Grover-weakened, then everything. Every piece of evidence counts,
 * so a file calling SHA-1 on three lines weighs three.
 */
export function codeHotspots(findings: Finding[]): Hotspot[] {
  const byPath = new Map<string, Hotspot>();
  for (const f of findings) {
    const tier = f.classification.tier;
    for (const e of [f.asset.evidence, ...f.asset.more_evidence]) {
      if (e.source_type !== "code") continue;
      let spot = byPath.get(e.location);
      if (!spot) {
        spot = { path: e.location, counts: { critical: 0, medium: 0, unknown: 0, safe: 0 }, total: 0, ticks: [] };
        byPath.set(e.location, spot);
      }
      spot.counts[tier] += 1;
      spot.total += 1;
      spot.ticks.push(tier);
    }
  }
  for (const s of byPath.values()) s.ticks.sort((a, b) => RANK[a] - RANK[b]);
  return [...byPath.values()].sort(
    (a, b) =>
      b.counts.critical - a.counts.critical ||
      b.counts.medium - a.counts.medium ||
      b.total - a.total ||
      a.path.localeCompare(b.path),
  );
}

/** The folder every path shares (`repo/src/`), so rows can show only what differs. */
export function commonDir(paths: string[]): string {
  if (!paths.length) return "";
  let prefix = paths[0]!.slice(0, paths[0]!.lastIndexOf("/") + 1);
  for (const p of paths) while (prefix && !p.startsWith(prefix)) prefix = prefix.slice(0, prefix.lastIndexOf("/", prefix.length - 2) + 1);
  return prefix;
}
