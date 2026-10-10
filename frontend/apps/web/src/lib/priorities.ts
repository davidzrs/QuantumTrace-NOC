import type { Finding } from "@quantumtrace/sdk";

export interface MigrationItem {
  ruleId: string;
  name: string;
  replacement: string | null;
  nistReference: string | null;
  count: number;
  internetFacing: number;
  classicallyBroken: boolean;
}

/**
 * Group critical findings by algorithm and rank what to migrate first:
 * classically broken > internet-facing (Harvest-Now-Decrypt-Later) > sheer count.
 */
export function migrationPriorities(findings: Finding[], limit = 5): MigrationItem[] {
  const groups = new Map<string, MigrationItem>();
  for (const f of findings) {
    const c = f.classification;
    if (c.tier !== "critical") continue;
    const item = groups.get(c.rule_id) ?? {
      ruleId: c.rule_id,
      name: c.name,
      replacement: c.replacement ?? null,
      nistReference: c.nist_reference ?? null,
      count: 0,
      internetFacing: 0,
      classicallyBroken: c.classically_broken ?? false,
    };
    item.count += 1;
    if (f.asset.exposure === "internet") item.internetFacing += 1;
    groups.set(c.rule_id, item);
  }
  return [...groups.values()]
    .sort(
      (a, b) =>
        Number(b.classicallyBroken) - Number(a.classicallyBroken) ||
        b.internetFacing - a.internetFacing ||
        b.count - a.count,
    )
    .slice(0, limit);
}
