/**
 * Reads a probe result for the popup. Every tier, name and replacement comes from the
 * engine: this file only groups and words what the API returned.
 */
import type { Finding, RiskTier, ScanResult } from "@quantumtrace/sdk";
import { TIER_ORDER } from "@quantumtrace/ui";

export interface Section {
  id: "negotiated" | "permitted" | "certificate";
  title: string;
  hint: string;
  findings: Finding[];
}

const byTier = (a: Finding, b: Finding) =>
  TIER_ORDER.indexOf(a.classification.tier) - TIER_ORDER.indexOf(b.classification.tier);

export function sections(result: ScanResult): Section[] {
  const cert = (f: Finding) => f.asset.usage?.startsWith("certificate") ?? false;
  const all: Section[] = [
    {
      id: "negotiated",
      title: "This connection",
      hint: "What the server chose for a client that offers post-quantum key exchange.",
      findings: result.findings.filter((f) => !cert(f) && f.asset.observation !== "permitted"),
    },
    {
      id: "permitted",
      title: "Still accepted over TLS 1.2",
      hint: "Older clients can still connect this way, so attackers can force a downgrade.",
      findings: result.findings.filter((f) => !cert(f) && f.asset.observation === "permitted"),
    },
    {
      id: "certificate",
      title: "Certificate",
      hint: "The key that proves the site's identity, and how its issuer signed it.",
      findings: result.findings.filter(cert),
    },
  ];
  return all
    .map((s) => ({ ...s, findings: [...s.findings].sort(byTier) }))
    .filter((s) => s.findings.length > 0);
}

/** The negotiated key exchange: the one answer people open the popup for. */
export function keyExchange(result: ScanResult): Finding | undefined {
  return result.findings.find(
    (f) => f.asset.usage === "tls-key-exchange" && f.asset.observation === "negotiated",
  );
}

export function headline(result: ScanResult, host: string): string {
  const { critical, medium } = result.score.counts;
  const total = result.findings.length;
  if (critical > 0) return `${critical} of ${total} findings on ${host} break under Shor's algorithm.`;
  if (medium > 0)
    return `Nothing on ${host} breaks under Shor's algorithm, but ${medium} ${medium === 1 ? "finding is" : "findings are"} Grover-weakened or legacy.`;
  return `Everything QuantumTrace saw on ${host} holds up against known quantum attacks.`;
}

export function worstTier(result: ScanResult): RiskTier {
  const tiers = new Set(result.findings.map((f) => f.classification.tier));
  return TIER_ORDER.find((t) => tiers.has(t)) ?? "safe";
}

/** Toolbar badge: the count in the worst tier, coloured by it ("PQ" when all resilient). */
export function badge(result: ScanResult): { text: string; tier: RiskTier } {
  const tier = worstTier(result);
  if (tier === "safe") return { text: "PQ", tier };
  return { text: String(result.findings.filter((f) => f.classification.tier === tier).length), tier };
}
