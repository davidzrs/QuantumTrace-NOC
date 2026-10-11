import type { Finding, RiskTier } from "@quantumtrace/sdk";

/** Under "No cryptography found.": what the scanners read, so people know what to upload instead. */
export const NOTHING_FOUND =
  "None of the scanners recognised anything in these files. QuantumTrace reads AWS posture exports (JSON), Python, Java and Go source, SSH and TLS server configs, certificates and keys, Java and Go builds, and .pcap or .pcapng captures.";

/** What the report's opening sentences are made of, counted over the findings in view. */
export interface Tally {
  c: number;
  m: number;
  u: number;
  s: number;
  internetCritical: number;
  hndl: number;
  internetHndl: number;
}

export function tally(findings: Finding[]): Tally {
  const count = (t: RiskTier) => findings.filter((f) => f.classification.tier === t).length;
  return {
    c: count("critical"),
    m: count("medium"),
    u: count("unknown"),
    s: count("safe"),
    internetCritical: findings.filter((f) => f.classification.tier === "critical" && f.asset.exposure === "internet").length,
    hndl: findings.filter((f) => f.classification.hndl).length,
    internetHndl: findings.filter((f) => f.classification.hndl && f.asset.exposure === "internet").length,
  };
}

/** The sentence under the headline: why the critical ones matter, then the rest by tier. */
export function heroSub({ c, m, u, s, internetCritical, hndl, internetHndl }: Tally): string {
  const rest = [
    m ? `${m} ${c ? "more " : ""}${m === 1 ? "is" : "are"} medium, weakened by Grover’s` : "",
    u ? `${u} ${u === 1 ? "is" : "are"} unclassified` : "",
    s ? `${s} ${s === 1 ? "is" : "are"} safe` : "",
  ].filter(Boolean);
  const list = rest.length > 1 ? `${rest.slice(0, -1).join(", ")} and ${rest.at(-1)}` : (rest[0] ?? "");
  const lead = c ? "Shor’s algorithm breaks them outright." : "";
  const harvest = hndl
    ? `${hndl} of them ${hndl === 1 ? "is a key exchange or encryption" : "are key exchanges or encryption"}, exposed to harvest-now, decrypt-later.`
    : "";
  // only key exchanges and encryption are harvested; a signature has to be forged live
  const harvested = internetHndl
    ? `, ${internetHndl} of them key exchanges or encryption whose traffic can be recorded today and decrypted later`
    : "";
  const exposure = c
    ? internetCritical
      ? `${internetCritical} of the critical ones sit on internet-facing endpoints${harvested}.`
      : "None of them faces the internet directly."
    : "";
  return [lead, harvest, list && `${list.charAt(0).toUpperCase()}${list.slice(1)}.`, exposure].filter(Boolean).join(" ");
}
