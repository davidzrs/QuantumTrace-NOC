import type { Finding } from "@quantumtrace/sdk";
import type { Evidence } from "./format";

/** Where the CBOM records a piece of evidence (see cbom/cyclonedx.py). */
function occurrenceAt(e: Evidence): string {
  const ctx = e.context ?? {};
  if (ctx.json_path) return `${e.location}#${ctx.json_path}`;
  if (ctx.packet) return `${e.location}/packet-${ctx.packet}`;
  return e.location;
}

type CbomOccurrence = { location?: unknown; line?: unknown; offset?: unknown; additionalContext?: unknown };
type CbomEntry = { evidence?: { occurrences?: CbomOccurrence[] } };

/**
 * The CBOM component that records this finding. One place can hold several components (a TLS
 * session's key exchange, cipher and MAC share a packet; an ELB policy's suites share a JSON
 * path), so an occurrence must also name the finding's usage and observed value.
 */
export function findComponent(cbom: Record<string, unknown> | undefined, f: Finding): unknown {
  const e = f.asset.evidence;
  const components = Array.isArray(cbom?.components) ? (cbom.components as CbomEntry[]) : [];
  const at = occurrenceAt(e);
  const what = `] ${f.asset.usage ?? ""} observed=${f.asset.observed}`;
  return components.find((c) =>
    c.evidence?.occurrences?.some(
      (o) =>
        o.location === at &&
        (o.line ?? null) === (e.line ?? null) &&
        (o.offset ?? null) === (e.column ?? null) &&
        typeof o.additionalContext === "string" &&
        o.additionalContext.endsWith(what),
    ),
  );
}
