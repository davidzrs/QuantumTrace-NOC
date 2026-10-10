import type { Finding } from "@quantumtrace/sdk";

export { algorithmLabel, usageLabel, variantLabel } from "@quantumtrace/ui";

const OBSERVATION_LABELS: Record<string, string> = {
  negotiated: "Seen negotiated in traffic",
  configured: "Explicitly configured",
  "in-code": "Called in source code",
  permitted: "Allowed by policy, not proven in use",
  offered: "Offered by one side only",
};

export const observationLabel = (o: string) => OBSERVATION_LABELS[o] ?? o;

const CONFIDENCE_LABELS: Record<string, string> = {
  high: "High confidence: read directly from the input",
  medium: "Medium confidence: inferred, e.g. a key size taken from elsewhere in the file",
  low: "Low confidence: the input was incomplete",
};

export const confidenceLabel = (c: string) => CONFIDENCE_LABELS[c] ?? c;

/** Human name for where a finding lives: KMS alias, cert domain, LB:port, or file. */
export function placeLabel(f: Finding): string {
  const ctx = f.asset.evidence.context ?? {};
  if (ctx.alias) return ctx.alias;
  if (ctx.domain) return ctx.domain;
  if (ctx.load_balancer) return ctx.port ? `${ctx.load_balancer}:${ctx.port}` : ctx.load_balancer;
  if (ctx.server) return `${ctx.service ?? "tcp"} ${ctx.sni ?? ctx.host ?? ctx.server}:${ctx.server_port}`;
  const loc = f.asset.evidence.location;
  const line = f.asset.evidence.line ? `:${f.asset.evidence.line}` : "";
  return `${loc.split("/").slice(-2).join("/")}${line}`;
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
export const formatDate = (iso: string) => dateFmt.format(new Date(iso));

export function downloadJson(filename: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}
