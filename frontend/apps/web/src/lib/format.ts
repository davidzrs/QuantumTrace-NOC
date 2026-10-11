import type { Classification, Finding } from "@quantumtrace/sdk";

export { algorithmLabel, usageLabel, variantLabel } from "@quantumtrace/ui";

export type Evidence = Finding["asset"]["evidence"];
export type Source = Evidence["source_type"];

const OBSERVATION_LABELS: Record<string, string> = {
  negotiated: "Negotiated on the wire",
  executed: "Seen running",
  configured: "Configured",
  "in-code": "Found in code",
  permitted: "Permitted by policy, not proven used",
  offered: "Offered by one side only",
};

export const observationLabel = (o: string) => OBSERVATION_LABELS[o] ?? o;

const OBSERVATION_NOTES: Record<string, string> = {
  negotiated: "Seen in the captured traffic.",
  executed: "Ran during a traced test run.",
  configured: "Set in a configuration file or a cloud export.",
  "in-code": "Called in the source code.",
  permitted: "A policy allows it; nothing here shows it in use.",
  offered: "One side offered it; the other may have picked something else.",
};

/** One line on where the evidence comes from, under its label. */
export const observationNote = (o: string) => OBSERVATION_NOTES[o] ?? "";

const CONFIDENCE_LABELS: Record<string, string> = {
  high: "High confidence, read directly from the input.",
  medium: "Medium confidence, inferred, e.g. a key size taken from elsewhere in the file.",
  low: "Low confidence, the input was incomplete.",
};

export const confidenceLabel = (c: string) => CONFIDENCE_LABELS[c] ?? c;

/**
 * What a runtime trace saw at one place, in a sentence: "Ran 14 times in 2 tests (key size
 * 1024)". Undefined when no trace covers the place.
 */
export function runtimeNote(execution: Evidence["execution"]): string | undefined {
  if (!execution) return undefined;
  const during = execution.run ? ` during ${execution.run}` : "";
  if (!execution.ran) return `Did not run${during}`;
  const times = execution.calls === null ? "Ran" : `Ran ${plural(execution.calls, "time")}`;
  const tests = execution.test_count ? ` in ${plural(execution.test_count, "test")}` : during;
  const { key_size: size, mode, via } = execution.parameters;
  const used = [size && `key size ${size}`, mode && `${mode} mode`, via && `through ${via}`].filter(Boolean);
  return `${times}${tests}${used.length ? ` (${used.join(", ")})` : ""}`;
}

export const EXPOSURE_LABEL: Record<string, string> = {
  internet: "Internet",
  internal: "Internal",
  unknown: "Not known",
};

export const SOURCE_LABEL: Record<Source, string> = {
  cloud: "Cloud posture",
  code: "Source code",
  network: "Network capture",
};

/** One word each, for places too tight for the full label (the debt strip's hover split). */
export const SOURCE_SHORT: Record<Source, string> = {
  cloud: "Cloud",
  code: "Code",
  network: "Network",
};

export const SOURCES: Source[] = ["cloud", "code", "network"];

/** Which source a scan note belongs to, from the scanner that wrote it. */
export function noteSource(scanner: string): Source | undefined {
  if (/cloud|aws/.test(scanner)) return "cloud";
  if (/code|source/.test(scanner)) return "code";
  if (/network|pcap|tls|probe/.test(scanner)) return "network";
  return undefined;
}

/** Human name for where a finding lives: KMS alias, cert domain, LB:port, server, or file. */
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

/** Full trace of one piece of evidence: file:line, ARN#json_path or flow (packet n). */
export function evidenceLabel(e: Evidence): string {
  const ctx = e.context ?? {};
  if (ctx.json_path) return `${e.location}#${ctx.json_path}`;
  if (ctx.packet) return `${e.location} (packet ${ctx.packet})`;
  if (e.line && e.column) return `${e.location}:${e.line}:${e.column}`;
  return e.line ? `${e.location}:${e.line}` : e.location;
}

/** Split "A (x, y), B" on top-level commas only. */
function splitRefs(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Standards to show beside a replacement: the PQC FIPS it names, then the NIST references. */
export function standards(c: Classification): { text: string; pqc: boolean }[] {
  const pqc = [...new Set((c.replacement ?? "").match(/FIPS 20[345]/g) ?? [])];
  const refs = c.nist_reference ? splitRefs(c.nist_reference) : [];
  return [
    ...pqc.map((text) => ({ text, pqc: true })),
    ...refs.filter((r) => !pqc.includes(r)).map((text) => ({ text, pqc: /FIPS 20[345]/.test(text) })),
  ];
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/** "Today, 16:58", "Yesterday, 09:12", else a medium date and time. */
export function formatWhen(iso: string, now = new Date()): string {
  const d = new Date(iso);
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 86_400_000);
  if (diff === 0) return `Today, ${timeFmt.format(d)}`;
  if (diff === 1) return `Yesterday, ${timeFmt.format(d)}`;
  return dateFmt.format(d);
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function downloadJson(filename: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}
