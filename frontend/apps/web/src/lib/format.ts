import type { Finding } from "@quantumtrace/sdk";

const USAGE_LABELS: Record<string, string> = {
  SIGN_VERIFY: "Signing key",
  ENCRYPT_DECRYPT: "Encryption key",
  KEY_AGREEMENT: "Key agreement",
  GENERATE_VERIFY_MAC: "MAC key",
  "signature-digest": "Signature digest",
  "certificate-key": "Certificate key",
  "certificate-signature": "Certificate signature",
  "certificate-signature-digest": "Certificate digest",
  "tls-protocol": "TLS version",
  "tls-key-exchange": "TLS key exchange",
  "tls-authentication": "TLS authentication",
  "tls-cipher": "TLS cipher",
  "tls-mac": "TLS record MAC",
  "tls-policy": "TLS policy",
  "tls-cipher-suite": "TLS cipher suite",
  transport: "Cleartext transport",
  // source code
  hash: "Hashing",
  mac: "Message authentication",
  kdf: "Key derivation",
  "kdf-prf": "Key derivation PRF",
  signature: "Signing",
  "key-generation": "Key generation",
  "key-agreement": "Key agreement",
  encryption: "Encryption",
  rng: "Random numbers",
  // ssh
  "ssh-key-exchange": "SSH key exchange",
  "ssh-host-key": "SSH host key",
  "ssh-cipher": "SSH cipher",
  "ssh-mac": "SSH MAC",
  "ssh-kex-hash": "SSH exchange hash",
  "ssh-signature-digest": "SSH signature digest",
};

export function usageLabel(usage: string | null | undefined): string {
  if (!usage) return "Unspecified";
  return USAGE_LABELS[usage] ?? usage.replace(/[-_]/g, " ");
}

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

const squash = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

function baseName(f: Finding): string {
  const size = f.asset.key_size;
  return size && !f.classification.name.includes(String(size))
    ? `${f.classification.name}-${size}`
    : f.classification.name;
}

/** Main label: the precise form when known (AES-128-GCM, x25519, ECDSA P-384, Ed25519). */
export function algorithmLabel(f: Finding): string {
  return f.asset.variant ?? baseName(f);
}

/** Secondary label: the algorithm family, only when the main label doesn't already say it. */
export function variantLabel(f: Finding): string | null {
  const v = f.asset.variant;
  if (!v) return null;
  const name = f.classification.name;
  return squash(v).includes(squash(name).replace(/\(.*\)/, "")) ? null : name;
}

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
