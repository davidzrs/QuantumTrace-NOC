import type { Finding } from "@quantumtrace/sdk";

/** Display labels shared by the web app and extension popups. Formatting only: tiers,
 * names and replacements always come from the engine. */

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
  "ssh-user-key": "SSH user key",
  // certificate and key files
  "private-key": "Private key",
  "public-key": "Public key",
};

export function usageLabel(usage: string | null | undefined): string {
  if (!usage) return "Unspecified";
  return USAGE_LABELS[usage] ?? usage.replace(/[-_]/g, " ");
}

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
