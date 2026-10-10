/** What the popup can check for a tab URL. Pure, so it is unit-tested. */
export type Target =
  | { kind: "probe"; host: string; port: number; key: string }
  | { kind: "cleartext"; host: string }
  | { kind: "unsupported" };

export function targetFromUrl(url: string | undefined): Target {
  if (!url) return { kind: "unsupported" };
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { kind: "unsupported" };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!host) return { kind: "unsupported" };
  if (parsed.protocol === "http:") return { kind: "cleartext", host };
  if (parsed.protocol !== "https:") return { kind: "unsupported" };
  const port = parsed.port ? Number(parsed.port) : 443;
  return { kind: "probe", host, port, key: `${host}:${port}` };
}
