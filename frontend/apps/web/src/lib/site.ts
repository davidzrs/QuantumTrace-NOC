/**
 * Which host and port to check for whatever someone pastes: a full link, a bare domain or
 * host:port. A plain http:// link is checked on 443, where the site's HTTPS would answer.
 * The API decides what may be probed (public addresses only); this only reads the input. Pure,
 * so it's tested.
 */
export type SiteTarget = { host: string; port: number } | { problem: string };

const EXAMPLE = "Paste a website address, such as https://example.com.";

export function siteTarget(input: string): SiteTarget {
  const text = input.trim();
  if (!text) return { problem: EXAMPLE };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { problem: `That isn’t a website address. ${EXAMPLE}` };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { problem: `Only websites can be checked here. ${EXAMPLE}` };
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) return { problem: EXAMPLE };
  const port = url.protocol === "https:" && url.port ? Number(url.port) : 443;
  return { host, port };
}

/** "example.com", or "example.com:8443" off the default port. */
export function siteLabel({ host, port }: { host: string; port: number }): string {
  const name = host.includes(":") ? `[${host}]` : host;
  return port === 443 ? name : `${name}:${port}`;
}
