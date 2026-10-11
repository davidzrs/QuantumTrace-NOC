/**
 * Scan history is per browser: the ids of the scans run here, newest first. The API has no
 * "list every scan" route, so nobody else's scans show up and ours don't follow us elsewhere.
 * Storage can be unavailable (private windows, blocked site data): history is then just empty.
 */
const KEY = "quantumtrace:scan-ids";
export const MAX_HISTORY = 50;

export function readHistory(): string[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(KEY) ?? "[]");
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

export function writeHistory(ids: string[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(ids.slice(0, MAX_HISTORY)));
  } catch {
    // History is a convenience; a scan still works without it.
  }
}

export function remember(id: string): void {
  writeHistory([id, ...readHistory().filter((x) => x !== id)]);
}

/** This browser's scans plus a signed-in account's, without duplicates, at most MAX_HISTORY. */
export function mergeHistory(local: string[], account: string[]): string[] {
  return [...new Set([...local, ...account])].slice(0, MAX_HISTORY);
}

export function forget(ids: string[]): void {
  const gone = new Set(ids);
  writeHistory(readHistory().filter((x) => !gone.has(x)));
}
