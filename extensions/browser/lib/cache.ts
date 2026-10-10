import type { ScanResult } from "@quantumtrace/sdk";

// Reopening the popup on the same site shouldn't re-run a multi-handshake probe.
const TTL_MS = 10 * 60 * 1000;

interface Entry {
  result: ScanResult;
  at: number;
}

const storage = () => browser.storage.session ?? browser.storage.local;

export async function cached(key: string): Promise<ScanResult | undefined> {
  const entry = (await storage().get(`probe:${key}`))[`probe:${key}`] as Entry | undefined;
  return entry && Date.now() - entry.at < TTL_MS ? entry.result : undefined;
}

export async function remember(key: string, result: ScanResult): Promise<void> {
  await storage().set({ [`probe:${key}`]: { result, at: Date.now() } satisfies Entry });
}

export async function forget(key: string): Promise<void> {
  await storage().remove(`probe:${key}`);
}
