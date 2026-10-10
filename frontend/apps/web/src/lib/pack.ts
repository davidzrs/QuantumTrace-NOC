/**
 * Compress files in the browser before upload. The hosted scanner can only receive about
 * 4 MB per request (a Vercel limit), but source code, JSON exports and handshake captures
 * gzip several times smaller. The API unpacks `name.gz` back to `name`.
 */
import type { UploadItem } from "@quantumtrace/sdk";
import { extOf, formatBytes } from "./intake";

/** Already compressed: gzipping again only costs time. */
const COMPRESSED = new Set([".zip", ".gz"]);

export class UploadTooLarge extends Error {}

export async function gzipItem(item: UploadItem): Promise<UploadItem> {
  if (COMPRESSED.has(extOf(item.path))) return item;
  const stream = item.file.stream().pipeThrough(new CompressionStream("gzip"));
  const blob = await new Response(stream).blob();
  const path = `${item.path}.gz`;
  return { file: new File([blob], path.slice(path.lastIndexOf("/") + 1)), path };
}

/** Gzip every file, then check the total against what one request may carry. */
export async function pack(items: UploadItem[], maxBytes: number): Promise<UploadItem[]> {
  const packed = await Promise.all(items.map(gzipItem));
  const total = packed.reduce((n, p) => n + p.file.size, 0);
  if (total > maxBytes) {
    throw new UploadTooLarge(
      `Even compressed, these files come to ${formatBytes(total)}, and this scanner receives up to ${formatBytes(maxBytes)} per scan. Scan a subfolder, or run QuantumTrace locally for bigger inputs.`,
    );
  }
  return packed;
}
