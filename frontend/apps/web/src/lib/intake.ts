/**
 * Decide, in the browser, which of the picked files go to the scanner. A codebase folder holds
 * thousands of files the scanners never read (assets, docs, dependencies), and uploads are
 * capped, so we send only what a scanner accepts and say what we left out.
 */
import type { UploadItem } from "@quantumtrace/sdk";

export type Kind = "code" | "cloud" | "capture" | "archive";

export const KINDS: { id: Kind; label: string; hint: string }[] = [
  { id: "code", label: "Source code", hint: "Python, Java and Go" },
  { id: "cloud", label: "Cloud exports", hint: "JSON from AWS KMS, ACM and load balancers" },
  { id: "capture", label: "Packet captures", hint: "TLS and SSH handshakes" },
  { id: "archive", label: "Zip archives", hint: "Unpacked and scanned on the server" },
];

const KIND_BY_EXT: Record<string, Kind> = {
  ".py": "code",
  ".java": "code",
  ".go": "code",
  ".json": "cloud",
  ".pcap": "capture",
  ".pcapng": "capture",
  ".cap": "capture",
  ".zip": "archive",
};

/** Folders never worth uploading: VCS metadata, dependencies, build output, caches. */
export const IGNORED_DIRS = new Set([
  ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", ".idea",
  ".vscode", ".gradle", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".next",
  "dist", "build", "target", "out",
]);

/** Generated files that look like cloud exports but never are. */
const IGNORED_FILES = new Set(["package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml"]);

/** The source scanner skips files above this size, so don't spend upload budget on them. */
export const MAX_CODE_BYTES = 2 * 1024 * 1024;
/** The API parses at most this many files per request. */
export const MAX_FILES = 1000;

export type Picked = UploadItem;

export interface Intake {
  /** Files that will be uploaded, with their paths inside the chosen folder. */
  send: Picked[];
  bytes: number;
  counts: Record<Kind, number>;
  /** Extensions of the files left out, most common first. */
  skipped: { total: number; byExt: [string, number][]; dirs: string[]; oversized: number };
  /** Top-level names: folders end in a slash. */
  roots: string[];
}

export function extOf(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
}

function ignoredDir(path: string): string | undefined {
  const parts = path.split("/").slice(0, -1);
  return parts.find((p) => IGNORED_DIRS.has(p));
}

/** Sort picked files into what gets sent and what doesn't. Pure, so it is easy to test. */
export function planIntake(picked: Picked[], skippedDirs: string[] = []): Intake {
  const send: Picked[] = [];
  const counts: Record<Kind, number> = { code: 0, cloud: 0, capture: 0, archive: 0 };
  const byExt = new Map<string, number>();
  const dirs = new Set(skippedDirs);
  const roots = new Set<string>();
  let bytes = 0;
  let oversized = 0;
  let total = 0;

  for (const p of picked) {
    const [top, ...rest] = p.path.split("/");
    roots.add(rest.length ? `${top}/` : (top ?? p.path));
    const dir = ignoredDir(p.path);
    if (dir) {
      dirs.add(dir);
      total += 1;
      continue;
    }
    const ext = extOf(p.path);
    const kind = KIND_BY_EXT[ext];
    const name = p.path.slice(p.path.lastIndexOf("/") + 1);
    if (!kind || IGNORED_FILES.has(name)) {
      byExt.set(ext || "no extension", (byExt.get(ext || "no extension") ?? 0) + 1);
      total += 1;
      continue;
    }
    if (kind === "code" && p.file.size > MAX_CODE_BYTES) {
      oversized += 1;
      total += 1;
      continue;
    }
    send.push(p);
    counts[kind] += 1;
    bytes += p.file.size;
  }

  return {
    send,
    bytes,
    counts,
    skipped: {
      total,
      byExt: [...byExt].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
      dirs: [...dirs].sort(),
      oversized,
    },
    roots: [...roots],
  };
}

/** Add a new pick to what is already staged. A file picked twice (same path) is sent once. */
export function mergePicked(staged: Picked[], added: Picked[]): Picked[] {
  const byPath = new Map(staged.map((p) => [p.path, p]));
  for (const p of added) byPath.set(p.path, p);
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

/** Files from an `<input>`: folder picks carry `webkitRelativePath`, plain picks only a name. */
export function fromInput(files: FileList): Picked[] {
  return [...files].map((file) => ({ file, path: file.webkitRelativePath || file.name }));
}

/**
 * Files from a drop, walking into dropped folders. Ignored folders are not entered at all
 * (a node_modules can hold 100k files), only reported. Entries must be read synchronously in
 * the drop handler, so call this before any await.
 */
export function fromDrop(dt: DataTransfer): Promise<{ picked: Picked[]; skippedDirs: string[] }> {
  const entries = [...dt.items]
    .map((item) => (item.kind === "file" ? item.webkitGetAsEntry() : null))
    .filter((e): e is FileSystemEntry => e !== null);
  // Browsers without the entries API: plain files only.
  if (!entries.length) {
    return Promise.resolve({ picked: fromInput(dt.files), skippedDirs: [] });
  }

  const picked: Picked[] = [];
  const skippedDirs = new Set<string>();

  const walk = async (entry: FileSystemEntry, prefix: string): Promise<void> => {
    const path = prefix + entry.name;
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) =>
        (entry as FileSystemFileEntry).file(resolve, reject),
      );
      picked.push({ file, path });
      return;
    }
    if (IGNORED_DIRS.has(entry.name)) {
      skippedDirs.add(entry.name);
      return;
    }
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    // readEntries returns at most ~100 entries per call; keep reading until it is empty.
    for (;;) {
      const batch = await new Promise<FileSystemEntry[]>((resolve, reject) =>
        reader.readEntries(resolve, reject),
      );
      if (!batch.length) break;
      await Promise.all(batch.map((child) => walk(child, `${path}/`)));
    }
  };

  return Promise.all(entries.map((e) => walk(e, ""))).then(() => ({
    picked: picked.sort((a, b) => a.path.localeCompare(b.path)),
    skippedDirs: [...skippedDirs],
  }));
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
