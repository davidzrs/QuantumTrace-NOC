/** Warnings the user dismissed, remembered per workspace and listed in the QuantumTrace view. */

/** The part of VS Code's `Memento` this needs. */
export interface Store {
  get<T>(key: string, fallback: T): T;
  update(key: string, value: unknown): PromiseLike<void>;
}

/** One dismissed warning, with enough to list it and find it again. */
export interface Dismissed {
  /** Occurrence identity: rule, usage and the trimmed line (see `occurrenceKey`). */
  key: string;
  /** What was dismissed, e.g. AES-128-ECB. */
  label: string;
  /** The engine's tier when it was dismissed. */
  tier: string;
  /** Zero-based line when it was dismissed (it may have moved since); null if not recorded. */
  line: number | null;
  /** The line of code, trimmed. */
  text: string;
}

export interface DismissedRow {
  /** Workspace-relative path the dismissal is stored under. */
  file: string;
  item: Dismissed;
}

const STATE_KEY = "quantumtrace.dismissed";

type State = Record<string, Dismissed[]>;

const lineOf = (key: string) => key.split("|").slice(2).join("|");

export function dismissed(key: string, label: string, tier: string, line: number): Dismissed {
  return { key, label, tier, line, text: lineOf(key) };
}

/** Versions before the list stored only the key. */
function upgrade(entry: Dismissed | string): Dismissed {
  if (typeof entry !== "string") return entry;
  const rule = entry.split("|")[0] || entry;
  return { key: entry, label: rule, tier: "unknown", line: null, text: lineOf(entry) };
}

export class Dismissals {
  constructor(private readonly store: Store) {}

  private get state(): State {
    const stored = this.store.get<Record<string, (Dismissed | string)[]>>(STATE_KEY, {});
    return Object.fromEntries(
      Object.entries(stored).map(([file, items]) => [file, items.map(upgrade)]),
    );
  }

  has(file: string, key: string): boolean {
    return this.state[file]?.some((item) => item.key === key) ?? false;
  }

  /** Every dismissed warning, by file and then by line. */
  list(): DismissedRow[] {
    return Object.entries(this.state)
      .sort(([a], [b]) => a.localeCompare(b))
      .flatMap(([file, items]) =>
        [...items]
          .sort((a, b) => (a.line ?? 0) - (b.line ?? 0))
          .map((item) => ({ file, item })),
      );
  }

  count(): number {
    return Object.values(this.state).reduce((total, items) => total + items.length, 0);
  }

  add(file: string, item: Dismissed): PromiseLike<void> {
    const items = this.state[file] ?? [];
    if (items.some((existing) => existing.key === item.key)) return Promise.resolve();
    return this.store.update(STATE_KEY, { ...this.state, [file]: [...items, item] });
  }

  remove(file: string, key: string): PromiseLike<void> {
    const items = (this.state[file] ?? []).filter((item) => item.key !== key);
    const next: State = { ...this.state, [file]: items };
    if (!items.length) delete next[file];
    return this.store.update(STATE_KEY, next);
  }

  clear(): PromiseLike<void> {
    return this.store.update(STATE_KEY, undefined);
  }
}
