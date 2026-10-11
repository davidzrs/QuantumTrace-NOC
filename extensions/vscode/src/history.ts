/** The marks a file had for each text it has read as. Undoing an edit brings back a text the
 * file has read as before, and with it its marks: at once, without asking the engine again. */
import { createHash } from "node:crypto";
import type { Occurrence } from "./occurrences";

/** Texts kept per file: an undo rarely goes back further than this between two scans. */
const KEPT = 50;

export class MarkHistory {
  private readonly files = new Map<string, Map<string, Occurrence[]>>();

  constructor(private readonly kept = KEPT) {}

  /** Records the marks of `file` while it reads as `text`. */
  remember(file: string, text: string, marks: readonly Occurrence[]): void {
    const texts = this.files.get(file) ?? new Map<string, Occurrence[]>();
    const id = digest(text);
    texts.delete(id); // so the text seen last is the last to be dropped
    texts.set(id, copy(marks));
    for (const oldest of texts.keys()) {
      if (texts.size <= this.kept) break;
      texts.delete(oldest);
    }
    this.files.set(file, texts);
  }

  /** The marks `file` had when it read as `text`, if it ever did. */
  recall(file: string, text: string): Occurrence[] | undefined {
    const marks = this.files.get(file)?.get(digest(text));
    return marks && copy(marks);
  }

  has(file: string): boolean {
    return this.files.has(file);
  }

  clear(): void {
    this.files.clear();
  }
}

const digest = (text: string) => createHash("sha256").update(text).digest("base64");

// a mark is edited in place when it is dismissed, so the history keeps its own copies
const copy = (marks: readonly Occurrence[]) => marks.map((o) => ({ ...o }));
