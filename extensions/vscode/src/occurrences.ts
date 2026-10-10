/** Turns engine findings into underlined places in a file, and keeps them in place while typing. */
import type { Finding } from "@quantumtrace/sdk";

/** One underlined place. A finding has several when the engine merged repeats within a file. */
export interface Occurrence {
  finding: Finding;
  /** Zero-based line and character span, as VS Code counts them. */
  line: number;
  start: number;
  end: number;
  /** Identity that survives line shifts, used to remember a dismissal. */
  key: string;
}

/** A text change, positioned against the document as it was before the change. */
export interface Edit {
  startLine: number;
  startChar: number;
  endLine: number;
  endChar: number;
  text: string;
}

export function occurrenceKey(finding: Finding, lineText: string): string {
  return [finding.classification.rule_id, finding.asset.usage ?? "", lineText.trim()].join("|");
}

/** Safe findings and non-code evidence are not underlined; lines the file no longer has are skipped. */
export function occurrences(
  findings: readonly Finding[],
  lineAt: (line: number) => string | undefined,
): Occurrence[] {
  const out: Occurrence[] = [];
  for (const finding of findings) {
    const { evidence, observed } = finding.asset;
    if (evidence.source_type !== "code" || finding.classification.tier === "safe") continue;
    for (const place of reportedPlaces(finding)) {
      const text = lineAt(place.line);
      if (text === undefined) continue;
      const [start, end] = span(text, observed, place.column);
      out.push({ finding, line: place.line, start, end, key: occurrenceKey(finding, text) });
    }
  }
  return out;
}

// same order as the web app (packages/ui/src/tiers.ts)
const TIER_RANK: Record<Finding["classification"]["tier"], number> = {
  critical: 0,
  medium: 1,
  unknown: 2,
  safe: 3,
};

/** Most severe first; findings of the same tier keep the engine's order. */
export function mostSevereFirst(items: readonly Occurrence[]): Occurrence[] {
  const rank = (o: Occurrence) => TIER_RANK[o.finding.classification.tier];
  return [...items].sort((a, b) => rank(a) - rank(b));
}

/** The engine reports the first hit in `evidence` and repeats in the file in `more_evidence`,
 * one-based. Returned zero-based, one place per line. */
function reportedPlaces(finding: Finding): { line: number; column: number | null }[] {
  const seen = new Set<number>();
  const places: { line: number; column: number | null }[] = [];
  for (const e of [finding.asset.evidence, ...finding.asset.more_evidence]) {
    if (e.source_type !== "code" || e.line === null || !Number.isInteger(e.line) || e.line < 1) continue;
    if (seen.has(e.line)) continue;
    seen.add(e.line);
    places.push({ line: e.line - 1, column: e.column !== null && e.column > 0 ? e.column - 1 : null });
  }
  return places;
}

/** The observed call where the engine found it, else wherever it is on the line (the file may
 * have changed since the scan), else the line without its indentation. */
function span(text: string, observed: string, column: number | null = null): [number, number] {
  if (observed && column !== null && text.startsWith(observed, column)) {
    return [column, column + observed.length];
  }
  const at = observed ? text.indexOf(observed) : -1;
  if (at >= 0) return [at, at + observed.length];
  const start = text.length - text.trimStart().length;
  const end = text.trimEnd().length;
  return end > start ? [start, end] : [0, Math.max(text.length, 1)];
}

/** Moves underlines along with the text around them. An edit that overlaps an underline drops
 * it: the code under it changed, and the next scan decides whether it comes back. */
export function applyEdits(items: readonly Occurrence[], edits: readonly Edit[]): Occurrence[] {
  // every edit is positioned against the old document, so apply them bottom-up
  const bottomUp = [...edits].sort(
    (a, b) => b.startLine - a.startLine || b.startChar - a.startChar,
  );
  return bottomUp.reduce<Occurrence[]>((kept, edit) => kept.flatMap((o) => moved(o, edit)), [
    ...items,
  ]);
}

function moved(o: Occurrence, edit: Edit): Occurrence[] {
  const notAfter = (lineA: number, charA: number, lineB: number, charB: number) =>
    lineA < lineB || (lineA === lineB && charA <= charB);
  if (notAfter(o.line, o.end, edit.startLine, edit.startChar)) return [o];
  if (!notAfter(edit.endLine, edit.endChar, o.line, o.start)) return [];

  const inserted = edit.text.split("\n");
  const line = o.line + inserted.length - 1 - (edit.endLine - edit.startLine);
  if (edit.endLine !== o.line) return [{ ...o, line }];
  const lastLength = inserted.at(-1)?.length ?? 0;
  const newEndChar = inserted.length > 1 ? lastLength : edit.startChar + lastLength;
  const shift = newEndChar - edit.endChar;
  return [{ ...o, line, start: o.start + shift, end: o.end + shift }];
}
