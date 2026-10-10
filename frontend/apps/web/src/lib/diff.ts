export type DiffOp = "same" | "del" | "add";

export interface DiffLine {
  op: DiffOp;
  text: string;
  /** Line number in the original file (same and del lines). */
  before?: number;
}

/**
 * Line diff by longest common subsequence. Snippets are a dozen lines, so the quadratic table is
 * fine. `start` numbers the original lines (the snippet's first line in its file).
 */
export function diffLines(before: string, after: string, start = 1): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      out.push({ op: "same", text: a[i]!, before: start + i });
      i++;
      j++;
    } else if (j < b.length && (i >= a.length || lcs[i]![j + 1]! >= lcs[i + 1]![j]!)) {
      out.push({ op: "add", text: b[j]! });
      j++;
    } else {
      out.push({ op: "del", text: a[i]!, before: start + i });
      i++;
    }
  }
  // Show removals before additions within a changed block.
  for (let k = 1; k < out.length; k++) {
    for (let m = k; m > 0 && out[m]!.op === "del" && out[m - 1]!.op === "add"; m--) {
      [out[m - 1], out[m]] = [out[m]!, out[m - 1]!];
    }
  }
  return out;
}
