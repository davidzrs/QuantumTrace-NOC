/** "Fix with AI": asks the QuantumTrace API to rewrite the lines around one finding, and works
 * out where that rewrite goes in the editor. The API holds the model's key; nothing here does. */
import { createClient, QuantumTraceError, type FixSuggestion } from "@quantumtrace/sdk";
import { apiFailure, type ApiOptions, EngineError } from "./engine";

/** One finding in the editor, to be fixed. */
export interface FixTarget {
  /** The file as it reads in the editor, saved or not. */
  text: string;
  /** Its path inside the workspace, with forward slashes. */
  name: string;
  /** Zero-based line of the finding. */
  line: number;
  ruleId: string;
  usage: string | null;
  /** The code the engine pointed at, as it reported it. */
  observed: string;
}

/** The engine merged this line with the same code earlier in the file, and the API writes its
 * fix for that first place only. */
export class EarlierPlaceError extends EngineError {
  /** `line` is the first place, zero-based. */
  constructor(readonly line: number) {
    super(`The fix is written for the first place this code appears, line ${line + 1}.`);
  }
}

/** Uploads the file, finds the same finding in the API's scan and asks for its fix. The scan is
 * deleted from the API afterwards: it was only there to be fixed. */
export async function requestFix(options: ApiOptions, target: FixTarget): Promise<FixSuggestion> {
  const client = createClient(options);
  let scanId: string | undefined;
  try {
    const scan = await client.scanFiles([new File([target.text], target.name)]);
    scanId = scan.id;
    const line = target.line + 1; // the engine counts from one
    const here = scan.findings.filter(
      ({ asset }) =>
        asset.usage === target.usage &&
        [asset.evidence, ...asset.more_evidence].some((e) => e.line === line),
    );
    // The marks come from the last scan of the saved file, and this scan reads the editor. An
    // unsaved edit elsewhere can change the rule: a key size the engine read from a line that
    // is now rewritten turns RSA-1024 into RSA. It is still the same code to fix.
    const match =
      here.find(({ classification }) => classification.rule_id === target.ruleId) ??
      here.find(
        ({ asset, classification }) =>
          asset.observed === target.observed && classification.tier !== "safe",
      );
    if (!match) {
      throw new EngineError(
        `The QuantumTrace API did not find this warning on line ${line}. Save the file, scan it again, then retry.`,
      );
    }
    const first = match.asset.evidence.line;
    if (first !== null && first !== line) throw new EarlierPlaceError(first - 1);
    return await client.suggestFix(scan.id, match.id);
  } catch (error) {
    throw fixFailure(options.baseUrl, error);
  } finally {
    if (scanId) await client.deleteScan(scanId).catch(() => undefined);
  }
}

function fixFailure(baseUrl: string, error: unknown): EngineError {
  if (error instanceof EngineError) return error;
  // the API words these for the reader: AI fixes are off, the limit was reached, try again
  const worded =
    error instanceof QuantumTraceError &&
    typeof error.detail === "string" &&
    [422, 429, 502, 503].includes(error.status);
  return worded ? new EngineError(error.message) : apiFailure(baseUrl, error);
}

/** Lines of the file to replace, and what to put there. */
export interface Replacement {
  /** Zero-based, both included. */
  startLine: number;
  endLine: number;
  /** The rewritten lines, indented like the ones they replace. */
  lines: string[];
}

/** Where a fix goes in the file. The engine sends a snippet without its common indentation and
 * cuts long lines, so the snippet is first checked against the file, then the indentation is
 * put back on the rewrite. Undefined when the file does not read as the snippet does: the fix
 * was written for other text, and applying it would overwrite code the model never saw. */
export function replacement(
  fix: FixSuggestion,
  lineAt: (line: number) => string | undefined,
): Replacement | undefined {
  const original = fix.original_snippet.split("\n");
  const startLine = fix.snippet_start_line - 1;
  const current: string[] = [];
  for (const [i] of original.entries()) {
    const text = lineAt(startLine + i);
    if (text === undefined) return undefined;
    current.push(text);
  }
  const indent = commonIndent(current);
  const unchanged = current.every((text, i) =>
    text.trim() ? text === indent + original[i] : !original[i]?.trim(),
  );
  if (!unchanged) return undefined;
  return {
    startLine,
    endLine: startLine + original.length - 1,
    lines: fix.fixed_snippet.split(/\r?\n/).map((text) => (text.trim() ? indent + text : "")),
  };
}

/** The whitespace every non-blank line starts with: what the engine removed from the snippet. */
function commonIndent(lines: readonly string[]): string {
  const indents = lines.filter((text) => text.trim()).map((text) => /^[ \t]*/.exec(text)?.[0] ?? "");
  return indents.reduce((common, indent) => {
    let shared = 0;
    while (shared < common.length && common[shared] === indent[shared]) shared += 1;
    return common.slice(0, shared);
  }, indents[0] ?? "");
}

/** "line 12" or "lines 10–14", counted from one as the editor shows them. */
export function linesLabel(startLine: number, endLine: number): string {
  return startLine === endLine ? `line ${startLine + 1}` : `lines ${startLine + 1}–${endLine + 1}`;
}

/** The whole suggestion in plain text, for the output channel: the pop-up has no room for it. */
export function report(fix: FixSuggestion, file: string): string {
  const endLine = fix.snippet_start_line - 1 + fix.original_snippet.split("\n").length - 1;
  const parts = [
    `Fix with AI: ${file}, ${linesLabel(fix.snippet_start_line - 1, endLine)}`,
    fix.summary,
    `Why: ${fix.explanation}`,
  ];
  if (fix.caveats.length) {
    parts.push(
      [fix.changed ? "Also change:" : "Change instead:", ...fix.caveats.map((c) => `  - ${c}`)].join(
        "\n",
      ),
    );
  }
  if (fix.changed) parts.push(["Rewrite:", ...fix.fixed_snippet.split(/\r?\n/).map((l) => `  ${l}`)].join("\n"));
  parts.push(`Written by ${fix.model} from those lines. Review it before you keep it.`);
  return parts.join("\n");
}
