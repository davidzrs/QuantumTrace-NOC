/** How the extension reaches the QuantumTrace engine: the local CLI, or the API through the SDK.
 * Nothing is classified here; both return the engine's findings as they are. */
import { execFile, type ExecFileException } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createClient, QuantumTraceError, type ScanResult } from "@quantumtrace/sdk";
import { isUnder } from "./runtime";

export type Scan = Pick<ScanResult, "findings" | "limitations" | "errors">;

export interface Engine {
  /** Scan files or directories under `root`. Code evidence comes back with absolute paths.
   * `trace` is the runtime trace of the project's last traced run, if there is one: the engine
   * reads it with the targets and says which of their findings ran. */
  scan(targets: readonly string[], root: string, trace?: string): Promise<Scan>;
  /** Scan one file as it reads in the editor, unsaved edits included. Undefined when this
   * engine cannot do that with the text staying on this machine: the file is then scanned
   * when it is saved. */
  scanText(text: string, file: string, root: string): Promise<Scan | undefined>;
}

/** A failure the user can act on: the message says what failed and what to do next. */
export class EngineError extends Error {}

/** The local CLI is not installed, or not where quantumtrace.cli.command points. */
export class CliNotFoundError extends EngineError {}

// Replaced by build.mjs. The package the web app offers for download is built with that
// deployment's API, so it can work on a machine that has no local scanner.
declare const __QT_DEFAULT_API_URL__: string | undefined;

/** The API this build offers when no local scanner is found; empty in a plain local build. */
export const DEFAULT_API_URL: string =
  typeof __QT_DEFAULT_API_URL__ === "string" ? __QT_DEFAULT_API_URL__ : "";

const MAX_CLI_OUTPUT = 128 * 1024 * 1024;
const SOURCE_EXTENSIONS = new Set([".py", ".java", ".go"]);
// directories the engine skips too (core/engine.py); pruned here only to avoid uploading them
const SKIPPED_DIRS = new Set([".git", ".venv", "node_modules", "__pycache__", ".idea", ".vscode"]);

/** Runs `<command> scan --format json -- <targets>`. Code never leaves the machine. */
export function cliEngine(command: readonly string[]): Engine {
  const scan = (targets: readonly string[], root: string) =>
    new Promise<Scan>((resolve, reject) => {
      const [bin, ...prefix] = command;
      if (!bin) {
        reject(
          new EngineError(
            "The setting quantumtrace.cli.command is empty. Set it to the command that runs the QuantumTrace CLI.",
          ),
        );
        return;
      }
      execFile(
        bin,
        [...prefix, "scan", "--format", "json", "--", ...targets],
        { cwd: root, maxBuffer: MAX_CLI_OUTPUT, windowsHide: true },
        (error, stdout, stderr) => {
          if (error) {
            reject(cliFailure(bin, error, stderr));
            return;
          }
          try {
            resolve(JSON.parse(stdout) as Scan);
          } catch {
            reject(
              new EngineError(
                `"${bin}" did not return a QuantumTrace scan. Check that quantumtrace.cli.command runs the QuantumTrace CLI.`,
              ),
            );
          }
        },
      );
    });
  return {
    // a folder that holds the trace is scanned with it anyway: naming it twice would read it twice
    scan: (targets, root, trace) =>
      scan(trace && !targets.some((t) => isUnder(trace, t)) ? [...targets, trace] : targets, root),
    // The CLI reads files, so the text goes into a copy with the same name in this machine's
    // temporary folder (the name tells the engine the language), deleted right after the scan.
    async scanText(text, file, root) {
      const folder = await mkdtemp(path.join(tmpdir(), "quantumtrace-"));
      const copy = path.join(folder, path.basename(file));
      try {
        await writeFile(copy, text);
        const result = await scan([copy], root);
        for (const { asset } of result.findings) {
          for (const evidence of [asset.evidence, ...asset.more_evidence]) {
            if (evidence.source_type === "code") evidence.location = file;
          }
        }
        return result;
      } finally {
        await rm(folder, { recursive: true, force: true });
      }
    },
  };
}

function cliFailure(bin: string, error: ExecFileException, stderr: string): EngineError {
  if (error.code === "ENOENT") {
    return new CliNotFoundError(
      `QuantumTrace CLI not found (tried "${bin}"). Install it, or set quantumtrace.cli.command to the command that runs it.`,
    );
  }
  const detail = stderr.trim().split(/\r?\n/).slice(-3).join(" ") || error.message;
  return new EngineError(`The QuantumTrace CLI failed: ${detail}`);
}

/** Scans with the local CLI. Only when the CLI is not installed, and only if `mayUseApi` agrees,
 * it scans through the API instead: code never leaves the machine without that answer. */
export function autoEngine(
  cli: Engine,
  api: Engine | undefined,
  mayUseApi: () => Promise<boolean>,
): Engine {
  return {
    async scan(targets, root, trace) {
      try {
        return await cli.scan(targets, root, trace);
      } catch (error) {
        if (!(error instanceof CliNotFoundError) || !api) throw error;
        if (await mayUseApi()) return api.scan(targets, root, trace);
        throw new CliNotFoundError(
          `${error.message} To scan through the QuantumTrace API instead, set quantumtrace.backend to api.`,
        );
      }
    },
    // unsaved text never goes to the API: without the CLI, the file is scanned when it is saved
    async scanText(text, file, root) {
      try {
        return await cli.scanText(text, file, root);
      } catch (error) {
        if (error instanceof CliNotFoundError) return undefined;
        throw error;
      }
    },
  };
}

export interface ApiOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: typeof fetch;
}

/** Uploads the source files under the targets, named by their path relative to `root`. */
export function apiEngine(options: ApiOptions): Engine {
  const client = createClient(options);
  return {
    async scan(targets, root, trace) {
      const paths = (await Promise.all(targets.map(sourceFiles))).flat();
      if (!paths.length) return { findings: [], limitations: [], errors: [] };
      // the trace names files, lines and tests, never data: it goes with the sources it describes
      if (trace) paths.push(trace);
      const files = await Promise.all(
        paths.map(async (file) => {
          const name = path.relative(root, file).split(path.sep).join("/");
          return new File([await readFile(file, "utf8")], name);
        }),
      );

      let result: ScanResult;
      try {
        result = await client.scanFiles(files);
      } catch (error) {
        throw apiFailure(options.baseUrl, error);
      }
      // the API reports paths relative to the upload; map them back onto this machine
      for (const { asset } of result.findings) {
        for (const evidence of [asset.evidence, ...asset.more_evidence]) {
          if (evidence.source_type === "code") {
            evidence.location = path.resolve(root, evidence.location);
          }
        }
      }
      return result;
    },
    // what goes to the API is what the user saved, not every pause while typing
    scanText: () => Promise.resolve(undefined),
  };
}

async function sourceFiles(target: string): Promise<string[]> {
  if (!(await stat(target)).isDirectory()) return [target];
  const found: string[] = [];
  for (const entry of await readdir(target, { withFileTypes: true })) {
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) found.push(...(await sourceFiles(full)));
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      found.push(full);
    }
  }
  return found;
}

/** What went wrong with a call to the API, and what to do about it. */
export function apiFailure(baseUrl: string, error: unknown): EngineError {
  if (!(error instanceof QuantumTraceError)) {
    return new EngineError(
      `Can't reach the QuantumTrace API at ${baseUrl}. Check quantumtrace.api.url and that the API is running.`,
    );
  }
  if (error.status === 401) {
    return new EngineError(
      'The QuantumTrace API rejected the API key. Run "QuantumTrace: Set API key".',
    );
  }
  return new EngineError(`The QuantumTrace API returned ${error.status}: ${error.message}`);
}
