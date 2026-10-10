/** How the extension reaches the QuantumTrace engine: the local CLI, or the API through the SDK.
 * Nothing is classified here; both return the engine's findings as they are. */
import { execFile, type ExecFileException } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import * as path from "node:path";
import { createClient, QuantumTraceError, type ScanResult } from "@quantumtrace/sdk";

export type Scan = Pick<ScanResult, "findings" | "limitations" | "errors">;

export interface Engine {
  /** Scan files or directories under `root`. Code evidence comes back with absolute paths. */
  scan(targets: readonly string[], root: string): Promise<Scan>;
}

/** A failure the user can act on: the message says what failed and what to do next. */
export class EngineError extends Error {}

const MAX_CLI_OUTPUT = 128 * 1024 * 1024;
const SOURCE_EXTENSIONS = new Set([".py", ".java", ".go"]);
// directories the engine skips too (core/engine.py); pruned here only to avoid uploading them
const SKIPPED_DIRS = new Set([".git", ".venv", "node_modules", "__pycache__", ".idea", ".vscode"]);

/** Runs `<command> scan --format json -- <targets>`. Code never leaves the machine. */
export function cliEngine(command: readonly string[]): Engine {
  return {
    scan: (targets, root) =>
      new Promise((resolve, reject) => {
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
      }),
  };
}

function cliFailure(bin: string, error: ExecFileException, stderr: string): EngineError {
  if (error.code === "ENOENT") {
    return new EngineError(
      `QuantumTrace CLI not found (tried "${bin}"). Install it, or set quantumtrace.cli.command to the command that runs it.`,
    );
  }
  const detail = stderr.trim().split(/\r?\n/).slice(-3).join(" ") || error.message;
  return new EngineError(`The QuantumTrace CLI failed: ${detail}`);
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
    async scan(targets, root) {
      const paths = (await Promise.all(targets.map(sourceFiles))).flat();
      if (!paths.length) return { findings: [], limitations: [], errors: [] };
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

function apiFailure(baseUrl: string, error: unknown): EngineError {
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
