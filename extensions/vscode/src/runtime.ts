/** "In use": running the project's own tests (or a debug session) with the QuantumTrace tracer,
 * so the engine can say which marked lines really ran and with what. The tracer only records;
 * nothing here, and nothing in the tracer, decides what a finding is. */
import { randomUUID } from "node:crypto";
import * as path from "node:path";

/** Where a traced run leaves its trace, inside the project folder. The engine reads it there. */
export const TRACE_FILE = path.join(".quantumtrace", "trace.jsonl");

export const traceFile = (root: string) => path.join(root, TRACE_FILE);

/** What to add to a process's environment so every Python it starts traces into `out`:
 * the tracer's folder goes first on PYTHONPATH, where Python finds its `sitecustomize`. */
export function tracerEnvironment(
  tracerFolder: string,
  root: string,
  out: string,
  base: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const earlier = base.PYTHONPATH;
  return {
    PYTHONPATH: earlier ? `${tracerFolder}${path.delimiter}${earlier}` : tracerFolder,
    QT_TRACE_FILE: out,
    QT_TRACE_ROOT: root,
    QT_TRACE_RUN: randomUUID().replaceAll("-", "").slice(0, 12),
  };
}

/** The file a program name stands for, looked up the way a shell would: as given when it is a
 * path, else in each folder of PATH (with Windows' executable extensions). Undefined when there
 * is no such program, which is worth knowing before a terminal is opened for it. */
export function findProgram(
  program: string,
  env: Readonly<Record<string, string | undefined>>,
  exists: (file: string) => boolean,
  platform: string = process.platform,
): string | undefined {
  const windows = platform === "win32";
  const endings =
    windows && !path.extname(program)
      ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
      : [""];
  const named = (file: string) => endings.map((ending) => file + ending).find(exists);
  if (program.includes("/") || (windows && program.includes("\\"))) return named(program);
  const folders = (env.PATH ?? env.Path ?? "").split(windows ? ";" : ":").filter(Boolean);
  for (const folder of folders) {
    const file = named(path.join(folder, program));
    if (file) return file;
  }
  return undefined;
}

/** Whether two paths name the same file. Windows does not tell `C:\a.py` from `c:\A.PY`. */
export function sameFile(a: string, b: string, platform: string = process.platform): boolean {
  const [left, right] = [path.resolve(a), path.resolve(b)];
  return platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

/** Whether `file` is inside `folder` (or is the folder itself). */
export function isUnder(file: string, folder: string, platform: string = process.platform): boolean {
  const relative = path.relative(path.resolve(folder), path.resolve(file));
  const outside = relative.startsWith("..") || path.isAbsolute(relative);
  return !outside || sameFile(file, folder, platform);
}
