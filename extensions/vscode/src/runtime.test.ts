import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
  findProgram,
  isUnder,
  sameFile,
  TRACE_FILE,
  traceFile,
  tracerEnvironment,
} from "./runtime";

const root = path.resolve("repo");

describe("tracerEnvironment", () => {
  const out = traceFile(root);

  it("puts the tracer first on PYTHONPATH and says where to write and what counts as the project", () => {
    const env = tracerEnvironment("/ext/tracer/python", root, out, {});
    expect(env.PYTHONPATH).toBe("/ext/tracer/python");
    expect(env.QT_TRACE_FILE).toBe(path.join(root, ".quantumtrace", "trace.jsonl"));
    expect(env.QT_TRACE_ROOT).toBe(root);
    expect(env.QT_TRACE_RUN).toMatch(/^[0-9a-f]{12}$/);
  });

  it("keeps the PYTHONPATH the environment already had, after the tracer", () => {
    const env = tracerEnvironment("/ext/tracer/python", root, out, { PYTHONPATH: "/my/libs" });
    expect(env.PYTHONPATH).toBe(`/ext/tracer/python${path.delimiter}/my/libs`);
  });

  it("adds nothing else: the rest of the environment is the caller's", () => {
    const env = tracerEnvironment("/t", root, out, { SECRET_TOKEN: "x", PATH: "/bin" });
    expect(Object.keys(env).sort()).toEqual(["PYTHONPATH", "QT_TRACE_FILE", "QT_TRACE_ROOT", "QT_TRACE_RUN"]);
  });

  it("gives every run its own id, shared by the processes it starts", () => {
    const first = tracerEnvironment("/t", root, out, {}).QT_TRACE_RUN;
    expect(tracerEnvironment("/t", root, out, {}).QT_TRACE_RUN).not.toBe(first);
  });
});

describe("findProgram", () => {
  const files = (...known: string[]) => (file: string) => known.includes(file);

  it("finds a program in the folders of PATH, first match first", () => {
    const env = { PATH: "/usr/local/bin:/usr/bin" };
    const exists = files(path.join("/usr/bin", "python"), path.join("/usr/local/bin", "python"));
    expect(findProgram("python", env, exists, "linux")).toBe(path.join("/usr/local/bin", "python"));
    expect(findProgram("pytest", env, exists, "linux")).toBeUndefined();
  });

  it("takes a path as it is given", () => {
    expect(findProgram("/venv/bin/python", {}, files("/venv/bin/python"), "linux")).toBe("/venv/bin/python");
    expect(findProgram("./run-tests", { PATH: "/usr/bin" }, files("./run-tests"), "linux")).toBe("./run-tests");
    expect(findProgram("/venv/bin/python", { PATH: "/usr/bin" }, files(), "linux")).toBeUndefined();
  });

  it("tries Windows' executable extensions when the name has none", () => {
    const env = { Path: "C:\\Python;C:\\Tools", PATHEXT: ".EXE;.CMD" };
    const exists = files(path.join("C:\\Tools", "pytest.CMD"), "C:\\venv\\Scripts\\python.EXE");
    expect(findProgram("pytest", env, exists, "win32")).toBe(path.join("C:\\Tools", "pytest.CMD"));
    expect(findProgram("C:\\venv\\Scripts\\python", env, exists, "win32")).toBe("C:\\venv\\Scripts\\python.EXE");
    expect(findProgram("pytest.exe", env, exists, "win32")).toBeUndefined();
  });
});

describe("TRACE_FILE", () => {
  it("is where the engine looks for a trace: .quantumtrace/trace.jsonl in the project", () => {
    expect(TRACE_FILE.split(path.sep)).toEqual([".quantumtrace", "trace.jsonl"]);
  });
});

describe("sameFile", () => {
  it("ignores case and separators on Windows only", () => {
    expect(sameFile("C:\\Repo\\app\\Auth.py", "c:/repo/app/auth.py", "win32")).toBe(
      process.platform === "win32",
    );
    expect(sameFile("/repo/app/auth.py", "/repo/app/Auth.py", "linux")).toBe(false);
    expect(sameFile("/repo/app/../app/auth.py", "/repo/app/auth.py", "linux")).toBe(true);
  });
});

describe("isUnder", () => {
  it("tells a file inside a folder from one beside it", () => {
    const trace = path.join(root, ".quantumtrace", "trace.jsonl");
    expect(isUnder(trace, root)).toBe(true);
    expect(isUnder(trace, path.join(root, "app"))).toBe(false);
    expect(isUnder(trace, path.join(root, "app", "auth.py"))).toBe(false);
    expect(isUnder(path.resolve("repo-two", "x.py"), root)).toBe(false);
    expect(isUnder(root, root)).toBe(true);
  });
});
