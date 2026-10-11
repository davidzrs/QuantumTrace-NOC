import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  apiEngine,
  autoEngine,
  cliEngine,
  CliNotFoundError,
  DEFAULT_API_URL,
  type Engine,
  EngineError,
  type Scan,
} from "./engine";
import { md5 } from "./fixtures";

/** Stands in for the CLI: `node -e <script>` receives the same arguments the CLI would. */
const fakeCli = (script: string) => [process.execPath, "-e", script];

let root: string;

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "qt-ext-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("DEFAULT_API_URL", () => {
  it("is empty unless the build sets it, so a plain build never offers an API by itself", () => {
    expect(DEFAULT_API_URL).toBe("");
  });
});

describe("cliEngine", () => {
  it("asks the CLI for JSON and returns its findings untouched", async () => {
    const echo =
      "console.log(JSON.stringify({findings: [], limitations: [], errors: process.argv.slice(1)}))";
    const scan = await cliEngine(fakeCli(echo)).scan([path.join(root, "a.py")], root);
    expect(scan.errors).toEqual(["scan", "--format", "json", "--", path.join(root, "a.py")]);
  });

  it("says how to fix a missing CLI", async () => {
    const scan = cliEngine(["quantumtrace-cli-that-is-not-installed"]).scan([root], root);
    await expect(scan).rejects.toThrow(EngineError);
    await expect(scan).rejects.toThrow(/not found.*quantumtrace\.cli\.command/);
  });

  it("passes on what the CLI printed when it fails", async () => {
    const scan = cliEngine(fakeCli("console.error('boom'); process.exit(2)")).scan([root], root);
    await expect(scan).rejects.toThrow(/CLI failed: boom/);
  });

  it("rejects output that is not a scan", async () => {
    const scan = cliEngine(fakeCli("console.log('hello')")).scan([root], root);
    await expect(scan).rejects.toThrow(/did not return a QuantumTrace scan/);
  });

  it("rejects an empty command", async () => {
    await expect(cliEngine([]).scan([root], root)).rejects.toThrow(/cli\.command is empty/);
  });

  describe("scanText", () => {
    // reports the file it was given: its text, its name and where it was, with one finding in it
    const reader = `
      const fs = require("node:fs"), path = require("node:path");
      const file = process.argv.at(-1);
      const place = { source_type: "code", location: file, line: 1 };
      console.log(JSON.stringify({
        findings: [{ asset: { evidence: place, more_evidence: [{ ...place, line: 3 }] } }],
        limitations: [],
        errors: [fs.readFileSync(file, "utf8"), path.basename(file), path.dirname(file)],
      }));`;

    it("scans the editor's text under the file's own name, and points the findings at the file", async () => {
      const file = path.join(root, "pkg", "keys.py");
      const scan = await cliEngine(fakeCli(reader)).scanText("import hashlib\r\nunsaved = 1\r\n", file, root);
      const [text, name, folder] = scan?.errors ?? [];
      expect(text).toBe("import hashlib\r\nunsaved = 1\r\n");
      expect(name).toBe("keys.py");
      const places = scan?.findings.flatMap(({ asset }) => [asset.evidence, ...asset.more_evidence]);
      expect(places?.map((place) => place.location)).toEqual([file, file]);
      // the copy was outside the workspace and is gone
      expect(path.resolve(folder ?? "").startsWith(path.resolve(root))).toBe(false);
      expect(existsSync(folder ?? "")).toBe(false);
    });

    it("removes the copy when the CLI fails too", async () => {
      const failing = `console.error(require("node:path").dirname(process.argv.at(-1))); process.exit(2)`;
      const error = await cliEngine(fakeCli(failing))
        .scanText("x = 1\n", path.join(root, "a.py"), root)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(EngineError);
      const folder = /CLI failed: (.*)$/.exec((error as Error).message)?.[1] ?? "";
      expect(folder).toContain("quantumtrace-");
      expect(existsSync(folder)).toBe(false);
    });
  });
});

describe("autoEngine", () => {
  const EMPTY: Scan = { findings: [], limitations: [], errors: [] };
  const viaApi: Scan = { ...EMPTY, errors: ["from the api"] };
  const missingCli = cliEngine(["quantumtrace-cli-that-is-not-installed"]);
  const workingCli = cliEngine(
    fakeCli("console.log(JSON.stringify({findings: [], limitations: [], errors: ['from the cli']}))"),
  );

  /** An API engine and an answer to the consent question, both counting how often they are used. */
  function setup(answer: boolean) {
    const calls = { api: 0, asked: 0 };
    const api: Engine = {
      scan: () => {
        calls.api += 1;
        return Promise.resolve(viaApi);
      },
      scanText: () => {
        calls.api += 1;
        return Promise.resolve(viaApi);
      },
    };
    const mayUseApi = () => {
      calls.asked += 1;
      return Promise.resolve(answer);
    };
    return { calls, api, mayUseApi };
  }

  it("uses the local CLI when it is there, without asking or uploading", async () => {
    const { calls, api, mayUseApi } = setup(true);
    const scan = await autoEngine(workingCli, api, mayUseApi).scan([root], root);
    expect(scan.errors).toEqual(["from the cli"]);
    expect(calls).toEqual({ api: 0, asked: 0 });
  });

  it("scans through the API when the CLI is missing and the user agreed", async () => {
    const { calls, api, mayUseApi } = setup(true);
    const scan = await autoEngine(missingCli, api, mayUseApi).scan([root], root);
    expect(scan).toBe(viaApi);
    expect(calls).toEqual({ api: 1, asked: 1 });
  });

  it("uploads nothing when the user said no, and says how to change that", async () => {
    const { calls, api, mayUseApi } = setup(false);
    const scan = autoEngine(missingCli, api, mayUseApi).scan([root], root);
    await expect(scan).rejects.toThrow(CliNotFoundError);
    await expect(scan).rejects.toThrow(/not found.*set quantumtrace\.backend to api/);
    expect(calls.api).toBe(0);
  });

  it("does not ask when there is no API to fall back to", async () => {
    const { calls, mayUseApi } = setup(true);
    const scan = autoEngine(missingCli, undefined, mayUseApi).scan([root], root);
    await expect(scan).rejects.toThrow(/not found.*quantumtrace\.cli\.command/);
    expect(calls.asked).toBe(0);
  });

  it("scans unsaved text with the CLI only: without it, nothing is asked or uploaded", async () => {
    const { calls, api, mayUseApi } = setup(true);
    const local = await autoEngine(workingCli, api, mayUseApi).scanText("x = 1\n", path.join(root, "a.py"), root);
    expect(local?.errors).toEqual(["from the cli"]);
    const none = await autoEngine(missingCli, api, mayUseApi).scanText("x = 1\n", path.join(root, "a.py"), root);
    expect(none).toBeUndefined();
    expect(calls).toEqual({ api: 0, asked: 0 });
  });

  it("does not fall back when the CLI is installed but fails", async () => {
    const { calls, api, mayUseApi } = setup(true);
    const broken = cliEngine(fakeCli("console.error('boom'); process.exit(2)"));
    await expect(autoEngine(broken, api, mayUseApi).scan([root], root)).rejects.toThrow(/boom/);
    expect(calls).toEqual({ api: 0, asked: 0 });
  });
});

describe("apiEngine", () => {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  beforeEach(async () => {
    await mkdir(path.join(root, "pkg"));
    await mkdir(path.join(root, "node_modules", "dep"), { recursive: true });
    await writeFile(path.join(root, "pkg", "a.py"), "import hashlib\n");
    await writeFile(path.join(root, "node_modules", "dep", "b.py"), "import hashlib\n");
    await writeFile(path.join(root, "notes.txt"), "not source\n");
  });

  it("uploads source files by relative path and maps evidence back to disk", async () => {
    const uploaded: string[] = [];
    const reported = structuredClone(md5);
    reported.asset.evidence.location = "pkg/a.py";
    const engine = apiEngine({
      baseUrl: "http://qt.test",
      apiKey: "k",
      fetch: async (_url, init) => {
        const form = init?.body as FormData;
        uploaded.push(...form.getAll("files").map((file) => (file as File).name));
        return json({ findings: [reported], limitations: [], errors: [] });
      },
    });

    const scan = await engine.scan([root], root);

    expect(uploaded).toEqual(["pkg/a.py"]);
    expect(scan.findings[0]?.asset.evidence.location).toBe(path.join(root, "pkg", "a.py"));
  });

  it("does not call the API when there is nothing to upload", async () => {
    const engine = apiEngine({
      baseUrl: "http://qt.test",
      fetch: () => Promise.reject(new Error("should not be called")),
    });
    await mkdir(path.join(root, "docs"));
    const scan = await engine.scan([path.join(root, "docs")], root);
    expect(scan.findings).toEqual([]);
  });

  it("never uploads unsaved text", async () => {
    const engine = apiEngine({
      baseUrl: "http://qt.test",
      fetch: () => Promise.reject(new Error("should not be called")),
    });
    const scan = engine.scanText("import hashlib\n", path.join(root, "pkg", "a.py"), root);
    await expect(scan).resolves.toBeUndefined();
  });

  it("points at the API key command on 401", async () => {
    const engine = apiEngine({
      baseUrl: "http://qt.test",
      fetch: async () => json({ detail: "Invalid or missing X-API-Key" }, 401),
    });
    await expect(engine.scan([root], root)).rejects.toThrow(/Set API key/);
  });

  it("names the URL when the API is unreachable", async () => {
    const engine = apiEngine({
      baseUrl: "http://qt.test",
      fetch: () => Promise.reject(new TypeError("fetch failed")),
    });
    await expect(engine.scan([root], root)).rejects.toThrow(/Can't reach.*http:\/\/qt\.test/);
  });
});
