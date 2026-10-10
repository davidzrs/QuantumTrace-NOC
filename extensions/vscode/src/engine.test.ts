import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { apiEngine, cliEngine, EngineError } from "./engine";
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
