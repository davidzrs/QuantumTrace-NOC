// Bundles the extension into dist/extension.js. When QT_API_URL is set, that API becomes the one
// the build offers to use on a machine with no local scanner (the web app sets it for the
// package it serves for download).
import { cpSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

await build({
  entryPoints: ["src/extension.ts"],
  outfile: "dist/extension.js",
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node20",
  external: ["vscode"],
  sourcemap: true,
  logLevel: "info",
  define: { __QT_DEFAULT_API_URL__: JSON.stringify(process.env.QT_API_URL ?? "") },
});

// The Python tracer runs inside the user's own interpreter, so it ships as plain files. Its one
// source is the backend package; this copy is what the packaged extension puts on PYTHONPATH.
const tracer = fileURLToPath(new URL("../../backend/src/quantumtrace/tracers/python", import.meta.url));
rmSync("tracer", { recursive: true, force: true });
cpSync(tracer, "tracer/python", { recursive: true, filter: (file) => !file.includes("__pycache__") });
