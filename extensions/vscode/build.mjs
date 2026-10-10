// Bundles the extension into dist/extension.js. When QT_API_URL is set, that API becomes the one
// the build offers to use on a machine with no local scanner (the web app sets it for the
// package it serves for download).
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
