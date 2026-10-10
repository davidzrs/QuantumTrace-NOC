// Builds the browser extension zips and the VS Code extension package into public/extension/ so
// the web app can offer them for download. The browser extension defaults to the same API as
// this web app, and to this web app for full reports, so it works straight after "Load
// unpacked". The VS Code extension offers that same API on machines with no local scanner.
import { execSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(dirname(fileURLToPath(import.meta.url)));
const extension = join(web, "..", "..", "..", "extensions", "browser");
const vscode = join(web, "..", "..", "..", "extensions", "vscode");
const outDir = join(web, "public", "extension");

// Vite reads .env files only after this script runs, so only real environment variables count.
const env = { ...process.env };
if (process.env.VITE_API_URL) env.WXT_API_URL = process.env.VITE_API_URL;
const webUrl =
  process.env.VITE_WEB_URL ??
  (process.env.VERCEL_PROJECT_PRODUCTION_URL && `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`);
if (webUrl) env.WXT_WEB_URL = webUrl;

for (const browser of ["chrome", "firefox"]) {
  // through the shell: on Windows pnpm is pnpm.cmd, which cannot be spawned directly
  execSync(`pnpm exec wxt zip -b ${browser}`, { cwd: extension, env, stdio: "inherit" });
}

mkdirSync(outDir, { recursive: true });
const zips = readdirSync(join(extension, ".output"));
for (const browser of ["chrome", "firefox"]) {
  const zip = zips.find((f) => f.endsWith(`-${browser}.zip`));
  if (!zip) throw new Error(`wxt zip produced no ${browser} zip in ${extension}/.output`);
  copyFileSync(join(extension, ".output", zip), join(outDir, `quantumtrace-${browser}.zip`));
}

const vsix = join(outDir, "quantumtrace-vscode.vsix");
const vscodeEnv = { ...env, QT_API_URL: process.env.VITE_API_URL ?? "" };
execSync("pnpm run build", { cwd: vscode, env: vscodeEnv, stdio: "inherit" });
execSync(`pnpm exec vsce package --no-dependencies --skip-license --out "${vsix}"`, {
  cwd: vscode,
  env: vscodeEnv,
  stdio: "inherit",
});
console.log(`Extension downloads written to ${outDir}`);
