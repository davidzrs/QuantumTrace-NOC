// Builds the browser extension zips into public/extension/ so the web app can offer them for
// download. The extension defaults to the same API as this web app, and to this web app for
// full reports, so it works straight after "Load unpacked".
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(dirname(fileURLToPath(import.meta.url)));
const extension = join(web, "..", "..", "..", "extensions", "browser");
const outDir = join(web, "public", "extension");

// Vite reads .env files only after this script runs, so only real environment variables count.
const env = { ...process.env };
if (process.env.VITE_API_URL) env.WXT_API_URL = process.env.VITE_API_URL;
const webUrl =
  process.env.VITE_WEB_URL ??
  (process.env.VERCEL_PROJECT_PRODUCTION_URL && `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`);
if (webUrl) env.WXT_WEB_URL = webUrl;

for (const browser of ["chrome", "firefox"]) {
  execFileSync("pnpm", ["exec", "wxt", "zip", "-b", browser], { cwd: extension, env, stdio: "inherit" });
}

mkdirSync(outDir, { recursive: true });
const zips = readdirSync(join(extension, ".output"));
for (const browser of ["chrome", "firefox"]) {
  const zip = zips.find((f) => f.endsWith(`-${browser}.zip`));
  if (!zip) throw new Error(`wxt zip produced no ${browser} zip in ${extension}/.output`);
  copyFileSync(join(extension, ".output", zip), join(outDir, `quantumtrace-${browser}.zip`));
}
console.log(`Extension zips written to ${outDir}`);
