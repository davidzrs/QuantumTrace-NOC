import type { ScanResult } from "@quantumtrace/sdk";
import { TierGlyph } from "@quantumtrace/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { HeroGlow, useScramble } from "../components/HeroGlow";
import { ChromeIcon, FirefoxIcon, VsCodeIcon } from "../components/BrandIcons";
import { RepoScan } from "../components/RepoScan";
import { ScanBench, type RunningScan } from "../components/ScanBench";
import { ScanTable } from "../components/ScanTable";
import { api } from "../lib/api";
import { accountState, saveScans, useAccount } from "../lib/account";
import { useDeleteScans } from "../lib/deleteScans";
import { readHistory, remember, writeHistory } from "../lib/history";
import type { Picked } from "../lib/intake";
import { pack, UploadTooLarge } from "../lib/pack";
import { TIER } from "../lib/tiers";

const MB = 1024 * 1024;
// Scans of a few files come back almost at once. Keep the progress view up long enough to read,
// then let the lanes fill before the report opens. Skipped when motion is reduced.
const MIN_SCAN_MS = 1200;
const FINISH_MS = 700;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const calm = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function Home() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [running, setRunning] = useState<RunningScan | null>(null);
  // Only this browser's scans, signed in or not. An account's scans are on the Account page.
  const signedIn = useAccount().status === "signed-in";
  const scans = useQuery({
    queryKey: ["scans", "browser"],
    queryFn: async () => {
      const ids = readHistory();
      if (!ids.length) return [];
      const found = await api.listScans(ids);
      // Forget scans the API no longer has (they expire after 30 days).
      const alive = new Set(found.map((s) => s.id));
      writeHistory(ids.filter((id) => alive.has(id)));
      return found.sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
  });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0 });

  const onScanned = (result: ScanResult) => {
    remember(result.id);
    if (accountState().status === "signed-in") {
      const { id, created_at, targets } = result;
      void saveScans([{ id, created_at, targets }]).catch(() => undefined);
    }
    queryClient.setQueryData(["scan", result.id], result);
    void queryClient.invalidateQueries({ queryKey: ["scans"] });
    void navigate(`/scans/${result.id}`);
  };
  const uploadScan = useMutation({
    mutationFn: async (items: Picked[]) => {
      // An API that reports max_unpacked_mb unpacks .gz uploads, so compress to fit more in.
      const limits = health.data;
      const ready = limits?.max_unpacked_mb ? await pack(items, limits.max_upload_mb * MB) : items;
      const started = Date.now();
      const result = await api.scanFiles(ready);
      if (!calm()) await sleep(MIN_SCAN_MS - (Date.now() - started));
      return result;
    },
    onMutate: (items) => setRunning({ started: Date.now(), items }),
    onSuccess: async (result) => {
      setRunning((r) => r && { ...r, result, finished: Date.now() });
      if (!calm()) await sleep(FINISH_MS);
      onScanned(result);
    },
    onSettled: () => setRunning(null),
  });
  const scanError = uploadScan.error;

  const deleteScans = useDeleteScans();
  const deleteAll = () => {
    const ids = scans.data?.map((s) => s.id) ?? [];
    const n = ids.length;
    const prompt =
      n === 1
        ? "Delete this scan? Its report and link stop working."
        : `Delete all ${n} scans? Their reports and links stop working.`;
    if (n && window.confirm(prompt)) deleteScans.mutate(ids);
  };

  return (
    <>
      <Hero />

      <main className="mx-auto grid max-w-[1240px] grid-cols-[minmax(0,1fr)] gap-12 px-4 pt-10 pb-16 sm:px-8 sm:pt-12">
        <ScanBench
          limitMb={health.data ? (health.data.max_unpacked_mb ?? health.data.max_upload_mb) : undefined}
          running={running}
          onScan={(items) => uploadScan.mutate(items)}
        >
          {scanError && !running && (
            <p role="alert" className="border-l-2 border-critical pl-4">
              {scanError instanceof UploadTooLarge
                ? scanError.message
                : `The scan didn’t run: ${scanError.message}. Check that the scanner is online and try again.`}
            </p>
          )}
          <RepoScan disabled={running !== null} onScanned={onScanned} />
        </ScanBench>

        {/* The two download panels share their columns, so the VS Code button centres under the
            browser pair instead of hugging the right edge. */}
        <div className="grid grid-cols-[minmax(0,1fr)] gap-x-16 gap-y-12 lg:grid-cols-[minmax(0,1fr)_auto]">
          <section aria-labelledby="extension-title" className="grid grid-cols-[minmax(0,1fr)] gap-x-16 gap-y-5 rounded-xl border border-rule bg-surface p-5 sm:px-7 sm:py-6 lg:col-span-2 lg:grid-cols-subgrid lg:items-center">
            <div className="grid gap-2">
              <h2 id="extension-title" className="font-display text-[19px] font-bold tracking-[-0.01em]">
                Check sites as you browse
              </h2>
              <p className="max-w-[68ch] text-ink-muted">
                The browser extension asks this scanner whether the site in your tab uses post-quantum
                key exchange, and what its certificate would lose to Shor’s algorithm. Unzip it, then load
                the folder from <span className="font-mono text-sm text-ink">chrome://extensions</span> with
                Developer mode on and “Load unpacked”. In Firefox, load the zip as a temporary add-on
                from <span className="font-mono text-sm text-ink">about:debugging</span>.
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <a href="/extension/quantumtrace-chrome.zip" download className="btn bg-raise">
                <ChromeIcon />
                Download for Chrome
              </a>
              <a href="/extension/quantumtrace-firefox.zip" download className="btn bg-raise">
                <FirefoxIcon />
                Download for Firefox
              </a>
            </div>
          </section>

          <section aria-labelledby="editor-title" className="grid grid-cols-[minmax(0,1fr)] gap-x-16 gap-y-5 rounded-xl border border-rule bg-surface p-5 sm:px-7 sm:py-6 lg:col-span-2 lg:grid-cols-subgrid lg:items-center">
            <div className="grid gap-2">
              <h2 id="editor-title" className="font-display text-[19px] font-bold tracking-[-0.01em]">
                Catch it as you write
              </h2>
              <p className="max-w-[68ch] text-ink-muted">
                The VS Code extension highlights the lines of Python, Java and Go that a quantum
                computer breaks or weakens, and says what to switch to. “Fix with AI” has this
                scanner’s model rewrite a flagged line in the editor, for you to review; it asks before
                sending the file. Open the Extensions view, pick
                “Install from VSIX…” in its <span className="font-mono text-sm text-ink">...</span> menu
                and choose the file. It runs the QuantumTrace CLI on your machine; without one, it asks
                before sending any file to this scanner.
              </p>
            </div>
            <div className="flex flex-wrap gap-3 lg:justify-center">
              <a href="/extension/quantumtrace-vscode.vsix" download className="btn bg-raise">
                <VsCodeIcon />
                Download for VS Code
              </a>
            </div>
          </section>
        </div>

        <section aria-labelledby="history-title" id="history" className="grid scroll-mt-16 grid-cols-[minmax(0,1fr)] gap-4">
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <h2 id="history-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
              Earlier scans
            </h2>
            <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1">
              <span className="text-sm text-ink-faint">
                {health.data?.persistent
                  ? "Kept for 30 days, listed only in this browser"
                  : "Held in memory until the API restarts"}
              </span>
              {signedIn && (
                <Link to="/account" className="link text-sm font-semibold text-ink-muted">
                  Your account’s scans
                </Link>
              )}
              {!!scans.data?.length && (
                <button
                  type="button"
                  onClick={deleteAll}
                  disabled={deleteScans.isPending}
                  className="link text-sm font-semibold text-ink-muted disabled:opacity-50"
                >
                  Delete all
                </button>
              )}
            </div>
          </div>
          {deleteScans.error && (
            <p role="alert" className="border-l-2 border-critical pl-4">
              {deleteScans.error.message}. Check that the scanner is online and try again.
            </p>
          )}
          {scans.data?.length ? (
            <ScanTable scans={scans.data} onDelete={(id) => deleteScans.mutate([id])} deleting={deleteScans.isPending} />
          ) : (
            <p className="text-ink-muted">
              {scans.isError
                ? "Scan history is unavailable while the scanner is offline."
                : "Nothing yet. Scans you run in this browser show up here, and only here."}
            </p>
          )}
        </section>
      </main>
    </>
  );
}

function Hero() {
  const [word, replay] = useScramble("break");
  return (
    <div className="relative overflow-hidden border-b border-rule bg-ground">
      <HeroGlow opacity={0.5} />
      <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-36 bg-gradient-to-b from-transparent to-ground" />
      <section className="relative mx-auto grid max-w-[1240px] items-center gap-10 px-4 pt-10 pb-10 [grid-template-columns:repeat(auto-fit,minmax(min(440px,100%),1fr))] sm:px-8 lg:pt-14 lg:pb-14">
        <div className="grid gap-5">
          <p className="text-sm text-ink-muted">Post-quantum readiness scanner for cloud, code and the wire</p>
          <h1 className="font-display text-[clamp(34px,4.4vw,58px)] leading-[1.02] font-[750] tracking-[-0.035em] text-balance">
            Find the cryptography a quantum computer will{" "}
            <span onMouseEnter={replay} className="font-mono font-medium tracking-[-0.04em] whitespace-nowrap text-critical">
              <span aria-hidden>{word}</span>
              <span className="sr-only">break</span>
            </span>
            .
          </h1>
          <p className="max-w-[58ch] text-base leading-[1.55] text-pretty text-ink-muted">
            QuantumTrace inventories every algorithm in your AWS exports, source code and packet
            captures, rates each one Critical, Medium or Safe against quantum attack, and maps it to its
            NIST replacement. Every result exports as a CycloneDX 1.6 CBOM.
          </p>
          <div>
            <a className="btn btn-primary" href="#upload">Upload files to scan</a>
          </div>
        </div>
        <WhyNow />
      </section>
    </div>
  );
}

function WhyNow() {
  return (
    <figure className="m-0 grid gap-4 rounded-xl border border-rule bg-surface px-6 pt-5 pb-5">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-3">
        <span className="font-semibold">Why now: harvest today, decrypt later</span>
        <span className="text-[13px] text-ink-faint">NIST IR 8547</span>
      </figcaption>
      <div className="relative h-[124px]" role="img" aria-label="FIPS 203, 204 and 205 published in 2024. Traffic recorded today stays readable later. RSA, ECDSA and ECDH are deprecated in 2030 and disallowed in 2035.">
        <div className="absolute inset-x-0 top-[62px] h-0.5 bg-rule-strong" />
        <div className="absolute top-[62px] right-0 left-[18%] h-0.5 bg-gradient-to-r from-critical to-critical/25" />
        <div className="absolute top-0 left-0 grid justify-items-start gap-1">
          <span className="font-display text-[22px] leading-none font-bold">2024</span>
          <span className="max-w-[12ch] text-xs leading-[1.2] text-ink-muted">FIPS 203, 204, 205 published</span>
        </div>
        <div className="absolute top-14 left-0 size-3.5 rounded-full bg-safe" />
        <div className="absolute top-[54px] left-[18%] size-[18px] rounded-full bg-ink shadow-[0_0_0_6px_rgba(232,235,239,0.12)]" />
        <div className="absolute top-[88px] left-[18%] grid -translate-x-1 gap-1">
          <span className="text-[13px] font-semibold">Today</span>
          <span className="max-w-[18ch] text-xs leading-[1.2] text-ink-muted max-sm:hidden">Traffic recorded now stays readable later</span>
        </div>
        <div className="absolute top-14 left-[62%] size-3.5 rotate-45 bg-critical" />
        <div className="absolute top-0 left-[62%] grid -translate-x-1.5 gap-1">
          <span className="font-display text-[22px] leading-none font-bold">2030</span>
          <span className="max-w-[16ch] text-xs leading-[1.2] text-ink-muted">RSA, ECDSA, ECDH deprecated</span>
        </div>
        <div className="absolute top-[54px] right-0 size-[18px] rotate-45 bg-critical" />
        <div className="absolute top-[88px] right-0 grid justify-items-end gap-1 text-right">
          <span className="font-display text-[22px] leading-none font-bold">2035</span>
          <span className="max-w-[14ch] text-xs leading-[1.2] text-ink-muted">Disallowed outright</span>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 border-t border-rule pt-4">
        {(
          [
            ["critical", "Asymmetric crypto Shor breaks: RSA, DSA, ECDSA, ECDH"],
            ["medium", "Symmetric and hashes Grover weakens: AES-128, 3DES, SHA-1"],
            ["safe", "Larger keys and post-quantum standards: AES-256, ML-KEM, ML-DSA"],
          ] as const
        ).map(([tier, text]) => (
          <div key={tier} className="grid content-start gap-1.5">
            <span className="flex items-center gap-2 font-semibold" style={{ color: TIER[tier].color }}>
              <TierGlyph tier={tier} size={10} />
              {TIER[tier].label}
            </span>
            <span className="text-[13px] leading-snug text-ink-muted">{text}</span>
          </div>
        ))}
      </div>
    </figure>
  );
}
