import { createClient, QuantumTraceError, type Finding, type ScanResult } from "@quantumtrace/sdk";
import { algorithmLabel, DebtStrip, TIER_META, TierGlyph, usageLabel } from "@quantumtrace/ui";
import { useCallback, useEffect, useState } from "react";
import { cached, forget, remember } from "../../lib/cache";
import { badge, headline, keyExchange, sections } from "../../lib/report";
import { loadSettings, type Settings } from "../../lib/settings";
import { targetFromUrl, type Target } from "../../lib/target";
import { setToolbarBadge } from "../../lib/toolbar";

type State =
  | { status: "loading" }
  | { status: "unsupported" }
  | { status: "cleartext"; host: string }
  | { status: "probing"; host: string }
  | { status: "error"; host: string; message: string }
  | { status: "done"; host: string; result: ScanResult };

const BADGE_COLORS = { critical: "#b3123f", medium: "#9a6a12", safe: "#0f7b6c", unknown: "#6b7685" };

export function App() {
  const [state, setState] = useState<State>({ status: "loading" });
  const [settings, setSettings] = useState<Settings>();
  const [target, setTarget] = useState<Target>();
  const [tabId, setTabId] = useState<number>();

  const run = useCallback(
    async (t: Extract<Target, { kind: "probe" }>, s: Settings, tab: number | undefined, fresh = false) => {
      const label = t.port === 443 ? t.host : t.key;
      if (fresh) await forget(t.key);
      const hit = await cached(t.key);
      if (hit) return setState({ status: "done", host: label, result: hit });
      setState({ status: "probing", host: label });
      let result: ScanResult;
      try {
        const api = createClient({ baseUrl: s.apiUrl, apiKey: s.apiKey || undefined });
        result = await api.probeTls(t.host, t.port);
      } catch (err) {
        return setState({ status: "error", host: label, message: explain(err, s) });
      }
      // Only the API call can fail the check: caching and the badge are extras.
      setState({ status: "done", host: label, result });
      await remember(t.key, result).catch(() => undefined);
      if (tab !== undefined) {
        const b = badge(result);
        await setToolbarBadge(tab, b.text, BADGE_COLORS[b.tier]);
      }
    },
    [],
  );

  useEffect(() => {
    void (async () => {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      const s = await loadSettings();
      const t = targetFromUrl(tab?.url);
      setSettings(s);
      setTarget(t);
      setTabId(tab?.id);
      if (t.kind === "unsupported") setState({ status: "unsupported" });
      else if (t.kind === "cleartext") setState({ status: "cleartext", host: t.host });
      else await run(t, s, tab?.id);
    })();
  }, [run]);

  const retry =
    settings && target?.kind === "probe" ? () => void run(target, settings, tabId, true) : undefined;

  return (
    <main className="popup">
      <header className="masthead">
        <span className="wordmark">QuantumTrace</span>
        <button type="button" className="link" onClick={() => void browser.runtime.openOptionsPage()}>
          Settings
        </button>
      </header>
      <Body state={state} settings={settings} onRetry={retry} />
    </main>
  );
}

function Body({
  state,
  settings,
  onRetry,
}: {
  state: State;
  settings: Settings | undefined;
  onRetry: (() => void) | undefined;
}) {
  switch (state.status) {
    case "loading":
      return null;
    case "unsupported":
      return (
        <p className="muted">
          Open a website to check it. QuantumTrace can only check pages served over HTTPS.
        </p>
      );
    case "cleartext":
      return (
        <>
          <p className="host mono">{state.host}</p>
          <p className="lede">This page isn’t served over HTTPS, so nothing encrypts it in transit.</p>
          <p className="muted">Open the HTTPS version of the site to check its cryptography.</p>
        </>
      );
    case "probing":
      return (
        <>
          <p className="host mono">{state.host}</p>
          <p className="muted" aria-live="polite">
            Handshaking with {state.host} from the QuantumTrace API…
          </p>
        </>
      );
    case "error":
      return (
        <>
          <p className="host mono">{state.host}</p>
          <p className="lede" role="alert">{state.message}</p>
          {onRetry && (
            <div className="actions">
              <button type="button" className="button" onClick={onRetry}>Try again</button>
            </div>
          )}
        </>
      );
    case "done":
      return <Report host={state.host} result={state.result} settings={settings} onRetry={onRetry} />;
  }
}

function Report({
  host,
  result,
  settings,
  onRetry,
}: {
  host: string;
  result: ScanResult;
  settings: Settings | undefined;
  onRetry: (() => void) | undefined;
}) {
  const kx = keyExchange(result);
  const [exporting, setExporting] = useState(false);

  async function exportCbom() {
    if (!settings) return;
    setExporting(true);
    try {
      const api = createClient({ baseUrl: settings.apiUrl, apiKey: settings.apiKey || undefined });
      const cbom = await api.getCbom(result.id);
      const url = URL.createObjectURL(new Blob([JSON.stringify(cbom, null, 2)], { type: "application/json" }));
      Object.assign(document.createElement("a"), { href: url, download: `${host}.cdx.json` }).click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <p className="host mono">{host}</p>
      {kx && (
        <div className="answer">
          <span className="answer-label">Post-quantum key exchange</span>
          <span className="answer-value" style={{ color: TIER_META[kx.classification.tier].color }}>
            <TierGlyph tier={kx.classification.tier} size={11} />
            {kx.classification.tier === "safe" ? "Yes" : "No"}
            <span className={kx.asset.variant ? "answer-detail mono" : "answer-detail"}>
              {algorithmLabel(kx)}
            </span>
          </span>
        </div>
      )}
      <p className="lede">{headline(result, host)}</p>
      <DebtStrip findings={result.findings} height={28} />

      {sections(result).map((s) => (
        <section key={s.id} className="section" aria-labelledby={`h-${s.id}`}>
          <h2 id={`h-${s.id}`}>{s.title}</h2>
          <p className="hint">{s.hint}</p>
          <ul className="rows">
            {s.findings.map((f) => (
              <Row key={f.id} finding={f} />
            ))}
          </ul>
        </section>
      ))}

      {result.limitations.length > 0 && (
        <details className="limits">
          <summary>What this check can’t see</summary>
          <ul>
            {result.limitations.map((n) => (
              <li key={n.message}>{n.message}</li>
            ))}
          </ul>
        </details>
      )}

      <div className="actions">
        {settings && (
          <a className="button primary" href={`${settings.webUrl.replace(/\/$/, "")}/scans/${result.id}`} target="_blank" rel="noreferrer">
            Open full report
          </a>
        )}
        <button type="button" className="button" onClick={() => void exportCbom()} disabled={exporting}>
          {exporting ? "Exporting…" : "Export CBOM"}
        </button>
        {onRetry && (
          <button type="button" className="link" onClick={onRetry}>Check again</button>
        )}
      </div>
    </>
  );
}

function Row({ finding: f }: { finding: Finding }) {
  const meta = TIER_META[f.classification.tier];
  const replacement = f.classification.tier !== "safe" ? f.classification.replacement : null;
  return (
    <li className="row">
      <span className="glyph" title={`${meta.label}: ${meta.threat}`}>
        <TierGlyph tier={f.classification.tier} />
      </span>
      <span className="row-main">
        <span className="row-title">
          {/* monospace only for real identifiers (x25519, AES-128-GCM), not rule names */}
          <span className={f.asset.variant ? "mono" : undefined}>{algorithmLabel(f)}</span>
          <span className="muted"> · {usageLabel(f.asset.usage)}</span>
        </span>
        {replacement && <span className="row-hint">Next step: {replacement}</span>}
      </span>
      <span className="row-tier" style={{ color: meta.color }}>{meta.label}</span>
    </li>
  );
}

function explain(err: unknown, s: Settings): string {
  if (err instanceof QuantumTraceError) {
    if (err.status === 401) return "The API needs a key. Add it in Settings.";
    if (err.status === 404)
      return `The API at ${s.apiUrl} has no TLS probe, so it's an older version. Restart it from the current code, or change its address in Settings.`;
    if (typeof err.detail === "string") return err.detail;
    return `The API answered with an error (${err.status}). Try again in a moment.`;
  }
  return `Couldn’t reach the QuantumTrace API at ${s.apiUrl}. Start it with \`make dev\`, or change its address in Settings.`;
}
