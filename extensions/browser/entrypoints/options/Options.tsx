import { useEffect, useState, type FormEvent } from "react";
import { DEFAULTS, LOCAL_API, loadSettings, originPattern, saveSettings, type Settings } from "../../lib/settings";

export function Options() {
  const [settings, setSettings] = useState<Settings>(DEFAULTS);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void loadSettings().then(setSettings);
  }, []);

  const set = (key: keyof Settings) => (e: { target: { value: string } }) =>
    setSettings((s) => ({ ...s, [key]: e.target.value.trim() }));

  async function save(e: FormEvent) {
    e.preventDefault();
    let pattern: string;
    try {
      pattern = originPattern(settings.apiUrl);
      new URL(settings.webUrl);
    } catch {
      setMessage("Enter full addresses, starting with http:// or https://.");
      return;
    }
    // The popup calls the API directly, so the extension needs permission for its origin.
    const granted = await browser.permissions.request({ origins: [pattern] });
    if (!granted) {
      setMessage(`Settings not saved: the extension needs access to ${pattern} to reach the API.`);
      return;
    }
    await saveSettings(settings);
    setMessage("Saved. Open the popup again to check a site with the new API.");
  }

  return (
    <form className="options" onSubmit={(e) => void save(e)}>
      <h1>QuantumTrace settings</h1>
      <p className="muted">
        The popup asks a QuantumTrace API to handshake with the site in your tab, because browsers
        don’t show extensions the TLS details. Only the site’s host name and port are sent.
      </p>
      <div className="field">
        <label htmlFor="api">API address</label>
        <input id="api" type="url" required value={settings.apiUrl} onChange={set("apiUrl")} />
        <small>`make dev` serves it at {LOCAL_API}.</small>
      </div>
      <div className="field">
        <label htmlFor="key">API key</label>
        <input id="key" type="password" autoComplete="off" value={settings.apiKey} onChange={set("apiKey")} />
        <small>Only if the API sets QT_API_KEY. Stored on this device only.</small>
      </div>
      <div className="field">
        <label htmlFor="web">Web app address</label>
        <input id="web" type="url" required value={settings.webUrl} onChange={set("webUrl")} />
        <small>Where “Open full report” goes. It must use the same API.</small>
      </div>
      <div className="actions">
        <button type="submit" className="button primary">Save settings</button>
        <span className="muted" role="status">{message}</span>
      </div>
    </form>
  );
}
