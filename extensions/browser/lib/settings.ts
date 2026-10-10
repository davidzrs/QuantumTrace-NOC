export interface Settings {
  apiUrl: string;
  apiKey: string;
  webUrl: string;
}

// 127.0.0.1, not localhost: `make dev` binds IPv4 loopback only, and localhost may resolve to
// ::1, where something else (e.g. a Docker port mapping) can be listening.
export const LOCAL_API = "http://127.0.0.1:8000";

// The zip the web app offers for download is built with WXT_API_URL / WXT_WEB_URL pointing at
// that deployment, so it works without visiting the settings page.
export const DEFAULTS: Settings = {
  apiUrl: import.meta.env.WXT_API_URL || LOCAL_API,
  apiKey: "",
  webUrl: import.meta.env.WXT_WEB_URL || "http://localhost:5173",
};

// storage.local, not sync: the API key stays on this device.
export async function loadSettings(): Promise<Settings> {
  const stored = await browser.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...(stored as Partial<Settings>) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({ ...settings });
}

/** Host-permission pattern for an API address, e.g. https://api.example.com/* */
export function originPattern(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.hostname}/*`;
}
