import { defineConfig } from "wxt";

const LOCAL_API = ["http://localhost:8000/*", "http://127.0.0.1:8000/*"];
// Set when the web app bundles the extension for download (frontend/apps/web/scripts).
const apiUrl = process.env.WXT_API_URL;

// Other API addresses, requested from the settings page.
const OPTIONAL_HOSTS = ["https://*/*", "http://*/*"];

// One codebase for Chrome (MV3) and Firefox (MV2): `pnpm build` / `pnpm build:firefox`.
export default defineConfig({
  srcDir: ".",
  modules: ["@wxt-dev/module-react"],
  manifest: ({ manifestVersion }) => ({
    name: "QuantumTrace",
    description: "Check whether the site in this tab is ready for post-quantum cryptography.",
    // activeTab: read the current tab's URL only when the user opens the popup.
    permissions: ["activeTab", "storage"],
    // The local API from `make dev`, plus the API this build defaults to.
    host_permissions: apiUrl ? [...new Set([...LOCAL_API, `${new URL(apiUrl).origin}/*`])] : LOCAL_API,
    // MV2 has no optional_host_permissions (WXT drops it): origins go in optional_permissions.
    ...(manifestVersion === 2
      ? { optional_permissions: OPTIONAL_HOSTS }
      : { optional_host_permissions: OPTIONAL_HOSTS }),
  }),
});
