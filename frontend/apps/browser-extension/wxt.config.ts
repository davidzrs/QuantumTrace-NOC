import { defineConfig } from "wxt";

// One codebase for Chrome (MV3) and Firefox: `pnpm build` / `pnpm build:firefox`.
export default defineConfig({
  srcDir: ".",
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "QuantumTrace",
    description: "Check whether the site in this tab is ready for post-quantum cryptography.",
    // activeTab: read the current tab's URL only when the user opens the popup.
    permissions: ["activeTab", "storage"],
    // The local API from `make dev`. Other API addresses are requested from the settings page.
    host_permissions: ["http://localhost:8000/*", "http://127.0.0.1:8000/*"],
    optional_host_permissions: ["https://*/*", "http://*/*"],
  },
});
