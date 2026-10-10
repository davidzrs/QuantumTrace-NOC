import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/600.css";
import "@fontsource/public-sans/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@quantumtrace/ui/tokens.css";
import "../shared.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Options } from "./Options";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Options />
  </StrictMode>,
);
