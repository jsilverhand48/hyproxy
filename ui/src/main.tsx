import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { installGlobalHandlers } from "./lib/logger";
import "./styles.css";

installGlobalHandlers();

const container = document.getElementById("root");
if (!container) throw new Error("missing #root");
createRoot(container).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
