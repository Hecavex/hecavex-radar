import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { DocumentationPage } from "./DocumentationPage";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing documentation application root.");

hydrateRoot(
  root,
  <StrictMode>
    <DocumentationPage />
  </StrictMode>,
);
root.dataset.hydrated = "true";
