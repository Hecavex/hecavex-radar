import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { DocumentationPage } from "./DocumentationPage";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing documentation application root.");
const language = root.dataset.pageLanguage === "lt" ? "lt" : "en";

hydrateRoot(
  root,
  <StrictMode>
    <DocumentationPage language={language} />
  </StrictMode>,
);
delete root.dataset.pageLanguage;
root.dataset.hydrated = "true";
