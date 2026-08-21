import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { DocumentationPage } from "./DocumentationPage";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <DocumentationPage />
  </StrictMode>,
);
