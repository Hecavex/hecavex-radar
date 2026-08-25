import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { StaticPage } from "./StaticPages.tsx";
import { decodeStaticPageBootstrap, type StaticPageKind } from "./lib/staticPageBootstrap.ts";
import "./styles.css";
import "./components/intelligenceTools.css";

const root = document.getElementById("root");
const kind = root?.dataset.pageKind as StaticPageKind | undefined;
const language = root?.dataset.pageLanguage === "lt" ? "lt" : "en";
if (!root?.dataset.pageBootstrap || !kind) throw new Error("Missing static page bootstrap.");
hydrateRoot(root, <StrictMode><StaticPage kind={kind} data={decodeStaticPageBootstrap(root.dataset.pageBootstrap)} language={language} /></StrictMode>);
delete root.dataset.pageBootstrap;
delete root.dataset.pageLanguage;
root.dataset.hydrated = "true";
