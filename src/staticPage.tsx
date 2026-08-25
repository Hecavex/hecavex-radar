import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { StaticPage } from "./StaticPages.tsx";
import { decodeStaticPageBootstrap, type StaticPageKind } from "./lib/staticPageBootstrap.ts";
import "./styles.css";
import "./components/intelligenceTools.css";

const root = document.getElementById("root");
const kind = root?.dataset.pageKind as StaticPageKind | undefined;
if (!root?.dataset.pageBootstrap || !kind) throw new Error("Missing static page bootstrap.");
hydrateRoot(root, <StrictMode><StaticPage kind={kind} data={decodeStaticPageBootstrap(root.dataset.pageBootstrap)} /></StrictMode>);
delete root.dataset.pageBootstrap;
root.dataset.hydrated = "true";
