/* global URL, document, getComputedStyle, process, setTimeout */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { gzipSync } from "node:zlib";

import axe from "axe-core";
import { JSDOM } from "jsdom";
import { chromium } from "playwright-core";
import { preview } from "vite";

const root = resolve(import.meta.dirname, "..");
const output = join(root, "dist");
const publicOrigin = "https://radar.hecavex.com";
const widths = [320, 360, 390, 768, 1024, 1280, 1440];
const pages = [
  { path: "/", marker: "Sampled discovery, not continuous monitoring" },
  { path: "/history/", marker: "Candidate history" },
  { path: "/methodology/", marker: "How a signal reaches Radar" },
  { path: "/docs/", marker: "HECAVEX Radar technical reference" },
];
const portfolioNavigation = ["Research", "Radar", "APT Notes", "Labs", "Data"];
const productNavigation = ["Overview", "History", "Methodology", "Docs"];
const mobileNavigation = [...productNavigation, "Source", ...portfolioNavigation];
const publicArtifactRawBytes = 512 * 1024;
const performanceBudgets = {
  htmlGzip: 512 * 1024,
  javascriptFileGzip: 225 * 1024,
  stylesheetFileGzip: 48 * 1024,
  scriptAndStyleGzip: 320 * 1024,
  publicDataFileGzip: 1024 * 1024,
  totalOutputBytes: 8 * 1024 * 1024,
};
const fontFiles = [
  "inter/inter-latin-400-normal.woff2",
  "inter/inter-latin-ext-400-normal.woff2",
  "inter/inter-latin-400-italic.woff2",
  "inter/inter-latin-ext-400-italic.woff2",
  "inter/inter-latin-500-normal.woff2",
  "inter/inter-latin-ext-500-normal.woff2",
  "inter/inter-latin-600-normal.woff2",
  "inter/inter-latin-ext-600-normal.woff2",
  "inter/inter-latin-700-normal.woff2",
  "inter/inter-latin-ext-700-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-400-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-ext-400-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-500-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-ext-500-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-600-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-ext-600-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-700-normal.woff2",
  "ibm-plex-mono/ibm-plex-mono-latin-ext-700-normal.woff2",
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function verifyDeploymentTopology() {
  const deploy = readFileSync(join(root, ".github", "workflows", "deploy-pages.yml"), "utf8");
  const ci = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");
  const collector = readFileSync(join(root, ".github", "workflows", "collect-certstream.yml"), "utf8");
  const hunter = readFileSync(join(root, ".github", "workflows", "hunt-urlscan.yml"), "utf8");
  const sync = readFileSync(join(root, ".github", "workflows", "sync-radar.yml"), "utf8");
  const historyPublisher = readFileSync(join(root, "hecavex_radar", "history.py"), "utf8");
  const snapshotPublisher = readFileSync(join(root, "hecavex_radar", "sync.py"), "utf8");
  const viteConfig = readFileSync(join(root, "vite.config.ts"), "utf8");

  assert(/workflows:\s*\["CI"\]/u.test(deploy), "Pages deployment must be gated only by the CI workflow.");
  assert(!deploy.includes("Sync radar snapshot"), "Pages deployment still listens directly to snapshot sync.");
  assert(!/^\s{2}workflow_dispatch:/mu.test(deploy), "Pages deployment must not bypass CI through manual dispatch.");
  assert(!/^\s{2}actions:\s*write\s*$/mu.test(collector), "CertStream collector retains unnecessary actions:write access.");
  assert(!collector.includes("gh workflow run deploy-pages.yml"), "CertStream collector still dispatches a duplicate Pages deployment.");
  const hunterGitAdds = hunter.match(/^\s+git add -- .*$/gmu) ?? [];
  assert(
    hunterGitAdds.length === 1 && hunterGitAdds[0].trim() === "git add -- data/urlscan",
    "URLScan hunter stages files outside its archive boundary.",
  );
  assert(ci.includes('- "data/urlscan/**"'), "Archive-only URLScan commits still trigger redundant CI and Pages runs.");
  assert(
    sync.includes("git add -- public/data/radar.json public/data/history.json data/history"),
    "Snapshot synchronization does not commit history and the live snapshot atomically.",
  );
  for (const setting of [
    "RADAR_HISTORY_DETAIL_DAYS",
    "RADAR_HISTORY_SUMMARY_DAYS",
    "RADAR_HISTORY_MAX_SIGNALS",
  ]) {
    assert(sync.includes(`vars.${setting}`), `Snapshot synchronization ignores repository variable ${setting}.`);
  }
  assert(
    snapshotPublisher.includes("MAXIMUM_SNAPSHOT_BYTES = 512 * 1024") &&
      historyPublisher.includes("MAXIMUM_PUBLIC_BYTES = 512 * 1024"),
    "Python public-artifact caps no longer match the deployment budget proof.",
  );
  assert(!viteConfig.includes("Date.now()"), "Vite prerendering still uses a nondeterministic wall-clock timestamp.");
}

function inputPins(path) {
  return readFileSync(path, "utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => /^[a-z0-9][a-z0-9._-]*==[^\s]+$/iu.test(line));
}

function verifyLock(path, expectedPins) {
  const lock = readFileSync(path, "utf8");
  assert(lock.includes("CPython 3.12 on GitHub Actions Linux x86_64"), `${relative(root, path)} has no target provenance.`);
  assert(!/^--(?:extra-)?index-url\b/mu.test(lock), `${relative(root, path)} must not embed a package index.`);
  for (const pin of expectedPins) {
    assert(lock.includes(`${pin} \\\n`), `${relative(root, path)} does not contain ${pin}.`);
  }

  const requirementStarts = [...lock.matchAll(/^([a-z0-9][a-z0-9._-]*==[^\s]+) \\\n((?:\s+--hash=sha256:[a-f0-9]{64}(?: \\)?\r?\n)+)/gimu)];
  const declared = [...lock.matchAll(/^[a-z0-9][a-z0-9._-]*==[^\s]+/gimu)];
  assert(requirementStarts.length === declared.length, `${relative(root, path)} contains a requirement without SHA-256 hashes.`);
  assert(declared.length >= expectedPins.length, `${relative(root, path)} is missing resolved transitive dependencies.`);
}

function verifyPythonAutomationLocks() {
  const requirements = join(root, "requirements");
  const runtimeLock = "requirements/automation-runtime-py312.lock";
  const ciLock = "requirements/automation-ci-py312.lock";
  const runtimePins = inputPins(join(requirements, "automation-runtime.in"));
  const ciPins = [...runtimePins, ...inputPins(join(requirements, "automation-ci.in"))];
  const project = readFileSync(join(root, "pyproject.toml"), "utf8");
  const projectPins = [...project.matchAll(/"([a-z0-9][a-z0-9._-]*==[^"\s]+)"/giu)].map((match) => match[1]);
  assert(
    new Set(projectPins).size === new Set(ciPins).size && projectPins.every((pin) => ciPins.includes(pin)),
    "Python automation inputs have drifted from the exact dependencies declared in pyproject.toml.",
  );
  verifyLock(join(root, runtimeLock), runtimePins);
  verifyLock(join(root, ciLock), ciPins);

  const workflowLocks = new Map([
    ["ci.yml", ciLock],
    ["collect-certstream.yml", runtimeLock],
    ["hunt-urlscan.yml", runtimeLock],
    ["sync-radar.yml", runtimeLock],
  ]);
  for (const [name, lock] of workflowLocks) {
    const workflow = readFileSync(join(root, ".github", "workflows", name), "utf8");
    assert(workflow.includes('python-version: "3.12"'), `${name} must run the Python 3.12 lock target.`);
    assert(workflow.includes(`--require-hashes -r ${lock}`), `${name} does not install its reviewed hash lock.`);
    assert(workflow.includes("--no-deps --no-build-isolation"), `${name} can still resolve dependencies outside its lock.`);
    assert(workflow.split(lock).length >= 3, `${name} does not include its lock in both installation and the pip cache key.`);
  }
}

function walk(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function outputPath(pathname) {
  const decoded = decodeURIComponent(pathname);
  if (decoded.endsWith("/")) return join(output, decoded.slice(1), "index.html");
  return join(output, decoded.slice(1));
}

function routeForFile(path) {
  const normalized = relative(output, path).split(sep).join("/");
  if (normalized === "index.html") return "/";
  return `/${normalized.replace(/index\.html$/, "")}`;
}

function parseFile(path) {
  return new JSDOM(readFileSync(path, "utf8"), { url: new URL(routeForFile(path), publicOrigin) }).window.document;
}

function verifyBuiltHtml() {
  const htmlFiles = walk(output).filter((path) => path.endsWith(".html"));
  assert(htmlFiles.length === pages.length, `Expected ${pages.length} HTML entries, found ${htmlFiles.length}.`);

  for (const path of htmlFiles) {
    const document = parseFile(path);
    const route = routeForFile(path);
    const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
    assert(new Set(ids).size === ids.length, `${route} contains duplicate IDs.`);
    assert(document.documentElement.lang === "en", `${route} is missing lang=en.`);
    assert(document.querySelectorAll("main").length === 1, `${route} must contain exactly one main element.`);
    assert(document.querySelectorAll("h1").length === 1, `${route} must contain exactly one h1.`);
    assert(document.querySelector('.skip-link[href="#main-content"]'), `${route} has no usable skip link.`);
    assert(document.querySelector('header.site-header[data-portfolio-shell="v1"]'), `${route} has no shared portfolio shell marker.`);
    assert(document.querySelector('.brand[href="https://hecavex.com/en/"]'), `${route} does not link the HECAVEX brand to Research.`);
    assert(document.querySelector('.product-identity[href="/"]'), `${route} does not link the Radar identity to its overview.`);
    assert(document.querySelectorAll(".portfolio-navigation a").length === 5, `${route} does not expose five portfolio links.`);
    assert(document.querySelectorAll(".product-navigation a").length === 4, `${route} does not expose four Radar links.`);
    assert(document.querySelector(".header-utility .source-link"), `${route} has no fixed Source utility.`);
    const portfolioLabels = [...document.querySelectorAll(".portfolio-navigation a")].map((anchor) => anchor.textContent?.trim());
    const productLabels = [...document.querySelectorAll(".product-navigation a")].map((anchor) => anchor.textContent?.trim());
    assert(JSON.stringify(portfolioLabels) === JSON.stringify(portfolioNavigation), `${route} changes the portfolio navigation order.`);
    assert(JSON.stringify(productLabels) === JSON.stringify(productNavigation), `${route} changes the Radar navigation order.`);
    const expectedLocalPage = new Map([
      ["/", "Overview"],
      ["/history/", "History"],
      ["/methodology/", "Methodology"],
      ["/docs/", "Docs"],
    ]).get(route);
    assert(
      document.querySelector('.portfolio-navigation a[aria-current="page"]')?.textContent?.trim() === "Radar",
      `${route} does not identify Radar as the active portfolio product.`,
    );
    assert(
      document.querySelector('.product-navigation a[aria-current="page"]')?.textContent?.trim() === expectedLocalPage,
      `${route} does not identify ${expectedLocalPage} as the active Radar page.`,
    );
    assert(document.querySelector('meta[name="description"]')?.content, `${route} has no description.`);
    assert(document.querySelector('link[rel="canonical"]')?.href, `${route} has no canonical URL.`);
    assert(document.querySelector('meta[property="og:image"]')?.content, `${route} has no Open Graph image.`);
    assert(document.querySelector('meta[name="twitter:card"]')?.content, `${route} has no Twitter card.`);
    const jsonLd = document.querySelector('script[type="application/ld+json"]')?.textContent;
    assert(jsonLd, `${route} has no JSON-LD.`);
    JSON.parse(jsonLd);

    const root = document.getElementById("root");
    assert(root, `${route} has no application root.`);
    const bootstrap = root.getAttribute("data-radar-bootstrap");
    const historyBootstrap = root.getAttribute("data-history-bootstrap");
    if (route === "/") {
      assert(bootstrap, `${route} has no embedded hydration snapshot.`);
      assert(!/[<>&"]/u.test(bootstrap), `${route} hydration snapshot is not safely attribute-encoded.`);
      const payload = JSON.parse(decodeURIComponent(bootstrap));
      assert(payload?.snapshot?.dataset === "live", `${route} hydration snapshot is not the live public dataset.`);
      assert(Number.isInteger(payload?.renderedAt), `${route} hydration snapshot has no stable render timestamp.`);
      assert(!historyBootstrap, `${route} embeds history data in the live dashboard.`);
    } else if (route === "/history/") {
      assert(historyBootstrap, `${route} has no embedded history artifact.`);
      assert(!/[<>&"]/u.test(historyBootstrap), `${route} history artifact is not safely attribute-encoded.`);
      const payload = JSON.parse(decodeURIComponent(historyBootstrap));
      assert(payload?.history?.dataset === "history", `${route} does not embed the public history dataset.`);
      assert(Number.isInteger(payload?.renderedAt), `${route} history artifact has no stable render timestamp.`);
      assert(!bootstrap, `${route} embeds the live dashboard snapshot.`);
    } else {
      assert(!bootstrap, `${route} embeds dashboard data outside the dashboard.`);
      assert(!historyBootstrap, `${route} embeds history data outside the history page.`);
    }

    for (const image of document.querySelectorAll("img")) {
      assert(image.hasAttribute("alt"), `${route} contains an image without an alt attribute.`);
    }

    for (const anchor of document.querySelectorAll("a[href]")) {
      const label = (anchor.textContent ?? "").trim() || anchor.getAttribute("aria-label");
      assert(label, `${route} contains an unlabelled link: ${anchor.outerHTML}`);
      const url = new URL(anchor.getAttribute("href"), document.baseURI);
      if (url.origin !== publicOrigin) continue;
      const target = outputPath(url.pathname);
      assert(existsSync(target), `${route} links to missing local target ${url.pathname}.`);
      if (url.hash && target.endsWith(".html")) {
        const targetDocument = parseFile(target);
        const fragment = decodeURIComponent(url.hash.slice(1));
        assert(targetDocument.getElementById(fragment), `${route} links to missing fragment ${url.pathname}${url.hash}.`);
      }
    }

    for (const element of document.querySelectorAll('script[src], link[rel="stylesheet"][href], img[src]')) {
      const raw = element.getAttribute("src") ?? element.getAttribute("href");
      const url = new URL(raw, document.baseURI);
      if (url.origin === publicOrigin) {
        assert(existsSync(outputPath(url.pathname)), `${route} references missing asset ${url.pathname}.`);
      }
    }
  }

  for (const page of pages) {
    const html = readFileSync(outputPath(page.path), "utf8");
    assert(html.includes(page.marker), `${page.path} is missing its meaningful prerendered content.`);
    assert(!html.includes("Enable JavaScript"), `${page.path} still uses an enable-JavaScript placeholder.`);
  }

  for (const fontFile of fontFiles) {
    const path = join(output, "fonts", fontFile);
    assert(existsSync(path), `Production output is missing self-hosted font ${fontFile}.`);
    assert(statSync(path).size > 5_000, `Self-hosted font ${fontFile} is unexpectedly small.`);
  }
  const css = walk(output)
    .filter((path) => path.endsWith(".css"))
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  assert(css.includes("IBM Plex Mono") && css.includes("inter-latin-ext-400-normal.woff2"), "Built CSS does not advertise the Cold Signal fonts.");
  assert(!/fonts\.(googleapis|gstatic)\.com/u.test(css), "Built CSS must not depend on remote font services.");
  assert(
    !/#(?:080c11|0d131a|17212d|24303d|344455|6db18a|dda94f)|rgb\((?:8 12 17|13 19 26|23 33 45|36 48 61|52 68 85|109 177 138|221 169 79)/iu.test(css),
    "Built CSS still contains a retired pre-Cold-Signal palette value.",
  );
}

function verifyIdentityArtwork() {
  for (const path of [join(root, "public", "hecavex-mark.svg"), join(output, "hecavex-mark.svg")]) {
    const mark = readFileSync(path, "utf8").toLowerCase();
    assert(mark.includes("#44c7dc"), `${relative(root, path)} is missing shared cyan #44c7dc.`);
    assert(mark.includes("#f2f8fb"), `${relative(root, path)} is missing shared white #f2f8fb.`);
    assert(!mark.includes("#ff6b6b"), `${relative(root, path)} still contains retired danger red #ff6b6b.`);
  }
}

function verifyPerformanceBudgets() {
  const files = walk(output);
  const totalBytes = files.reduce((total, path) => total + statSync(path).size, 0);
  assert(
    totalBytes <= performanceBudgets.totalOutputBytes,
    `Built output is ${totalBytes} bytes; budget is ${performanceBudgets.totalOutputBytes}.`,
  );

  const compressed = (path) => gzipSync(readFileSync(path), { level: 9 }).byteLength;
  const compressedSizes = (paths) => paths.map((path) => ({ path: relative(output, path), size: compressed(path) }));
  const largest = (entries) => entries.reduce((maximum, entry) => (entry.size > maximum.size ? entry : maximum));
  const htmlSizes = compressedSizes(files.filter((candidate) => candidate.endsWith(".html")));
  for (const { path, size } of htmlSizes) {
    assert(size <= performanceBudgets.htmlGzip, `${path} is ${size} gzip bytes; HTML budget is ${performanceBudgets.htmlGzip}.`);
  }
  const scripts = files.filter((candidate) => candidate.endsWith(".js"));
  const styles = files.filter((candidate) => candidate.endsWith(".css"));
  const scriptSizes = compressedSizes(scripts);
  const styleSizes = compressedSizes(styles);
  for (const { path, size } of scriptSizes) {
    assert(size <= performanceBudgets.javascriptFileGzip, `${path} is ${size} gzip bytes; JavaScript file budget is ${performanceBudgets.javascriptFileGzip}.`);
  }
  for (const { path, size } of styleSizes) {
    assert(size <= performanceBudgets.stylesheetFileGzip, `${path} is ${size} gzip bytes; stylesheet budget is ${performanceBudgets.stylesheetFileGzip}.`);
  }
  const executableBytes = [...scriptSizes, ...styleSizes].reduce((total, entry) => total + entry.size, 0);
  assert(
    executableBytes <= performanceBudgets.scriptAndStyleGzip,
    `Scripts and styles total ${executableBytes} gzip bytes; budget is ${performanceBudgets.scriptAndStyleGzip}.`,
  );
  const dataSizes = compressedSizes(
    ["radar.json", "history.json", "collection-health.json"].map((name) => join(output, "data", name)),
  );
  for (const { path, size } of dataSizes) {
    const name = path.replace(/^data\//u, "");
    assert(size <= performanceBudgets.publicDataFileGzip, `data/${name} is ${size} gzip bytes; data budget is ${performanceBudgets.publicDataFileGzip}.`);
  }
  const replaceable = new Set([
    join(output, "data", "radar.json"),
    join(output, "data", "history.json"),
    join(output, "index.html"),
    join(output, "history", "index.html"),
  ]);
  const fixedBytes = files
    .filter((path) => !replaceable.has(path))
    .reduce((total, path) => total + statSync(path).size, 0);
  const currentHydrationHtmlBytes =
    statSync(join(output, "index.html")).size + statSync(join(output, "history", "index.html")).size;
  const worstCaseOutputBytes =
    fixedBytes +
    2 * publicArtifactRawBytes +
    currentHydrationHtmlBytes +
    2 * (3 * publicArtifactRawBytes + 1024);
  assert(
    worstCaseOutputBytes <= performanceBudgets.totalOutputBytes,
    `Maximum accepted public artifacts could produce ${worstCaseOutputBytes} output bytes; total budget is ${performanceBudgets.totalOutputBytes}.`,
  );
  return {
    totalBytes,
    html: largest(htmlSizes),
    javascript: largest(scriptSizes),
    stylesheet: largest(styleSizes),
    executableBytes,
    publicData: largest(dataSizes),
    worstCaseOutputBytes,
  };
}

async function focusWithTab(page, locator, limit = 12) {
  for (let attempt = 0; attempt < limit; attempt += 1) {
    if (await locator.evaluate((element) => document.activeElement === element)) return true;
    await page.keyboard.press("Tab");
  }
  return locator.evaluate((element) => document.activeElement === element);
}

async function verifyMobileKeyboardNavigation(page, entry, width) {
  const summary = page.locator(".mobile-navigation summary");
  assert(await focusWithTab(page, summary), `${entry.path} mobile menu cannot be reached with Tab at ${width}px.`);
  const summaryFocus = await summary.evaluate((element) => {
    const style = getComputedStyle(element);
    return { outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
  });
  assert(
    summaryFocus.outlineStyle !== "none" && parseFloat(summaryFocus.outlineWidth) >= 2,
    `${entry.path} mobile menu has no visible keyboard focus at ${width}px.`,
  );

  await page.keyboard.press("Enter");
  assert(await page.locator(".mobile-navigation").evaluate((element) => element.hasAttribute("open")), `${entry.path} mobile menu does not open with Enter at ${width}px.`);

  for (const label of mobileNavigation) {
    await page.keyboard.press("Tab");
    const active = await page.evaluate(() => ({
      label: document.activeElement?.textContent?.replace(/\s+/gu, " ").trim(),
      outlineStyle: document.activeElement ? getComputedStyle(document.activeElement).outlineStyle : "none",
      outlineWidth: document.activeElement ? getComputedStyle(document.activeElement).outlineWidth : "0",
    }));
    assert(active.label === label, `${entry.path} keyboard navigation expected ${label}, reached ${active.label ?? "nothing"} at ${width}px.`);
    assert(
      active.outlineStyle !== "none" && parseFloat(active.outlineWidth) >= 2,
      `${entry.path} ${label} link has no visible keyboard focus at ${width}px.`,
    );
  }

  await summary.focus();
  await page.keyboard.press("Space");
  assert(!(await page.locator(".mobile-navigation").evaluate((element) => element.hasAttribute("open"))), `${entry.path} mobile menu does not close with Space at ${width}px.`);
}

async function verifyAccessibility(browser, origin, width) {
  const context = await browser.newContext({ viewport: { width, height: 900 }, bypassCSP: true });
  const page = await context.newPage();
  try {
    for (const entry of pages) {
      await page.goto(`${origin}${entry.path}`, { waitUntil: "networkidle" });
      await page.addScriptTag({ content: axe.source });
      const result = await page.evaluate(async () => {
        const report = await globalThis.axe.run(document, {
          resultTypes: ["violations"],
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
        });
        return report.violations
          .filter((violation) => violation.impact === "serious" || violation.impact === "critical")
          .map((violation) => ({ id: violation.id, impact: violation.impact, targets: violation.nodes.map((node) => node.target) }));
      });
      assert(result.length === 0, `${entry.path} has serious accessibility violations at ${width}px: ${JSON.stringify(result)}`);
    }
  } finally {
    await context.close();
  }
}

function chromeExecutable() {
  const candidates = [
    process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(Boolean);
  return candidates.find((path) => existsSync(path));
}

async function verifyInBrowser() {
  const executablePath = chromeExecutable();
  assert(executablePath, "Chrome or Chromium is required for responsive and accessibility verification.");

  const server = await preview({
    root,
    configFile: false,
    preview: { host: "127.0.0.1", port: 0, strictPort: false },
  });
  const address = server.httpServer.address();
  assert(address && typeof address !== "string", "Vite preview did not expose a TCP address.");
  const origin = `http://127.0.0.1:${address.port}`;
  const browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"] });

  try {
    for (const width of widths) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      const page = await context.newPage();
      for (const entry of pages) {
        const browserErrors = [];
        const onConsole = (message) => {
          if (message.type() === "error") browserErrors.push(`console: ${message.text()}`);
        };
        const onPageError = (error) => browserErrors.push(`page: ${error.message}`);
        page.on("console", onConsole);
        page.on("pageerror", onPageError);
        await page.goto(`${origin}${entry.path}`, { waitUntil: "networkidle" });
        assert(await page.locator("#root").getAttribute("data-hydrated") === "true", `${entry.path} did not hydrate under its production CSP at ${width}px.`);
        const layout = await page.evaluate(() => {
          const heading = document.querySelector("main h1")?.getBoundingClientRect();
          const headingStyle = document.querySelector("main h1") ? getComputedStyle(document.querySelector("main h1")) : null;
          const networkBar = document.querySelector(".network-bar")?.getBoundingClientRect();
          const productBar = document.querySelector(".product-bar")?.getBoundingClientRect();
          const hero = document.querySelector(".hero")?.getBoundingClientRect();
          const metricGrid = document.querySelector(".metric-grid")?.getBoundingClientRect();
          const contentToc = document.querySelector(".methodology-toc, .docs-toc");
          const contentTocStyle = contentToc ? getComputedStyle(contentToc) : null;
          const methodologyFieldList = document.querySelector(".methodology-field-list");
          const methodologyFields = methodologyFieldList ? [...methodologyFieldList.children] : [];
          const methodologyFieldListRect = methodologyFieldList?.getBoundingClientRect();
          const finalMethodologyFieldRect = methodologyFields.at(-1)?.getBoundingClientRect();
          return {
            clientWidth: document.documentElement.clientWidth,
            documentWidth: document.documentElement.scrollWidth,
            bodyWidth: document.body.scrollWidth,
            headingHeight: heading?.height ?? 0,
            headingRight: heading?.right ?? 0,
            headingFontSize: headingStyle ? parseFloat(headingStyle.fontSize) : 0,
            networkHeight: networkBar?.height ?? 0,
            productHeight: productBar?.height ?? 0,
            heroHeight: hero?.height ?? 0,
            metricTop: metricGrid?.top ?? 0,
            contentTocBorderTop: contentTocStyle?.borderTop ?? "",
            contentTocBorderBottom: contentTocStyle?.borderBottom ?? "",
            methodologyFieldCount: methodologyFields.length,
            methodologyFieldListLeft: methodologyFieldListRect?.left ?? 0,
            methodologyFieldListRight: methodologyFieldListRect?.right ?? 0,
            finalMethodologyFieldLeft: finalMethodologyFieldRect?.left ?? 0,
            finalMethodologyFieldRight: finalMethodologyFieldRect?.right ?? 0,
          };
        });
        assert(
          layout.documentWidth <= layout.clientWidth + 1 && layout.bodyWidth <= layout.clientWidth + 1,
          `${entry.path} overflows horizontally at ${width}px (${layout.documentWidth}/${layout.bodyWidth} > ${layout.clientWidth}).`,
        );
        assert(layout.headingHeight > 0 && layout.headingHeight < 540, `${entry.path} has an oversized h1 at ${width}px.`);
        assert(layout.headingFontSize <= 64.1, `${entry.path} exceeds the 64px display-heading ceiling at ${width}px.`);
        assert(layout.headingRight <= layout.clientWidth + 1, `${entry.path} h1 escapes the viewport at ${width}px.`);
        assert(Math.abs(layout.networkHeight - 64) <= 1, `${entry.path} network row is ${layout.networkHeight}px at ${width}px, expected 64px.`);

        if (width > 1160) {
          assert(Math.abs(layout.productHeight - 52) <= 1, `${entry.path} product row is ${layout.productHeight}px at ${width}px, expected 52px.`);
        } else {
          assert(layout.productHeight === 0, `${entry.path} exposes the desktop product row at ${width}px.`);
        }
        if (width === 1440 && entry.path === "/") {
          assert(layout.heroHeight > 0 && layout.heroHeight <= 430, `Radar hero is ${layout.heroHeight}px at 1440x900; budget is 430px.`);
          assert(layout.metricTop > 0 && layout.metricTop < 760, `Radar summary starts below useful 1440x900 content at ${layout.metricTop}px.`);
        }
        if (entry.path === "/methodology/" || entry.path === "/docs/") {
          assert(
            layout.contentTocBorderTop === layout.contentTocBorderBottom && layout.contentTocBorderTop.startsWith("1px solid "),
            `${entry.path} content navigation dividers are not a matching 1px pair at ${width}px ` +
              `(${layout.contentTocBorderTop || "none"}/${layout.contentTocBorderBottom || "none"}).`,
          );
        }
        if (entry.path === "/methodology/") {
          assert(layout.methodologyFieldCount === 7, `Methodology field reference has ${layout.methodologyFieldCount} entries instead of 7.`);
          assert(
            Math.abs(layout.finalMethodologyFieldLeft - (layout.methodologyFieldListLeft + 1)) <= 1 &&
              Math.abs(layout.finalMethodologyFieldRight - (layout.methodologyFieldListRight - 1)) <= 1,
            `Methodology field grid exposes an empty final cell at ${width}px.`,
          );
        }

        await page.keyboard.press("Tab");
        const focus = await page.evaluate(() => {
          const active = document.activeElement;
          const rect = active?.getBoundingClientRect();
          const style = active ? getComputedStyle(active) : null;
          return {
            className: active?.className,
            top: rect?.top,
            outlineStyle: style?.outlineStyle,
            outlineWidth: style?.outlineWidth,
          };
        });
        assert(focus.className === "skip-link" && (focus.top ?? -1) >= 0, `${entry.path} skip link is not first and visible.`);
        assert(
          focus.outlineStyle !== "none" && parseFloat(focus.outlineWidth ?? "0") >= 2,
          `${entry.path} focused skip link has no visible outline.`,
        );

        if (width <= 1160) {
          const summary = page.locator(".mobile-navigation summary");
          assert(await summary.isVisible(), `${entry.path} mobile menu is not reachable at ${width}px.`);
          await verifyMobileKeyboardNavigation(page, entry, width);
          await summary.click();
          for (const label of mobileNavigation) {
            assert(
              await page.locator(".mobile-navigation-panel a", { hasText: label }).isVisible(),
              `${entry.path} mobile navigation hides ${label} at ${width}px.`,
            );
          }
          await summary.click();
        } else {
          for (const label of portfolioNavigation) {
            assert(
              await page.locator(".portfolio-navigation a", { hasText: label }).isVisible(),
              `${entry.path} desktop portfolio navigation hides ${label} at ${width}px.`,
            );
          }
          for (const label of productNavigation) {
            assert(
              await page.locator(".product-navigation a", { hasText: label }).isVisible(),
              `${entry.path} desktop product navigation hides ${label} at ${width}px.`,
            );
          }
          assert(await page.locator(".header-utility .source-link").isVisible(), `${entry.path} desktop Source utility is hidden at ${width}px.`);
        }

        assert(browserErrors.length === 0, `${entry.path} failed its CSP-enforced browser smoke test at ${width}px: ${browserErrors.join(" | ")}`);
        page.off("console", onConsole);
        page.off("pageerror", onPageError);
      }
      await context.close();
      if (width === 390 || width === 1024) await verifyAccessibility(browser, origin, width);
    }

    const delayedContext = await browser.newContext({ viewport: { width: 390, height: 900 } });
    const delayedPage = await delayedContext.newPage();
    await delayedPage.route("**/data/radar.json", async (route) => {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 750));
      await route.continue();
    });
    await delayedPage.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
    const delayedText = await delayedPage.locator("#root").innerText();
    assert(delayedText.includes("Sampled discovery, not continuous monitoring"), "Radar discards prerendered content while refreshing its snapshot.");
    assert(!delayedText.includes("Loading recent signals"), "Radar replaces prerendered content with a loading state during hydration.");
    assert(await delayedPage.locator("#root").getAttribute("data-hydrated") === "true", "Radar did not hydrate its embedded snapshot before refresh.");
    await delayedPage.waitForLoadState("networkidle");
    await delayedContext.close();

    const noScriptContext = await browser.newContext({ viewport: { width: 390, height: 900 }, javaScriptEnabled: false });
    const noScriptPage = await noScriptContext.newPage();
    for (const entry of pages) {
      await noScriptPage.goto(`${origin}${entry.path}`, { waitUntil: "load" });
      assert(await noScriptPage.locator("main#main-content").isVisible(), `${entry.path} has no visible no-JS main content.`);
      assert((await noScriptPage.locator("body").innerText()).includes(entry.marker), `${entry.path} loses core content without JavaScript.`);
      const summary = noScriptPage.locator(".mobile-navigation summary");
      await summary.click();
      assert(await noScriptPage.locator(".mobile-navigation-panel a", { hasText: "Methodology" }).isVisible(), `${entry.path} no-JS menu does not open.`);
    }
    await noScriptContext.close();
  } finally {
    await browser.close();
    await new Promise((resolveClose, rejectClose) => {
      server.httpServer.close((error) => (error ? rejectClose(error) : resolveClose()));
    });
  }
}

verifyDeploymentTopology();
verifyPythonAutomationLocks();
verifyBuiltHtml();
verifyIdentityArtwork();
const performance = verifyPerformanceBudgets();
await verifyInBrowser();
process.stdout.write(
  `Measured production sizes: ${performance.totalBytes} bytes total; ` +
    `${performance.html.path} ${performance.html.size} bytes gzip (largest HTML); ` +
    `${performance.javascript.path} ${performance.javascript.size} bytes gzip (largest JavaScript); ` +
    `${performance.stylesheet.path} ${performance.stylesheet.size} bytes gzip (largest stylesheet); ` +
    `${performance.executableBytes} bytes gzip JavaScript/CSS total; ` +
    `${performance.publicData.path} ${performance.publicData.size} bytes gzip (largest public JSON); ` +
    `${performance.worstCaseOutputBytes} bytes maximum proven output.\n`,
);
process.stdout.write(`Verified ${pages.length} hydratable static pages at ${widths.join(", ")}px with links, fragments, metadata, CSP, delayed-refresh retention, no-JS content, keyboard navigation, overflow, focus, and accessibility checks.\n`);
