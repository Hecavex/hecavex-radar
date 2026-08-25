/* global URL, document, getComputedStyle, navigator, process, setTimeout, window */

import { createHash } from "node:crypto";
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
const analyticsToken = process.env.HECAVEX_ANALYTICS_TOKEN?.trim() ?? "";
const widths = [320, 360, 390, 768, 1024, 1280, 1440];
const pages = [
  { path: "/", marker: "Sampled discovery, not continuous monitoring" },
  { path: "/lt/", marker: "Atrankinis aptikimas, o ne nuolatinė stebėsena" },
  { path: "/history/", marker: "Candidate history" },
  { path: "/brands/", marker: "Reviewed Lithuanian brand registry" },
  { path: "/changes/", marker: "What changed" },
  { path: "/trends/", marker: "Discovery trends and review quality" },
  { path: "/associations/", marker: "Published associations" },
  { path: "/tools/", marker: "Check your indicators locally" },
  { path: "/dataset/", marker: "Radar dataset distributions" },
  { path: "/lt/tendencijos/", marker: "Aptikimo tendencijos ir peržiūros kokybė" },
  { path: "/lt/sasajos/", marker: "Paskelbtos sąsajos" },
  { path: "/lt/irankiai/", marker: "Patikrinkite indikatorius vietoje" },
  { path: "/lt/duomenys/", marker: "Radaro duomenų rinkiniai" },
  { path: "/methodology/", marker: "How a signal reaches Radar" },
  { path: "/docs/", marker: "HECAVEX Radar technical reference" },
  { path: "/lt/dokumentacija/", marker: "HECAVEX Radaro techninis žinynas" },
  { path: "/404.html", marker: "This route has no signal." },
];
const portfolioNavigation = ["Research", "Radar", "APT Notes", "Labs", "Data"];
const productNavigation = ["Overview", "Changes", "Brands", "Trends", "Associations", "Tools", "Methodology", "Docs"];
const lithuanianProductNavigation = ["Apžvalga", "Pokyčiai", "Prekių ženklai", "Tendencijos", "Sąsajos", "Įrankiai", "Metodologija", "Dokumentacija"];

function productNavigationForPath(path) {
  return path.startsWith("/lt/") ? lithuanianProductNavigation : productNavigation;
}

function mobileNavigationForPath(path) {
  return [
    ...productNavigationForPath(path),
    path.startsWith("/lt/") ? "English" : "Lietuviškai",
    "Source",
    ...portfolioNavigation,
  ];
}
const publicArtifactRawBytes = 512 * 1024;
const stixBundleRawBytes = 2 * 1024 * 1024;
const signalDetailFileRawBytes = 16 * 1024;
const signalDetailSetRawBytes = 3 * 1024 * 1024;
const performanceBudgets = {
  htmlGzip: 512 * 1024,
  javascriptFileGzip: 225 * 1024,
  stylesheetFileGzip: 48 * 1024,
  scriptAndStyleGzip: 320 * 1024,
  publicDataFileGzip: 1024 * 1024,
  totalOutputBytes: 16 * 1024 * 1024,
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
  const assetHunter = readFileSync(join(root, ".github", "workflows", "hunt-brand-assets.yml"), "utf8");
  const ctSearch = readFileSync(join(root, ".github", "workflows", "poll-ct-search.yml"), "utf8");
  const domainContext = readFileSync(join(root, ".github", "workflows", "enrich-domain-context.yml"), "utf8");
  const sync = readFileSync(join(root, ".github", "workflows", "sync-radar.yml"), "utf8");
  const historyPublisher = readFileSync(join(root, "hecavex_radar", "history.py"), "utf8");
  const snapshotPublisher = readFileSync(join(root, "hecavex_radar", "sync.py"), "utf8");
  const stixPublisher = readFileSync(join(root, "hecavex_radar", "stix.py"), "utf8");
  const viteConfig = readFileSync(join(root, "vite.config.ts"), "utf8");

  assert(
    /workflows:\s*\["CI",\s*"Sync radar snapshot",\s*"Collect CertStream candidates"\]/u.test(deploy),
    "Pages deployment must follow code CI, snapshot synchronization, and public collection-health updates.",
  );
  assert(
    deploy.includes("github.event.workflow_run.name == 'CI'") &&
      deploy.includes("github.event.workflow_run.name == 'Sync radar snapshot'") &&
      deploy.includes("github.event.workflow_run.name == 'Collect CertStream candidates'") &&
      deploy.includes("github.event.workflow_run.conclusion == 'failure'") &&
      deploy.includes("github.event.workflow_run.event == 'schedule'") &&
      deploy.includes("github.event.workflow_run.event == 'workflow_dispatch'"),
    "Pages deployment no longer limits each upstream workflow to its approved trigger semantics.",
  );
  assert(
    deploy.includes('git diff --quiet "${EXPECTED_SHA}..${actual_sha}" -- public/data/') &&
      deploy.includes("public/data/collection-health.json") &&
      deploy.includes("test -f dist/404.html") &&
      deploy.includes("test -f dist/data/radar.stix.json") &&
      deploy.includes("test -f dist/data/feed-manifest.json") &&
      deploy.includes("test -f dist/data/pipeline-health.json") &&
      deploy.includes("test -f dist/data/related-observations.json") &&
      deploy.includes("test -f dist/data/schemas/radar-v2.schema.json") &&
      deploy.includes("! grep -Fq 'Allow: /data/radar.stix.json' dist/robots.txt") &&
      deploy.includes("git merge-base --is-ancestor") &&
      deploy.includes("data/(certstream|ct-search|enrichment|urlscan|history)/|public/data/"),
    "Pages deployment freshness checks no longer cover every staged public-data boundary.",
  );
  assert(!/^\s{2}workflow_dispatch:/mu.test(deploy), "Pages deployment must not bypass CI through manual dispatch.");
  assert(!/^\s{2}actions:\s*write\s*$/mu.test(collector), "CertStream collector retains unnecessary actions:write access.");
  assert(!collector.includes("gh workflow run deploy-pages.yml"), "CertStream collector still dispatches a duplicate Pages deployment.");
  const collectorGitAdds = collector.match(/^\s+git add -- .*$/gmu) ?? [];
  assert(
    collectorGitAdds.length === 1 &&
      collectorGitAdds[0].trim() === "git add -- data/certstream public/data/collection-health.json",
    "CertStream collector stages files outside its archive and public-health boundaries.",
  );
  const hunterGitAdds = hunter.match(/^\s+git add -- .*$/gmu) ?? [];
  assert(
    hunterGitAdds.length === 1 && hunterGitAdds[0].trim() === "git add -- data/urlscan",
    "URLScan hunter stages files outside its archive boundary.",
  );
  const assetHunterGitAdds = assetHunter.match(/^\s+git add -- .*$/gmu) ?? [];
  assert(
    assetHunterGitAdds.length === 1 && assetHunterGitAdds[0].trim() === "git add -- data/urlscan",
    "Official asset hunter stages files outside its URLScan archive boundary.",
  );
  assert(
    assetHunter.includes('cron: "47 3,15 * * *"') &&
      assetHunter.includes("group: radar-archive-writer") &&
      assetHunter.includes("ref: main") &&
      assetHunter.includes("persist-credentials: false"),
    "Official asset hunter schedule, serialization, or main-branch boundary drifted.",
  );
  assert(
    hunter.includes("group: radar-archive-writer") && sync.includes("group: radar-archive-writer"),
    "URLScan archive and snapshot writers are no longer serialized.",
  );
  assert(
    ctSearch.includes('cron: "43 * * * *"') &&
      ctSearch.includes("group: radar-certstream-writer") &&
      ctSearch.includes("git add -- data/ct-search data/certstream") &&
      ctSearch.includes("CT_SEARCH_REPLAY_IDS") &&
      ctSearch.includes("CT_SEARCH_REPLAY_ROWS") &&
      ctSearch.includes("if: always()"),
    "Checkpointed CT search schedule, serialization, replay boundary, or durable state publication drifted.",
  );
  assert(
    domainContext.includes('cron: "13 1,7,13,19 * * *"') &&
      domainContext.includes("group: radar-archive-writer") &&
      domainContext.includes("vars.DOMAIN_CONTEXT_RUN_BUDGET_SECONDS") &&
      domainContext.includes("git add -- data/enrichment/domain-context.json") &&
      domainContext.includes("if: always()"),
    "DNS/RDAP context schedule, serialization, or durable state publication drifted.",
  );
  for (const [name, workflow] of [
    ["CertStream collection", collector],
    ["URLScan hunt", hunter],
    ["official asset hunt", assetHunter],
    ["checkpointed CT search", ctSearch],
    ["DNS/RDAP context", domainContext],
  ]) {
    assert(
      workflow.includes('base_sha="$(git rev-parse HEAD^)"') &&
        workflow.includes("git fetch --no-tags origin main") &&
        workflow.includes('[[ "${upstream_sha}" != "${base_sha}" ]]') &&
        workflow.includes("data/(certstream|ct-search|enrichment|urlscan|history)/|public/data/") &&
        workflow.includes("Code or configuration changed after checkout") &&
        workflow.includes("git rebase origin/main") &&
        !workflow.includes("git pull --rebase origin main"),
      `${name} does not restrict generated-output rebases to reviewed data-only paths.`,
    );
  }
  assert(
    sync.includes('base_sha="$(git rev-parse HEAD^)"') &&
      sync.includes("python -m hecavex_radar.publication") &&
      sync.includes("git fetch --no-tags origin main") &&
      sync.includes('[[ "${upstream_sha}" != "${base_sha}" ]]') &&
      sync.includes("data/(certstream|ct-search|enrichment|urlscan|review)/") &&
      sync.includes("Source inputs changed while this snapshot was being built") &&
      sync.includes("public/data/collection-health\\.json") &&
      sync.includes("Code or configuration changed after checkout") &&
      sync.includes("git rebase origin/main") &&
      !sync.includes("git pull --rebase origin main"),
    "snapshot synchronization does not invalidate stale source inputs while allowing only volatile health rebases.",
  );
  assert(
    ci.includes('- "data/certstream/**"') &&
      ci.includes('- "data/ct-search/**"') &&
      ci.includes('- "data/enrichment/**"') &&
      ci.includes('- "data/urlscan/**"') &&
      !ci.includes('- "public/data/**"'),
    "CI path filters no longer ignore only archive-only collection changes.",
  );
  assert(
    sync.includes("public/data/radar.json") &&
      sync.includes("public/data/radar.stix.json") &&
      sync.includes("public/data/radar-reviewed.stix.json") &&
      sync.includes("public/data/radar.index.json") &&
      sync.includes("public/data/radar-shards") &&
      sync.includes("public/data/history.json") &&
      sync.includes("public/data/changes.json") &&
      sync.includes("public/data/events.json") &&
      sync.includes("public/data/events.atom.xml") &&
      sync.includes("public/data/events.rss.xml") &&
      sync.includes("public/data/events.feed.json") &&
      sync.includes("public/data/brand-feeds.json") &&
      sync.includes("public/data/brands") &&
      sync.includes("public/data/daily-trends.json") &&
      sync.includes("public/data/quality-metrics.json") &&
      sync.includes("public/data/pipeline-health.json") &&
      sync.includes("public/data/related-observations.json") &&
      sync.includes("public/data/feed-manifest.json") &&
      sync.includes("public/data/schemas") &&
      sync.includes("public/data/signals") &&
      sync.includes("public/data/*.sha256") &&
      sync.includes("data/history") &&
      sync.includes("RADAR_STIX_OUTPUT: public/data/radar.stix.json"),
    "Snapshot synchronization does not stage the STIX projection, sidecars, history, and live snapshot atomically.",
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
      historyPublisher.includes("MAXIMUM_PUBLIC_BYTES = 512 * 1024") &&
      stixPublisher.includes("MAXIMUM_STIX_BUNDLE_BYTES = 2 * 1024 * 1024"),
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
    ["hunt-brand-assets.yml", runtimeLock],
    ["poll-ct-search.yml", runtimeLock],
    ["enrich-domain-context.yml", runtimeLock],
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
  const robots = readFileSync(join(output, "robots.txt"), "utf8");
  const llms = readFileSync(join(output, "llms.txt"), "utf8");
  assert(robots.includes("Content-Signal: search=yes, ai-input=yes, ai-train=no"), "Built robots.txt lost the reviewed content-use signal.");
  assert(!robots.includes("Allow: /data/radar.stix.json"), "Raw STIX observables must not be explicitly allowed for crawler retrieval.");
  for (const endpoint of [
    "radar.json",
    "radar.stix.json",
    "radar-reviewed.stix.json",
    "history.json",
    "collection-health.json",
    "pipeline-health.json",
    "changes.json",
    "related-observations.json",
    "events.json",
    "events.atom.xml",
    "events.rss.xml",
    "events.feed.json",
    "brand-feeds.json",
    "daily-trends.json",
    "quality-metrics.json",
    "radar.index.json",
    "feed-manifest.json",
  ]) {
    assert(llms.includes(`https://radar.hecavex.com/data/${endpoint}`), `Built llms.txt omits approved endpoint ${endpoint}.`);
  }
  for (const endpoint of [
    "radar.json",
    "history.json",
    "events.json",
    "brand-feeds.json",
    "daily-trends.json",
    "quality-metrics.json",
  ]) {
    assert(robots.includes(`Allow: /data/${endpoint}`), `Built robots.txt does not allow the intended aggregate endpoint ${endpoint}.`);
  }
  assert(robots.includes("Disallow: /data/radar.stix.json") && robots.includes("Disallow: /data/radar-reviewed.stix.json"), "Built robots.txt no longer excludes raw STIX observables from crawler discovery.");
  assert(llms.includes("must not be made clickable or visited automatically"), "Built llms.txt lost the candidate-handling safety boundary.");

  const htmlFiles = walk(output).filter((path) => path.endsWith(".html"));
  const snapshot = JSON.parse(readFileSync(join(output, "data", "radar.json"), "utf8"));
  const history = JSON.parse(readFileSync(join(output, "data", "history.json"), "utf8"));
  const brands = JSON.parse(readFileSync(join(root, "data", "brands-lt.json"), "utf8"));
  const signalIds = new Set([...snapshot.signals, ...history.signals].map((signal) => signal.id));
  const expectedHtmlCount = 20 + (signalIds.size * 2) + (brands.entries.length * 2);
  assert(htmlFiles.length === expectedHtmlCount, `Expected ${expectedHtmlCount} static HTML entries, found ${htmlFiles.length}.`);
  assert(!htmlFiles.some((path) => relative(output, path).startsWith(`templates${sep}`)), "Build output still exposes route templates.");
  assert(!existsSync(join(output, "signals", "index.html")), "Build output creates a soft-404 landing page at /signals/.");

  for (const path of htmlFiles) {
    const document = parseFile(path);
    const route = routeForFile(path);
    const notFound = route === "/404.html";
    const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
    assert(new Set(ids).size === ids.length, `${route} contains duplicate IDs.`);
    const lithuanian = route.startsWith("/lt/");
    assert(document.documentElement.lang === (lithuanian ? "lt" : "en"), `${route} has the wrong document language.`);
    assert(document.querySelectorAll("main").length === 1, `${route} must contain exactly one main element.`);
    assert(document.querySelectorAll("h1").length === 1, `${route} must contain exactly one h1.`);
    assert(document.querySelector('.skip-link[href="#main-content"]'), `${route} has no usable skip link.`);
    assert(document.querySelector('header.site-header[data-portfolio-shell="v2"]'), `${route} has no shared portfolio shell marker.`);
    assert(document.querySelector(`.brand[href="https://hecavex.com/${lithuanian ? "lt" : "en"}/"]`), `${route} does not link the HECAVEX brand to the correct Research edition.`);
    assert(document.querySelector(`.product-identity[href="${lithuanian ? "/lt/" : "/"}"]`), `${route} does not link the Radar identity to its localized overview.`);
    assert(document.querySelectorAll(".portfolio-navigation a").length === 5, `${route} does not expose five portfolio links.`);
    assert(document.querySelectorAll(".product-navigation a").length === 8, `${route} exposes the wrong Radar navigation set.`);
    assert(document.querySelector(".header-utility .source-link"), `${route} has no fixed Source utility.`);
    const analyticsLoaders = [...document.querySelectorAll("script:not([src])")].filter((script) =>
      script.textContent.includes("https://static.cloudflareinsights.com/beacon.min.js"),
    );
    assert(
      analyticsLoaders.length === (analyticsToken ? 1 : 0),
      `${route} does not match the configured Cloudflare Web Analytics state.`,
    );
    if (analyticsToken) {
      assert(
        analyticsLoaders[0].textContent.includes('navigator.doNotTrack==="1"') &&
          analyticsLoaders[0].textContent.includes('window.doNotTrack==="1"') &&
          analyticsLoaders[0].getAttribute("data-hecavex-analytics-token") === analyticsToken,
        `${route} has an unexpected Cloudflare Web Analytics configuration.`,
      );
    }
    const portfolioLabels = [...document.querySelectorAll(".portfolio-navigation a")].map((anchor) => anchor.textContent?.trim());
    const productLabels = [...document.querySelectorAll(".product-navigation a")].map((anchor) => anchor.textContent?.trim());
    assert(JSON.stringify(portfolioLabels) === JSON.stringify(portfolioNavigation), `${route} changes the portfolio navigation order.`);
    const expectedProductNavigation = productNavigationForPath(route);
    assert(JSON.stringify(productLabels) === JSON.stringify(expectedProductNavigation), `${route} changes the Radar navigation order.`);
    const expectedLocalPage = new Map([
      ["/", "Overview"],
      ["/lt/", "Apžvalga"],
      ["/history/", "Changes"],
      ["/changes/", "Changes"],
      ["/lt/pokyciai/", "Pokyčiai"],
      ["/brands/", "Brands"],
      ["/lt/prekes-zenklai/", "Prekių ženklai"],
      ["/trends/", "Trends"],
      ["/lt/tendencijos/", "Tendencijos"],
      ["/associations/", "Associations"],
      ["/lt/sasajos/", "Sąsajos"],
      ["/tools/", "Tools"],
      ["/lt/irankiai/", "Įrankiai"],
      ["/dataset/", "Docs"],
      ["/lt/duomenys/", "Dokumentacija"],
      ["/methodology/", "Methodology"],
      ["/lt/metodologija/", "Metodologija"],
      ["/docs/", "Docs"],
      ["/lt/dokumentacija/", "Dokumentacija"],
    ]).get(route) ?? (
      route.startsWith("/signals/")
        ? "Overview"
        : route.startsWith("/lt/signalai/")
          ? "Apžvalga"
          : route.startsWith("/brands/")
            ? "Brands"
            : route.startsWith("/lt/prekes-zenklai/")
              ? "Prekių ženklai"
              : undefined
    );
    assert(
      document.querySelector('.portfolio-navigation a[aria-current="page"]')?.textContent?.trim() === "Radar",
      `${route} does not identify Radar as the active portfolio product.`,
    );
    if (!notFound) assert(document.querySelector('.product-navigation a[aria-current="page"]')?.textContent?.trim() === expectedLocalPage, `${route} does not identify ${expectedLocalPage} as the active Radar page.`);
    assert(document.querySelector('meta[name="description"]')?.content, `${route} has no description.`);
    if (notFound) {
      assert(document.querySelector('meta[name="robots"]')?.content === "noindex, follow", "Custom 404 page must remain noindex, follow.");
      assert(!document.querySelector('link[rel="canonical"]'), "Custom 404 page must not canonicalize missing routes to a valid page.");
      assert(!document.querySelector('.product-navigation a[aria-current="page"]'), "Custom 404 page must not identify a nonexistent local section as current.");
    } else {
      assert(document.querySelector('link[rel="canonical"]')?.href, `${route} has no canonical URL.`);
    }
    assert(document.querySelector('meta[property="og:image"]')?.content, `${route} has no Open Graph image.`);
    if (
      route === "/" ||
      route === "/lt/" ||
      route.startsWith("/signals/") ||
      route.startsWith("/lt/signalai/") ||
      route.startsWith("/brands/") ||
      route.startsWith("/lt/prekes-zenklai/")
    ) {
      assert(document.querySelector('meta[name="twitter:card"]')?.content, `${route} has no Twitter card.`);
    }
    const jsonLd = document.querySelector('script[type="application/ld+json"]')?.textContent;
    if (notFound) assert(!jsonLd, "Custom 404 page must not publish structured data for a nonexistent resource.");
    const contentSecurityPolicy = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content;
    let structuredData = null;
    if (jsonLd) {
      const jsonLdHash = createHash("sha256").update(jsonLd, "utf8").digest("base64");
      assert(contentSecurityPolicy?.includes(`'sha256-${jsonLdHash}'`), `${route} Content Security Policy does not authorize its exact JSON-LD payload.`);
      structuredData = JSON.parse(jsonLd);
    }
    if (route === "/") {
      assert(
        document.querySelector('link[rel="alternate"][type="application/stix+json;version=2.1"][href="https://radar.hecavex.com/data/radar.stix.json"]'),
        "Radar overview does not advertise the STIX 2.1 alternate distribution.",
      );
      assert(
        document.querySelector('link[rel="alternate"][type="application/stix+json;version=2.1"][href="https://radar.hecavex.com/data/radar-reviewed.stix.json"]'),
        "Radar overview does not advertise the reviewed STIX 2.1 alternate distribution.",
      );
      assert(structuredData, "Radar overview has no Dataset JSON-LD.");
      const serializedStructuredData = JSON.stringify(structuredData);
      assert(
        serializedStructuredData.includes("application/stix+json;version=2.1") &&
          serializedStructuredData.includes("https://radar.hecavex.com/data/radar.stix.json") &&
          serializedStructuredData.includes("https://radar.hecavex.com/data/radar-reviewed.stix.json") &&
          serializedStructuredData.includes("https://radar.hecavex.com/data/radar.index.json") &&
          serializedStructuredData.includes("https://radar.hecavex.com/data/feed-manifest.json") &&
          serializedStructuredData.includes("checkpointed crt.sh keyword search") &&
          serializedStructuredData.includes("DNS-over-HTTPS and RDAP context"),
        "Radar Dataset metadata omits a declared collection method or machine-readable distribution.",
      );
    }
    if (route === "/" || route === "/lt/") {
      const signalPrefix = lithuanian ? "/lt/signalai/" : "/signals/";
      const privacyMarker = lithuanian ? "nėra pridedamas prie bendrinamo URL" : "never added to the shared URL";
      assert(document.querySelector(".hero.radar-hero"), `${route} omits the shared Radar hero.`);
      assert(document.querySelector(".activity-strip"), `${route} omits the compact activity strip.`);
      assert(document.querySelector(".filter-shell"), `${route} omits the shared candidate filters.`);
      assert(document.querySelector(".signal-table"), `${route} omits the shared signal table.`);
      assert(document.querySelector(".export-actions"), `${route} omits defanged filtered-view exports.`);
      assert(
        document.querySelector(".filter-privacy-note")?.textContent?.includes(privacyMarker),
        `${route} does not disclose local-only free-text search.`,
      );
      assert(
        document.querySelector(`tbody tr[id^="signal-"] .signal-deep-link[href^="${signalPrefix}"]`),
        `${route} omits localized durable per-signal links.`,
      );
      assert(
        document.querySelector('tbody tr[id^="signal-"] button[aria-haspopup="dialog"]'),
        `${route} omits in-page signal detail controls.`,
      );
      assert(document.querySelector(".radar-route-grid"), `${route} omits dedicated exploration routes.`);
      assert(document.querySelector(".collection-disclosure"), `${route} omits the collection disclosure.`);
    }
    if (route === "/brands/") {
      assert(document.querySelectorAll(".brand-table tbody tr").length >= 40, "Detection scope does not prerender the reviewed brand registry.");
      assert(document.querySelector(".scope-boundaries"), "Detection scope omits registry interpretation boundaries.");
      assert(document.querySelector('.brand-hub-link[href^="/brands/"]'), "Detection scope omits per-brand activity links.");
    }

    const root = document.getElementById("root");
    assert(root, `${route} has no application root.`);
    const bootstrap = root.getAttribute("data-radar-bootstrap");
    const historyBootstrap = root.getAttribute("data-history-bootstrap");
    const staticBootstrap = root.getAttribute("data-page-bootstrap");
    const pageLanguage = root.getAttribute("data-page-language");
    const ltChangesBootstrap = root.getAttribute("data-lt-changes-bootstrap");
    if (route === "/" || route === "/lt/") {
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
    } else if (route === "/lt/pokyciai/") {
      assert(ltChangesBootstrap, `${route} has no localized changes bootstrap.`);
      const payload = JSON.parse(decodeURIComponent(ltChangesBootstrap));
      assert(payload?.snapshot?.dataset === "live" && payload?.history?.dataset === "history", `${route} embeds the wrong localized data.`);
    } else if ([
      "/changes/", "/trends/", "/associations/", "/tools/", "/dataset/",
      "/lt/tendencijos/", "/lt/sasajos/", "/lt/irankiai/", "/lt/duomenys/",
    ].includes(route)) {
      assert(staticBootstrap, `${route} has no embedded static artifact bootstrap.`);
      assert(pageLanguage === (route.startsWith("/lt/") ? "lt" : "en"), `${route} embeds the wrong static-page language.`);
      const payload = JSON.parse(decodeURIComponent(staticBootstrap));
      assert(payload?.snapshot?.dataset === "live" && payload?.history?.dataset === "history", `${route} embeds the wrong static data.`);
    } else if (route === "/docs/" || route === "/lt/dokumentacija/") {
      assert(pageLanguage === (route.startsWith("/lt/") ? "lt" : "en"), `${route} embeds the wrong documentation language.`);
    } else if (route.startsWith("/signals/") || route.startsWith("/lt/signalai/")) {
      assert(staticBootstrap, `${route} has no permanent signal bootstrap.`);
      const payload = JSON.parse(decodeURIComponent(staticBootstrap));
      assert(payload?.signal?.id && payload?.generatedAt, `${route} embeds invalid signal data.`);
    } else if ((route.startsWith("/brands/") && route !== "/brands/") || (route.startsWith("/lt/prekes-zenklai/") && route !== "/lt/prekes-zenklai/")) {
      assert(staticBootstrap, `${route} has no brand activity bootstrap.`);
      const payload = JSON.parse(decodeURIComponent(staticBootstrap));
      assert(payload?.brand?.brand && Array.isArray(payload?.signals), `${route} embeds invalid brand data.`);
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

  const sitemapDocument = new JSDOM(readFileSync(join(output, "sitemap.xml"), "utf8"), {
    contentType: "text/xml",
  }).window.document;
  assert(!sitemapDocument.querySelector("parsererror"), "Generated sitemap.xml is not valid XML.");
  const sitemapLocations = new Set(
    [...sitemapDocument.querySelectorAll("loc")].map((node) => node.textContent?.trim()).filter(Boolean),
  );
  const expectedLocations = new Set(
    htmlFiles
      .map((path) => routeForFile(path))
      .filter((route) => route !== "/404.html")
      .map((route) => `${publicOrigin}${route}`),
  );
  assert(sitemapLocations.size === expectedLocations.size, "Generated sitemap does not contain exactly the public HTML routes.");
  for (const location of expectedLocations) {
    assert(sitemapLocations.has(location), `Generated sitemap omits ${location}.`);
  }
  assert(!sitemapLocations.has(`${publicOrigin}/404.html`), "Generated sitemap includes the custom 404 page.");

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

const detailFields = ["schemaVersion", "dataset", "signalId", "domain", "generatedAt", "observations"];
const domainContextFields = ["observedAt", "dns", "registration"];
const dnsContextFields = ["a", "aaaa", "cname", "ns", "mx", "minimumTtl", "queriesCompleted"];
const registrationContextFields = ["registrar", "registeredAt", "updatedAt", "expiresAt", "statuses"];
const observationFields = ["source", "observedAt", "page", "network", "assessment", "certificate"];
const pageFields = ["title", "httpStatus"];
const networkFields = ["ipAddress", "asn", "asnDescription", "asnRegistry"];
const assessmentFields = ["urlscanVerdictScore", "urlscanCategories", "redirectedToDomain"];
const certificateFields = [
  "countryName",
  "issuer",
  "commonName",
  "notBefore",
  "notAfter",
  "subjectAltNames",
  "subjectAltNameCount",
  "serialNumberHex",
  "fingerprints",
];
const fingerprintFields = ["md5", "sha1", "sha256"];
const utcTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const signalIdentifier = /^[a-f\d]{20}$/u;
const lowerHex = /^[a-f\d]+$/u;
const stixUuid = /^[a-f\d]{8}-[a-f\d]{4}-5[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/u;
const stixBundleFields = ["type", "id", "objects"];
const stixDomainFields = ["type", "spec_version", "id", "value"];
const stixObservedRequiredFields = [
  "type",
  "spec_version",
  "id",
  "created",
  "modified",
  "first_observed",
  "last_observed",
  "number_observed",
  "object_refs",
  "x_hecavex_com_signal_id",
  "x_hecavex_com_sources",
  "x_hecavex_com_status",
  "x_hecavex_com_matching_score",
  "x_hecavex_com_evidence_tier",
  "x_hecavex_com_review_state",
  "x_hecavex_com_lt_relevance",
  "x_hecavex_com_observation_only",
  "x_hecavex_com_radar_first_seen",
  "x_hecavex_com_radar_last_seen",
];
const stixObservedOptionalFields = ["external_references", "x_hecavex_com_brand", "x_hecavex_com_reason_codes"];
const supportedSources = new Set(["CertStream", "URLScan", "HECAVEX"]);
const stixDomainNamespace = "00abedb4-aa42-466c-9c01-fed23315a9b7";
const urlNamespace = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return isRecord(value) && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function hasRequiredAndOptionalFields(value, required, optional) {
  const allowed = new Set([...required, ...optional]);
  return (
    isRecord(value) &&
    required.every((field) => Object.hasOwn(value, field)) &&
    Object.keys(value).every((field) => allowed.has(field))
  );
}

function timestampValue(value) {
  if (typeof value !== "string" || !utcTimestamp.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function uuidBytes(value) {
  const compact = value.replaceAll("-", "");
  assert(/^[a-f\d]{32}$/u.test(compact), `Invalid UUID namespace ${value}.`);
  return Uint8Array.from(compact.match(/.{2}/gu), (pair) => Number.parseInt(pair, 16));
}

function uuid5(namespace, name) {
  // UUIDv5 requires SHA-1 under RFC 9562 section 5.5. This is deterministic
  // naming for public STIX identifiers, never a security or integrity hash.
  const digest = createHash("sha1").update(uuidBytes(namespace)).update(name, "utf8").digest().subarray(0, 16);
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function refangedRadarDomain(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("[:]") || value.includes(":")) return null;
  const domain = value.replaceAll("[.]", ".");
  if (domain.length > 253 || domain !== domain.toLowerCase() || domain.includes("[") || domain.includes("]")) return null;
  const labels = domain.split(".");
  if (labels.length < 2) return null;
  return labels.every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/u.test(label)) ? domain : null;
}

function isDefangedIp(value) {
  if (typeof value !== "string" || /[@/?#]/u.test(value)) return false;
  if (value.includes("[.]")) {
    if (value.includes(":") || value.replaceAll("[.]", "").includes(".")) return false;
    const octets = value.split("[.]");
    return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255);
  }
  const refanged = value.replaceAll("[:]", ":");
  return value.includes("[:]") && !refanged.includes("[") && !refanged.includes("]") && /^[a-f\d:]+$/u.test(refanged);
}

function verifyDomainContext(context, generatedAt, label) {
  assert(hasExactFields(context, domainContextFields), `${label} has unexpected fields.`);
  const observedAt = timestampValue(context.observedAt);
  assert(observedAt !== null && observedAt <= generatedAt + 5 * 60 * 1000, `${label} has an invalid observedAt.`);
  assert(hasExactFields(context.dns, dnsContextFields), `${label} has invalid DNS fields.`);
  const dns = context.dns;
  const uniqueList = (value, validator) =>
    Array.isArray(value) && value.length <= 12 && new Set(value).size === value.length && value.every(validator);
  assert(uniqueList(dns.a, isDefangedIp) && uniqueList(dns.aaaa, isDefangedIp), `${label} has invalid IP answers.`);
  for (const field of ["cname", "ns"]) {
    assert(uniqueList(dns[field], (value) => refangedRadarDomain(value) !== null), `${label} has invalid ${field} answers.`);
  }
  assert(
    uniqueList(dns.mx, (value) => {
      if (typeof value !== "string") return false;
      const separator = value.indexOf(" ");
      return separator > 0 && /^\d{1,5}$/u.test(value.slice(0, separator)) && refangedRadarDomain(value.slice(separator + 1)) !== null;
    }),
    `${label} has invalid MX answers.`,
  );
  assert(
    (dns.minimumTtl === null || (Number.isInteger(dns.minimumTtl) && dns.minimumTtl >= 0)) &&
      Number.isInteger(dns.queriesCompleted) &&
      dns.queriesCompleted >= 0 &&
      dns.queriesCompleted <= 5,
    `${label} has invalid DNS counters.`,
  );
  if (context.registration === null) return;
  const registration = context.registration;
  assert(
    hasRequiredAndOptionalFields(registration, registrationContextFields, ["domain"]),
    `${label} has invalid registration fields.`,
  );
  assert(
    registration.domain === undefined || refangedRadarDomain(registration.domain) !== null,
    `${label} has an invalid registration scope.`,
  );
  assert(
    registration.registrar === null ||
      (typeof registration.registrar === "string" && registration.registrar.length > 0 && registration.registrar.length <= 160),
    `${label} has an invalid registrar.`,
  );
  for (const field of ["registeredAt", "updatedAt", "expiresAt"]) {
    assert(registration[field] === null || timestampValue(registration[field]) !== null, `${label} has an invalid ${field}.`);
  }
  assert(
    uniqueList(registration.statuses, (value) => typeof value === "string" && /^[a-z\d-]{1,64}$/u.test(value)),
    `${label} has invalid registration statuses.`,
  );
}

function verifyStixBundle() {
  const snapshot = JSON.parse(readFileSync(join(output, "data", "radar.json"), "utf8"));
  assert(Array.isArray(snapshot.signals), "Built radar.json has no signal list for STIX verification.");
  const path = join(output, "data", "radar.stix.json");
  const rawBytes = statSync(path).size;
  assert(rawBytes > 0 && rawBytes <= stixBundleRawBytes, "Built radar.stix.json is empty or larger than 2 MiB.");

  let bundle;
  try {
    bundle = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("Built radar.stix.json is not valid UTF-8 JSON.");
  }
  assert(hasExactFields(bundle, stixBundleFields), "STIX bundle does not use its exact top-level fields.");
  assert(bundle.type === "bundle" && typeof bundle.id === "string", "STIX bundle has the wrong type or no identifier.");
  assert(stixUuid.test(bundle.id.replace(/^bundle--/u, "")), "STIX bundle identifier is not a namespaced UUIDv5.");
  assert(Array.isArray(bundle.objects), "STIX bundle has no object list.");
  assert(bundle.objects.length === snapshot.signals.length * 2, "STIX bundle is not a one-to-one projection of live signals.");

  const expectedSignals = [...snapshot.signals].sort((left, right) => {
    const leftDomain = refangedRadarDomain(left.domain) ?? "";
    const rightDomain = refangedRadarDomain(right.domain) ?? "";
    return leftDomain.localeCompare(rightDomain) || String(left.id).localeCompare(String(right.id));
  });
  const radarNamespace = uuid5(urlNamespace, "https://radar.hecavex.com/data/radar.stix.json");
  const objectIds = new Set();
  const expectedObjectIds = [];
  for (let index = 0; index < expectedSignals.length; index += 1) {
    const signal = expectedSignals[index];
    const domain = refangedRadarDomain(signal.domain);
    assert(domain !== null, `Live signal ${signal.id} cannot be safely represented as a STIX domain-name.`);
    const domainObject = bundle.objects[index * 2];
    const observed = bundle.objects[index * 2 + 1];
    const label = `STIX signal ${signal.id}`;

    assert(hasExactFields(domainObject, stixDomainFields), `${label} domain-name object has unexpected fields.`);
    assert(domainObject.type === "domain-name" && domainObject.spec_version === "2.1", `${label} has the wrong SCO type or version.`);
    assert(typeof domainObject.id === "string" && domainObject.id.startsWith("domain-name--"), `${label} has no domain-name ID.`);
    assert(stixUuid.test(domainObject.id.slice("domain-name--".length)), `${label} domain-name ID is not a UUIDv5.`);
    assert(
      domainObject.id === `domain-name--${uuid5(stixDomainNamespace, JSON.stringify({ value: domain }))}`,
      `${label} domain-name ID is not the deterministic STIX 2.1 identifier.`,
    );
    assert(domainObject.value === domain, `${label} does not contain the corresponding raw normalized domain.`);
    assert(
      !["[", "]", "/", "?", ":", "#"].some((character) => domainObject.value.includes(character)),
      `${label} domain-name value is defanged or contains URL data.`,
    );

    assert(isRecord(observed), `${label} has no Observed Data object.`);
    const observedKeys = Object.keys(observed);
    assert(
      stixObservedRequiredFields.every((field) => Object.hasOwn(observed, field)) &&
        observedKeys.every((field) => stixObservedRequiredFields.includes(field) || stixObservedOptionalFields.includes(field)),
      `${label} Observed Data object has missing or unexpected fields.`,
    );
    assert(observed.type === "observed-data" && observed.spec_version === "2.1", `${label} has the wrong SDO type or version.`);
    assert(typeof observed.id === "string" && observed.id.startsWith("observed-data--"), `${label} has no Observed Data ID.`);
    assert(stixUuid.test(observed.id.slice("observed-data--".length)), `${label} Observed Data ID is not a UUIDv5.`);
    assert(
      observed.id === `observed-data--${uuid5(radarNamespace, `observed-data:${signal.id}:${signal.firstSeen}`)}`,
      `${label} Observed Data ID is not the deterministic Radar identifier.`,
    );
    assert(observed.created === signal.firstSeen && observed.modified === snapshot.generatedAt, `${label} version timestamps drift from the snapshot.`);
    assert(timestampValue(observed.created) !== null && timestampValue(observed.modified) !== null, `${label} version timestamps are malformed.`);
    assert(timestampValue(observed.created) <= timestampValue(observed.modified), `${label} was modified before it was created.`);
    assert(
      observed.first_observed === signal.lastSeen && observed.last_observed === signal.lastSeen && observed.number_observed === 1,
      `${label} must represent exactly one latest observation.`,
    );
    assert(Array.isArray(observed.object_refs) && observed.object_refs.length === 1 && observed.object_refs[0] === domainObject.id, `${label} does not reference its SCO exactly once.`);
    assert(observed.x_hecavex_com_signal_id === signal.id, `${label} lost the Radar signal identifier.`);
    const expectedSources = [...signal.sources].sort();
    assert(expectedSources.every((source) => supportedSources.has(source)), `${label} contains an unsupported Radar source.`);
    assert(JSON.stringify(observed.x_hecavex_com_sources) === JSON.stringify(expectedSources), `${label} source metadata drifted.`);
    assert(observed.x_hecavex_com_status === signal.status, `${label} status metadata drifted.`);
    assert(observed.x_hecavex_com_matching_score === signal.confidence, `${label} matching score metadata drifted.`);
    assert(observed.x_hecavex_com_evidence_tier === signal.evidenceTier, `${label} evidence tier metadata drifted.`);
    assert(observed.x_hecavex_com_review_state === signal.reviewState, `${label} review state metadata drifted.`);
    assert(observed.x_hecavex_com_lt_relevance === signal.ltRelevance, `${label} Lithuanian-relevance metadata drifted.`);
    assert(observed.x_hecavex_com_observation_only === true, `${label} lost its observation-only boundary.`);
    assert(
      observed.x_hecavex_com_radar_first_seen === signal.firstSeen && observed.x_hecavex_com_radar_last_seen === signal.lastSeen,
      `${label} lost its Radar observation interval.`,
    );
    if (signal.brand === null) {
      assert(!Object.hasOwn(observed, "x_hecavex_com_brand"), `${label} invents a null brand property.`);
    } else {
      assert(observed.x_hecavex_com_brand === signal.brand, `${label} brand metadata drifted.`);
    }
    const expectedReasons = signal.reasonCodes ?? [];
    if (expectedReasons.length === 0) {
      assert(!Object.hasOwn(observed, "x_hecavex_com_reason_codes"), `${label} invents empty reason metadata.`);
    } else {
      assert(JSON.stringify(observed.x_hecavex_com_reason_codes) === JSON.stringify(expectedReasons), `${label} reason metadata drifted.`);
    }
    assert(!Object.hasOwn(observed, "confidence") && !Object.hasOwn(observed, "revoked"), `${label} misuses a standard STIX verdict property.`);

    const expectedReferenceUrl =
      expectedSources.includes("URLScan") && typeof signal.referenceUrl === "string" ? signal.referenceUrl : null;
    if (expectedReferenceUrl === null) {
      assert(!Object.hasOwn(observed, "external_references"), `${label} exposes an external reference without a URLScan result.`);
    } else {
      assert(
        Array.isArray(observed.external_references) && observed.external_references.length === 1,
        `${label} must expose exactly one URLScan external reference.`,
      );
      const reference = observed.external_references[0];
      assert(
        hasExactFields(reference, ["source_name", "url"]) &&
          reference.source_name === "URLScan" &&
          reference.url === expectedReferenceUrl &&
          /^https:\/\/urlscan\.io\/result\/[a-f\d-]{36}\/$/u.test(reference.url),
        `${label} exposes an unsafe or mismatched URLScan external reference.`,
      );
    }

    for (const id of [domainObject.id, observed.id]) {
      assert(!objectIds.has(id), `STIX bundle contains duplicate object ID ${id}.`);
      objectIds.add(id);
      expectedObjectIds.push(id);
    }
  }
  const bundleKey = JSON.stringify({ generated_at: snapshot.generatedAt, object_ids: expectedObjectIds });
  assert(bundle.id === `bundle--${uuid5(radarNamespace, bundleKey)}`, "STIX bundle identifier does not match its exact projected contents.");
  return { path, rawBytes };
}

function isNullableText(value, maximum) {
  return (
    value === null ||
    (typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      value.trim() === value &&
      !/[\p{Cc}\p{Cf}]/u.test(value) &&
      !/https?:\/\//iu.test(value) &&
      !/\S+@\S+/u.test(value))
  );
}

function isNullableHex(value, length) {
  return value === null || (typeof value === "string" && value.length === length && lowerHex.test(value));
}

function verifyPageDetail(value, label) {
  if (value === null) return;
  assert(hasExactFields(value, pageFields), `${label} page does not use the exact version-1 fields.`);
  assert(isNullableText(value.title, 160), `${label} page title is unsafe or malformed.`);
  assert(
    value.httpStatus === null ||
      (Number.isInteger(value.httpStatus) && value.httpStatus >= 100 && value.httpStatus <= 599),
    `${label} page status is malformed.`,
  );
  assert(value.title !== null || value.httpStatus !== null, `${label} contains an empty page object.`);
}

function verifyNetworkDetail(value, label) {
  if (value === null) return;
  assert(hasExactFields(value, networkFields), `${label} network does not use the exact version-1 fields.`);
  assert(
    value.ipAddress === null ||
      (typeof value.ipAddress === "string" &&
        value.ipAddress.length <= 80 &&
        (value.ipAddress.includes("[.]") || value.ipAddress.includes("[:]"))),
    `${label} network address is not defanged.`,
  );
  assert(
    value.asn === null || (Number.isInteger(value.asn) && value.asn >= 1 && value.asn <= 4_294_967_295),
    `${label} ASN is malformed.`,
  );
  assert(isNullableText(value.asnDescription, 160), `${label} ASN description is unsafe or malformed.`);
  assert(isNullableText(value.asnRegistry, 32), `${label} ASN registry is unsafe or malformed.`);
  assert(
    value.ipAddress !== null || value.asn !== null || value.asnDescription !== null || value.asnRegistry !== null,
    `${label} contains an empty network object.`,
  );
}

function verifyAssessmentDetail(value, label) {
  if (value === null) return;
  assert(hasExactFields(value, assessmentFields), `${label} assessment does not use the exact version-1 fields.`);
  assert(
    value.urlscanVerdictScore === null ||
      (Number.isInteger(value.urlscanVerdictScore) &&
        value.urlscanVerdictScore >= -100 &&
        value.urlscanVerdictScore <= 100),
    `${label} URLScan verdict score is malformed.`,
  );
  assert(
    Array.isArray(value.urlscanCategories) &&
      value.urlscanCategories.length <= 8 &&
      new Set(value.urlscanCategories).size === value.urlscanCategories.length &&
      value.urlscanCategories.every(
        (category) => typeof category === "string" && /^[a-z\d](?:[a-z\d-]{0,30}[a-z\d])?$/u.test(category),
      ),
    `${label} URLScan categories are malformed.`,
  );
  assert(
    value.redirectedToDomain === null ||
      (typeof value.redirectedToDomain === "string" &&
        value.redirectedToDomain.length <= 505 &&
        value.redirectedToDomain.includes("[.]") &&
        !/[@/?#:\\]/u.test(value.redirectedToDomain)),
    `${label} redirect destination is not a defanged domain.`,
  );
  assert(
    value.urlscanVerdictScore !== null ||
      value.urlscanCategories.length > 0 ||
      value.redirectedToDomain !== null,
    `${label} contains an empty assessment object.`,
  );
}

function verifyCertificateDetail(value, label) {
  if (value === null) return;
  assert(hasExactFields(value, certificateFields), `${label} certificate does not use the exact version-1 fields.`);
  assert(
    hasExactFields(value.fingerprints, fingerprintFields),
    `${label} certificate fingerprints do not use the exact version-1 fields.`,
  );
  assert(isNullableHex(value.fingerprints.md5, 32), `${label} certificate MD5 is malformed.`);
  assert(isNullableHex(value.fingerprints.sha1, 40), `${label} certificate SHA-1 is malformed.`);
  assert(isNullableHex(value.fingerprints.sha256, 64), `${label} certificate SHA-256 is malformed.`);
  assert(
    value.countryName === null || (typeof value.countryName === "string" && /^[A-Z]{2}$/u.test(value.countryName)),
    `${label} certificate country is malformed.`,
  );
  assert(isNullableText(value.issuer, 200), `${label} certificate issuer is unsafe or malformed.`);
  assert(
    value.commonName === null ||
      (typeof value.commonName === "string" &&
        value.commonName.length <= 509 &&
        !/[@/?#:\\]/u.test(value.commonName) &&
        value.commonName.includes("[.]")),
    `${label} certificate common name is not defanged.`,
  );
  const notBefore = value.notBefore === null ? null : timestampValue(value.notBefore);
  const notAfter = value.notAfter === null ? null : timestampValue(value.notAfter);
  assert(value.notBefore === null || notBefore !== null, `${label} certificate not-before timestamp is malformed.`);
  assert(value.notAfter === null || notAfter !== null, `${label} certificate not-after timestamp is malformed.`);
  assert(notBefore === null || notAfter === null || notBefore <= notAfter, `${label} certificate validity range is reversed.`);
  assert(
    Array.isArray(value.subjectAltNames) &&
      value.subjectAltNames.length <= 12 &&
      new Set(value.subjectAltNames).size === value.subjectAltNames.length &&
      value.subjectAltNames.every(
        (name) => typeof name === "string" && name.length <= 509 && !/[@/?#:\\]/u.test(name) && name.includes("[.]"),
      ),
    `${label} certificate subject alternative names are malformed.`,
  );
  assert(
    Number.isInteger(value.subjectAltNameCount) &&
      value.subjectAltNameCount >= value.subjectAltNames.length &&
      value.subjectAltNameCount <= 500,
    `${label} certificate subject alternative name count is malformed.`,
  );
  assert(
    value.serialNumberHex === null ||
      (typeof value.serialNumberHex === "string" &&
        value.serialNumberHex.length >= 1 &&
        value.serialNumberHex.length <= 80 &&
        lowerHex.test(value.serialNumberHex)),
    `${label} certificate serial number is malformed.`,
  );
  assert(
    value.countryName !== null ||
      value.issuer !== null ||
      value.commonName !== null ||
      value.notBefore !== null ||
      value.notAfter !== null ||
      value.subjectAltNameCount > 0 ||
      value.serialNumberHex !== null ||
      Object.values(value.fingerprints).some((fingerprint) => fingerprint !== null),
    `${label} contains an empty certificate object.`,
  );
}

function verifyObservation(value, signal, generatedAt, label) {
  assert(hasExactFields(value, observationFields), `${label} does not use the exact version-1 fields.`);
  assert(value.source === "URLScan" || value.source === "CertStream", `${label} source is unsupported.`);
  assert(signal.sources.includes(value.source), `${label} source is absent from its live signal.`);
  const observedAt = timestampValue(value.observedAt);
  assert(observedAt !== null && observedAt <= generatedAt + 5 * 60 * 1000, `${label} timestamp is malformed or in the future.`);
  verifyPageDetail(value.page, label);
  verifyNetworkDetail(value.network, label);
  verifyAssessmentDetail(value.assessment, label);
  verifyCertificateDetail(value.certificate, label);
  if (value.source === "CertStream") {
    assert(
      value.page === null && value.network === null && value.assessment === null && value.certificate !== null,
      `${label} exposes fields CertStream does not supply.`,
    );
  } else {
    assert(
      value.page !== null || value.network !== null || value.assessment !== null || value.certificate !== null,
      `${label} contains no URLScan evidence.`,
    );
  }
}

function verifySignalDetails() {
  const snapshot = JSON.parse(readFileSync(join(output, "data", "radar.json"), "utf8"));
  assert(Array.isArray(snapshot.signals), "Built radar.json has no signal list for sidecar verification.");
  const signals = new Map();
  const expected = new Map();
  for (const signal of snapshot.signals) {
    assert(isRecord(signal) && signalIdentifier.test(signal.id), "Built radar.json contains an invalid signal identifier.");
    assert(!signals.has(signal.id), `Built radar.json contains duplicate signal ${signal.id}.`);
    signals.set(signal.id, signal);
    if (signal.detailAvailable === true) {
      expected.set(`data/signals/${signal.id.slice(0, 2)}/${signal.id}.json`, signal);
    }
  }

  const detailRoot = join(output, "data", "signals");
  const files = existsSync(detailRoot) ? walk(detailRoot) : [];
  let totalBytes = 0;
  for (const path of files) {
    const relativePath = relative(output, path).split(sep).join("/");
    assert(
      /^data\/signals\/[a-f\d]{2}\/[a-f\d]{20}\.json$/u.test(relativePath),
      `Unexpected file inside the signal-detail tree: ${relativePath}.`,
    );
    const signal = expected.get(relativePath);
    assert(signal, `${relativePath} is an orphan sidecar without detailAvailable=true.`);
    const byteLength = statSync(path).size;
    assert(byteLength > 0, `${relativePath} is empty.`);
    assert(byteLength <= signalDetailFileRawBytes, `${relativePath} is larger than 16 KiB.`);
    totalBytes += byteLength;
    assert(totalBytes <= signalDetailSetRawBytes, "Signal-detail sidecars exceed the 3 MiB aggregate budget.");

    let detail;
    try {
      detail = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new Error(`${relativePath} is not valid UTF-8 JSON.`);
    }
    assert(
      hasRequiredAndOptionalFields(detail, detailFields, ["domainContext"]),
      `${relativePath} does not use the allowed version-1 top-level fields.`,
    );
    assert(detail.schemaVersion === 1 && detail.dataset === "signal-detail", `${relativePath} has the wrong schema identity.`);
    assert(detail.signalId === signal.id && detail.domain === signal.domain, `${relativePath} does not match its live signal.`);
    const generatedAt = timestampValue(detail.generatedAt);
    assert(generatedAt !== null, `${relativePath} has an invalid generatedAt timestamp.`);
    assert(
      Array.isArray(detail.observations) && detail.observations.length <= 2,
      `${relativePath} must contain at most two observations.`,
    );
    detail.observations.forEach((observation, index) =>
      verifyObservation(observation, signal, generatedAt, `${relativePath} observation ${index + 1}`),
    );
    assert(
      new Set(detail.observations.map((observation) => observation.source)).size === detail.observations.length,
      `${relativePath} contains duplicate observation sources.`,
    );
    if (Object.hasOwn(detail, "domainContext")) {
      verifyDomainContext(detail.domainContext, generatedAt, `${relativePath} domain context`);
    }
    assert(
      detail.observations.length > 0 || Object.hasOwn(detail, "domainContext"),
      `${relativePath} has neither a source observation nor DNS/RDAP context.`,
    );
    expected.delete(relativePath);
  }
  assert(expected.size === 0, `Missing signal-detail sidecars: ${[...expected.keys()].join(", ")}.`);
  return { files, totalBytes };
}

function assertPublicFeedUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is not an absolute URL.`);
  }
  assert(parsed.protocol === "https:" && parsed.origin === publicOrigin, `${label} leaves the canonical Radar origin.`);
  assert(!parsed.username && !parsed.password && !parsed.search && !parsed.hash, `${label} contains unsafe URL components.`);
  return parsed;
}

function verifySyndicationFeeds() {
  const directory = JSON.parse(readFileSync(join(output, "data", "brand-feeds.json"), "utf8"));
  const registry = JSON.parse(readFileSync(join(root, "data", "brands-lt.json"), "utf8"));
  assert(directory?.dataset === "radar-brand-feeds" && Array.isArray(directory.brands), "Brand feed directory is malformed.");
  assert(directory.brands.length === registry.entries.length, "Brand feed directory does not cover every reviewed brand.");
  assert(new Set(directory.brands.map((entry) => entry.slug)).size === directory.brands.length, "Brand feed directory contains duplicate slugs.");

  const groups = [
    {
      label: "global",
      atom: "/data/events.atom.xml",
      rss: "/data/events.rss.xml",
      jsonFeed: "/data/events.feed.json",
    },
    ...directory.brands,
  ];
  for (const group of groups) {
    const label = `${group.label ?? group.brand} feed`;
    for (const [format, path] of Object.entries({ atom: group.atom, rss: group.rss, jsonFeed: group.jsonFeed })) {
      assert(typeof path === "string" && path.startsWith("/data/"), `${label} has an invalid ${format} path.`);
      assert(existsSync(outputPath(path)), `${label} ${format} file is missing.`);
      assert(existsSync(outputPath(`${path}.sha256`)), `${label} ${format} checksum is missing.`);
    }

    const atom = new JSDOM(readFileSync(outputPath(group.atom), "utf8"), { contentType: "text/xml" }).window.document;
    assert(!atom.querySelector("parsererror") && atom.documentElement.localName === "feed", `${label} Atom document is malformed.`);
    for (const link of atom.querySelectorAll("link[href]")) {
      assertPublicFeedUrl(link.getAttribute("href"), `${label} Atom link`);
    }

    const rss = new JSDOM(readFileSync(outputPath(group.rss), "utf8"), { contentType: "text/xml" }).window.document;
    assert(!rss.querySelector("parsererror") && rss.documentElement.localName === "rss", `${label} RSS document is malformed.`);
    for (const link of rss.querySelectorAll("channel > link, item > link")) {
      assertPublicFeedUrl(link.textContent?.trim(), `${label} RSS link`);
    }

    const jsonFeed = JSON.parse(readFileSync(outputPath(group.jsonFeed), "utf8"));
    assert(jsonFeed.version === "https://jsonfeed.org/version/1.1" && Array.isArray(jsonFeed.items), `${label} JSON Feed is malformed.`);
    assertPublicFeedUrl(jsonFeed.home_page_url, `${label} JSON Feed home_page_url`);
    assertPublicFeedUrl(jsonFeed.feed_url, `${label} JSON Feed feed_url`);
    for (const item of jsonFeed.items) assertPublicFeedUrl(item.url, `${label} JSON Feed item URL`);
  }
}

function verifyPerformanceBudgets(signalDetails, stixBundle) {
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
  const dataSizes = compressedSizes([
    ...[
      "radar.json",
      "radar.stix.json",
      "history.json",
      "collection-health.json",
      "changes.json",
      "pipeline-health.json",
      "related-observations.json",
      "events.json",
      "events.atom.xml",
      "events.rss.xml",
      "events.feed.json",
      "brand-feeds.json",
      "daily-trends.json",
      "quality-metrics.json",
    ].map((name) => join(output, "data", name)),
    ...walk(join(output, "data", "brands")),
    ...signalDetails.files,
  ]);
  for (const { path, size } of dataSizes) {
    const name = path.replace(/^data\//u, "");
    assert(size <= performanceBudgets.publicDataFileGzip, `data/${name} is ${size} gzip bytes; data budget is ${performanceBudgets.publicDataFileGzip}.`);
  }
  const replaceable = new Set([
    join(output, "data", "radar.json"),
    stixBundle.path,
    join(output, "data", "history.json"),
    join(output, "index.html"),
    join(output, "history", "index.html"),
    ...signalDetails.files,
  ]);
  const fixedBytes = files
    .filter((path) => !replaceable.has(path))
    .reduce((total, path) => total + statSync(path).size, 0);
  const currentHydrationHtmlBytes =
    statSync(join(output, "index.html")).size + statSync(join(output, "history", "index.html")).size;
  const worstCaseOutputBytes =
    fixedBytes +
    2 * publicArtifactRawBytes +
    stixBundleRawBytes +
    currentHydrationHtmlBytes +
    2 * (3 * publicArtifactRawBytes + 1024) +
    signalDetailSetRawBytes;
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
    signalDetailBytes: signalDetails.totalBytes,
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
  const expectedNavigation = mobileNavigationForPath(entry.path);
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

  for (const label of expectedNavigation) {
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

async function fulfillAnalyticsScript(route) {
  await route.fulfill({
    contentType: "application/javascript",
    headers: { "access-control-allow-origin": "*" },
    body: "",
  });
}

async function verifyAccessibility(browser, origin, width) {
  const context = await browser.newContext({ viewport: { width, height: 900 }, bypassCSP: true });
  const page = await context.newPage();
  await page.route("https://static.cloudflareinsights.com/beacon.min.js", fulfillAnalyticsScript);
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

async function verifySignalDialog(browser, origin, width, language) {
  const rootPath = language === "lt" ? "/lt/" : "/";
  const permanentPrefix = language === "lt" ? "/lt/signalai/" : "/signals/";
  const closeLabel = language === "lt" ? "Užverti signalo informaciją" : "Close signal details";
  const context = await browser.newContext({ viewport: { width, height: 900 }, bypassCSP: true });
  const page = await context.newPage();
  await page.route("https://static.cloudflareinsights.com/beacon.min.js", fulfillAnalyticsScript);
  try {
    await page.goto(`${origin}${rootPath}`, { waitUntil: "networkidle" });
    const firstRow = page.locator('.signal-table tbody tr[id^="signal-"]').first();
    const candidateTrigger = firstRow.locator("button.candidate-link");
    const timelineTrigger = firstRow.locator("button.record-link");
    const permanentPath = await firstRow.locator("a.signal-deep-link").getAttribute("href");
    assert(
      permanentPath?.startsWith(permanentPrefix),
      `${rootPath} signal has no localized permanent record path at ${width}px.`,
    );

    await candidateTrigger.click();
    const dialog = page.locator('[role="dialog"]');
    assert(await dialog.isVisible(), `${rootPath} candidate control did not open a signal dialog at ${width}px.`);
    const closeButton = dialog.locator(`button[aria-label="${closeLabel}"]`);
    assert(await closeButton.count() === 1, `${rootPath} signal dialog does not expose its localized close label at ${width}px.`);
    assert(
      await closeButton.evaluate((element) => element === document.activeElement),
      `${rootPath} signal dialog did not place focus on its localized Close control at ${width}px.`,
    );
    const relevanceRow = dialog.locator(".candidate-provenance-full");
    assert(await relevanceRow.count() === 1, `${rootPath} signal dialog has no full-width Lithuanian relevance row at ${width}px.`);
    const relevanceLayout = await relevanceRow.evaluate((element) => {
      const row = element.getBoundingClientRect();
      const grid = element.parentElement?.getBoundingClientRect();
      return grid ? { rowLeft: row.left, rowRight: row.right, gridLeft: grid.left, gridRight: grid.right } : null;
    });
    assert(
      relevanceLayout &&
        Math.abs(relevanceLayout.rowLeft - relevanceLayout.gridLeft) <= 2 &&
        Math.abs(relevanceLayout.rowRight - relevanceLayout.gridRight) <= 2,
      `${rootPath} Lithuanian relevance does not span the provenance grid at ${width}px: ${JSON.stringify(relevanceLayout)}.`,
    );
    assert(
      await dialog.locator("a.permanent-record-link").getAttribute("href") === permanentPath,
      `${rootPath} signal dialog does not preserve its permanent record path at ${width}px.`,
    );
    if (await dialog.locator(".signal-intelligence").count()) {
      await dialog.locator(".detail-observations, .detail-state.error").first().waitFor({ state: "visible" });
      assert(!(await dialog.locator(".detail-state.error").count()), `${rootPath} signal detail sidecar failed to load at ${width}px.`);
    }

    await page.addScriptTag({ content: axe.source });
    const violations = await page.evaluate(async () => {
      const report = await globalThis.axe.run(document, {
        resultTypes: ["violations"],
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
      });
      return report.violations
        .filter((violation) => violation.impact === "serious" || violation.impact === "critical")
        .map((violation) => ({ id: violation.id, impact: violation.impact, targets: violation.nodes.map((node) => node.target) }));
    });
    assert(violations.length === 0, `${rootPath} open signal dialog has serious accessibility violations at ${width}px: ${JSON.stringify(violations)}`);

    await page.keyboard.press("Escape");
    assert(!(await dialog.count()), `${rootPath} signal dialog did not close with Escape at ${width}px.`);
    assert(await candidateTrigger.evaluate((element) => element === document.activeElement), `${rootPath} signal dialog did not restore candidate focus at ${width}px.`);

    await timelineTrigger.click();
    const reopenedDialog = page.locator('[role="dialog"]');
    assert(await reopenedDialog.isVisible(), `${rootPath} timeline control did not open a signal dialog at ${width}px.`);
    await reopenedDialog.locator(`button[aria-label="${closeLabel}"]`).click();
    assert(!(await reopenedDialog.count()), `${rootPath} signal dialog did not close from its localized Close control at ${width}px.`);
    assert(await timelineTrigger.evaluate((element) => element === document.activeElement), `${rootPath} signal dialog did not restore timeline focus at ${width}px.`);
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
      let analyticsRequests = 0;
      await page.route("https://static.cloudflareinsights.com/beacon.min.js", async (route) => {
        analyticsRequests += 1;
        await fulfillAnalyticsScript(route);
      });
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
          const radarHeroCopy = document.querySelector(".radar-hero .hero-copy")?.getBoundingClientRect();
          const radarFreshness = document.querySelector(".radar-hero .freshness-card")?.getBoundingClientRect();
          const metricGrid = document.querySelector(".activity-strip")?.getBoundingClientRect();
          const contentToc = document.querySelector(".methodology-toc, .docs-toc");
          const contentTocStyle = contentToc ? getComputedStyle(contentToc) : null;
          const longFormCopy = document.querySelector(".methodology-heading > p, .docs-heading > p");
          const longFormStyle = longFormCopy ? getComputedStyle(longFormCopy) : null;
          const docsTableCell = document.querySelector(".docs-table td");
          const docsTableCellStyle = docsTableCell ? getComputedStyle(docsTableCell) : null;
          const methodologyFieldList = document.querySelector(".methodology-field-list");
          const methodologyFields = methodologyFieldList ? [...methodologyFieldList.children] : [];
          const methodologyFieldListRect = methodologyFieldList?.getBoundingClientRect();
          const finalMethodologyFieldRect = methodologyFields.at(-1)?.getBoundingClientRect();
          const penultimateMethodologyFieldRect = methodologyFields.at(-2)?.getBoundingClientRect();
          const candidateCell = document.querySelector(".signal-table .indicator-cell");
          const candidateInner = candidateCell?.querySelector(":scope > div");
          const candidateCellRect = candidateCell?.getBoundingClientRect();
          const candidateControls = candidateInner ? [...candidateInner.querySelectorAll("button, a")] : [];
          const candidateControlsFit = candidateCellRect
            ? candidateControls.every((control) => {
                const rect = control.getBoundingClientRect();
                return rect.width > 0 && rect.left >= candidateCellRect.left - 1 && rect.right <= candidateCellRect.right + 1;
              })
            : true;
          const signalTable = document.querySelector(".signal-table");
          const signalTableRect = signalTable?.getBoundingClientRect();
          const hostNames = [...document.querySelectorAll(".signal-table .host-name")];
          const longestHost = hostNames.sort((left, right) => (right.textContent?.length ?? 0) - (left.textContent?.length ?? 0))[0];
          const hostingCellRect = longestHost?.closest("td")?.getBoundingClientRect();
          const hostStyle = longestHost ? getComputedStyle(longestHost) : null;
          const overviewBlocks = [
            ["hero", ".radar-hero"],
            ["activity", ".activity-strip"],
            ["filters", ".filter-shell"],
            ["table", ".table-panel"],
            ["exports", ".export-actions"],
            ["routes", ".radar-route-grid"],
            ["disclosure", ".collection-disclosure"],
          ].map(([name, selector]) => {
            const rect = document.querySelector(selector)?.getBoundingClientRect();
            return rect
              ? { name, width: rect.width, height: rect.height, left: rect.left, right: rect.right }
              : { name, width: 0, height: 0, left: 0, right: 0 };
          });
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
            radarHeroCopyWidth: radarHeroCopy?.width ?? 0,
            radarHeroCopyBottom: radarHeroCopy?.bottom ?? 0,
            radarFreshnessTop: radarFreshness?.top ?? 0,
            radarFreshnessWidth: radarFreshness?.width ?? 0,
            metricTop: metricGrid?.top ?? 0,
            contentTocBorderTop: contentTocStyle?.borderTop ?? "",
            contentTocBorderBottom: contentTocStyle?.borderBottom ?? "",
            longFormAlign: longFormStyle?.textAlign ?? "",
            longFormAlignLast: longFormStyle?.textAlignLast ?? "",
            longFormHyphens: longFormStyle?.hyphens ?? "",
            docsTableCellAlign: docsTableCellStyle?.textAlign ?? "",
            methodologyFieldCount: methodologyFields.length,
            methodologyFieldListLeft: methodologyFieldListRect?.left ?? 0,
            methodologyFieldListRight: methodologyFieldListRect?.right ?? 0,
            finalMethodologyFieldLeft: finalMethodologyFieldRect?.left ?? 0,
            finalMethodologyFieldRight: finalMethodologyFieldRect?.right ?? 0,
            penultimateMethodologyFieldLeft: penultimateMethodologyFieldRect?.left ?? 0,
            penultimateMethodologyFieldRight: penultimateMethodologyFieldRect?.right ?? 0,
            candidateControlCount: candidateControls.length,
            candidateControlsFit,
            candidateInnerClientWidth: candidateInner?.clientWidth ?? 0,
            candidateInnerScrollWidth: candidateInner?.scrollWidth ?? 0,
            hostingColumnRatio: signalTableRect && hostingCellRect ? hostingCellRect.width / signalTableRect.width : 0,
            hostOverflowX: hostStyle?.overflowX ?? "",
            hostOverflowY: hostStyle?.overflowY ?? "",
            hostClientHeight: longestHost?.clientHeight ?? 0,
            hostScrollHeight: longestHost?.scrollHeight ?? 0,
            overviewBlocks,
          };
        });
        const overview = entry.path === "/" || entry.path === "/lt/";
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
        if (overview) {
          for (const block of layout.overviewBlocks) {
            assert(
              block.width > 0 && block.height > 0,
              `${entry.path} ${block.name} block has no rendered geometry at ${width}px.`,
            );
            assert(
              block.left >= -1 && block.right <= layout.clientWidth + 1,
              `${entry.path} ${block.name} block escapes the viewport at ${width}px (${block.left}-${block.right}).`,
            );
          }
        }
        if (width === 1440 && overview) {
          assert(layout.heroHeight > 0 && layout.heroHeight <= 430, `Radar hero is ${layout.heroHeight}px at 1440x900; budget is 430px.`);
          assert(layout.metricTop > 0 && layout.metricTop < 760, `Radar summary starts below useful 1440x900 content at ${layout.metricTop}px.`);
          assert(
            layout.hostingColumnRatio >= 0.21 && layout.hostingColumnRatio <= 0.23,
            `Radar hosting column uses ${(layout.hostingColumnRatio * 100).toFixed(1)}% of the table at 1440px instead of 22%.`,
          );
          assert(
            layout.hostOverflowX !== "hidden" &&
              layout.hostOverflowY !== "hidden" &&
              layout.hostScrollHeight <= layout.hostClientHeight + 1,
            "Radar hosting evidence is clipped instead of visibly wrapped.",
          );
        }
        if (width <= 760 && overview) {
          assert(
            layout.radarHeroCopyWidth >= layout.clientWidth * 0.8,
            `Radar hero copy is squeezed to ${layout.radarHeroCopyWidth}px at ${width}px.`,
          );
          assert(
            layout.radarFreshnessWidth >= layout.clientWidth * 0.8,
            `Radar freshness card is squeezed to ${layout.radarFreshnessWidth}px at ${width}px.`,
          );
          assert(
            layout.radarFreshnessTop >= layout.radarHeroCopyBottom - 1,
            `Radar freshness card overlaps the hero copy at ${width}px.`,
          );
          assert(
            layout.candidateControlCount === 3 &&
              layout.candidateControlsFit &&
              layout.candidateInnerScrollWidth <= layout.candidateInnerClientWidth + 1,
            `Radar candidate controls overflow their mobile card at ${width}px.`,
          );
        }
        if (["/methodology/", "/lt/metodologija/", "/docs/", "/lt/dokumentacija/"].includes(entry.path)) {
          assert(
            layout.contentTocBorderTop === layout.contentTocBorderBottom && layout.contentTocBorderTop.startsWith("1px solid "),
            `${entry.path} content navigation dividers are not a matching 1px pair at ${width}px ` +
              `(${layout.contentTocBorderTop || "none"}/${layout.contentTocBorderBottom || "none"}).`,
          );
          assert(
            layout.longFormAlign === "justify" && layout.longFormAlignLast === "left" && layout.longFormHyphens === "auto",
            `${entry.path} long-form prose alignment drifted at ${width}px ` +
              `(${layout.longFormAlign}/${layout.longFormAlignLast}/${layout.longFormHyphens}).`,
          );
          if (entry.path === "/docs/" || entry.path === "/lt/dokumentacija/") {
            assert(layout.docsTableCellAlign !== "justify", `Documentation table cells inherited prose justification at ${width}px.`);
          }
        }
        if (entry.path === "/methodology/" || entry.path === "/lt/metodologija/") {
          assert(layout.methodologyFieldCount === 8, `Methodology field reference has ${layout.methodologyFieldCount} entries instead of 8.`);
          if (width <= 760) {
            assert(
              Math.abs(layout.finalMethodologyFieldLeft - (layout.methodologyFieldListLeft + 1)) <= 1 &&
                Math.abs(layout.finalMethodologyFieldRight - (layout.methodologyFieldListRight - 1)) <= 1,
              `Methodology field grid exposes an empty final cell at ${width}px.`,
            );
          } else {
            assert(
              Math.abs(layout.penultimateMethodologyFieldLeft - (layout.methodologyFieldListLeft + 1)) <= 1 &&
                Math.abs(layout.finalMethodologyFieldRight - (layout.methodologyFieldListRight - 1)) <= 1 &&
                Math.abs(layout.finalMethodologyFieldLeft - layout.penultimateMethodologyFieldRight) <= 2,
              `Methodology field grid does not fill its final two-column row at ${width}px.`,
            );
          }
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
          const expectedMobileNavigation = mobileNavigationForPath(entry.path);
          const summary = page.locator(".mobile-navigation summary");
          assert(await summary.isVisible(), `${entry.path} mobile menu is not reachable at ${width}px.`);
          await verifyMobileKeyboardNavigation(page, entry, width);
          await summary.click();
          for (const label of expectedMobileNavigation) {
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
          for (const label of productNavigationForPath(entry.path)) {
            assert(
              await page.locator(".product-navigation a", { hasText: label }).isVisible(),
              `${entry.path} desktop product navigation hides ${label} at ${width}px.`,
            );
          }
          assert(await page.locator(".header-utility .source-link").isVisible(), `${entry.path} desktop Source utility is hidden at ${width}px.`);
        }

        if (width === 1440 && overview) {
          const sourceLabel = entry.path === "/lt/" ? "Šaltinis" : "Source";
          await page.locator("#signal-search").fill("private local search");
          assert(!page.url().includes("private") && !page.url().includes("query="), `${entry.path} free-text signal search leaked into the URL.`);
          await page.locator(`select[aria-label="${sourceLabel}"]`).selectOption("CertStream");
          assert(
            page.url().includes("source=CertStream") && !page.url().includes("private"),
            `${entry.path} controlled source filter did not produce a safe shareable URL.`,
          );
          assert(
            await page.locator(".export-actions button", { hasText: "CSV" }).isVisible(),
            `${entry.path} defanged CSV export is not visible.`,
          );
        }

        assert(browserErrors.length === 0, `${entry.path} failed its CSP-enforced browser smoke check at ${width}px: ${browserErrors.join(" | ")}`);
        page.off("console", onConsole);
        page.off("pageerror", onPageError);
      }
      assert(
        analyticsRequests === (analyticsToken ? pages.length : 0),
        `Cloudflare Web Analytics loaded ${analyticsRequests} times for ${pages.length} pages at ${width}px.`,
      );
      await context.close();
      if (width === 390 || width === 1024) {
        await verifyAccessibility(browser, origin, width);
        await verifySignalDialog(browser, origin, width, "en");
        await verifySignalDialog(browser, origin, width, "lt");
      }
    }

    const delayedContext = await browser.newContext({ viewport: { width: 390, height: 900 } });
    const delayedPage = await delayedContext.newPage();
    await delayedPage.route("https://static.cloudflareinsights.com/beacon.min.js", fulfillAnalyticsScript);
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

    const dntContext = await browser.newContext({ viewport: { width: 390, height: 900 } });
    await dntContext.addInitScript(() => {
      Object.defineProperty(navigator, "doNotTrack", { configurable: true, get: () => "1" });
      Object.defineProperty(window, "doNotTrack", { configurable: true, value: "1" });
    });
    const dntPage = await dntContext.newPage();
    let dntAnalyticsRequests = 0;
    await dntPage.route("https://static.cloudflareinsights.com/beacon.min.js", async (route) => {
      dntAnalyticsRequests += 1;
      await route.abort();
    });
    for (const entry of pages) {
      await dntPage.goto(`${origin}${entry.path}`, { waitUntil: "networkidle" });
    }
    assert(dntAnalyticsRequests === 0, "Cloudflare Web Analytics loaded despite the browser's Do Not Track signal.");
    await dntContext.close();

    const noScriptContext = await browser.newContext({ viewport: { width: 390, height: 900 }, javaScriptEnabled: false });
    const noScriptPage = await noScriptContext.newPage();
    for (const entry of pages) {
      await noScriptPage.goto(`${origin}${entry.path}`, { waitUntil: "load" });
      assert(await noScriptPage.locator("main#main-content").isVisible(), `${entry.path} has no visible no-JS main content.`);
      assert((await noScriptPage.locator("body").innerText()).includes(entry.marker), `${entry.path} loses core content without JavaScript.`);
      const summary = noScriptPage.locator(".mobile-navigation summary");
      await summary.click();
      const methodologyLabel = entry.path.startsWith("/lt/") ? "Metodologija" : "Methodology";
      assert(await noScriptPage.locator(".mobile-navigation-panel a", { hasText: methodologyLabel }).isVisible(), `${entry.path} no-JS menu does not open.`);
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
const signalDetails = verifySignalDetails();
const stixBundle = verifyStixBundle();
verifySyndicationFeeds();
const performance = verifyPerformanceBudgets(signalDetails, stixBundle);
await verifyInBrowser();
process.stdout.write(
  `Measured production sizes: ${performance.totalBytes} bytes total; ` +
    `${performance.html.path} ${performance.html.size} bytes gzip (largest HTML); ` +
    `${performance.javascript.path} ${performance.javascript.size} bytes gzip (largest JavaScript); ` +
    `${performance.stylesheet.path} ${performance.stylesheet.size} bytes gzip (largest stylesheet); ` +
    `${performance.executableBytes} bytes gzip JavaScript/CSS total; ` +
    `${performance.publicData.path} ${performance.publicData.size} bytes gzip (largest public JSON); ` +
    `${performance.signalDetailBytes} bytes across signal-detail sidecars; ` +
    `${performance.worstCaseOutputBytes} bytes maximum proven output.\n`,
);
process.stdout.write(`Verified ${pages.length} hydratable static pages at ${widths.join(", ")}px with links, fragments, metadata, CSP, delayed-refresh retention, no-JS content, keyboard navigation, overflow, focus, and accessibility checks.\n`);
