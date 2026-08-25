/* global URL, console */

import { readFile } from "node:fs/promises";

import { parseSnapshot } from "../src/lib/data.ts";

const readJson = async (relative) => JSON.parse(await readFile(new URL(relative, import.meta.url), "utf8"));
const snapshots = [
  ["checked-in live snapshot", await readJson("../public/data/radar.json")],
  ["minimal v2 fixture", await readJson("../tests/fixtures/radar-snapshot-v2-minimal.json")],
];

for (const [label, snapshot] of snapshots) {
  const parsed = parseSnapshot(snapshot);
  if (parsed.schemaVersion !== 2 || parsed.dataset !== "live") {
    throw new Error(`The browser loader did not accept the ${label}.`);
  }
}

for (const unsupportedVersion of [1, 3]) {
  const unsupported = JSON.parse(JSON.stringify(snapshots[1][1]));
  unsupported.schemaVersion = unsupportedVersion;
  let rejected = false;
  try {
    parseSnapshot(unsupported);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error(`The browser loader accepted unsupported snapshot schema v${unsupportedVersion}.`);
  }
}

console.log("Validated live snapshot v2 compatibility and unsupported-version rejection in the browser loader.");
