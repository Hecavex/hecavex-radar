/* global URL, console, structuredClone */

import { readFile } from "node:fs/promises";

import { parseSnapshot } from "../src/lib/data.ts";
import { parseCollectionHealth } from "../src/lib/collectionHealth.ts";

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

const relayedCollectionHealth = await readJson("../tests/fixtures/collection-health-v1-relayed.json");
const parsedCollectionHealth = parseCollectionHealth(relayedCollectionHealth);
if (
  parsedCollectionHealth.latestAttempt?.trigger !== "cadence-relay" ||
  parsedCollectionHealth.latestAttempt.scheduleStatus !== "relayed"
) {
  throw new Error("The browser loader did not preserve CertStream relay provenance.");
}

const scheduledCollectionHealth = structuredClone(relayedCollectionHealth);
Object.assign(scheduledCollectionHealth.latestAttempt, {
  trigger: "schedule",
  scheduledFor: scheduledCollectionHealth.latestAttempt.startedAt,
  scheduleStatus: "scheduled",
  delaySeconds: 0,
});
parseCollectionHealth(scheduledCollectionHealth);

const invalidCollectionHealth = [
  ["schedule trigger with relay status", { trigger: "schedule", scheduleStatus: "relayed" }],
  ["relay trigger with unknown status", { trigger: "cadence-relay", scheduleStatus: "unknown" }],
  ["manual trigger with unknown status", { trigger: "manual", scheduleStatus: "unknown" }],
  ["unknown trigger with manual status", { trigger: "unknown", scheduleStatus: "manual" }],
  ["scheduled attempt with an inaccurate delay", {
    trigger: "schedule",
    scheduledFor: scheduledCollectionHealth.latestAttempt.startedAt,
    scheduleStatus: "scheduled",
    delaySeconds: 1,
  }],
];
for (const [label, attemptPatch] of invalidCollectionHealth) {
  const invalid = structuredClone(relayedCollectionHealth);
  Object.assign(invalid.latestAttempt, attemptPatch);
  let rejected = false;
  try {
    parseCollectionHealth(invalid);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error(`The browser loader accepted ${label}.`);
}

console.log("Validated live snapshot v2 compatibility, exact collection-health scheduling provenance, and unsupported-version rejection in the browser loader.");
