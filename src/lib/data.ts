import { SIGNAL_STATUSES, type RadarSignal, type RadarSnapshot, type RadarSource } from "../types";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isStringOrNull = (value: unknown): value is string | null => value === null || typeof value === "string";

function isSignal(value: unknown): value is RadarSignal {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    typeof value.url === "string" &&
    typeof value.domain === "string" &&
    typeof value.firstSeen === "string" &&
    typeof value.lastSeen === "string" &&
    Array.isArray(value.sources) &&
    value.sources.every((source) => typeof source === "string") &&
    typeof value.status === "string" &&
    SIGNAL_STATUSES.includes(value.status as RadarSignal["status"]) &&
    isStringOrNull(value.brand) &&
    isStringOrNull(value.country) &&
    isStringOrNull(value.host) &&
    isStringOrNull(value.screenshotUrl) &&
    typeof value.confidence === "number" &&
    value.confidence >= 0 &&
    value.confidence <= 100
  );
}

function isSource(value: unknown): value is RadarSource {
  if (!isRecord(value)) return false;
  return (
    typeof value.name === "string" &&
    typeof value.homepage === "string" &&
    isStringOrNull(value.fetchedAt) &&
    typeof value.records === "number" &&
    (value.state === "healthy" || value.state === "partial" || value.state === "skipped") &&
    isStringOrNull(value.note)
  );
}

export function parseSnapshot(value: unknown): RadarSnapshot {
  if (
    !isRecord(value) ||
    value.schemaVersion !== 1 ||
    (value.dataset !== "demo" && value.dataset !== "live") ||
    typeof value.generatedAt !== "string" ||
    !Array.isArray(value.signals) ||
    !value.signals.every(isSignal) ||
    !Array.isArray(value.sources) ||
    !value.sources.every(isSource)
  ) {
    throw new Error("The radar snapshot does not match schema version 1.");
  }
  return value as RadarSnapshot;
}

export async function loadSnapshot(signal?: AbortSignal): Promise<RadarSnapshot> {
  const response = await fetch("/data/radar.json", {
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal,
  });
  if (!response.ok) throw new Error(`Snapshot request failed with HTTP ${response.status}.`);
  return parseSnapshot(await response.json());
}
