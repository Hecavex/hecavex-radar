import { readBoundedJson } from "./boundedJson.ts";

export type ChangeWindow = {
  hours: 24 | 168;
  from: string;
  to: string;
  events: number;
  uniqueSignals: number;
  firstPublications: number;
  statusChanges: number;
  observations: number;
  reobservations: number;
  bySource: Record<string, number>;
  byStatus: Record<string, number>;
  byReason: Record<string, number>;
  byBrand: Record<string, number>;
};

export type ChangeAggregate = {
  schemaVersion: 1;
  dataset: "radar-change-aggregate";
  generatedAt: string;
  privacy: "Aggregate counters only; signal-level history remains in history.json.";
  windows: [ChangeWindow, ChangeWindow];
};

const MAXIMUM_ARTIFACT_BYTES = 128 * 1024;
const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
const TOP_LEVEL_KEYS = ["schemaVersion", "dataset", "generatedAt", "privacy", "windows"] as const;
const WINDOW_KEYS = [
  "hours",
  "from",
  "to",
  "events",
  "uniqueSignals",
  "firstPublications",
  "statusChanges",
  "observations",
  "reobservations",
  "bySource",
  "byStatus",
  "byReason",
  "byBrand",
] as const;
const COUNTER_KEYS = [
  "events",
  "uniqueSignals",
  "firstPublications",
  "statusChanges",
  "observations",
  "reobservations",
] as const;
const MAP_KEYS = ["bySource", "byStatus", "byReason", "byBrand"] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  return actual.length === required.length && actual.every((key, index) => key === required[index]);
}

function timestampValue(value: unknown): number | null {
  if (typeof value !== "string" || !ISO_UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function isCounter(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 2_000_000_000;
}

function isCountMap(value: unknown): value is Record<string, number> {
  if (!isRecord(value)) return false;
  const entries = Object.entries(value);
  return entries.length <= 64 && entries.every(([key, count]) => (
    key.length >= 1 &&
    key.length <= 160 &&
    key.trim() === key &&
    !CONTROL_OR_FORMAT.test(key) &&
    isCounter(count)
  ));
}

function parseWindow(value: unknown, generatedAt: number): ChangeWindow | null {
  if (!isRecord(value) || !hasExactKeys(value, WINDOW_KEYS) || (value.hours !== 24 && value.hours !== 168)) {
    return null;
  }
  const from = timestampValue(value.from);
  const to = timestampValue(value.to);
  if (
    from === null ||
    to === null ||
    to !== generatedAt ||
    to - from !== value.hours * 60 * 60 * 1000 ||
    !COUNTER_KEYS.every((key) => isCounter(value[key])) ||
    !MAP_KEYS.every((key) => isCountMap(value[key])) ||
    Number(value.uniqueSignals) > Number(value.events) ||
    Number(value.reobservations) > Number(value.observations)
  ) return null;
  return value as ChangeWindow;
}

export function parseChangeAggregate(value: unknown): ChangeAggregate {
  if (!isRecord(value) || !hasExactKeys(value, TOP_LEVEL_KEYS)) {
    throw new Error("The change aggregate does not match schema version 1.");
  }
  const generatedAt = timestampValue(value.generatedAt);
  if (
    value.schemaVersion !== 1 ||
    value.dataset !== "radar-change-aggregate" ||
    value.privacy !== "Aggregate counters only; signal-level history remains in history.json." ||
    generatedAt === null ||
    !Array.isArray(value.windows) ||
    value.windows.length !== 2
  ) throw new Error("The change aggregate does not match schema version 1.");

  const windows = value.windows.map((window) => parseWindow(window, generatedAt));
  if (
    windows.some((window) => window === null) ||
    new Set(windows.map((window) => window?.hours)).size !== 2
  ) throw new Error("The change aggregate does not match schema version 1.");
  return { ...value, windows: windows as [ChangeWindow, ChangeWindow] } as ChangeAggregate;
}

export async function loadChangeAggregate(signal: AbortSignal): Promise<ChangeAggregate | null> {
  try {
    const response = await fetch("/data/changes.json", {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal,
    });
    if (!response.ok) return null;
    return parseChangeAggregate(await readBoundedJson(response, MAXIMUM_ARTIFACT_BYTES));
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return null;
    return null;
  }
}
