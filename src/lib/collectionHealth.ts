import { readBoundedJson } from "./boundedJson.ts";

const MAXIMUM_COLLECTION_HEALTH_BYTES = 32 * 1024;

export const COLLECTION_OUTCOMES = [
  "healthy-empty",
  "healthy-matches",
  "no-input",
  "partial",
  "failed",
] as const;

export type CollectionOutcome = (typeof COLLECTION_OUTCOMES)[number];
export type CollectionScheduleStatus = "scheduled" | "delayed" | "relayed" | "manual" | "unknown";

export type CollectionAttempt = {
  startedAt: string;
  collectorStartedAt: string | null;
  endedAt: string;
  trigger: "schedule" | "cadence-relay" | "manual" | "unknown";
  scheduledFor: string | null;
  scheduleStatus: CollectionScheduleStatus;
  delaySeconds: number | null;
  expectedListeningSeconds: number;
  listeningSeconds: number;
  messages: number;
  dnsNames: number;
  matches: number;
  newRecords: number;
  connectionAttempts: number;
  connections: number;
  outcome: CollectionOutcome;
  summary: string;
};

export type CollectionHealth = {
  schemaVersion: 1;
  dataset: "certstream-collection-health";
  generatedAt: string;
  expectedIntervalSeconds: number;
  staleAfterSeconds: number;
  lastSuccessAt: string | null;
  freshness: {
    status: "current" | "stale" | "unavailable";
    referenceAt: string | null;
    ageSeconds: number | null;
  };
  latestAttempt: CollectionAttempt | null;
};

const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ATTEMPT_KEYS = [
  "startedAt",
  "collectorStartedAt",
  "endedAt",
  "trigger",
  "scheduledFor",
  "scheduleStatus",
  "delaySeconds",
  "expectedListeningSeconds",
  "listeningSeconds",
  "messages",
  "dnsNames",
  "matches",
  "newRecords",
  "connectionAttempts",
  "connections",
  "outcome",
  "summary",
] as const;
const HEALTH_KEYS = [
  "schemaVersion",
  "dataset",
  "generatedAt",
  "expectedIntervalSeconds",
  "staleAfterSeconds",
  "lastSuccessAt",
  "freshness",
  "latestAttempt",
] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

const timestampValue = (value: unknown): number | null => {
  if (typeof value !== "string" || !ISO_UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
};

const isCounter = (value: unknown, maximum = 2_000_000_000): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= maximum;

const isSeconds = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 86_400;

function isAttempt(value: unknown): value is CollectionAttempt {
  if (!isRecord(value) || !hasExactKeys(value, ATTEMPT_KEYS)) return false;
  const startedAt = timestampValue(value.startedAt);
  const collectorStartedAt = value.collectorStartedAt === null ? null : timestampValue(value.collectorStartedAt);
  const validCollectorStart = value.collectorStartedAt === null || collectorStartedAt !== null;
  const endedAt = timestampValue(value.endedAt);
  const scheduledFor = value.scheduledFor === null ? null : timestampValue(value.scheduledFor);
  const scheduled = value.scheduleStatus === "scheduled" || value.scheduleStatus === "delayed";
  const validScheduleProvenance =
    (value.trigger === "schedule" &&
      scheduled &&
      startedAt !== null &&
      scheduledFor !== null &&
      scheduledFor <= startedAt &&
      isCounter(value.delaySeconds, 86_400) &&
      value.delaySeconds === Math.trunc((startedAt - scheduledFor) / 1_000)) ||
    (value.trigger === "cadence-relay" &&
      value.scheduleStatus === "relayed" &&
      value.scheduledFor === null &&
      value.delaySeconds === null) ||
    (value.trigger === "manual" &&
      value.scheduleStatus === "manual" &&
      value.scheduledFor === null &&
      value.delaySeconds === null) ||
    (value.trigger === "unknown" &&
      value.scheduleStatus === "unknown" &&
      value.scheduledFor === null &&
      value.delaySeconds === null);
  return (
    startedAt !== null &&
    validCollectorStart &&
    endedAt !== null &&
    (collectorStartedAt === null || (startedAt <= collectorStartedAt && collectorStartedAt <= endedAt)) &&
    (value.trigger === "schedule" || value.trigger === "cadence-relay" || value.trigger === "manual" || value.trigger === "unknown") &&
    (scheduled || value.scheduleStatus === "relayed" || value.scheduleStatus === "manual" || value.scheduleStatus === "unknown") &&
    validScheduleProvenance &&
    isSeconds(value.expectedListeningSeconds) &&
    isSeconds(value.listeningSeconds) &&
    isCounter(value.messages) &&
    isCounter(value.dnsNames) &&
    isCounter(value.matches) &&
    value.dnsNames >= value.matches &&
    isCounter(value.newRecords) &&
    isCounter(value.connectionAttempts) &&
    isCounter(value.connections) &&
    value.connectionAttempts >= value.connections &&
    typeof value.outcome === "string" &&
    COLLECTION_OUTCOMES.includes(value.outcome as CollectionOutcome) &&
    typeof value.summary === "string" &&
    value.summary.length > 0 &&
    value.summary.length <= 240 &&
    value.summary.trim() === value.summary
  );
}

export function parseCollectionHealth(value: unknown): CollectionHealth {
  if (!isRecord(value) || !hasExactKeys(value, HEALTH_KEYS)) {
    throw new Error("The collection-health artifact does not match schema version 1.");
  }
  const generatedAt = timestampValue(value.generatedAt);
  const lastSuccessAt = value.lastSuccessAt === null ? null : timestampValue(value.lastSuccessAt);
  const freshness = value.freshness;
  const validFreshness =
    isRecord(freshness) &&
    hasExactKeys(freshness, ["status", "referenceAt", "ageSeconds"]) &&
    (freshness.status === "current" || freshness.status === "stale" || freshness.status === "unavailable") &&
    freshness.referenceAt === value.lastSuccessAt &&
    (lastSuccessAt === null
      ? freshness.status === "unavailable" && freshness.ageSeconds === null
      : isCounter(freshness.ageSeconds));
  if (
    value.schemaVersion !== 1 ||
    value.dataset !== "certstream-collection-health" ||
    generatedAt === null ||
    !isCounter(value.expectedIntervalSeconds, 86_400) ||
    !isCounter(value.staleAfterSeconds, 7 * 86_400) ||
    (value.lastSuccessAt !== null && lastSuccessAt === null) ||
    (lastSuccessAt !== null && lastSuccessAt > generatedAt) ||
    !validFreshness ||
    (value.latestAttempt !== null && !isAttempt(value.latestAttempt)) ||
    (value.latestAttempt === null && lastSuccessAt !== null) ||
    (isAttempt(value.latestAttempt) && timestampValue(value.latestAttempt.endedAt)! > generatedAt)
  ) {
    throw new Error("The collection-health artifact does not match schema version 1.");
  }
  return value as CollectionHealth;
}

export async function loadCollectionHealth(signal?: AbortSignal): Promise<CollectionHealth> {
  const response = await fetch("/data/collection-health.json", {
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal,
  });
  if (!response.ok) throw new Error(`Collection-health request failed with HTTP ${response.status}.`);
  return parseCollectionHealth(await readBoundedJson(response, MAXIMUM_COLLECTION_HEALTH_BYTES));
}
