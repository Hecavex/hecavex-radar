import { REASON_CODES, SIGNAL_STATUSES, type RadarSignal, type RadarSnapshot, type RadarSource } from "../types.ts";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isStringOrNull = (value: unknown): value is string | null => value === null || typeof value === "string";
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const URLSCAN_SCREENSHOT =
  /^https:\/\/urlscan\.io\/screenshots\/[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}\.png$/i;
const SOURCE_HOMEPAGES: Record<string, string> = {
  CertStream: "https://certstream.dev/",
  URLScan: "https://urlscan.io/",
  HECAVEX: "https://hecavex.com/",
};

const timestampValue = (value: unknown): number | null => {
  if (typeof value !== "string" || !ISO_UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
};

const isUrlscanScreenshot = (value: unknown): value is string | null => {
  if (value === null) return true;
  return typeof value === "string" && URLSCAN_SCREENSHOT.test(value);
};

const isUrlscanReference = (value: unknown): value is string | null | undefined =>
  value === undefined ||
  value === null ||
  (typeof value === "string" && /^https:\/\/urlscan\.io\/result\/[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}\/$/i.test(value));

const isHashes = (value: unknown): value is string[] | undefined =>
  value === undefined ||
  (Array.isArray(value) &&
    value.length <= 8 &&
    value.every(
      (digest) =>
        typeof digest === "string" &&
        /^[a-f\d]{64}$/.test(digest) &&
        digest === digest.toLowerCase() &&
        digest !== EMPTY_SHA256,
    ));

const isReasonCodes = (value: unknown): boolean =>
  value === undefined ||
  (Array.isArray(value) &&
    value.length <= 16 &&
    new Set(value).size === value.length &&
    value.every((reason) => typeof reason === "string" && REASON_CODES.includes(reason as typeof REASON_CODES[number])));

function isSignal(value: unknown): value is RadarSignal {
  if (!isRecord(value)) return false;
  const firstSeen = timestampValue(value.firstSeen);
  const lastSeen = timestampValue(value.lastSeen);
  return (
    typeof value.id === "string" &&
    /^[a-f\d]{20}$/.test(value.id) &&
    typeof value.url === "string" &&
    typeof value.domain === "string" &&
    firstSeen !== null &&
    lastSeen !== null &&
    firstSeen <= lastSeen &&
    Array.isArray(value.sources) &&
    value.sources.every((source) => typeof source === "string" && SOURCE_HOMEPAGES[source] !== undefined) &&
    typeof value.status === "string" &&
    SIGNAL_STATUSES.includes(value.status as RadarSignal["status"]) &&
    isStringOrNull(value.brand) &&
    isStringOrNull(value.country) &&
    isStringOrNull(value.host) &&
    isUrlscanScreenshot(value.screenshotUrl) &&
    isUrlscanReference(value.referenceUrl) &&
    isHashes(value.hashes) &&
    isReasonCodes(value.reasonCodes) &&
    (value.detailAvailable === undefined || value.detailAvailable === true) &&
    typeof value.confidence === "number" &&
    Number.isInteger(value.confidence) &&
    value.confidence >= 0 &&
    value.confidence <= 100
  );
}

function isSource(value: unknown): value is RadarSource {
  if (!isRecord(value)) return false;
  const expectedHomepage = typeof value.name === "string" ? SOURCE_HOMEPAGES[value.name] : undefined;
  return (
    expectedHomepage !== undefined &&
    value.homepage === expectedHomepage &&
    (value.fetchedAt === null || timestampValue(value.fetchedAt) !== null) &&
    typeof value.records === "number" &&
    Number.isInteger(value.records) &&
    value.records >= 0 &&
    (value.state === "healthy" || value.state === "partial" || value.state === "skipped") &&
    isStringOrNull(value.note)
  );
}

export function parseSnapshot(value: unknown): RadarSnapshot {
  const generatedAt = isRecord(value) ? timestampValue(value.generatedAt) : null;
  const lastSuccessfulSyncAt = isRecord(value) ? timestampValue(value.lastSuccessfulSyncAt) : null;
  if (
    !isRecord(value) ||
    value.schemaVersion !== 1 ||
    value.dataset !== "live" ||
    generatedAt === null ||
    lastSuccessfulSyncAt === null ||
    generatedAt > lastSuccessfulSyncAt ||
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
