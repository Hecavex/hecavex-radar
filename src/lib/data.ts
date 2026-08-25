import {
  BRAND_EVIDENCE_VALUES,
  EVIDENCE_TIERS,
  CORROBORATION_METHODS,
  DISCOVERY_METHODS,
  LT_RELEVANCE_VALUES,
  REASON_CODES,
  REVIEW_STATES,
  SIGNAL_STATUSES,
  type RadarSignal,
  type RadarSnapshot,
  type RadarSource,
} from "../types.ts";
import { readBoundedJson } from "./boundedJson.ts";

const MAXIMUM_SNAPSHOT_BYTES = 512 * 1024;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DEFANGED_DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\[\.\])+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
const DEFANGED_URL = /^hxxps?:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\[\.\])+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::[0-9]{1,5})?(?:\/[A-Za-z0-9%:@!$&'()*+,;=._~\u005b\u005d\x2f\x2d]*)?$/;
const URLSCAN_SCREENSHOT =
  /^https:\/\/urlscan\.io\/screenshots\/[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}\.png$/i;
const SOURCE_HOMEPAGES: Record<string, string> = {
  CertStream: "https://certstream.dev/",
  URLScan: "https://urlscan.io/",
  HECAVEX: "https://hecavex.com/",
};
const SNAPSHOT_FIELDS = ["schemaVersion", "dataset", "generatedAt", "lastSuccessfulSyncAt", "signals", "sources"] as const;
const SIGNAL_FIELDS = [
  "id", "url", "domain", "firstSeen", "lastSeen", "sources", "status", "brand", "country", "host",
  "screenshotUrl", "referenceUrl", "hashes", "brandEvidence", "reasonCodes", "discoveredVia", "corroboratedBy",
  "detailAvailable", "matchScore", "evidenceTier", "reviewState", "ltRelevance", "confidence",
] as const;
const SOURCE_FIELDS = ["name", "homepage", "fetchedAt", "records", "state", "note"] as const;

const hasOnlyFields = (value: Record<string, unknown>, allowed: readonly string[], required: readonly string[]): boolean => {
  const allowedSet = new Set(allowed);
  return required.every((field) => Object.hasOwn(value, field)) && Object.keys(value).every((field) => allowedSet.has(field));
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

const isControlledMethods = (value: unknown, methods: readonly string[]): boolean =>
  value === undefined ||
  (Array.isArray(value) && value.length <= methods.length && new Set(value).size === value.length &&
    value.every((method) => typeof method === "string" && methods.includes(method)));

const isBoundedTextOrNull = (value: unknown, maximum: number): value is string | null =>
  value === null || (typeof value === "string" && value.length <= maximum);

const isBrandEvidence = (value: unknown): boolean =>
  value === undefined ||
  (Array.isArray(value) &&
    value.length <= BRAND_EVIDENCE_VALUES.length &&
    new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && BRAND_EVIDENCE_VALUES.includes(item as typeof BRAND_EVIDENCE_VALUES[number])));

function isSignal(value: unknown): value is RadarSignal {
  if (!isRecord(value)) return false;
  const firstSeen = timestampValue(value.firstSeen);
  const lastSeen = timestampValue(value.lastSeen);
  const score = value.matchScore ?? value.confidence;
  const urlDomain = typeof value.url === "string"
    ? value.url.replace(/^hxxps?:\/\//, "").split(/[/:]/, 1)[0]
    : null;
  return (
    hasOnlyFields(value, SIGNAL_FIELDS, [
      "id", "url", "domain", "firstSeen", "lastSeen", "sources", "status", "brand", "country", "host",
      "screenshotUrl", "matchScore", "evidenceTier", "reviewState", "ltRelevance", "confidence",
    ]) &&
    typeof value.id === "string" &&
    /^[a-f\d]{20}$/.test(value.id) &&
    typeof value.url === "string" &&
    value.url.length <= 2048 &&
    DEFANGED_URL.test(value.url) &&
    typeof value.domain === "string" &&
    value.domain.length <= 512 &&
    DEFANGED_DOMAIN.test(value.domain) &&
    urlDomain === value.domain &&
    firstSeen !== null &&
    lastSeen !== null &&
    firstSeen <= lastSeen &&
    Array.isArray(value.sources) &&
    value.sources.length >= 1 &&
    value.sources.length <= 3 &&
    new Set(value.sources).size === value.sources.length &&
    value.sources.every((source) => typeof source === "string" && SOURCE_HOMEPAGES[source] !== undefined) &&
    typeof value.status === "string" &&
    SIGNAL_STATUSES.includes(value.status as RadarSignal["status"]) &&
    isBoundedTextOrNull(value.brand, 120) &&
    isBoundedTextOrNull(value.country, 80) &&
    isBoundedTextOrNull(value.host, 160) &&
    isUrlscanScreenshot(value.screenshotUrl) &&
    isUrlscanReference(value.referenceUrl) &&
    isHashes(value.hashes) &&
    isBrandEvidence(value.brandEvidence) &&
    isReasonCodes(value.reasonCodes) &&
    isControlledMethods(value.discoveredVia, DISCOVERY_METHODS) &&
    isControlledMethods(value.corroboratedBy, CORROBORATION_METHODS) &&
    (value.detailAvailable === undefined || value.detailAvailable === true) &&
    typeof score === "number" &&
    Number.isInteger(score) &&
    score >= 0 &&
    score <= 100 &&
    (value.matchScore === undefined ||
      (typeof value.matchScore === "number" && Number.isInteger(value.matchScore) && value.matchScore >= 0 && value.matchScore <= 100)) &&
    typeof value.confidence === "number" &&
    Number.isInteger(value.confidence) &&
    value.confidence >= 0 &&
    value.confidence <= 100 &&
    value.confidence === value.matchScore &&
    (value.evidenceTier === undefined ||
      (typeof value.evidenceTier === "string" && EVIDENCE_TIERS.includes(value.evidenceTier as typeof EVIDENCE_TIERS[number]))) &&
    (value.reviewState === undefined ||
      (typeof value.reviewState === "string" && REVIEW_STATES.includes(value.reviewState as typeof REVIEW_STATES[number]))) &&
    (value.ltRelevance === undefined ||
      (typeof value.ltRelevance === "string" && LT_RELEVANCE_VALUES.includes(value.ltRelevance as typeof LT_RELEVANCE_VALUES[number])))
  );
}

function isSource(value: unknown): value is RadarSource {
  if (!isRecord(value)) return false;
  const expectedHomepage = typeof value.name === "string" ? SOURCE_HOMEPAGES[value.name] : undefined;
  return (
    hasOnlyFields(value, SOURCE_FIELDS, SOURCE_FIELDS) &&
    expectedHomepage !== undefined &&
    value.homepage === expectedHomepage &&
    (value.fetchedAt === null || timestampValue(value.fetchedAt) !== null) &&
    typeof value.records === "number" &&
    Number.isInteger(value.records) &&
    value.records >= 0 &&
    value.records <= 25_000 &&
    (value.state === "healthy" || value.state === "partial" || value.state === "skipped") &&
    isBoundedTextOrNull(value.note, 240)
  );
}

export function parseSnapshot(value: unknown): RadarSnapshot {
  const generatedAt = isRecord(value) ? timestampValue(value.generatedAt) : null;
  const lastSuccessfulSyncAt = isRecord(value) ? timestampValue(value.lastSuccessfulSyncAt) : null;
  if (
    !isRecord(value) ||
    !hasOnlyFields(value, SNAPSHOT_FIELDS, SNAPSHOT_FIELDS) ||
    value.schemaVersion !== 2 ||
    value.dataset !== "live" ||
    generatedAt === null ||
    lastSuccessfulSyncAt === null ||
    generatedAt > lastSuccessfulSyncAt ||
    !Array.isArray(value.signals) ||
    !value.signals.every(isSignal) ||
    !Array.isArray(value.sources) ||
    value.sources.length !== 3 ||
    !value.sources.every(isSource) ||
    new Set(value.sources.map((source) => source.name)).size !== 3
  ) {
    throw new Error("The radar snapshot does not match a supported schema version.");
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
  return parseSnapshot(await readBoundedJson(response, MAXIMUM_SNAPSHOT_BYTES));
}
