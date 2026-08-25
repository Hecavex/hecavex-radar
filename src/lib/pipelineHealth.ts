import { readBoundedJson } from "./boundedJson.ts";

const MAXIMUM_PIPELINE_HEALTH_BYTES = 128 * 1024;

export type PipelineOutcome = "completed" | "partial" | "failed" | "empty";

export type PipelineWindow = {
  hours: 24 | 168;
  from: string;
  to: string;
  collection: {
    scheduledSlots: number;
    recordedAttempts: number;
    healthyAttempts: number;
    recordedSchedulePercent: number;
    listeningCoveragePercent: number;
    scheduledListeningCeilingPercent: number;
    expectedListeningSeconds: number;
    listeningSeconds: number;
    messages: number;
    dnsNames: number;
    outcomes: Record<string, number>;
  };
  screening: {
    matches: number;
    newArchiveRecords: number;
    firstPublications: number;
    bySource: Record<string, number>;
  };
  enrichment: {
    observations: number;
    uniqueSignals: number;
    page: number;
    network: number;
    assessment: number;
    certificate: number;
    dns: number;
    rdap: number;
  };
  publication: {
    events: number;
    observations: number;
    statusTransitions: number;
    uniqueSignals: number;
  };
};

export type CtSearchRun = {
  generatedAt: string;
  provider?: "crt.sh";
  latestRun: {
    startedAt: string;
    endedAt: string;
    outcome: PipelineOutcome;
    queriesAttempted: number;
    queriesCompleted: number;
    queriesBacklogged: number;
    rowsProcessed: number;
    dnsNames: number;
    matches: number;
    newRecords: number;
  };
};

export type DomainContextRun = {
  generatedAt: string;
  recordCount: number;
  latestRun: {
    startedAt: string;
    endedAt: string;
    outcome: PipelineOutcome;
    attempted: number;
    completed: number;
  };
};

export type PipelineHealth = {
  schemaVersion: 1;
  dataset: "radar-pipeline-health";
  generatedAt: string;
  privacy: "Aggregate counters only; no candidate names or detector payloads.";
  current: {
    publishedSignals: number;
    ctSearch: CtSearchRun | null;
    domainContext: DomainContextRun | null;
  };
  windows: [PipelineWindow, PipelineWindow];
};

const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TOP_LEVEL_KEYS = ["schemaVersion", "dataset", "generatedAt", "privacy", "current", "windows"] as const;
const CURRENT_KEYS = [
  "publishedSignals",
  "sourceStates",
  "sourceRecords",
  "certstream",
  "urlscan",
  "ctSearch",
  "domainContext",
] as const;
const WINDOW_KEYS = ["hours", "from", "to", "collection", "screening", "enrichment", "publication"] as const;
const COLLECTION_KEYS = [
  "scheduledSlots",
  "recordedAttempts",
  "healthyAttempts",
  "recordedSchedulePercent",
  "listeningCoveragePercent",
  "scheduledListeningCeilingPercent",
  "expectedListeningSeconds",
  "listeningSeconds",
  "messages",
  "dnsNames",
  "outcomes",
] as const;
const SCREENING_KEYS = ["matches", "newArchiveRecords", "firstPublications", "bySource"] as const;
const ENRICHMENT_KEYS = [
  "observations",
  "uniqueSignals",
  "page",
  "network",
  "assessment",
  "certificate",
  "dns",
  "rdap",
] as const;
const PUBLICATION_KEYS = ["events", "observations", "statusTransitions", "uniqueSignals"] as const;
const CT_RUN_KEYS = [
  "startedAt",
  "endedAt",
  "outcome",
  "queriesAttempted",
  "queriesCompleted",
  "queriesBacklogged",
  "rowsProcessed",
  "dnsNames",
  "matches",
  "newRecords",
] as const;
const CONTEXT_RUN_KEYS = ["startedAt", "endedAt", "outcome", "attempted", "completed"] as const;
const CERTSTREAM_KEYS = ["generatedAt", "lastSuccessAt", "freshness", "latestAttempt"] as const;
const CERTSTREAM_ATTEMPT_KEYS = [
  "startedAt",
  "endedAt",
  "outcome",
  "listeningSeconds",
  "messages",
  "dnsNames",
  "matches",
  "newRecords",
] as const;
const URLSCAN_KEYS = ["generatedAt", "configured", "lastOutcome", "lastAttemptAt"] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

const hasExactKeysWithOptional = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean => {
  const actual = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => key in value) && actual.every((key) => permitted.has(key));
};

const timestampValue = (value: unknown): number | null => {
  if (typeof value !== "string" || !ISO_UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
};

const isCounter = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 2_000_000_000;

const isFiniteNumber = (value: unknown, maximum: number): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= maximum;

const isOutcome = (value: unknown): value is PipelineOutcome =>
  value === "completed" || value === "partial" || value === "failed" || value === "empty";

const isCertstreamOutcome = (value: unknown): boolean =>
  value === "healthy-empty" ||
  value === "healthy-matches" ||
  value === "no-input" ||
  value === "partial" ||
  value === "failed";

const isUrlscanOutcome = (value: unknown): boolean =>
  value === "skipped-not-configured" || value === "completed" || value === "budget-limited" || value === "failed";

const isAggregateMap = (value: unknown): value is Record<string, number> =>
  isRecord(value) &&
  Object.keys(value).length <= 64 &&
  Object.entries(value).every(
    ([key, count]) => /^[A-Za-z0-9 ._-]{1,48}$/.test(key) && isCounter(count),
  );

const isSourceStateMap = (value: unknown): boolean =>
  isRecord(value) &&
  Object.keys(value).length <= 16 &&
  Object.entries(value).every(
    ([key, state]) =>
      /^[A-Za-z0-9 ._-]{1,48}$/.test(key) && (state === "healthy" || state === "partial" || state === "skipped"),
  );

function isCertstreamSummary(value: unknown, artifactGeneratedAt: number): boolean {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactKeys(value, CERTSTREAM_KEYS)) return false;
  const generatedAt = timestampValue(value.generatedAt);
  const lastSuccessAt = value.lastSuccessAt === null ? null : timestampValue(value.lastSuccessAt);
  if (
    generatedAt === null ||
    generatedAt > artifactGeneratedAt ||
    (value.lastSuccessAt !== null && lastSuccessAt === null) ||
    (lastSuccessAt !== null && lastSuccessAt > generatedAt)
  ) return false;

  const freshness = value.freshness;
  if (
    !isRecord(freshness) ||
    !hasExactKeys(freshness, ["status", "referenceAt", "ageSeconds"]) ||
    (freshness.status !== "current" && freshness.status !== "stale" && freshness.status !== "unavailable") ||
    freshness.referenceAt !== value.lastSuccessAt ||
    (lastSuccessAt === null
      ? freshness.status !== "unavailable" || freshness.ageSeconds !== null
      : !isCounter(freshness.ageSeconds))
  ) return false;

  const attempt = value.latestAttempt;
  if (attempt === null) return lastSuccessAt === null;
  if (!isRecord(attempt) || !hasExactKeys(attempt, CERTSTREAM_ATTEMPT_KEYS)) return false;
  const startedAt = timestampValue(attempt.startedAt);
  const endedAt = timestampValue(attempt.endedAt);
  return (
    startedAt !== null &&
    endedAt !== null &&
    startedAt <= endedAt &&
    endedAt <= generatedAt &&
    isCertstreamOutcome(attempt.outcome) &&
    isFiniteNumber(attempt.listeningSeconds, 86_400) &&
    CERTSTREAM_ATTEMPT_KEYS.slice(4).every((key) => isCounter(attempt[key]))
  );
}

function isUrlscanSummary(value: unknown, artifactGeneratedAt: number): boolean {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactKeysWithOptional(value, URLSCAN_KEYS, ["lastSuccessAt"])) return false;
  const generatedAt = timestampValue(value.generatedAt);
  const lastAttemptAt = timestampValue(value.lastAttemptAt);
  const lastSuccessAt = value.lastSuccessAt === undefined || value.lastSuccessAt === null
    ? null
    : timestampValue(value.lastSuccessAt);
  return (
    generatedAt !== null &&
    generatedAt <= artifactGeneratedAt &&
    typeof value.configured === "boolean" &&
    isUrlscanOutcome(value.lastOutcome) &&
    lastAttemptAt !== null &&
    lastAttemptAt <= generatedAt &&
    (value.lastSuccessAt === undefined || value.lastSuccessAt === null || lastSuccessAt !== null) &&
    (lastSuccessAt === null || lastSuccessAt <= generatedAt)
  );
}

function parseCtSearch(value: unknown, artifactGeneratedAt: number): CtSearchRun | null {
  if (value === null) return null;
  if (!isRecord(value) || !hasExactKeysWithOptional(value, ["generatedAt", "latestRun"], ["provider"])) return null;
  const generatedAt = timestampValue(value.generatedAt);
  const run = value.latestRun;
  if (
    generatedAt === null ||
    generatedAt > artifactGeneratedAt ||
    (value.provider !== undefined && value.provider !== "crt.sh") ||
    !isRecord(run) ||
    !hasExactKeys(run, CT_RUN_KEYS)
  ) return null;
  const startedAt = timestampValue(run.startedAt);
  const endedAt = timestampValue(run.endedAt);
  if (
    startedAt === null ||
    endedAt === null ||
    startedAt > endedAt ||
    endedAt > generatedAt ||
    !isOutcome(run.outcome) ||
    !CT_RUN_KEYS.slice(3).every((key) => isCounter(run[key])) ||
    Number(run.queriesCompleted) > Number(run.queriesAttempted)
  ) return null;
  return value as CtSearchRun;
}

function parseDomainContext(value: unknown, artifactGeneratedAt: number): DomainContextRun | null {
  if (value === null) return null;
  if (!isRecord(value) || !hasExactKeys(value, ["generatedAt", "latestRun", "recordCount"])) return null;
  const generatedAt = timestampValue(value.generatedAt);
  const run = value.latestRun;
  if (
    generatedAt === null ||
    generatedAt > artifactGeneratedAt ||
    !isCounter(value.recordCount) ||
    !isRecord(run) ||
    !hasExactKeys(run, CONTEXT_RUN_KEYS)
  ) return null;
  const startedAt = timestampValue(run.startedAt);
  const endedAt = timestampValue(run.endedAt);
  if (
    startedAt === null ||
    endedAt === null ||
    startedAt > endedAt ||
    endedAt > generatedAt ||
    !isOutcome(run.outcome) ||
    !isCounter(run.attempted) ||
    !isCounter(run.completed) ||
    run.completed > run.attempted
  ) return null;
  return value as DomainContextRun;
}

function parseWindow(value: unknown, artifactGeneratedAt: number): PipelineWindow | null {
  if (!isRecord(value) || !hasExactKeys(value, WINDOW_KEYS) || (value.hours !== 24 && value.hours !== 168)) return null;
  const from = timestampValue(value.from);
  const to = timestampValue(value.to);
  if (from === null || to === null || to !== artifactGeneratedAt || to - from !== value.hours * 60 * 60 * 1000) return null;

  const collection = value.collection;
  const screening = value.screening;
  const enrichment = value.enrichment;
  const publication = value.publication;
  if (
    !isRecord(collection) ||
    !hasExactKeys(collection, COLLECTION_KEYS) ||
    !COLLECTION_KEYS.slice(0, 3).every((key) => isCounter(collection[key])) ||
    !isFiniteNumber(collection.recordedSchedulePercent, 100) ||
    !isFiniteNumber(collection.listeningCoveragePercent, 100) ||
    !isFiniteNumber(collection.scheduledListeningCeilingPercent, 100) ||
    !isCounter(collection.expectedListeningSeconds) ||
    !isFiniteNumber(collection.listeningSeconds, value.hours * 60 * 60) ||
    !isCounter(collection.messages) ||
    !isCounter(collection.dnsNames) ||
    !isAggregateMap(collection.outcomes) ||
    Number(collection.healthyAttempts) > Number(collection.recordedAttempts)
  ) return null;
  if (
    !isRecord(screening) ||
    !hasExactKeys(screening, SCREENING_KEYS) ||
    !isCounter(screening.matches) ||
    !isCounter(screening.newArchiveRecords) ||
    !isCounter(screening.firstPublications) ||
    !isAggregateMap(screening.bySource)
  ) return null;
  if (
    !isRecord(enrichment) ||
    !hasExactKeys(enrichment, ENRICHMENT_KEYS) ||
    !ENRICHMENT_KEYS.every((key) => isCounter(enrichment[key]))
  ) return null;
  if (
    !isRecord(publication) ||
    !hasExactKeys(publication, PUBLICATION_KEYS) ||
    !PUBLICATION_KEYS.every((key) => isCounter(publication[key]))
  ) return null;
  return value as PipelineWindow;
}

export function parsePipelineHealth(value: unknown): PipelineHealth {
  if (!isRecord(value) || !hasExactKeys(value, TOP_LEVEL_KEYS)) {
    throw new Error("The pipeline-health artifact does not match schema version 1.");
  }
  const generatedAt = timestampValue(value.generatedAt);
  const current = value.current;
  if (
    value.schemaVersion !== 1 ||
    value.dataset !== "radar-pipeline-health" ||
    generatedAt === null ||
    value.privacy !== "Aggregate counters only; no candidate names or detector payloads." ||
    !isRecord(current) ||
    !hasExactKeys(current, CURRENT_KEYS) ||
    !isCounter(current.publishedSignals) ||
    !isSourceStateMap(current.sourceStates) ||
    !isAggregateMap(current.sourceRecords) ||
    !isCertstreamSummary(current.certstream, generatedAt) ||
    !isUrlscanSummary(current.urlscan, generatedAt) ||
    !Array.isArray(value.windows) ||
    value.windows.length !== 2
  ) {
    throw new Error("The pipeline-health artifact does not match schema version 1.");
  }

  const windows = value.windows.map((window) => parseWindow(window, generatedAt));
  if (windows.some((window) => window === null) || new Set(windows.map((window) => window?.hours)).size !== 2) {
    throw new Error("The pipeline-health artifact does not match schema version 1.");
  }
  const ctSearch = parseCtSearch(current.ctSearch, generatedAt);
  const domainContext = parseDomainContext(current.domainContext, generatedAt);
  if ((current.ctSearch !== null && ctSearch === null) || (current.domainContext !== null && domainContext === null)) {
    throw new Error("The pipeline-health artifact does not match schema version 1.");
  }

  return {
    schemaVersion: 1,
    dataset: "radar-pipeline-health",
    generatedAt: value.generatedAt as string,
    privacy: "Aggregate counters only; no candidate names or detector payloads.",
    current: { publishedSignals: current.publishedSignals, ctSearch, domainContext },
    windows: windows as [PipelineWindow, PipelineWindow],
  };
}

export async function loadPipelineHealth(signal?: AbortSignal): Promise<PipelineHealth> {
  const response = await fetch("/data/pipeline-health.json", {
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal,
  });
  if (!response.ok) throw new Error(`Pipeline-health request failed with HTTP ${response.status}.`);
  return parsePipelineHealth(await readBoundedJson(response, MAXIMUM_PIPELINE_HEALTH_BYTES));
}
