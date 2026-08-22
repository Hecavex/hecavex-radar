export const SIGNAL_STATUSES = [
  "active",
  "suspected",
  "offline",
  "mitigated",
  "unknown",
] as const;

export type SignalStatus = (typeof SIGNAL_STATUSES)[number];

export const REASON_CODES = [
  "brand-domain-match",
  "brand-title-match",
  "provider-verdict",
  "primary-html-hash-pivot",
  "brand-exact-token",
  "brand-joined-affix",
  "brand-split-token",
  "brand-lookalike-edit",
  "suspicious-context",
  "punycode",
  "different-tld",
  "multiple-hyphens",
  "hecavex-public-export",
  "manual-review",
  "first-publication",
  "source-status-change",
] as const;

export type ReasonCode = (typeof REASON_CODES)[number];

export type RadarSignal = {
  id: string;
  url: string;
  domain: string;
  firstSeen: string;
  lastSeen: string;
  sources: string[];
  status: SignalStatus;
  brand: string | null;
  country: string | null;
  host: string | null;
  screenshotUrl: string | null;
  referenceUrl?: string | null;
  hashes?: string[];
  reasonCodes?: ReasonCode[];
  confidence: number;
};

export type SourceState = "healthy" | "partial" | "skipped";

export type RadarSource = {
  name: string;
  homepage: string;
  fetchedAt: string | null;
  records: number;
  state: SourceState;
  note: string | null;
};

export type RadarSnapshot = {
  schemaVersion: 1;
  dataset: "live";
  generatedAt: string;
  signals: RadarSignal[];
  sources: RadarSource[];
};

export type Filters = {
  query: string;
  status: SignalStatus | "all";
  source: string;
  brand: string;
  country: string;
  minimumConfidence: number;
};

export type HistoryTransition = {
  eventId: string;
  observedAt: string;
  previousStatus: SignalStatus | null;
  status: SignalStatus;
  sources: string[];
  reasonCodes: ReasonCode[];
};

export type RadarHistorySignal = {
  id: string;
  domain: string;
  brand: string;
  firstSeen: string;
  lastSeen: string;
  observationCount: number;
  sources: string[];
  latestStatus: SignalStatus;
  reasonCodes: ReasonCode[];
  statusTransitions: HistoryTransition[];
};

export type RadarHistory = {
  schemaVersion: 1;
  dataset: "history";
  generatedAt: string;
  detailRetentionDays: number;
  summaryRetentionDays: number;
  signals: RadarHistorySignal[];
};
