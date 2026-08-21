export const SIGNAL_STATUSES = [
  "active",
  "suspected",
  "offline",
  "mitigated",
  "unknown",
] as const;

export type SignalStatus = (typeof SIGNAL_STATUSES)[number];

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
