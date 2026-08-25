import type { RelatedObservations } from "./relatedObservations.ts";
import type { RadarHistory, RadarSnapshot } from "../types.ts";

export type RadarEvent = {
  id: string;
  signalId: string;
  type: "first-publication" | "reobservation" | "status-change" | "retraction";
  occurredAt: string;
  domain: string;
  brand: string;
  status: string;
  previousStatus: string | null;
  sources: string[];
  signalPath: string;
};

export type RadarEventArtifact = {
  schemaVersion: 1;
  dataset: "radar-events";
  generatedAt: string;
  window: { days: number; from: string; to: string };
  totalAvailable: number;
  truncated: boolean;
  events: RadarEvent[];
};

export type DailyTrendRow = {
  date: string;
  partialDay: boolean;
  collectorCoverage: {
    windowSeconds: number;
    scheduledSlots: number;
    recordedAttempts: number;
    healthyAttempts: number;
    recordedSchedulePercent: number | null;
    listeningCoveragePercent: number | null;
    scheduledListeningCeilingPercent: number | null;
    listeningSeconds: number;
    outcomes: Record<string, number>;
  };
  discovery: {
    events: number;
    uniqueSignals: number;
    observations: number;
    reobservations: number;
    firstPublications: number;
    statusChanges: number;
    facetSampleSize: number;
    evidenceClassifiedSignals: number;
    byBrand: Record<string, number>;
    bySource: Record<string, number>;
    byEvidenceTier: Record<string, number>;
    byReason: Record<string, number>;
  };
};

export type DailyTrends = {
  schemaVersion: 1;
  dataset: "radar-daily-trends";
  generatedAt: string;
  retentionDays: number;
  from: string;
  to: string;
  semantics: string;
  facetSemantics: string;
  seriesSemantics: string;
  omittedZeroDays: number;
  collectorSchedule: { expectedIntervalSeconds: number; expectedListeningSeconds: number; derivedFrom: string };
  series: DailyTrendRow[];
  privacy: string;
};

export type QualityMetrics = {
  schemaVersion: 1;
  dataset: "radar-quality-metrics";
  generatedAt: string;
  semantics: string;
  reviewSample: {
    assessments: number;
    uniqueSignals: number;
    outcomes: Record<string, number>;
    byBrand: Record<string, number>;
    bySource: Record<string, number>;
    sourceLinkedAssessments: number;
    byEvidence: Record<string, number>;
    byDispositionReason: Record<string, number>;
    byDetectionReason: Record<string, number>;
  };
  reviewCoverage: { eligiblePublishedSignals: number; assessedSignals: number; percent: number | null; scope: string };
  reviewLatencyHours: { sampleSize: number; median: number | null; p90: number | null; minimum: number | null; maximum: number | null; scope: string };
  currentExclusions: { sampleSize: number; exact: number; subdomainPolicies: number; byReason: Record<string, number>; scope: string };
  precision: { available: boolean; sampleSize: number; estimatePercent: number | null; reason: string };
  privacy: string;
};

export type StaticPageData = {
  snapshot: RadarSnapshot;
  history: RadarHistory;
  events: RadarEventArtifact;
  trends: DailyTrends;
  quality: QualityMetrics;
  related: RelatedObservations;
  renderedAt: number;
};

export type StaticPageKind = "changes" | "trends" | "associations" | "tools" | "dataset";

export function encodeStaticPageBootstrap(data: StaticPageData): string {
  return encodeURIComponent(JSON.stringify(data));
}

export function decodeStaticPageBootstrap(value: string): StaticPageData {
  const parsed: unknown = JSON.parse(decodeURIComponent(value));
  if (typeof parsed !== "object" || parsed === null || !("snapshot" in parsed) || !("history" in parsed)) {
    throw new Error("The embedded Radar page data is invalid.");
  }
  return parsed as StaticPageData;
}
