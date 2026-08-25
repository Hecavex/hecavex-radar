import { evidenceTierLabel, signalEvidenceTier, signalMatchScore } from "./dashboard.ts";
import type { RadarSignal } from "../types.ts";

const FORMULA_PREFIX = /^[\t\r ]*[=+\-@]/u;

function safePlainText(value: string): string {
  return [...value].filter((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint >= 32 && codePoint !== 127;
  }).join("");
}

export function safeCsvCell(value: string | number | null): string {
  let text = safePlainText(value === null ? "" : String(value));
  if (FORMULA_PREFIX.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function publicRow(signal: RadarSignal) {
  return {
    signalId: signal.id,
    indicator: safePlainText(signal.url),
    domain: safePlainText(signal.domain),
    potentialBrandMatch: signal.brand ? safePlainText(signal.brand) : null,
    firstSeen: signal.firstSeen,
    lastSeen: signal.lastSeen,
    sources: signal.sources.map(safePlainText),
    discoveredVia: signal.discoveredVia ?? [],
    corroboratedBy: signal.corroboratedBy ?? [],
    sourceReportedStatus: signal.status,
    hostingCountryObserved: signal.country ? safePlainText(signal.country) : null,
    hostSummary: signal.host ? safePlainText(signal.host) : null,
    matchScore: signalMatchScore(signal),
    evidenceTier: signalEvidenceTier(signal),
    reviewState: signal.reviewState ?? "unreviewed",
    lithuanianRelevance: signal.ltRelevance ?? "unknown",
    reasonCodes: signal.reasonCodes ?? [],
  };
}

export function signalsAsJson(signals: RadarSignal[], snapshotGeneratedAt: string): string {
  return `${JSON.stringify({
    schemaVersion: 1,
    dataset: "filtered-defanged-view",
    snapshotGeneratedAt,
    warning: "Automated candidates, not maliciousness verdicts. Indicators are defanged and must not be made clickable.",
    signals: signals.map(publicRow),
  }, null, 2)}\n`;
}

export function signalsAsCsv(signals: RadarSignal[]): string {
  const headings = [
    "signal_id",
    "defanged_indicator",
    "defanged_domain",
    "potential_brand_match",
    "first_seen_utc",
    "last_seen_utc",
    "sources",
    "discovered_via",
    "corroborated_by",
    "source_reported_status",
    "hosting_country_observed",
    "host_summary",
    "match_score",
    "evidence_state",
    "review_state",
    "lithuanian_relevance",
    "reason_codes",
  ];
  const rows = signals.map((signal) => {
    const row = publicRow(signal);
    return [
      row.signalId,
      row.indicator,
      row.domain,
      row.potentialBrandMatch,
      row.firstSeen,
      row.lastSeen,
      row.sources.join(";"),
      row.discoveredVia.join(";"),
      row.corroboratedBy.join(";"),
      row.sourceReportedStatus,
      row.hostingCountryObserved,
      row.hostSummary,
      row.matchScore,
      evidenceTierLabel(row.evidenceTier),
      row.reviewState,
      row.lithuanianRelevance,
      row.reasonCodes.join(";"),
    ].map(safeCsvCell).join(",");
  });
  return `${[headings.map(safeCsvCell).join(","), ...rows].join("\r\n")}\r\n`;
}

export function downloadText(filename: string, contents: string, type: string): void {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
