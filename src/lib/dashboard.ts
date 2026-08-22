import type { Filters, RadarSignal, RadarSnapshot } from "../types.ts";

export const DEFAULT_FILTERS: Filters = {
  query: "",
  status: "all",
  source: "all",
  brand: "all",
  country: "all",
  minimumConfidence: 0,
};

function includes(value: string | null, query: string): boolean {
  return value?.toLocaleLowerCase().includes(query) ?? false;
}

export function filterSignals(signals: RadarSignal[], filters: Filters): RadarSignal[] {
  const query = filters.query.trim().toLocaleLowerCase();
  return signals.filter((signal) => {
    const queryMatches =
      query.length === 0 ||
      includes(signal.url, query) ||
      includes(signal.domain, query) ||
      includes(signal.brand, query) ||
      includes(signal.country, query) ||
      includes(signal.host, query) ||
      signal.sources.some((source) => source.toLocaleLowerCase().includes(query));

    return (
      queryMatches &&
      (filters.status === "all" || signal.status === filters.status) &&
      (filters.source === "all" || signal.sources.includes(filters.source)) &&
      (filters.brand === "all" || signal.brand === filters.brand) &&
      (filters.country === "all" || signal.country === filters.country) &&
      signal.confidence >= filters.minimumConfidence
    );
  });
}

export function uniqueValues(signals: RadarSignal[], key: "brand" | "country"): string[] {
  return [...new Set(signals.map((signal) => signal[key]).filter((value): value is string => Boolean(value)))].sort(
    (left, right) => left.localeCompare(right),
  );
}

export function sourceNames(signals: RadarSignal[]): string[] {
  return [...new Set(signals.flatMap((signal) => signal.sources))].sort((left, right) => left.localeCompare(right));
}

export function dashboardMetrics(snapshot: RadarSnapshot) {
  const { signals } = snapshot;
  return {
    total: signals.length,
    active: signals.filter((signal) => signal.status === "active").length,
    highConfidence: signals.filter((signal) => signal.confidence >= 80).length,
    brands: new Set(signals.map((signal) => signal.brand).filter(Boolean)).size,
    countries: new Set(signals.map((signal) => signal.country).filter(Boolean)).size,
  };
}

export function topGroups(signals: RadarSignal[], key: "brand" | "country", limit = 5) {
  const counts = new Map<string, number>();
  for (const signal of signals) {
    const value = signal[key] ?? "Unknown";
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((left, right) => right.count - left.count || left.name.localeCompare(right.name))
    .slice(0, limit);
}
