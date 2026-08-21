import { describe, expect, it } from "vitest";

import { dashboardMetrics, filterSignals, topGroups } from "../src/lib/dashboard";
import type { RadarSignal, RadarSnapshot } from "../src/types";

const signal = (overrides: Partial<RadarSignal>): RadarSignal => ({
  id: "one",
  url: "hxxps://login[.]example[.]test",
  domain: "login[.]example[.]test",
  firstSeen: "2026-08-21T08:00:00.000Z",
  lastSeen: "2026-08-21T09:00:00.000Z",
  sources: ["HECAVEX"],
  status: "suspected",
  brand: "Example Bank",
  country: "LT",
  host: "Example Host",
  screenshotUrl: null,
  confidence: 78,
  ...overrides,
});

const signals = [
  signal({}),
  signal({ id: "two", domain: "mail[.]example[.]test", url: "hxxps://mail[.]example[.]test" }),
  signal({ id: "three", brand: "Example Mail", country: "DE", status: "active", confidence: 96, sources: ["PhishTank"] }),
];

describe("dashboard data", () => {
  it("searches and combines filters", () => {
    expect(
      filterSignals(signals, {
        query: "mail",
        status: "active",
        source: "PhishTank",
        brand: "all",
        country: "all",
        minimumConfidence: 90,
      }).map((item) => item.id),
    ).toEqual(["three"]);
  });

  it("calculates summary metrics", () => {
    const snapshot: RadarSnapshot = {
      schemaVersion: 1,
      dataset: "live",
      generatedAt: "2026-08-21T10:00:00.000Z",
      signals,
      sources: [],
    };
    expect(dashboardMetrics(snapshot)).toEqual({ total: 3, active: 1, highConfidence: 1, brands: 2, countries: 2 });
  });

  it("orders grouped values by count", () => {
    expect(topGroups(signals, "brand", 2)).toEqual([
      { name: "Example Bank", count: 2 },
      { name: "Example Mail", count: 1 },
    ]);
  });
});
