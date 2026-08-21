import { describe, expect, it } from "vitest";

import { parseSnapshot } from "../src/lib/data";

describe("snapshot schema", () => {
  it("rejects data with an unsupported schema", () => {
    expect(() => parseSnapshot({ schemaVersion: 2, signals: [], sources: [] })).toThrow(/schema version 1/);
  });

  it("accepts an empty version 1 snapshot", () => {
    expect(
      parseSnapshot({
        schemaVersion: 1,
        dataset: "live",
        generatedAt: "2026-08-21T10:00:00.000Z",
        signals: [],
        sources: [],
      }).signals,
    ).toEqual([]);
  });
});
