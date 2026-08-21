import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { parseSnapshot } from "../src/lib/data";
import { formatDateTime, formatRelativeTime } from "../src/lib/format";

const validSignal = {
  id: "a".repeat(20),
  url: "hxxps://secure-swedbank[.]example/login",
  domain: "secure-swedbank[.]example",
  firstSeen: "2026-08-21T09:00:00.000Z",
  lastSeen: "2026-08-21T10:00:00.000Z",
  sources: ["URLScan"],
  status: "active",
  brand: "Swedbank",
  country: null,
  host: null,
  screenshotUrl: null,
  confidence: 92,
};

const snapshot = (overrides: Record<string, unknown> = {}) => ({
  schemaVersion: 1,
  dataset: "live",
  generatedAt: "2026-08-21T10:00:00.000Z",
  signals: [],
  sources: [],
  ...overrides,
});

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

  it("rejects demo snapshots", () => {
    expect(() =>
      parseSnapshot({
        schemaVersion: 1,
        dataset: "demo",
        generatedAt: "2026-08-21T10:00:00.000Z",
        signals: [],
        sources: [],
      }),
    ).toThrow(/schema version 1/);
  });

  it("rejects malformed and non-canonical timestamps before rendering", () => {
    expect(() => parseSnapshot(snapshot({ generatedAt: "not-a-date" }))).toThrow(/schema version 1/);
    expect(() => parseSnapshot(snapshot({ generatedAt: "2026-02-30T10:00:00.000Z" }))).toThrow(/schema version 1/);
    expect(() => parseSnapshot(snapshot({ signals: [{ ...validSignal, firstSeen: "invalid" }] }))).toThrow(
      /schema version 1/,
    );
  });

  it("rejects a signal whose first-seen time is later than its last-seen time", () => {
    expect(() =>
      parseSnapshot(
        snapshot({
          signals: [
            {
              ...validSignal,
              firstSeen: "2026-08-21T10:00:00.000Z",
              lastSeen: "2026-08-21T09:00:00.000Z",
            },
          ],
        }),
      ),
    ).toThrow(/schema version 1/);
  });

  it("keeps time formatting safe even when called with invalid application data", () => {
    expect(formatDateTime("not-a-date")).toBe("Unknown time");
    expect(formatRelativeTime("not-a-date")).toBe("Unknown time");
  });

  it("accepts only fixed source homepage pairs and non-negative integer counts", () => {
    const source = {
      name: "URLScan",
      homepage: "https://urlscan.io/",
      fetchedAt: "2026-08-21T10:00:00.000Z",
      records: 1,
      state: "healthy",
      note: null,
    };
    expect(parseSnapshot(snapshot({ sources: [source] })).sources).toEqual([source]);
    expect(() => parseSnapshot(snapshot({ sources: [{ ...source, homepage: "javascript:alert(1)" }] }))).toThrow(
      /schema version 1/,
    );
    expect(() => parseSnapshot(snapshot({ sources: [{ ...source, records: -1 }] }))).toThrow(/schema version 1/);
    expect(() => parseSnapshot(snapshot({ sources: [{ ...source, records: 1.5 }] }))).toThrow(/schema version 1/);
  });

  it("rejects malformed hash evidence", () => {
    const signal = {
      id: "a".repeat(20),
      url: "hxxps://secure-swedbank[.]example/login",
      domain: "secure-swedbank[.]example",
      firstSeen: "2026-08-21T09:00:00.000Z",
      lastSeen: "2026-08-21T10:00:00.000Z",
      sources: ["URLScan"],
      status: "active",
      brand: "Swedbank",
      country: null,
      host: null,
      screenshotUrl: null,
      hashes: ["not-a-sha256"],
      confidence: 92,
    };
    expect(() => parseSnapshot({
      schemaVersion: 1,
      dataset: "live",
      generatedAt: "2026-08-21T10:00:00.000Z",
      signals: [signal],
      sources: [],
    })).toThrow(/schema version 1/);
  });

  it("rejects evidence links outside URLScan", () => {
    const signal = {
      id: "a".repeat(20),
      url: "hxxps://secure-swedbank[.]example/login",
      domain: "secure-swedbank[.]example",
      firstSeen: "2026-08-21T09:00:00.000Z",
      lastSeen: "2026-08-21T10:00:00.000Z",
      sources: ["URLScan"],
      status: "active",
      brand: "Swedbank",
      country: null,
      host: null,
      screenshotUrl: null,
      referenceUrl: "https://attacker.example/report",
      confidence: 92,
    };
    expect(() => parseSnapshot({
      schemaVersion: 1,
      dataset: "live",
      generatedAt: "2026-08-21T10:00:00.000Z",
      signals: [signal],
      sources: [],
    })).toThrow(/schema version 1/);
  });

  it("rejects URLScan screenshots carrying query data", () => {
    const signal = {
      id: "a".repeat(20),
      url: "hxxps://secure-swedbank[.]example/login",
      domain: "secure-swedbank[.]example",
      firstSeen: "2026-08-21T09:00:00.000Z",
      lastSeen: "2026-08-21T10:00:00.000Z",
      sources: ["URLScan"],
      status: "suspected",
      brand: "Swedbank",
      country: null,
      host: null,
      screenshotUrl: "https://urlscan.io/screenshots/example.png?token=private",
      referenceUrl: null,
      hashes: [],
      confidence: 90,
    };
    expect(() => parseSnapshot({
      schemaVersion: 1,
      dataset: "live",
      generatedAt: "2026-08-21T10:00:00.000Z",
      signals: [signal],
      sources: [],
    })).toThrow(/schema version 1/);
  });

  it("rejects URLScan screenshot paths without a scan UUID", () => {
    expect(() =>
      parseSnapshot(
        snapshot({
          signals: [
            {
              ...validSignal,
              screenshotUrl: "https://urlscan.io/screenshots/example.png",
            },
          ],
        }),
      ),
    ).toThrow(/schema version 1/);
  });

  it("accepts the checked-in production snapshot", () => {
    const body = readFileSync(resolve(process.cwd(), "public/data/radar.json"), "utf8");
    expect(parseSnapshot(JSON.parse(body)).dataset).toBe("live");
  });
});
