import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CollectionHealth } from "../src/components/CollectionHealth";
import { parseCollectionHealth } from "../src/lib/collectionHealth";

const health = {
  schemaVersion: 1,
  dataset: "certstream-collection-health",
  generatedAt: "2026-08-21T19:17:53.656Z",
  expectedIntervalSeconds: 1800,
  staleAfterSeconds: 5400,
  lastSuccessAt: "2026-08-21T19:17:53.656Z",
  freshness: {
    status: "current",
    referenceAt: "2026-08-21T19:17:53.656Z",
    ageSeconds: 0,
  },
  latestAttempt: {
    startedAt: "2026-08-21T19:13:30.000Z",
    collectorStartedAt: "2026-08-21T19:13:43.649Z",
    endedAt: "2026-08-21T19:17:53.656Z",
    trigger: "schedule",
    scheduledFor: "2026-08-21T19:02:00.000Z",
    scheduleStatus: "delayed",
    delaySeconds: 690,
    expectedListeningSeconds: 240,
    listeningSeconds: 240,
    messages: 89_532,
    dnsNames: 160_340,
    matches: 0,
    newRecords: 0,
    connectionAttempts: 1,
    connections: 1,
    outcome: "healthy-empty",
    summary: "Input was processed successfully; no candidate matched the publication heuristic.",
  },
} as const;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("collection-health contract", () => {
  it("accepts bounded operational telemetry and rejects extra raw fields", () => {
    expect(parseCollectionHealth(health).latestAttempt?.dnsNames).toBe(160_340);
    expect(() =>
      parseCollectionHealth({
        ...health,
        latestAttempt: { ...health.latestAttempt, rawCandidates: ["sensitive.example"] },
      }),
    ).toThrow(/schema version 1/i);
  });

  it("rejects contradictory timing and count fields", () => {
    expect(() =>
      parseCollectionHealth({
        ...health,
        latestAttempt: { ...health.latestAttempt, matches: 200_000 },
      }),
    ).toThrow(/schema version 1/i);
    expect(() =>
      parseCollectionHealth({
        ...health,
        latestAttempt: { ...health.latestAttempt, endedAt: "2026-08-21T18:00:00.000Z" },
      }),
    ).toThrow(/schema version 1/i);
  });
});

describe("public collection health", () => {
  it("shows actual timing, schedule delay, freshness, and input counts to visitors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: async () => health }),
    );
    render(<CollectionHealth now={Date.parse("2026-08-21T19:30:00.000Z")} />);

    const section = await screen.findByRole("region", { name: "Latest CertStream attempt" });
    expect(within(section).getByText("Healthy empty")).toBeInTheDocument();
    expect(within(section).getByText("Delayed by 11m 30s")).toBeInTheDocument();
    expect(within(section).getByText("Current")).toBeInTheDocument();
    expect(within(section).getByText("240.0s")).toBeInTheDocument();
    expect(within(section).getByText("89,532")).toBeInTheDocument();
    expect(within(section).getByText("160,340")).toBeInTheDocument();
    expect(within(section).getByText(/no certificate names or unpublished candidates/i)).toBeInTheDocument();
  });

  it("renders a bounded error state when the artifact is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    render(<CollectionHealth />);

    expect(await screen.findByText(/temporarily unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/offline/i)).not.toBeInTheDocument();
  });
});
