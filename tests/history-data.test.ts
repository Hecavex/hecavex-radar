import { describe, expect, it } from "vitest";

import { parseHistory } from "../src/lib/historyData.ts";

const valid = {
  schemaVersion: 1,
  dataset: "history",
  generatedAt: "2026-08-22T10:00:00.000Z",
  detailRetentionDays: 30,
  summaryRetentionDays: 730,
  signals: [
    {
      id: "e378396179035765fd2e",
      domain: "secure-swedbank[.]example",
      brand: "Swedbank",
      firstSeen: "2026-08-21T09:00:00.000Z",
      lastSeen: "2026-08-22T09:00:00.000Z",
      observationCount: 2,
      sources: ["CertStream"],
      latestStatus: "suspected",
      reasonCodes: ["brand-domain-match", "suspicious-context"],
      statusTransitions: [
        {
          eventId: "b".repeat(32),
          observedAt: "2026-08-21T09:00:00.000Z",
          previousStatus: null,
          status: "suspected",
          sources: ["CertStream"],
          reasonCodes: ["brand-domain-match", "first-publication"],
        },
      ],
    },
  ],
};

describe("history schema", () => {
  it("accepts a bounded typed history artifact", async () => {
    expect((await parseHistory(valid)).signals[0]?.observationCount).toBe(2);
  });

  it("rejects unknown reason codes and lifecycle values", async () => {
    const unknownReason = structuredClone(valid);
    unknownReason.signals[0]!.reasonCodes = ["private-rule"];
    await expect(parseHistory(unknownReason)).rejects.toThrow(/schema version 1/);

    const badStatus = structuredClone(valid);
    badStatus.signals[0]!.latestStatus = "benign";
    await expect(parseHistory(badStatus)).rejects.toThrow(/schema version 1/);
  });

  it("rejects malformed transition provenance", async () => {
    const malformed = structuredClone(valid);
    malformed.signals[0]!.statusTransitions[0]!.eventId = "not-an-event";
    await expect(parseHistory(malformed)).rejects.toThrow(/schema version 1/);
  });

  it("rejects extra fields, malformed domains, and unrelated stable IDs", async () => {
    const extra = structuredClone(valid) as typeof valid & { privateNote?: string };
    extra.privateNote = "must not cross the publication boundary";
    await expect(parseHistory(extra)).rejects.toThrow(/schema version 1/);

    const malformedDomain = structuredClone(valid);
    malformedDomain.signals[0]!.domain = "https://secure-swedbank.example";
    await expect(parseHistory(malformedDomain)).rejects.toThrow(/schema version 1/);

    const unrelatedId = structuredClone(valid);
    unrelatedId.signals[0]!.id = "a".repeat(20);
    await expect(parseHistory(unrelatedId)).rejects.toThrow(/schema version 1/);
  });

  it("rejects retention and count values above their public bounds", async () => {
    const retention = structuredClone(valid);
    retention.detailRetentionDays = 91;
    await expect(parseHistory(retention)).rejects.toThrow(/schema version 1/);

    const count = structuredClone(valid);
    count.signals[0]!.observationCount = 2_147_483_648;
    await expect(parseHistory(count)).rejects.toThrow(/schema version 1/);
  });
});
