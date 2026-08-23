import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Dashboard } from "../src/components/Dashboard";
import type { RadarSnapshot } from "../src/types";

const NOW = Date.parse("2026-08-23T14:30:00.000Z");

function snapshot(lastSuccessfulSyncAt: string): RadarSnapshot {
  return {
    schemaVersion: 1,
    dataset: "live",
    generatedAt: "2026-08-23T11:00:00.000Z",
    lastSuccessfulSyncAt,
    signals: [],
    sources: [],
  };
}

describe("snapshot freshness", () => {
  it("uses the successful sync heartbeat instead of the last data change", () => {
    render(<Dashboard snapshot={snapshot("2026-08-23T14:00:00.000Z")} now={NOW} />);

    expect(screen.getByText("Snapshot sync current")).toBeInTheDocument();
    expect(screen.getByText("Checked 30 minutes ago")).toBeInTheDocument();
    expect(screen.getByText(/Data last changed 3 hours ago/)).toBeInTheDocument();
    expect(screen.queryByText("Snapshot sync delayed")).not.toBeInTheDocument();
  });

  it("reports a heartbeat older than two hours as delayed", () => {
    render(<Dashboard snapshot={snapshot("2026-08-23T12:29:59.999Z")} now={NOW} />);

    expect(screen.getByText("Snapshot sync delayed")).toBeInTheDocument();
  });

  it("keeps a heartbeat exactly two hours old current", () => {
    render(<Dashboard snapshot={snapshot("2026-08-23T12:30:00.000Z")} now={NOW} />);

    expect(screen.getByText("Snapshot sync current")).toBeInTheDocument();
  });
});
