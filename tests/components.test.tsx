import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SignalTable } from "../src/components/SignalTable";
import type { RadarSignal } from "../src/types";

function makeSignal(index: number): RadarSignal {
  return {
    id: `signal-${index}`,
    url: `hxxps://signal-${index}[.]example[.]test/path`,
    domain: `signal-${index}[.]example[.]test`,
    firstSeen: "2026-08-21T08:00:00.000Z",
    lastSeen: "2026-08-21T09:00:00.000Z",
    sources: ["HECAVEX"],
    status: "suspected",
    brand: null,
    country: null,
    host: null,
    screenshotUrl: null,
    confidence: 70,
  };
}

describe("signal table", () => {
  it("paginates result sets", () => {
    render(<SignalTable signals={Array.from({ length: 30 }, (_, index) => makeSignal(index + 1))} />);
    expect(screen.getByText("signal-1[.]example[.]test")).toBeInTheDocument();
    expect(screen.queryByText("signal-26[.]example[.]test")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.getByText("signal-26[.]example[.]test")).toBeInTheDocument();
    expect(within(screen.getByText(/page/i).parentElement!).getByText("2")).toBeInTheDocument();
  });

  it("shows a useful empty state", () => {
    render(<SignalTable signals={[]} />);
    expect(screen.getByRole("heading", { name: "No matching signals" })).toBeInTheDocument();
  });
});
