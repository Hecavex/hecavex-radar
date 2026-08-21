import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Documentation } from "../src/components/Documentation";
import { FilterBar } from "../src/components/FilterBar";
import { Methodology } from "../src/components/Methodology";
import { SignalTable } from "../src/components/SignalTable";
import { SiteFooter } from "../src/components/SiteFooter";
import { SiteHeader } from "../src/components/SiteHeader";
import { SourcePanel } from "../src/components/SourcePanel";
import { DEFAULT_FILTERS } from "../src/lib/dashboard";
import type { RadarSignal, RadarSource } from "../src/types";

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

  it("presents confidence as a score rather than a percentage", () => {
    const { container } = render(<SignalTable signals={[makeSignal(1)]} />);
    expect(within(container).getByLabelText("70 confidence score out of 100")).toHaveTextContent("70/100");
    expect(within(container).getByRole("region", { name: "Potential phishing signals" })).toHaveAttribute("tabindex", "0");
  });

  it("shows passive URLScan evidence without linking to the suspicious site", () => {
    const signal = {
      ...makeSignal(1),
      referenceUrl: "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
      hashes: ["a".repeat(64)],
    };
    render(<SignalTable signals={[signal]} />);
    fireEvent.click(screen.getByRole("button", { name: /view evidence/i }));
    expect(screen.getByRole("link", { name: /open report/i })).toHaveAttribute("href", signal.referenceUrl);
    expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
    expect(screen.getByText(/primary html response evidence supplied with this observation/i)).toBeInTheDocument();
    expect(screen.getByText(/contacts urlscan\.io/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: signal.url })).not.toBeInTheDocument();
  });
});

describe("dashboard controls", () => {
  it("labels confidence filters as scores out of 100", () => {
    render(<FilterBar signals={[makeSignal(1)]} filters={DEFAULT_FILTERS} onChange={() => undefined} />);
    expect(screen.getByLabelText("Minimum confidence score")).toHaveDisplayValue("Any score");
    expect(screen.getByRole("option", { name: "Score 90/100 or higher" })).toBeInTheDocument();
  });

  it("separates healthy sources from optional sources that are off", () => {
    const sources: RadarSource[] = [
      {
        name: "URLScan",
        homepage: "https://urlscan.io/",
        fetchedAt: "2026-08-21T09:00:00.000Z",
        records: 1,
        state: "healthy",
        note: null,
      },
      {
        name: "HECAVEX",
        homepage: "https://hecavex.com/",
        fetchedAt: null,
        records: 0,
        state: "skipped",
        note: "Not configured",
      },
    ];

    render(<SourcePanel sources={sources} />);
    expect(screen.getByText("1 loaded · 1 optional off")).toBeInTheDocument();
    expect(screen.queryByText("1/2 active")).not.toBeInTheDocument();
  });
});

describe("methodology", () => {
  it("provides a self-contained explanation with internal section navigation", () => {
    render(<Methodology />);

    const section = screen.getByRole("region", { name: "How a signal reaches Radar" });
    expect(section).toHaveAttribute("id", "methodology");
    expect(within(section).getByRole("list", { name: "Publication stages" }).children).toHaveLength(4);
    expect(within(section).getByText(/urlscan can enrich certstream/i)).toBeInTheDocument();
    expect(within(section).getByRole("link", { name: "Brand matching" })).toHaveAttribute("href", "#matching");
    expect(section.querySelector('a[href*="github.com"]')).toBeNull();
  });
});

describe("on-site documentation", () => {
  it("contains core architecture, source, contract, deployment, and licensing material", () => {
    render(<Documentation />);

    expect(screen.getByRole("heading", { name: "HECAVEX Radar technical reference" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Python pipeline, static viewer" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Three public observation labels" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Signal field reference" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Workflow schedule" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Software licensing does not relicense data" })).toBeInTheDocument();
  });

  it("routes core navigation and data terms to local pages", () => {
    const { unmount } = render(<SiteHeader currentPage="radar" />);
    expect(screen.getByRole("link", { name: "Methodology" })).toHaveAttribute("href", "/methodology/");
    expect(screen.getByRole("link", { name: "Docs" })).toHaveAttribute("href", "/docs/");
    unmount();

    render(<SiteFooter />);
    expect(screen.getByRole("link", { name: "Data terms & attribution" })).toHaveAttribute("href", "/docs/#data-terms");
  });
});
