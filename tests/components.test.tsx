import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Documentation } from "../src/components/Documentation";
import { CollectionDisclosure } from "../src/components/CollectionDisclosure";
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

  it("cycles focus through the evidence dialog in both directions", () => {
    const signal = {
      ...makeSignal(1),
      screenshotUrl: "https://urlscan.io/screenshots/11111111-1111-1111-1111-111111111111.png",
      referenceUrl: "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
    };
    render(<SignalTable signals={[signal]} />);
    fireEvent.click(screen.getByRole("button", { name: /view evidence/i }));

    const close = screen.getByRole("button", { name: "Close capture" });
    const last = screen.getByRole("link", { name: /open report/i });
    expect(close).toHaveFocus();

    last.focus();
    fireEvent.keyDown(last, { key: "Tab" });
    expect(close).toHaveFocus();

    fireEvent.keyDown(close, { key: "Tab", shiftKey: true });
    expect(last).toHaveFocus();
  });

  it("restores focus to the exact evidence trigger after close and Escape", () => {
    const signal = {
      ...makeSignal(1),
      referenceUrl: "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
    };
    render(<SignalTable signals={[signal]} />);
    const trigger = screen.getByRole("button", { name: /view evidence/i });

    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("button", { name: "Close capture" }));
    expect(trigger).toHaveFocus();

    fireEvent.click(trigger);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("isolates background controls while evidence is open and restores them on close", () => {
    const signal = {
      ...makeSignal(1),
      referenceUrl: "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
    };
    render(
      <>
        <button type="button">Background action</button>
        <SignalTable signals={[signal]} />
      </>,
    );
    const background = screen.getByRole("button", { name: "Background action" });
    fireEvent.click(screen.getByRole("button", { name: /view evidence/i }));

    expect(background).toHaveAttribute("inert");
    expect(background).toHaveAttribute("aria-hidden", "true");
    background.focus();
    expect(screen.getByRole("button", { name: "Close capture" })).toHaveFocus();

    fireEvent.click(screen.getByRole("button", { name: "Close capture" }));
    expect(background).not.toHaveAttribute("inert");
    expect(background).not.toHaveAttribute("aria-hidden");
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
    expect(screen.getByText(/archive read succeeded/i)).toBeInTheDocument();
    expect(screen.getByText(/optional source not configured/i)).toBeInTheDocument();
    expect(screen.getByText(/zero rows can be a healthy empty result/i)).toBeInTheDocument();
  });

  it("distinguishes a failed refresh from the previous successful archive read", () => {
    render(
      <SourcePanel
        sources={[
          {
            name: "CertStream",
            homepage: "https://certstream.dev/",
            fetchedAt: "2026-08-21T09:00:00.000Z",
            records: 2,
            state: "partial",
            note: "Unavailable during this sync; 2 recent records retained",
          },
        ]}
      />,
    );
    expect(screen.getByText(/latest refresh was incomplete; last successful archive read/i)).toBeInTheDocument();
  });
});

describe("collection disclosure", () => {
  it("states scheduled coverage, measured latest-attempt runtime, URLScan absence, and the service boundary", () => {
    render(<CollectionDisclosure />);
    expect(screen.getByRole("heading", { name: /sampled discovery, not continuous monitoring/i })).toBeInTheDocument();
    expect(screen.getByText(/192 scheduled minutes per day/i)).toBeInTheDocument();
    expect(screen.getByText(/latest measured attempt is shown below/i)).toBeInTheDocument();
    expect(screen.getByText(/no result is not a benign verdict/i)).toBeInTheDocument();
    expect(screen.getByText(/neither proof nor probability/i)).toBeInTheDocument();
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
    expect(screen.getByRole("heading", { name: "Deliberately published datasets" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Maintained on a best-effort basis" })).toBeInTheDocument();
    expect(screen.getByText(/at most 13\.3% of wall-clock time/i)).toBeInTheDocument();
    expect(screen.getByText(/83,875 messages containing 146,591 DNS names/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Cookieless performance measurement" })).toBeInTheDocument();
    expect(screen.getByText(/sends no custom analytics events/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Software licensing does not relicense data" })).toBeInTheDocument();
  });

  it("routes core navigation and data terms to local pages", () => {
    const { container, unmount } = render(<SiteHeader currentPage="radar" />);
    const header = container.querySelector<HTMLElement>('.site-header[data-portfolio-shell="v1"]')!;
    const portfolioNavigation = header.querySelector<HTMLElement>(".portfolio-navigation")!;
    const productNavigation = header.querySelector<HTMLElement>(".product-navigation")!;
    expect(within(portfolioNavigation).getByRole("link", { name: "Research" })).toHaveAttribute(
      "href",
      "https://hecavex.com/en/research/",
    );
    expect(within(portfolioNavigation).getByRole("link", { name: "Radar" })).toHaveAttribute("aria-current", "page");
    expect(within(portfolioNavigation).getByRole("link", { name: "Data" })).toHaveAttribute(
      "href",
      "https://labs.hecavex.com/data/",
    );
    expect(within(productNavigation).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(within(productNavigation).getByRole("link", { name: "Methodology" })).toHaveAttribute("href", "/methodology/");
    expect(within(productNavigation).getByRole("link", { name: "Docs" })).toHaveAttribute("href", "/docs/");
    expect(within(header).getByRole("link", { name: "HECAVEX Research" })).toHaveAttribute(
      "href",
      "https://hecavex.com/en/",
    );
    expect(container.querySelector(".product-identity")).toHaveAttribute("href", "/");
    expect(container.querySelector(".header-utility .source-link")).toHaveAttribute(
      "href",
      "https://github.com/Hecavex/hecavex-radar",
    );
    expect(screen.getByText("Menu").closest("summary")).toBeInTheDocument();
    unmount();

    render(<SiteFooter />);
    expect(screen.getByRole("link", { name: "Research" })).toHaveAttribute("href", "https://hecavex.com/en/research/");
    expect(screen.getByRole("link", { name: "Security" })).toHaveAttribute("href", "/.well-known/security.txt");
    expect(screen.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "https://hecavex.com/en/privacy/");
    expect(screen.getByText(/cookieless Cloudflare Web Analytics/i)).toBeInTheDocument();
  });

  it("closes the mobile navigation with Escape and restores summary focus", () => {
    const { container } = render(<SiteHeader currentPage="history" />);
    const details = container.querySelector<HTMLDetailsElement>(".mobile-navigation")!;
    const summary = within(details).getByText("Menu").closest("summary")!;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    expect(summary).toHaveAttribute("aria-label", "Close navigation menu");

    fireEvent.keyDown(document, { key: "Escape" });

    expect(details.open).toBe(false);
    expect(summary).toHaveFocus();
  });
});
