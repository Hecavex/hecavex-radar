import { Activity, DatabaseZap, RadioTower } from "lucide-react";
import { useEffect, useState } from "react";

import { formatDateTime, formatNumber } from "../lib/format.ts";
import {
  loadPipelineHealth,
  type DomainContextRun,
  type PipelineHealth,
  type PipelineOutcome,
  type PipelineWindow,
} from "../lib/pipelineHealth.ts";

const outcomeLabels: Record<PipelineOutcome, string> = {
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
  empty: "Empty",
};

function percentage(value: number): string {
  return `${new Intl.NumberFormat("en-GB", { maximumFractionDigits: 2 }).format(value)}%`;
}

function WindowSummary({ window }: { window: PipelineWindow }) {
  const label = window.hours === 24 ? "Past 24 hours" : "Past 7 days";
  return (
    <article className="pipeline-window">
      <header>
        <span>{label}</span>
        <time dateTime={window.to} title={`${formatDateTime(window.to)} UTC`}>ending {formatDateTime(window.to)} UTC</time>
      </header>
      <div className="pipeline-window-lead">
        <strong>{percentage(window.collection.listeningCoveragePercent)}</strong>
        <span>actual live-stream listening coverage</span>
      </div>
      <dl>
        <div>
          <dt>Recorded attempts</dt>
          <dd>{formatNumber(window.collection.recordedAttempts)} / {formatNumber(window.collection.scheduledSlots)}</dd>
        </div>
        <div>
          <dt>Healthy attempts</dt>
          <dd>{formatNumber(window.collection.healthyAttempts)}</dd>
        </div>
        <div>
          <dt>DNS names processed</dt>
          <dd>{formatNumber(window.collection.dnsNames)}</dd>
        </div>
        <div>
          <dt>Heuristic matches</dt>
          <dd>{formatNumber(window.screening.matches)}</dd>
        </div>
        <div>
          <dt>New archive rows</dt>
          <dd>{formatNumber(window.screening.newArchiveRecords)}</dd>
        </div>
        <div>
          <dt>Publication events</dt>
          <dd>{formatNumber(window.publication.events)}</dd>
        </div>
      </dl>
      <p>
        The configured schedule could cover at most {percentage(window.collection.scheduledListeningCeilingPercent)} of this
        period before runner delays or failures.
      </p>
    </article>
  );
}

function OutcomeBadge({ outcome }: { outcome: PipelineOutcome }) {
  return <span className={`pipeline-outcome outcome-${outcome}`}>{outcomeLabels[outcome]}</span>;
}

function ContextSummary({ context }: { context: DomainContextRun }) {
  return (
    <div className="pipeline-current-run">
      <div>
        <strong>Passive DNS / RDAP</strong>
        <OutcomeBadge outcome={context.latestRun.outcome} />
      </div>
      <span>{formatNumber(context.latestRun.completed)} of {formatNumber(context.latestRun.attempted)} selected lookups completed</span>
      <small>{formatNumber(context.recordCount)} bounded context records retained · ended {formatDateTime(context.latestRun.endedAt)} UTC</small>
    </div>
  );
}

export function PipelineHealthPanel() {
  const [health, setHealth] = useState<PipelineHealth | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    loadPipelineHealth(controller.signal)
      .then((value) => setHealth(value))
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setUnavailable(true);
      });
    return () => controller.abort();
  }, []);

  if (!health) {
    return (
      <section className="pipeline-health-panel pipeline-health-state" aria-labelledby="pipeline-health-title">
        <div>
          <p className="eyebrow"><Activity aria-hidden="true" /> Pipeline health</p>
          <h2 id="pipeline-health-title">Bounded collection windows</h2>
        </div>
        <p role="status">
          {unavailable
            ? "Aggregate pipeline-health metadata is temporarily unavailable. No coverage is inferred."
            : "Loading aggregate pipeline-health metadata…"}
        </p>
        {unavailable ? <a href="/data/pipeline-health.json">Open the aggregate JSON</a> : null}
      </section>
    );
  }

  const day = health.windows.find((window) => window.hours === 24)!;
  const week = health.windows.find((window) => window.hours === 168)!;
  return (
    <section className="pipeline-health-panel" aria-labelledby="pipeline-health-title">
      <div className="pipeline-health-heading">
        <div>
          <p className="eyebrow"><Activity aria-hidden="true" /> Pipeline health</p>
          <h2 id="pipeline-health-title">Bounded collection windows</h2>
        </div>
        <p>
          Repository-observed, aggregate counters for sampled best-effort collection. They are not continuous monitoring,
          complete CT coverage, or a measure of all phishing activity.
        </p>
      </div>
      <div className="pipeline-health-layout">
        <WindowSummary window={day} />
        <WindowSummary window={week} />
        <article className="pipeline-current">
          <header>
            <DatabaseZap aria-hidden="true" />
            <div><span>Current bounded jobs</span><small>{formatNumber(health.current.publishedSignals)} signals published</small></div>
          </header>
          {health.current.ctSearch ? (
            <div className="pipeline-current-run">
              <div>
                <strong>Checkpointed CT search</strong>
                <OutcomeBadge outcome={health.current.ctSearch.latestRun.outcome} />
              </div>
              <span>
                {formatNumber(health.current.ctSearch.latestRun.queriesCompleted)} of {formatNumber(health.current.ctSearch.latestRun.queriesAttempted)} bounded queries completed
              </span>
              <small>
                {formatNumber(health.current.ctSearch.latestRun.rowsProcessed)} indexed rows processed · {formatNumber(health.current.ctSearch.latestRun.queriesBacklogged)} queries backlogged
              </small>
            </div>
          ) : (
            <p className="pipeline-current-empty">No current public CT-search run summary.</p>
          )}
          {health.current.domainContext ? <ContextSummary context={health.current.domainContext} /> : (
            <p className="pipeline-current-empty">No current public passive DNS/RDAP run summary.</p>
          )}
          <footer>
            <RadioTower aria-hidden="true" />
            No candidate names, DNS answers, registration values, query terms, or cursors are included here.
          </footer>
        </article>
      </div>
      <p className="pipeline-health-footer">
        Zero matches means no row matched during recorded attempts, not that the unseen intervals were clean. <a href="/docs/#operations">Interpret the schedules</a> or <a href="/data/pipeline-health.json">inspect the aggregate JSON</a>.
      </p>
    </section>
  );
}
