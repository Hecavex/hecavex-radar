import { useEffect, useState } from "react";

import { formatRelativeTime } from "../lib/format";
import {
  loadCollectionHealth,
  type CollectionAttempt,
  type CollectionHealth as CollectionHealthArtifact,
  type CollectionOutcome,
} from "../lib/collectionHealth";

const outcomeLabels: Record<CollectionOutcome, string> = {
  "healthy-empty": "Healthy empty",
  "healthy-matches": "Healthy with matches",
  "no-input": "No input",
  partial: "Partial",
  failed: "Failed",
};

function duration(value: number): string {
  if (value < 60) return `${value.toFixed(value < 10 ? 1 : 0)} seconds`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
}

function exactNumber(value: number): string {
  return new Intl.NumberFormat("en-GB").format(value);
}

function exactTimestamp(value: string): string {
  return `${new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(Date.parse(value))} UTC`;
}

function listeningSeconds(value: number): string {
  return `${new Intl.NumberFormat("en-GB", { minimumFractionDigits: 1, maximumFractionDigits: 3 }).format(value)}s`;
}

function scheduleLabel(attempt: CollectionAttempt): string {
  if (attempt.scheduleStatus === "manual") return "Manual run";
  if (attempt.scheduleStatus === "unknown") return "Schedule unknown";
  if (attempt.scheduleStatus === "delayed") return `Delayed by ${duration(attempt.delaySeconds ?? 0)}`;
  return `Scheduled · ${duration(attempt.delaySeconds ?? 0)} start delay`;
}

export function CollectionHealth({ now = Date.now() }: { now?: number }) {
  const [health, setHealth] = useState<CollectionHealthArtifact | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    loadCollectionHealth(controller.signal)
      .then((value) => setHealth(value))
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setUnavailable(true);
      });
    return () => controller.abort();
  }, []);

  if (!health) {
    return (
      <section className="collection-health" aria-labelledby="collection-health-title">
        <div>
          <p className="eyebrow">Collection health</p>
          <h3 id="collection-health-title">Latest CertStream attempt</h3>
        </div>
        <p role="status">
          {unavailable ? "Public collection-health metadata is temporarily unavailable." : "Loading public attempt telemetry…"}
        </p>
        <noscript>
          <p><a href="/data/collection-health.json">View the public collection-health JSON</a>.</p>
        </noscript>
      </section>
    );
  }

  if (health.latestAttempt === null) {
    return (
      <section className="collection-health" aria-labelledby="collection-health-title">
        <div className="collection-health-heading">
          <div>
            <p className="eyebrow">Collection health</p>
            <h3 id="collection-health-title">Latest CertStream attempt</h3>
          </div>
          <span className="health-badge">Awaiting first measured attempt</span>
        </div>
        <p className="collection-health-summary">
          Collection-health instrumentation is ready. The first completed scheduled or manual workflow will replace this
          bootstrap document with actual timing and aggregate counts.
        </p>
        <p className="collection-health-note">
          No legacy listening duration is inferred from a configured window. <a href="/data/collection-health.json">View
          the public JSON</a>.
        </p>
      </section>
    );
  }

  const attempt = health.latestAttempt;
  const lastSuccessAge = health.lastSuccessAt === null ? null : Math.max(0, now - Date.parse(health.lastSuccessAt));
  const isFresh = lastSuccessAge !== null && lastSuccessAge <= health.staleAfterSeconds * 1000;
  const freshnessLabel = lastSuccessAge === null ? "No successful window recorded" : isFresh ? "Current" : "Stale";

  return (
    <section className="collection-health" aria-labelledby="collection-health-title">
      <div className="collection-health-heading">
        <div>
          <p className="eyebrow">Collection health</p>
          <h3 id="collection-health-title">Latest CertStream attempt</h3>
        </div>
        <div className="collection-health-statuses" aria-label="Latest collection statuses">
          <span className={`health-badge outcome-${attempt.outcome}`}>{outcomeLabels[attempt.outcome]}</span>
          <span className={`health-badge schedule-${attempt.scheduleStatus}`}>{scheduleLabel(attempt)}</span>
          <span className={`health-badge freshness-${isFresh ? "current" : "stale"}`}>{freshnessLabel}</span>
        </div>
      </div>
      <p className="collection-health-summary">{attempt.summary}</p>
      <dl className="collection-health-grid">
        <div>
          <dt>Actual attempt</dt>
          <dd>
            <time dateTime={attempt.startedAt}>{exactTimestamp(attempt.startedAt)}</time>
            <span>ended <time dateTime={attempt.endedAt}>{exactTimestamp(attempt.endedAt)}</time></span>
          </dd>
        </div>
        <div>
          <dt>Listening</dt>
          <dd>
            {listeningSeconds(attempt.listeningSeconds)}
            <span>of {exactNumber(attempt.expectedListeningSeconds)}s expected</span>
          </dd>
        </div>
        <div>
          <dt>Messages</dt>
          <dd>{exactNumber(attempt.messages)}</dd>
        </div>
        <div>
          <dt>DNS names</dt>
          <dd>{exactNumber(attempt.dnsNames)}</dd>
        </div>
        <div>
          <dt>Matches</dt>
          <dd>
            {exactNumber(attempt.matches)}
            <span>{exactNumber(attempt.newRecords)} new archive records</span>
          </dd>
        </div>
        <div>
          <dt>Last success</dt>
          <dd>
            {health.lastSuccessAt ? formatRelativeTime(health.lastSuccessAt, now) : "Not recorded"}
            <span>{health.lastSuccessAt ? exactTimestamp(health.lastSuccessAt) : "Awaiting a healthy window"}</span>
          </dd>
        </div>
      </dl>
      <p className="collection-health-note">
        Counts describe this bounded attempt only. They contain no certificate names or unpublished candidates. A delayed
        start is reported separately from whether the listening window processed usable input.
      </p>
    </section>
  );
}
