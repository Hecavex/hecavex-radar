import { CheckCircle2, CircleDashed, RadioTower } from "lucide-react";

import { formatRelativeTime } from "../lib/format.ts";
import type { RadarSource } from "../types.ts";

export function SourcePanel({ sources, now = Date.now() }: { sources: RadarSource[]; now?: number }) {
  const healthy = sources.filter((source) => source.state === "healthy").length;
  const partial = sources.filter((source) => source.state === "partial").length;
  const skipped = sources.filter((source) => source.state === "skipped").length;
  const statusSummary = [
    `${healthy} loaded`,
    partial ? `${partial} partial` : null,
    skipped ? `${skipped} optional off` : null,
  ].filter(Boolean).join(" · ");

  const sourceDetail = (source: RadarSource) => {
    if (source.state === "skipped") {
      return "Optional source not configured for this deployment.";
    }
    if (source.state === "partial") {
      return source.fetchedAt
        ? `Latest refresh was incomplete; last successful archive read ${formatRelativeTime(source.fetchedAt, now)}.`
        : "Latest refresh was incomplete; no successful archive-read time is available.";
    }
    if (source.records === 0) {
      return source.fetchedAt
        ? `Archive read succeeded ${formatRelativeTime(source.fetchedAt, now)}; no qualifying recent rows were loaded.`
        : "Archive read succeeded; no qualifying recent rows were loaded.";
    }
    return source.fetchedAt
      ? `Archive read succeeded ${formatRelativeTime(source.fetchedAt, now)}.`
      : "Archive read succeeded; its timestamp is unavailable.";
  };

  return (
    <article className="panel source-panel">
      <div className="panel-heading">
        <h2>Publication inputs</h2>
        <span>{statusSummary}</span>
      </div>
      <ul className="source-list">
        {sources.map((source) => {
          const Icon = source.state === "healthy" ? CheckCircle2 : source.state === "partial" ? RadioTower : CircleDashed;
          return (
            <li key={source.name}>
              <Icon className={source.state} aria-hidden="true" />
              <div>
                <a href={source.homepage} target="_blank" rel="noreferrer">{source.name}</a>
                <span>{source.note}</span>
                <small>{sourceDetail(source)}</small>
              </div>
              <strong aria-label={`${source.records} qualifying ${source.records === 1 ? "row" : "rows"}`}>
                {source.records}
              </strong>
            </li>
          );
        })}
      </ul>
      <p className="source-panel-note">
        Source timestamps describe the most recent snapshot archive read, not a collector connection or provider-wide
        freshness guarantee. Zero rows can be a healthy empty result; it does not mean that no certificates or phishing
        sites existed.
      </p>
    </article>
  );
}
