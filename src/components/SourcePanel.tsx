import { CheckCircle2, CircleDashed, RadioTower } from "lucide-react";

import { formatRelativeTime } from "../lib/format";
import type { RadarSource } from "../types";

export function SourcePanel({ sources }: { sources: RadarSource[] }) {
  return (
    <article className="panel source-panel">
      <div className="panel-heading">
        <h2>Source coverage</h2>
        <span>{sources.filter((source) => source.state === "healthy").length}/{sources.length} active</span>
      </div>
      <ul className="source-list">
        {sources.map((source) => {
          const Icon = source.state === "healthy" ? CheckCircle2 : source.state === "partial" ? RadioTower : CircleDashed;
          return (
            <li key={source.name}>
              <Icon className={source.state} aria-hidden="true" />
              <div>
                <a href={source.homepage} target="_blank" rel="noreferrer">{source.name}</a>
                <span>{source.note ?? (source.fetchedAt ? `Synced ${formatRelativeTime(source.fetchedAt)}` : "Not configured")}</span>
              </div>
              <strong>{source.records}</strong>
            </li>
          );
        })}
      </ul>
    </article>
  );
}
