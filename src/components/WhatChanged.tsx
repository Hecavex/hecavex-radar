import { ArrowDownRight, Clock3, RefreshCw, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { loadChangeAggregate, type ChangeWindow } from "../lib/changeData.ts";
import { evidenceTierLabel, signalEvidenceTier } from "../lib/dashboard.ts";
import { formatDateTime, formatRelativeTime } from "../lib/format.ts";
import type { RadarSignal } from "../types.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

export function WhatChanged({
  signals,
  now,
  onSelect,
}: {
  signals: RadarSignal[];
  now: number;
  onSelect: (signal: RadarSignal) => void;
}) {
  const summary = useMemo(() => {
    const cutoff = now - DAY_MS;
    const changed = signals
      .filter((signal) => Date.parse(signal.lastSeen) >= cutoff)
      .sort((left, right) => Date.parse(right.lastSeen) - Date.parse(left.lastSeen));
    const discovered = changed.filter((signal) => Date.parse(signal.firstSeen) >= cutoff);
    const reobserved = changed.filter((signal) => Date.parse(signal.firstSeen) < cutoff);
    const corroborated = changed.filter((signal) => signalEvidenceTier(signal) !== "name-only");
    return { changed, discovered, reobserved, corroborated };
  }, [now, signals]);
  const [publishedWindow, setPublishedWindow] = useState<ChangeWindow | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void loadChangeAggregate(controller.signal).then((aggregate) => {
      if (!controller.signal.aborted) setPublishedWindow(aggregate?.windows.find((window) => window.hours === 24) ?? null);
    });
    return () => controller.abort();
  }, []);

  return (
    <section className="change-panel" aria-labelledby="changes-title">
      <div className="change-heading">
        <div>
          <p className="eyebrow"><Clock3 aria-hidden="true" /> Current 24-hour window</p>
          <h2 id="changes-title">What changed</h2>
        </div>
        <p>{publishedWindow ? "Publisher-counted events, with current candidate links below." : "Derived from timestamps in this retained snapshot."}</p>
      </div>
      <div className="change-layout">
        <div className="change-metrics" aria-label="Recent candidate changes">
          <div><Sparkles aria-hidden="true" /><strong>{publishedWindow?.firstPublications ?? summary.discovered.length}</strong><span>First publications</span></div>
          <div><RefreshCw aria-hidden="true" /><strong>{publishedWindow?.reobservations ?? summary.reobserved.length}</strong><span>Reobservations</span></div>
          <div><ArrowDownRight aria-hidden="true" /><strong>{publishedWindow?.statusChanges ?? 0}</strong><span>Status changes</span></div>
        </div>
        <ol className="change-list">
          {summary.changed.slice(0, 6).map((signal) => {
            const isNew = Date.parse(signal.firstSeen) >= now - DAY_MS;
            return (
              <li key={signal.id}>
                <a href={`#signal-${signal.id}`} onClick={() => onSelect(signal)}>
                  <span className={`change-kind ${isNew ? "new" : "reobserved"}`}>{isNew ? "New" : "Seen again"}</span>
                  <code>{signal.domain}</code>
                  <span>{signal.brand ?? "No brand classification"} · {evidenceTierLabel(signalEvidenceTier(signal))}</span>
                  <time dateTime={signal.lastSeen} title={`${formatDateTime(signal.lastSeen)} UTC`}>
                    {formatRelativeTime(signal.lastSeen, now)}
                  </time>
                </a>
              </li>
            );
          })}
          {summary.changed.length === 0 ? <li className="change-empty">No retained candidate changed during this window.</li> : null}
        </ol>
      </div>
    </section>
  );
}
