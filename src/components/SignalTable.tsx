import { Check, ChevronLeft, ChevronRight, Copy, FileSearch, Link2, SearchX } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { brandPath } from "../lib/brandRegistry.ts";
import { evidenceTierLabel, signalEvidenceTier, signalMatchScore } from "../lib/dashboard.ts";
import { formatDateTime, formatRelativeTime, sentenceCase } from "../lib/format.ts";
import { signalPath } from "../lib/signalRoutes.ts";
import type { RadarSignal } from "../types.ts";
import { ScreenshotModal } from "./ScreenshotModal.tsx";

const PAGE_SIZE = 12;

interface DetailState {
  signal: RadarSignal;
  trigger: HTMLButtonElement;
}

function MatchScore({ signal }: { signal: RadarSignal }) {
  const value = signalMatchScore(signal);
  const level = value >= 80 ? "high" : value >= 50 ? "medium" : "low";
  return <span className={`confidence ${level}`} aria-label={`${value} match score out of 100`}><span>{value}</span><small>/100 match</small></span>;
}

export function SignalTable({ signals, now = Date.now(), snapshotGeneratedAt, onFacet }: {
  signals: RadarSignal[];
  now?: number;
  snapshotGeneratedAt: string;
  onFacet: (key: "brand" | "source" | "country", value: string) => void;
}) {
  const [page, setPage] = useState(1);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DetailState | null>(null);
  const pages = Math.max(1, Math.ceil(signals.length / PAGE_SIZE));

  useEffect(() => setPage((current) => Math.min(current, pages)), [pages]);
  const pageSignals = useMemo(() => signals.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [signals, page]);

  const copy = async (signal: RadarSignal) => {
    await navigator.clipboard.writeText(signal.url);
    setCopiedId(signal.id);
    window.setTimeout(() => setCopiedId(null), 1400);
  };
  const closeDetail = useCallback(() => setDetail(null), []);

  if (!signals.length) return <div className="empty-state"><SearchX aria-hidden="true" /><h3>No matching candidates</h3><p>Adjust the local search or controlled filters to widen the view.</p></div>;

  return <div className="table-panel">
    <div className="table-scroll" role="region" aria-label="Potential phishing candidates" tabIndex={0}>
      <table className="signal-table">
        <colgroup><col className="candidate-column" /><col className="brand-column" /><col className="evidence-column" /><col className="hosting-column" /><col className="timeline-column" /></colgroup>
        <thead><tr><th scope="col">Candidate</th><th scope="col">Potential brand</th><th scope="col">Evidence</th><th scope="col">Hosting observed</th><th scope="col">Timeline</th></tr></thead>
        <tbody>{pageSignals.map((signal) => {
          const tier = signalEvidenceTier(signal);
          return <tr key={signal.id} id={`signal-${signal.id}`}>
            <td className="indicator-cell" data-label="Candidate"><div><button className="candidate-link" type="button" aria-haspopup="dialog" onClick={(event) => setDetail({ signal, trigger: event.currentTarget })}><code title={signal.url}>{signal.url}</code></button><button type="button" onClick={() => void copy(signal)} aria-label={`Copy defanged URL ${signal.url}`}>{copiedId === signal.id ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}</button><a className="signal-deep-link" href={signalPath(signal)} aria-label={`Open permanent record for ${signal.domain}`}><Link2 aria-hidden="true" /></a></div><span>{signal.domain}</span></td>
            <td data-label="Potential brand">{signal.brand ? <><a className="brand-target" href={brandPath(signal.brand)}>{signal.brand}</a><div className="source-chips">{signal.sources.map((source) => <button type="button" key={source} onClick={() => onFacet("source", source)}>{source}</button>)}</div></> : <span className="unknown">Unclassified</span>}</td>
            <td data-label="Evidence"><span className={`status-pill ${signal.status}`}><i aria-hidden="true" />{sentenceCase(signal.status)}</span><MatchScore signal={signal} /><span className={`evidence-tier ${tier}`}>{evidenceTierLabel(tier)}</span></td>
            <td data-label="Hosting observed"><strong className="host-name" title={signal.host ?? undefined}>{signal.host ?? "Unknown host"}</strong>{signal.country ? <button className="facet-button country" type="button" onClick={() => onFacet("country", signal.country!)}>{signal.country}</button> : <span className="country">Unknown country</span>}</td>
            <td data-label="Timeline"><time dateTime={signal.lastSeen} title={`${formatDateTime(signal.lastSeen)} UTC`}>Last {formatRelativeTime(signal.lastSeen, now)}</time><span className="first-seen" title={`${formatDateTime(signal.firstSeen)} UTC`}>First {formatRelativeTime(signal.firstSeen, now)}</span><button className="record-link" type="button" aria-haspopup="dialog" onClick={(event) => setDetail({ signal, trigger: event.currentTarget })}>View details <FileSearch aria-hidden="true" /></button></td>
          </tr>;
        })}</tbody>
      </table>
    </div>
    <div className="pagination"><p>Showing <strong>{(page - 1) * PAGE_SIZE + 1}-{Math.min(page * PAGE_SIZE, signals.length)}</strong> of {signals.length}</p><div><button type="button" disabled={page === 1} onClick={() => setPage((value) => value - 1)}><ChevronLeft aria-hidden="true" /> Previous</button><span>Page <strong>{page}</strong> of {pages}</span><button type="button" disabled={page === pages} onClick={() => setPage((value) => value + 1)}>Next <ChevronRight aria-hidden="true" /></button></div></div>
    {detail ? <ScreenshotModal signal={detail.signal} snapshotGeneratedAt={snapshotGeneratedAt} returnFocus={detail.trigger} onClose={closeDetail} /> : null}
  </div>;
}
