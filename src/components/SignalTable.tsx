import { Camera, Check, ChevronLeft, ChevronRight, Copy, FileSearch, SearchX } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { formatDateTime, formatRelativeTime, sentenceCase } from "../lib/format.ts";
import type { RadarSignal } from "../types.ts";
import { ScreenshotModal } from "./ScreenshotModal.tsx";

const PAGE_SIZE = 25;

interface CaptureState {
  signal: RadarSignal;
  trigger: HTMLButtonElement;
}

function Confidence({ value }: { value: number }) {
  const level = value >= 80 ? "high" : value >= 50 ? "medium" : "low";
  return (
    <span className={`confidence ${level}`} aria-label={`${value} confidence score out of 100`}>
      <span>{value}</span><small>/100</small>
    </span>
  );
}

export function SignalTable({ signals, now = Date.now() }: { signals: RadarSignal[]; now?: number }) {
  const [page, setPage] = useState(1);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [capture, setCapture] = useState<CaptureState | null>(null);
  const pages = Math.max(1, Math.ceil(signals.length / PAGE_SIZE));

  useEffect(() => setPage(1), [signals]);
  const pageSignals = useMemo(() => signals.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [signals, page]);

  const copy = async (signal: RadarSignal) => {
    await navigator.clipboard.writeText(signal.url);
    setCopiedId(signal.id);
    window.setTimeout(() => setCopiedId(null), 1400);
  };
  const closeCapture = useCallback(() => setCapture(null), []);

  if (signals.length === 0) {
    return (
      <div className="empty-state">
        <SearchX aria-hidden="true" />
        <h3>No matching signals</h3>
        <p>Adjust the search or filters to widen the result set.</p>
      </div>
    );
  }

  return (
    <div className="table-panel">
      <div className="table-scroll" role="region" aria-label="Potential phishing signals" tabIndex={0}>
        <table>
          <thead>
            <tr>
              <th scope="col">Indicator</th>
              <th scope="col">Target</th>
              <th scope="col">Source</th>
              <th scope="col">State</th>
              <th scope="col">Host</th>
              <th scope="col">Timeline</th>
              <th scope="col"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {pageSignals.map((signal) => (
              <tr key={signal.id}>
                <td className="indicator-cell" data-label="Indicator">
                  <div>
                    <code title={signal.url}>{signal.url}</code>
                    <button type="button" onClick={() => void copy(signal)} aria-label={`Copy defanged URL ${signal.url}`}>
                      {copiedId === signal.id ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                    </button>
                  </div>
                  <span>{signal.domain}</span>
                </td>
                <td data-label="Target">{signal.brand ? <strong className="brand-target">{signal.brand}</strong> : <span className="unknown">Unclassified</span>}</td>
                <td data-label="Source">
                  <div className="source-chips">
                    {signal.sources.map((source) => <span key={source}>{source}</span>)}
                  </div>
                </td>
                <td data-label="State">
                  <span className={`status-pill ${signal.status}`}><i aria-hidden="true" />{sentenceCase(signal.status)}</span>
                  <Confidence value={signal.confidence} />
                </td>
                <td data-label="Host">
                  <strong className="host-name">{signal.host ?? "Unknown host"}</strong>
                  <span className="country">{signal.country ?? "Unknown country"}</span>
                </td>
                <td data-label="Timeline">
                  <time dateTime={signal.lastSeen} title={formatDateTime(signal.lastSeen)}>{formatRelativeTime(signal.lastSeen, now)}</time>
                  <span className="first-seen">First {formatRelativeTime(signal.firstSeen, now)}</span>
                </td>
                <td className="capture-cell" data-label="Evidence">
                  {signal.screenshotUrl || signal.referenceUrl || signal.hashes?.length || signal.reasonCodes?.length || signal.detailAvailable ? (
                    <button
                      type="button"
                      aria-haspopup="dialog"
                      onClick={(event) => setCapture({ signal, trigger: event.currentTarget })}
                      aria-label={`View evidence and domain intelligence for ${signal.domain}`}
                    >
                      {signal.screenshotUrl ? <Camera aria-hidden="true" /> : <FileSearch aria-hidden="true" />}
                    </button>
                  ) : <span aria-label="No evidence available">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <p>
          Showing <strong>{(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, signals.length)}</strong> of {signals.length}
        </p>
        <div>
          <button type="button" disabled={page === 1} onClick={() => setPage((value) => value - 1)}>
            <ChevronLeft aria-hidden="true" /> Previous
          </button>
          <span>Page <strong>{page}</strong> of {pages}</span>
          <button type="button" disabled={page === pages} onClick={() => setPage((value) => value + 1)}>
            Next <ChevronRight aria-hidden="true" />
          </button>
        </div>
      </div>
      {capture && (
        <ScreenshotModal signal={capture.signal} returnFocus={capture.trigger} onClose={closeCapture} />
      )}
    </div>
  );
}
