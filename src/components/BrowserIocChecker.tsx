import {
  CheckCircle2,
  FileLock2,
  SearchCheck,
  ShieldQuestion,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";
import { type ChangeEvent, useMemo, useRef, useState } from "react";

import {
  MAXIMUM_IOC_FILE_BYTES,
  MAXIMUM_IOC_LINES,
  checkIocs,
  parseIocInput,
  type IocCheckResult,
} from "../lib/iocCheck.ts";
import { formatDateTime } from "../lib/format.ts";
import type { RadarHistory, RadarSignal } from "../types.ts";

type ResultFilter = "all" | "matched" | "unknown" | "invalid";

const PAGE_SIZE = 50;

const kindLabels: Record<NonNullable<IocCheckResult["kind"]>, string> = {
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
};

function resultState(result: IocCheckResult): Exclude<ResultFilter, "all"> {
  if (result.error) return "invalid";
  return result.matches.length > 0 ? "matched" : "unknown";
}

export type BrowserIocCheckerProps = {
  signals: readonly RadarSignal[];
  history: RadarHistory | null;
  signalHref?: (signalId: string) => string;
};

export function BrowserIocChecker({
  signals,
  history,
  signalHref = (signalId) => `/signals/${signalId}/`,
}: BrowserIocCheckerProps) {
  const [input, setInput] = useState("");
  const [submitted, setSubmitted] = useState<ReturnType<typeof parseIocInput> | null>(null);
  const [fileMessage, setFileMessage] = useState<string | null>(null);
  const [filter, setFilter] = useState<ResultFilter>("all");
  const [page, setPage] = useState(1);
  const fileInput = useRef<HTMLInputElement>(null);

  const results = useMemo(
    () => submitted ? checkIocs(submitted.indicators, signals, history) : [],
    [history, signals, submitted],
  );
  const counts = useMemo(() => ({
    matched: results.filter((result) => resultState(result) === "matched").length,
    unknown: results.filter((result) => resultState(result) === "unknown").length,
    invalid: results.filter((result) => resultState(result) === "invalid").length,
  }), [results]);
  const filteredResults = useMemo(
    () => filter === "all" ? results : results.filter((result) => resultState(result) === filter),
    [filter, results],
  );
  const pageCount = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const visibleResults = filteredResults.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const runCheck = () => {
    const bytes = new TextEncoder().encode(input).byteLength;
    if (bytes > MAXIMUM_IOC_FILE_BYTES) {
      setFileMessage(`Input is larger than ${MAXIMUM_IOC_FILE_BYTES / 1024} KiB.`);
      setSubmitted(null);
      return;
    }
    setSubmitted(parseIocInput(input));
    setFileMessage(null);
    setFilter("all");
    setPage(1);
  };

  const clear = () => {
    setInput("");
    setSubmitted(null);
    setFileMessage(null);
    setFilter("all");
    setPage(1);
    if (fileInput.current) fileInput.current.value = "";
  };

  const readFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAXIMUM_IOC_FILE_BYTES) {
      setFileMessage(`${file.name} exceeds the ${MAXIMUM_IOC_FILE_BYTES / 1024} KiB local file limit.`);
      return;
    }
    try {
      const contents = await file.text();
      setInput(contents);
      setSubmitted(null);
      setFileMessage(`${file.name} was read locally. It has not been uploaded.`);
    } catch {
      setFileMessage(`The browser could not read ${file.name}.`);
    }
  };

  return (
    <section className="radar-tool radar-ioc-checker" aria-labelledby="ioc-checker-title">
      <header className="radar-tool-heading">
        <div>
          <p className="eyebrow"><SearchCheck aria-hidden="true" /> Local IOC lookup</p>
          <h2 id="ioc-checker-title">Check indicators against Radar</h2>
        </div>
        <p>
          Exact-match domains, URLs, and hashes against the current snapshot and retained public history.
          Normalisation and matching happen only in this browser.
        </p>
      </header>

      <div className="radar-tool-notice radar-tool-notice--privacy">
        <FileLock2 aria-hidden="true" />
        <div>
          <strong>Your indicators are not transmitted</strong>
          <p>
            This tool makes no lookup request and stores no submitted value. Pasted text and selected files remain
            in page memory until you clear them, refresh, or close the tab.
          </p>
        </div>
      </div>

      <div className="radar-ioc-input">
        <label htmlFor="radar-ioc-values">One indicator per line</label>
        <textarea
          id="radar-ioc-values"
          value={input}
          onChange={(event) => {
            setInput(event.target.value);
            setSubmitted(null);
            setFileMessage(null);
          }}
          rows={10}
          spellCheck="false"
          autoCapitalize="none"
          autoComplete="off"
          aria-describedby="radar-ioc-help"
          placeholder={'example[.]lt\nhxxps://example[.]lt/login\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'}
        />
        <p id="radar-ioc-help">
          Up to {MAXIMUM_IOC_LINES.toLocaleString("en-GB")} lines or {MAXIMUM_IOC_FILE_BYTES / 1024} KiB.
          HTTP(S), hxxp(s), common dot defangs, MD5, SHA-1 and SHA-256 are accepted. Blank and # comment lines are ignored.
        </p>
        <div className="radar-ioc-actions">
          <button type="button" className="radar-tool-button radar-tool-button--primary" onClick={runCheck} disabled={!input.trim()}>
            <SearchCheck aria-hidden="true" /> Check locally
          </button>
          <label className="radar-tool-button radar-tool-file-button">
            <Upload aria-hidden="true" /> Read text file
            <input ref={fileInput} type="file" accept=".txt,text/plain" onChange={(event) => void readFile(event)} />
          </label>
          <button type="button" className="radar-tool-button" onClick={clear} disabled={!input && !submitted && !fileMessage}>
            <Trash2 aria-hidden="true" /> Clear from memory
          </button>
        </div>
        {fileMessage ? <p className="radar-tool-message" role="status">{fileMessage}</p> : null}
      </div>

      {submitted ? (
        <div className="radar-ioc-results">
          <p className="sr-only" role="status">
            Checked {results.length} unique indicators: {counts.matched} exact matches, {counts.unknown} unknown,
            and {counts.invalid} unsupported.
          </p>
          <div className="radar-tool-notice radar-tool-notice--warning">
            <ShieldQuestion aria-hidden="true" />
            <div>
              <strong>No match means unknown, not safe</strong>
              <p>
                Radar is a bounded observation dataset, not an allow-list. Absence does not establish reputation,
                intent, or safety, and an exact match is not by itself proof of maliciousness.
              </p>
            </div>
          </div>

          <div className="radar-tool-summary" aria-label="IOC check summary">
            <button type="button" className={filter === "all" ? "active" : ""} onClick={() => { setFilter("all"); setPage(1); }}>
              <span>Checked</span><strong>{results.length}</strong>
            </button>
            <button type="button" className={filter === "matched" ? "active" : ""} onClick={() => { setFilter("matched"); setPage(1); }}>
              <span>Exact matches</span><strong>{counts.matched}</strong>
            </button>
            <button type="button" className={filter === "unknown" ? "active" : ""} onClick={() => { setFilter("unknown"); setPage(1); }}>
              <span>Unknown</span><strong>{counts.unknown}</strong>
            </button>
            <button type="button" className={filter === "invalid" ? "active" : ""} onClick={() => { setFilter("invalid"); setPage(1); }}>
              <span>Unsupported</span><strong>{counts.invalid}</strong>
            </button>
          </div>

          {submitted.truncated || submitted.duplicateCount > 0 || submitted.ignoredCount > 0 ? (
            <p className="radar-tool-message" role="status">
              {submitted.truncated ? `Only the first ${MAXIMUM_IOC_LINES.toLocaleString("en-GB")} lines were checked. ` : ""}
              {submitted.duplicateCount > 0 ? `${submitted.duplicateCount} duplicate line(s) were collapsed. ` : ""}
              {submitted.ignoredCount > 0 ? `${submitted.ignoredCount} blank or comment line(s) were ignored.` : ""}
            </p>
          ) : null}

          {visibleResults.length === 0 ? (
            <div className="radar-tool-empty">No results are present in this view.</div>
          ) : (
            <div className="radar-tool-table-scroll">
              <table className="radar-tool-table">
                <thead>
                  <tr>
                    <th>Submitted indicator</th>
                    <th>Local result</th>
                    <th>Exact Radar record</th>
                    <th>Observed timeline</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleResults.map((result) => {
                    const state = resultState(result);
                    return (
                      <tr key={`${result.kind ?? "invalid"}:${result.normalized ?? result.raw}`}>
                        <td>
                          <span className="radar-tool-kicker">{result.kind ? kindLabels[result.kind] : "Unsupported"}</span>
                          <code>{result.normalized ?? result.raw}</code>
                        </td>
                        <td>
                          <span className={`radar-ioc-state radar-ioc-state--${state}`}>
                            {state === "matched" ? <CheckCircle2 aria-hidden="true" /> : state === "unknown" ? <ShieldQuestion aria-hidden="true" /> : <XCircle aria-hidden="true" />}
                            {state === "matched" ? "Exact match" : state === "unknown" ? "Not observed" : "Not checked"}
                          </span>
                          {result.error ? <small>{result.error}</small> : null}
                        </td>
                        <td>
                          {result.matches.length === 0 ? <span className="radar-tool-muted">No record</span> : (
                            <ul className="radar-ioc-matches">
                              {result.matches.map((match) => (
                                <li key={`${match.signalId}:${match.matchedField}`}>
                                  <a href={signalHref(match.signalId)}>{match.domain}</a>
                                  <span>{match.brand ?? "Unassigned brand"} · {match.datasets.join(" + ")}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                        <td>
                          {result.matches.length === 0 ? <span className="radar-tool-muted">Unknown</span> : (
                            <span className="radar-ioc-timeline">
                              First {formatDateTime(result.matches[0].firstSeen)} UTC<br />
                              Last {formatDateTime(result.matches[0].lastSeen)} UTC
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {pageCount > 1 ? (
            <nav className="radar-tool-pagination" aria-label="IOC result pages">
              <button type="button" onClick={() => setPage(Math.max(1, safePage - 1))} disabled={safePage === 1}>Previous</button>
              <span>Page {safePage} of {pageCount}</span>
              <button type="button" onClick={() => setPage(Math.min(pageCount, safePage + 1))} disabled={safePage === pageCount}>Next</button>
            </nav>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
