import { Check, Copy, ExternalLink, X } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

import { formatDateTime } from "../lib/format.ts";
import { loadSignalDetail } from "../lib/signalDetail.ts";
import type { RadarSignal, SignalCertificateDetail, SignalDetail, SignalDetailObservation } from "../types.ts";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

interface IsolatedElement {
  element: HTMLElement;
  inert: string | null;
  ariaHidden: string | null;
}

function focusableElements(dialog: HTMLElement) {
  return Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (element) => element.tabIndex >= 0 && !element.closest("[hidden], [inert], [aria-hidden='true']"),
  );
}

function isolateBackground(modalBackdrop: HTMLElement) {
  const isolated: IsolatedElement[] = [];
  let branch = modalBackdrop;

  while (branch.parentElement) {
    const parent = branch.parentElement;
    for (const sibling of Array.from(parent.children)) {
      if (sibling === branch || !(sibling instanceof HTMLElement)) continue;
      isolated.push({
        element: sibling,
        inert: sibling.getAttribute("inert"),
        ariaHidden: sibling.getAttribute("aria-hidden"),
      });
      sibling.setAttribute("inert", "");
      sibling.setAttribute("aria-hidden", "true");
    }

    if (parent === document.body) break;
    branch = parent;
  }

  return () => {
    for (const { element, inert, ariaHidden } of isolated.reverse()) {
      if (inert === null) element.removeAttribute("inert");
      else element.setAttribute("inert", inert);

      if (ariaHidden === null) element.removeAttribute("aria-hidden");
      else element.setAttribute("aria-hidden", ariaHidden);
    }
  };
}

interface ScreenshotModalProps {
  signal: RadarSignal;
  returnFocus: HTMLElement;
  onClose: () => void;
}

type DetailLoadState =
  | { status: "idle" | "loading" }
  | { status: "ready"; detail: SignalDetail }
  | { status: "error" };

function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function CopyableValue({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  };

  return (
    <span className="detail-copyable">
      <code>{value}</code>
      <button
        type="button"
        onClick={() => void copy()}
        aria-label={copied ? `${label} copied` : `Copy ${label} ${value}`}
      >
        {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      </button>
      <span className="sr-only" aria-live="polite">{copied ? "Copied" : ""}</span>
    </span>
  );
}

function CertificateDetail({ certificate }: { certificate: SignalCertificateDetail }) {
  const fingerprints = [
    ["MD5", certificate.fingerprints.md5],
    ["SHA-1", certificate.fingerprints.sha1],
    ["SHA-256", certificate.fingerprints.sha256],
  ] as const;
  const hasFingerprints = fingerprints.some(([, digest]) => digest !== null);

  return (
    <section className="detail-group" aria-label="TLS certificate">
      <h5>TLS certificate</h5>
      <dl className="detail-grid">
        {certificate.issuer ? <DetailItem label="Issuer"><span>{certificate.issuer}</span></DetailItem> : null}
        {certificate.countryName ? <DetailItem label="Declared country"><span>{certificate.countryName}</span></DetailItem> : null}
        {certificate.commonName ? (
          <DetailItem label="Common name"><CopyableValue value={certificate.commonName} label="certificate common name" /></DetailItem>
        ) : null}
        {certificate.serialNumberHex ? (
          <DetailItem label="Serial number"><CopyableValue value={certificate.serialNumberHex} label="certificate serial number" /></DetailItem>
        ) : null}
        {certificate.notBefore ? (
          <DetailItem label="Valid from"><time dateTime={certificate.notBefore}>{formatDateTime(certificate.notBefore)} UTC</time></DetailItem>
        ) : null}
        {certificate.notAfter ? (
          <DetailItem label="Valid until"><time dateTime={certificate.notAfter}>{formatDateTime(certificate.notAfter)} UTC</time></DetailItem>
        ) : null}
      </dl>
      {certificate.subjectAltNames.length > 0 ? (
        <div className="detail-list">
          <h6>Related certificate names</h6>
          <ul>
            {certificate.subjectAltNames.map((name) => (
              <li key={name}><CopyableValue value={name} label="certificate DNS name" /></li>
            ))}
          </ul>
          {certificate.subjectAltNameCount > certificate.subjectAltNames.length ? (
            <p>
              Showing {certificate.subjectAltNames.length} of {certificate.subjectAltNameCount} related certificate names.
            </p>
          ) : null}
        </div>
      ) : null}
      {hasFingerprints ? (
        <div className="detail-list">
          <h6>Certificate fingerprints</h6>
          <p>MD5 and SHA-1 values are legacy identifiers for pivots, not proof of certificate security.</p>
          <ul>
            {fingerprints.map(([algorithm, digest]) => digest ? (
              <li key={algorithm}>
                <span>{algorithm}</span>
                <CopyableValue value={digest} label={`${algorithm} certificate fingerprint`} />
              </li>
            ) : null)}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function ObservationDetail({ observation }: { observation: SignalDetailObservation }) {
  return (
    <article className="detail-observation">
      <header>
        <div>
          <span className="source-chip">{observation.source}</span>
          <h4>Observed {formatDateTime(observation.observedAt)} UTC</h4>
        </div>
      </header>
      {observation.page ? (
        <section className="detail-group" aria-label="Observed page">
          <h5>Observed page</h5>
          <dl className="detail-grid">
            {observation.page.title ? <DetailItem label="Page title"><span>{observation.page.title}</span></DetailItem> : null}
            {observation.page.httpStatus !== null ? (
              <DetailItem label="Page HTTP status"><code>{observation.page.httpStatus}</code></DetailItem>
            ) : null}
          </dl>
        </section>
      ) : null}
      {observation.network ? (
        <section className="detail-group" aria-label="Observed network">
          <h5>Observed network</h5>
          <dl className="detail-grid">
            {observation.network.ipAddress ? (
              <DetailItem label="IP address"><CopyableValue value={observation.network.ipAddress} label="defanged IP address" /></DetailItem>
            ) : null}
            {observation.network.asn !== null ? (
              <DetailItem label="Autonomous system"><CopyableValue value={`AS${observation.network.asn}`} label="autonomous system" /></DetailItem>
            ) : null}
            {observation.network.asnDescription ? (
              <DetailItem label="AS description"><span>{observation.network.asnDescription}</span></DetailItem>
            ) : null}
            {observation.network.asnRegistry ? (
              <DetailItem label="AS registry"><span>{observation.network.asnRegistry}</span></DetailItem>
            ) : null}
          </dl>
        </section>
      ) : null}
      {observation.assessment ? (
        <section className="detail-group" aria-label="URLScan assessment">
          <h5>URLScan assessment</h5>
          <dl className="detail-grid">
            {observation.assessment.urlscanVerdictScore !== null ? (
              <DetailItem label="URLScan verdict score">
                <strong>{observation.assessment.urlscanVerdictScore}</strong><span className="detail-scale"> / -100 to 100</span>
              </DetailItem>
            ) : null}
            {observation.assessment.urlscanCategories.length > 0 ? (
              <DetailItem label="Reported categories">
                <span className="detail-tags">
                  {observation.assessment.urlscanCategories.map((category) => <span key={category}>{category}</span>)}
                </span>
              </DetailItem>
            ) : null}
            {observation.assessment.redirectedToDomain ? (
              <DetailItem label="Observed redirect destination">
                <CopyableValue
                  value={observation.assessment.redirectedToDomain}
                  label="defanged redirect destination"
                />
              </DetailItem>
            ) : null}
          </dl>
          <p className="detail-note">
            Provider assessment is separate from Radar confidence. A redirect is observed behavior, not a benign verdict;
            destination and content can vary by visitor, time, or cloaking rules.
          </p>
        </section>
      ) : null}
      {observation.certificate ? <CertificateDetail certificate={observation.certificate} /> : null}
    </article>
  );
}

export function ScreenshotModal({ signal, returnFocus, onClose }: ScreenshotModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const [detailState, setDetailState] = useState<DetailLoadState>({
    status: signal.detailAvailable ? "loading" : "idle",
  });
  const [detailAttempt, setDetailAttempt] = useState(0);

  useEffect(() => {
    if (!signal.detailAvailable) {
      setDetailState({ status: "idle" });
      return;
    }
    const controller = new AbortController();
    setDetailState({ status: "loading" });
    void loadSignalDetail(signal, controller.signal)
      .then((detail) => {
        if (!controller.signal.aborted) setDetailState({ status: "ready", detail });
      })
      .catch(() => {
        if (!controller.signal.aborted) setDetailState({ status: "error" });
      });
    return () => controller.abort();
  }, [detailAttempt, signal.detailAvailable, signal.domain, signal.id]);

  useLayoutEffect(() => {
    const backdrop = backdropRef.current;
    const dialog = dialogRef.current;
    if (!backdrop || !dialog) return;

    closeRef.current?.focus({ preventScroll: true });
    const restoreBackground = isolateBackground(backdrop);

    const focusInsideDialog = (last = false) => {
      const focusable = focusableElements(dialog);
      const target = last ? focusable.at(-1) : focusable[0];
      (target ?? dialog).focus({ preventScroll: true });
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        onClose();
        return;
      }

      if (event.key !== "Tab") return;
      const focusable = focusableElements(dialog);
      const first = focusable[0];
      const last = focusable.at(-1);
      const active = document.activeElement;

      if (!first || !last) {
        event.preventDefault();
        dialog.focus({ preventScroll: true });
      } else if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    };

    const onFocusIn = (event: FocusEvent) => {
      if (!(event.target instanceof Node) || dialog.contains(event.target)) return;
      focusInsideDialog();
    };

    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("focusin", onFocusIn);
      restoreBackground();
      if (returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
    };
  }, [onClose, returnFocus]);

  return (
    <div ref={backdropRef} className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section ref={dialogRef} className="capture-modal" role="dialog" aria-modal="true" aria-labelledby="capture-title" tabIndex={-1}>
        <div className="capture-heading">
          <div>
            <p className="eyebrow">Passive evidence</p>
            <h2 id="capture-title">{signal.domain}</h2>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close capture">
            <X aria-hidden="true" />
          </button>
        </div>
        {signal.detailAvailable ? (
          <section className="signal-intelligence" aria-labelledby="signal-intelligence-title">
            <div className="signal-intelligence-heading">
              <div>
                <p className="eyebrow">Domain intelligence</p>
                <h3 id="signal-intelligence-title">Passive context</h3>
              </div>
              <span>Radar score {signal.confidence}/100</span>
            </div>
            {detailState.status === "loading" ? (
              <div className="detail-state" role="status" aria-live="polite">
                <p>Loading bounded public metadata from Radar's static archive.</p>
              </div>
            ) : null}
            {detailState.status === "error" ? (
              <div className="detail-state error" role="status">
                <p>Domain intelligence is temporarily unavailable. The core signal and any archived evidence remain below.</p>
                <button type="button" onClick={() => setDetailAttempt((attempt) => attempt + 1)}>Try again</button>
              </div>
            ) : null}
            {detailState.status === "ready" ? (
              <div className="detail-observations">
                {detailState.detail.observations.map((observation) => (
                  <ObservationDetail key={observation.source} observation={observation} />
                ))}
              </div>
            ) : null}
          </section>
        ) : null}
        {signal.screenshotUrl ? (
          <div className="capture-frame">
            <img src={signal.screenshotUrl} alt={`Archived screenshot for ${signal.domain}`} referrerPolicy="no-referrer" />
          </div>
        ) : (
          <div className="evidence-empty"><p>No archived screenshot is available for this observation.</p></div>
        )}
        {signal.hashes?.length ? (
          <section className="evidence-hashes" aria-labelledby="hashes-title">
            <h3 id="hashes-title">Observed SHA-256 hashes</h3>
            <p>Primary HTML response evidence supplied with this observation; hashes are safe to copy for defensive pivots.</p>
            <ul>{signal.hashes.map((digest) => <li key={digest}><code>{digest}</code></li>)}</ul>
          </section>
        ) : null}
        {signal.reasonCodes?.length ? (
          <section className="evidence-hashes" aria-labelledby="reasons-title">
            <h3 id="reasons-title">Publication reason codes</h3>
            <p>Controlled public provenance labels explain why this candidate passed validation; they are not verdicts.</p>
            <ul>{signal.reasonCodes.map((reason) => <li key={reason}><code>{reason}</code></li>)}</ul>
          </section>
        ) : null}
        <div className="capture-footer">
          <p>Viewing a screenshot or report contacts urlscan.io. The suspicious website is not contacted.</p>
          <div className="capture-links">
            {signal.screenshotUrl ? (
              <a href={signal.screenshotUrl} target="_blank" rel="noreferrer noopener">
                Open image <ExternalLink aria-hidden="true" />
              </a>
            ) : null}
            {signal.referenceUrl ? (
              <a href={signal.referenceUrl} target="_blank" rel="noreferrer noopener">
                Open report <ExternalLink aria-hidden="true" />
              </a>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}
