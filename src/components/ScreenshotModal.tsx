import { ExternalLink, X } from "lucide-react";
import { useEffect, useRef } from "react";

import type { RadarSignal } from "../types";

export function ScreenshotModal({ signal, onClose }: { signal: RadarSignal; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    closeRef.current?.focus();
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="capture-modal" role="dialog" aria-modal="true" aria-labelledby="capture-title">
        <div className="capture-heading">
          <div>
            <p className="eyebrow">Passive evidence</p>
            <h2 id="capture-title">{signal.domain}</h2>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close capture">
            <X aria-hidden="true" />
          </button>
        </div>
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
