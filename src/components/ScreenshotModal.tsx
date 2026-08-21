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
            <p className="eyebrow">Passive capture</p>
            <h2 id="capture-title">{signal.domain}</h2>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close capture">
            <X aria-hidden="true" />
          </button>
        </div>
        <div className="capture-frame">
          <img src={signal.screenshotUrl!} alt={`Archived screenshot for ${signal.domain}`} referrerPolicy="no-referrer" />
        </div>
        <div className="capture-footer">
          <p>The suspicious website is not contacted. Images are limited to approved screenshot providers.</p>
          <a href={signal.screenshotUrl!} target="_blank" rel="noreferrer">
            Open image <ExternalLink aria-hidden="true" />
          </a>
        </div>
      </section>
    </div>
  );
}
