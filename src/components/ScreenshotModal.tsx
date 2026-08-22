import { ExternalLink, X } from "lucide-react";
import { useLayoutEffect, useRef } from "react";

import type { RadarSignal } from "../types.ts";

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

export function ScreenshotModal({ signal, returnFocus, onClose }: ScreenshotModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

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
