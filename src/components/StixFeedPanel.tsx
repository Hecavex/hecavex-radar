import { Check, Copy, Download, FileJson2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

const STIX_FEED_URL = "https://radar.hecavex.com/data/radar.stix.json";
const REVIEWED_STIX_FEED_URL = "https://radar.hecavex.com/data/radar-reviewed.stix.json";

type CopyState = "idle" | "copied" | "failed";

export function StixFeedPanel() {
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const resetTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(resetTimer.current), []);

  const copyFeedUrl = async () => {
    try {
      await navigator.clipboard.writeText(STIX_FEED_URL);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }

    window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => setCopyState("idle"), 3000);
  };

  return (
    <section className="stix-feed-panel" aria-labelledby="stix-feed-title">
      <div className="stix-feed-copy">
        <FileJson2 aria-hidden="true" />
        <div>
          <p className="eyebrow">Machine-readable distribution</p>
          <h2 id="stix-feed-title">STIX 2.1 observations</h2>
          <p>
            The observation feed contains current automated candidates. The separate reviewed Indicator feed remains
            empty until an analyst confirms eligible evidence. Neither feed is a blocklist.
          </p>
        </div>
      </div>
      <div className="stix-feed-access">
        <div className="stix-feed-actions">
          <a href="/data/radar.stix.json" download>
            <Download aria-hidden="true" /> Observations
          </a>
          <a className="reviewed-feed-link" href="/data/radar-reviewed.stix.json" download title={REVIEWED_STIX_FEED_URL}>
            <Download aria-hidden="true" /> Reviewed
          </a>
          <button type="button" onClick={() => void copyFeedUrl()}>
            {copyState === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
            {copyState === "copied" ? "URL copied" : copyState === "failed" ? "Copy unavailable" : "Copy URL"}
          </button>
        </div>
        <span className="sr-only" aria-live="polite">
          {copyState === "copied" ? "STIX feed URL copied to clipboard." : copyState === "failed" ? "The STIX feed URL could not be copied." : ""}
        </span>
      </div>
    </section>
  );
}
