import { Check, Copy, Download, FileJson2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

const STIX_FEED_URL = "https://radar.hecavex.com/data/radar.stix.json";

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
        <p className="eyebrow"><FileJson2 aria-hidden="true" /> Machine-readable intelligence</p>
        <h2 id="stix-feed-title">Current Radar candidates, also published as STIX 2.1</h2>
        <p>
          Whenever Radar successfully publishes a material snapshot, the static pull feed republishes its current
          potential and suspected observations. The UI stays defanged; STIX uses raw domain-name observables. It is not
          a blocklist, maliciousness verdict, or claim of attribution.
        </p>
      </div>
      <div className="stix-feed-access">
        <span>Stable feed URL</span>
        <code>{STIX_FEED_URL}</code>
        <div className="stix-feed-actions">
          <a href="/data/radar.stix.json" download>
            <Download aria-hidden="true" /> Download STIX 2.1
          </a>
          <button type="button" onClick={() => void copyFeedUrl()}>
            {copyState === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
            {copyState === "copied" ? "URL copied" : copyState === "failed" ? "Copy unavailable" : "Copy feed URL"}
          </button>
        </div>
        <span className="sr-only" aria-live="polite">
          {copyState === "copied" ? "STIX feed URL copied to clipboard." : copyState === "failed" ? "The STIX feed URL could not be copied." : ""}
        </span>
      </div>
    </section>
  );
}
