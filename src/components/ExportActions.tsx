import { FileJson2, Sheet } from "lucide-react";

import { downloadText, signalsAsCsv, signalsAsJson } from "../lib/export.ts";
import type { RadarSignal } from "../types.ts";
import type { SiteLanguage } from "./SiteHeader.tsx";

export function ExportActions({ signals, snapshotGeneratedAt, language = "en" }: {
  signals: RadarSignal[];
  snapshotGeneratedAt: string;
  language?: SiteLanguage;
}) {
  const date = snapshotGeneratedAt.slice(0, 10);
  const lt = language === "lt";

  return (
    <div className="export-actions" aria-label={lt ? "Eksportuoti dabartinę filtruotą peržiūrą" : "Export current filtered view"}>
      <span>{lt ? "Neutralizuota išvestis" : "Defanged view"}</span>
      <button
        type="button"
        disabled={signals.length === 0}
        onClick={() => downloadText(`hecavex-radar-${date}.csv`, signalsAsCsv(signals), "text/csv;charset=utf-8")}
      >
        <Sheet aria-hidden="true" /> CSV
      </button>
      <button
        type="button"
        disabled={signals.length === 0}
        onClick={() => downloadText(
          `hecavex-radar-${date}.json`,
          signalsAsJson(signals, snapshotGeneratedAt),
          "application/json;charset=utf-8",
        )}
      >
        <FileJson2 aria-hidden="true" /> JSON
      </button>
    </div>
  );
}
