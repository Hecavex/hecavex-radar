import type { RadarSignal } from "../types.ts";

export function signalPath(signal: Pick<RadarSignal, "id"> | string, language: "en" | "lt" = "en"): string {
  const id = typeof signal === "string" ? signal : signal.id;
  return language === "lt" ? `/lt/signalai/${id}/` : `/signals/${id}/`;
}

export function signalJsonPath(signal: Pick<RadarSignal, "id">): string {
  return `/data/signals/${signal.id.slice(0, 2)}/${signal.id}.json`;
}
