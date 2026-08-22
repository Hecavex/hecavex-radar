import type { RadarHistory } from "../types.ts";
import { parseHistory } from "./historyData.ts";

export type HistoryBootstrap = {
  history: RadarHistory;
  renderedAt: number;
};

export function encodeHistoryBootstrap(history: RadarHistory, renderedAt: number): string {
  if (!Number.isInteger(renderedAt) || renderedAt < 0) throw new Error("The prerender timestamp is invalid.");
  return encodeURIComponent(JSON.stringify({ history, renderedAt }));
}

export async function decodeHistoryBootstrap(value: string): Promise<HistoryBootstrap> {
  const decoded: unknown = JSON.parse(decodeURIComponent(value));
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("The embedded radar history is invalid.");
  }
  const candidate = decoded as Record<string, unknown>;
  if (!Number.isInteger(candidate.renderedAt) || (candidate.renderedAt as number) < 0) {
    throw new Error("The embedded history render timestamp is invalid.");
  }
  return { history: await parseHistory(candidate.history), renderedAt: candidate.renderedAt as number };
}
