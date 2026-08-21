import { parseSnapshot } from "./data";
import type { RadarSnapshot } from "../types";

export type SnapshotBootstrap = {
  snapshot: RadarSnapshot;
  renderedAt: number;
};

export function encodeSnapshotBootstrap(snapshot: RadarSnapshot, renderedAt: number): string {
  if (!Number.isInteger(renderedAt) || renderedAt < 0) {
    throw new Error("The prerender timestamp is invalid.");
  }
  return encodeURIComponent(JSON.stringify({ snapshot, renderedAt }));
}

export function decodeSnapshotBootstrap(value: string): SnapshotBootstrap {
  const decoded: unknown = JSON.parse(decodeURIComponent(value));
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("The embedded radar snapshot is invalid.");
  }

  const candidate = decoded as Record<string, unknown>;
  if (!Number.isInteger(candidate.renderedAt) || (candidate.renderedAt as number) < 0) {
    throw new Error("The embedded radar render timestamp is invalid.");
  }

  return {
    snapshot: parseSnapshot(candidate.snapshot),
    renderedAt: candidate.renderedAt as number,
  };
}
