import { parseSnapshot } from "../lib/data.ts";
import { parseHistory } from "../lib/historyData.ts";
import type { RadarHistory, RadarSnapshot } from "../types.ts";

export type LtChangesBootstrap = {
  snapshot: RadarSnapshot;
  history: RadarHistory;
  renderedAt: number;
};

export function encodeLtChangesBootstrap(snapshot: RadarSnapshot, history: RadarHistory, renderedAt: number): string {
  if (!Number.isInteger(renderedAt) || renderedAt < 0) throw new Error("Netinkamas generavimo laikas.");
  return encodeURIComponent(JSON.stringify({ snapshot, history, renderedAt }));
}

export async function decodeLtChangesBootstrap(value: string): Promise<LtChangesBootstrap> {
  const decoded: unknown = JSON.parse(decodeURIComponent(value));
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("Netinkami įterpti pokyčių duomenys.");
  }
  const candidate = decoded as Record<string, unknown>;
  if (!Number.isInteger(candidate.renderedAt) || (candidate.renderedAt as number) < 0) {
    throw new Error("Netinkamas įterptų duomenų generavimo laikas.");
  }
  return {
    snapshot: parseSnapshot(candidate.snapshot),
    history: await parseHistory(candidate.history),
    renderedAt: candidate.renderedAt as number,
  };
}
