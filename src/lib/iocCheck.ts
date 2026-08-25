import type { RadarHistory, RadarHistorySignal, RadarSignal } from "../types.ts";

export const MAXIMUM_IOC_FILE_BYTES = 256 * 1024;
export const MAXIMUM_IOC_LINES = 5_000;

export type IocKind = "domain" | "url" | "md5" | "sha1" | "sha256";
export type IocDataset = "current" | "history";

export type NormalizedIoc = {
  raw: string;
  normalized: string | null;
  kind: IocKind | null;
  error: string | null;
};

export type IocMatch = {
  signalId: string;
  domain: string;
  brand: string | null;
  firstSeen: string;
  lastSeen: string;
  status: RadarSignal["status"];
  datasets: IocDataset[];
  matchedField: IocKind;
};

export type IocCheckResult = NormalizedIoc & {
  matches: IocMatch[];
};

export type ParsedIocInput = {
  indicators: NormalizedIoc[];
  duplicateCount: number;
  ignoredCount: number;
  truncated: boolean;
};

const DOMAIN_LABEL = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/u;
const HASHES: ReadonlyArray<[IocKind, RegExp]> = [
  ["md5", /^[a-f\d]{32}$/u],
  ["sha1", /^[a-f\d]{40}$/u],
  ["sha256", /^[a-f\d]{64}$/u],
];

function stripLineDecoration(value: string): string {
  let cleaned = value.trim().replace(/^(?:[-*+]\s+|\d+[.)]\s+)/u, "").trim();
  const wrappers: ReadonlyArray<[string, string]> = [
    ["`", "`"],
    ["\"", "\""],
    ["'", "'"],
    ["<", ">"],
  ];
  for (const [opening, closing] of wrappers) {
    if (cleaned.startsWith(opening) && cleaned.endsWith(closing) && cleaned.length > 2) {
      cleaned = cleaned.slice(opening.length, -closing.length).trim();
      break;
    }
  }
  return cleaned;
}

function refangHostSeparators(value: string): string {
  return value
    .replaceAll("[.]", ".")
    .replaceAll("(.)", ".")
    .replaceAll("{.}", ".")
    .replaceAll("[:]", ":");
}

function isDomainName(hostname: string): boolean {
  if (
    hostname.length < 4 ||
    hostname.length > 253 ||
    hostname !== hostname.toLowerCase() ||
    hostname.startsWith(".") ||
    hostname.endsWith(".") ||
    /^\d+(?:\.\d+){3}$/u.test(hostname) ||
    hostname.includes(":")
  ) return false;

  const labels = hostname.split(".");
  if (labels.length < 2 || !labels.every((label) => label.length <= 63 && DOMAIN_LABEL.test(label))) return false;
  const tld = labels.at(-1)!;
  return /^(?:[a-z]{2,63}|xn--[a-z\d-]{2,59})$/u.test(tld);
}

function canonicalHostname(value: string): string | null {
  const refanged = refangHostSeparators(value).toLowerCase().replace(/\.$/u, "");
  if (/[/\\@?#\s]/u.test(refanged)) return null;
  try {
    const hostname = new URL(`http://${refanged}`).hostname.toLowerCase().replace(/\.$/u, "");
    return isDomainName(hostname) ? hostname : null;
  } catch {
    return null;
  }
}

export function defangDomain(hostname: string): string {
  return hostname.replaceAll(".", "[.]");
}

function normalizeDomain(value: string): string | null {
  const hostname = canonicalHostname(value);
  return hostname ? defangDomain(hostname) : null;
}

function normalizeUrl(value: string): string | null {
  const refanged = refangHostSeparators(value)
    .replace(/^hxxps:/iu, "https:")
    .replace(/^hxxp:/iu, "http:");
  try {
    const parsed = new URL(refanged);
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) return null;
    const hostname = canonicalHostname(parsed.hostname);
    if (!hostname) return null;
    const scheme = parsed.protocol === "https:" ? "hxxps:" : "hxxp:";
    const port = parsed.port ? `:${parsed.port}` : "";
    return `${scheme}//${defangDomain(hostname)}${port}${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return null;
  }
}

export function normalizeIoc(rawValue: string): NormalizedIoc {
  const raw = stripLineDecoration(rawValue);
  if (!raw) return { raw, normalized: null, kind: null, error: "Empty line" };
  if (raw.length > 2_048) return { raw, normalized: null, kind: null, error: "Indicator exceeds 2,048 characters" };

  const lowercase = raw.toLowerCase();
  for (const [kind, pattern] of HASHES) {
    if (pattern.test(lowercase)) return { raw, normalized: lowercase, kind, error: null };
  }

  if (/^(?:hxxps?|https?):\/\//iu.test(raw)) {
    const normalized = normalizeUrl(raw);
    return normalized
      ? { raw, normalized, kind: "url", error: null }
      : { raw, normalized: null, kind: null, error: "Unsupported or malformed HTTP(S) URL" };
  }

  const normalized = normalizeDomain(raw);
  return normalized
    ? { raw, normalized, kind: "domain", error: null }
    : { raw, normalized: null, kind: null, error: "Not a supported domain, HTTP(S) URL, MD5, SHA-1, or SHA-256 value" };
}

export function parseIocInput(value: string): ParsedIocInput {
  const allLines = value.split(/\r?\n/u);
  const lines = allLines.slice(0, MAXIMUM_IOC_LINES);
  const indicators: NormalizedIoc[] = [];
  const seen = new Set<string>();
  let duplicateCount = 0;
  let ignoredCount = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      ignoredCount += 1;
      continue;
    }
    const indicator = normalizeIoc(trimmed);
    const key = indicator.normalized && indicator.kind
      ? `${indicator.kind}\u0000${indicator.normalized}`
      : `invalid\u0000${indicator.raw}`;
    if (seen.has(key)) {
      duplicateCount += 1;
      continue;
    }
    seen.add(key);
    indicators.push(indicator);
  }

  return {
    indicators,
    duplicateCount,
    ignoredCount,
    truncated: allLines.length > MAXIMUM_IOC_LINES,
  };
}

function matchKey(match: IocMatch): string {
  return `${match.signalId}\u0000${match.matchedField}`;
}

function addMatch(index: Map<string, IocMatch[]>, key: string, match: IocMatch): void {
  const existing = index.get(key) ?? [];
  const duplicate = existing.find((candidate) => matchKey(candidate) === matchKey(match));
  if (duplicate) {
    for (const dataset of match.datasets) {
      if (!duplicate.datasets.includes(dataset)) duplicate.datasets.push(dataset);
    }
    duplicate.datasets.sort();
    return;
  }
  existing.push(match);
  index.set(key, existing);
}

function currentMatch(signal: RadarSignal, matchedField: IocKind): IocMatch {
  return {
    signalId: signal.id,
    domain: signal.domain,
    brand: signal.brand,
    firstSeen: signal.firstSeen,
    lastSeen: signal.lastSeen,
    status: signal.status,
    datasets: ["current"],
    matchedField,
  };
}

function historyMatch(signal: RadarHistorySignal): IocMatch {
  return {
    signalId: signal.id,
    domain: signal.domain,
    brand: signal.brand,
    firstSeen: signal.firstSeen,
    lastSeen: signal.lastSeen,
    status: signal.latestStatus,
    datasets: ["history"],
    matchedField: "domain",
  };
}

export function checkIocs(
  indicators: readonly NormalizedIoc[],
  currentSignals: readonly RadarSignal[],
  history: RadarHistory | null,
): IocCheckResult[] {
  const index = new Map<string, IocMatch[]>();

  for (const signal of currentSignals) {
    const domain = normalizeDomain(signal.domain);
    if (domain) addMatch(index, `domain\u0000${domain}`, currentMatch(signal, "domain"));

    const url = normalizeUrl(signal.url);
    if (url) addMatch(index, `url\u0000${url}`, currentMatch(signal, "url"));

    for (const digest of signal.hashes ?? []) {
      const normalized = normalizeIoc(digest);
      if (normalized.normalized && normalized.kind) {
        addMatch(index, `${normalized.kind}\u0000${normalized.normalized}`, currentMatch(signal, normalized.kind));
      }
    }
  }

  for (const signal of history?.signals ?? []) {
    const domain = normalizeDomain(signal.domain);
    if (domain) addMatch(index, `domain\u0000${domain}`, historyMatch(signal));
  }

  return indicators.map((indicator) => ({
    ...indicator,
    matches: indicator.normalized && indicator.kind
      ? [...(index.get(`${indicator.kind}\u0000${indicator.normalized}`) ?? [])]
      : [],
  }));
}
