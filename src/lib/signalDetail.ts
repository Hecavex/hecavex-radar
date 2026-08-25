import type {
  RadarSignal,
  SignalAssessmentDetail,
  SignalCertificateDetail,
  SignalDetail,
  SignalDetailObservation,
  SignalNetworkDetail,
  SignalPageDetail,
} from "../types.ts";

export const MAXIMUM_SIGNAL_DETAIL_BYTES = 16 * 1024;

const MAXIMUM_OBSERVATIONS = 2;
const MAXIMUM_SUBJECT_ALT_NAMES = 12;
const MAXIMUM_SUBJECT_ALT_NAME_COUNT = 500;
const MAXIMUM_URLSCAN_CATEGORIES = 8;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const ISO_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const IDENTIFIER = /^[a-f\d]{20}$/;
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
const EMAIL_ADDRESS = /(?:^|\s)[^\s@]+@[^\s@]+(?:$|\s)/u;
const LIVE_URL_TEXT = /https?:\/\//iu;
const LOWER_HEX = /^[a-f\d]+$/;
const URLSCAN_CATEGORY = /^[a-z\d](?:[a-z\d-]{0,30}[a-z\d])?$/;

const DETAIL_FIELDS = ["schemaVersion", "dataset", "signalId", "domain", "generatedAt", "observations"];
const OBSERVATION_FIELDS = [
  "source",
  "observedAt",
  "page",
  "network",
  "assessment",
  "certificate",
];
const PAGE_FIELDS = ["title", "httpStatus"];
const NETWORK_FIELDS = ["ipAddress", "asn", "asnDescription", "asnRegistry"];
const ASSESSMENT_FIELDS = ["urlscanVerdictScore", "urlscanCategories", "redirectedToDomain"];
const CERTIFICATE_FIELDS = [
  "countryName",
  "issuer",
  "commonName",
  "notBefore",
  "notAfter",
  "subjectAltNames",
  "subjectAltNameCount",
  "serialNumberHex",
  "fingerprints",
];
const FINGERPRINT_FIELDS = ["md5", "sha1", "sha256"];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function hasExactFields(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((field) => Object.hasOwn(value, field));
}

function timestampValue(value: unknown): number | null {
  if (typeof value !== "string" || !ISO_UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function isCleanText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value.trim() === value &&
    value.replace(/\s+/gu, " ") === value &&
    !CONTROL_OR_FORMAT.test(value)
  );
}

function isSafeText(value: unknown, maximum: number): value is string | null {
  return (
    value === null ||
    (isCleanText(value, maximum) && !EMAIL_ADDRESS.test(` ${value} `) && !LIVE_URL_TEXT.test(value))
  );
}

function isDefangedDomain(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 505 ||
    value !== value.toLowerCase() ||
    /[@/?#:\\]/u.test(value)
  ) {
    return false;
  }
  const labels = value.split("[.]");
  if (labels.length < 2 || labels.some((label) => label.length === 0 || label.length > 63)) return false;
  if (!labels.every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/u.test(label))) return false;
  const tld = labels.at(-1)!;
  return tld.startsWith("xn--") || /^[a-z]{2,63}$/u.test(tld);
}

function isDefangedCertificateName(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  return value.startsWith("*[.]") ? isDefangedDomain(value.slice(4)) : isDefangedDomain(value);
}

function isDefangedIp(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string" || value.length === 0 || value.length > 80 || /[@/?#]/u.test(value)) return false;
  if (value.includes("[.]")) {
    if (value.replaceAll("[.]", "").includes(".") || value.includes(":")) return false;
    const octets = value.split("[.]");
    return (
      octets.length === 4 &&
      octets.every((octet) => /^\d{1,3}$/u.test(octet) && String(Number(octet)) === octet && Number(octet) <= 255)
    );
  }
  if (!value.includes("[:]") || value.replaceAll("[:]", "").includes(":") || value.includes(".")) return false;
  const refanged = value.replaceAll("[:]", ":");
  if (!/^[a-f\d:]+$/u.test(refanged)) return false;
  if ((refanged.match(/::/gu) ?? []).length > 1 || refanged.includes(":::")) return false;
  const segments = refanged.split(":");
  const compacted = refanged.includes("::");
  return (
    (compacted ? segments.filter(Boolean).length < 8 : segments.length === 8) &&
    segments.filter(Boolean).every((segment) => /^[a-f\d]{1,4}$/u.test(segment)) &&
    (compacted || segments.length === 8)
  );
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || timestampValue(value) !== null;
}

function isNullableHex(value: unknown, length: number): value is string | null {
  return value === null || (typeof value === "string" && value.length === length && LOWER_HEX.test(value));
}

function isPage(value: unknown): value is SignalPageDetail | null {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactFields(value, PAGE_FIELDS)) return false;
  const status = value.httpStatus;
  return (
    isSafeText(value.title, 160) &&
    (status === null || (typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599)) &&
    (value.title !== null || status !== null)
  );
}

function isNetwork(value: unknown): value is SignalNetworkDetail | null {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactFields(value, NETWORK_FIELDS)) return false;
  const asn = value.asn;
  return (
    isDefangedIp(value.ipAddress) &&
    (asn === null || (typeof asn === "number" && Number.isInteger(asn) && asn >= 1 && asn <= 4_294_967_295)) &&
    isSafeText(value.asnDescription, 160) &&
    isSafeText(value.asnRegistry, 32) &&
    (value.ipAddress !== null || asn !== null || value.asnDescription !== null || value.asnRegistry !== null)
  );
}

function isAssessment(value: unknown): value is SignalAssessmentDetail | null {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactFields(value, ASSESSMENT_FIELDS)) return false;
  const score = value.urlscanVerdictScore;
  const categories = value.urlscanCategories;
  const redirectedToDomain = value.redirectedToDomain;
  return (
    (score === null || (typeof score === "number" && Number.isInteger(score) && score >= -100 && score <= 100)) &&
    Array.isArray(categories) &&
    categories.length <= MAXIMUM_URLSCAN_CATEGORIES &&
    new Set(categories).size === categories.length &&
    categories.every((category) => typeof category === "string" && URLSCAN_CATEGORY.test(category)) &&
    (redirectedToDomain === null || isDefangedDomain(redirectedToDomain)) &&
    (score !== null || categories.length > 0 || redirectedToDomain !== null)
  );
}

function isCertificate(value: unknown): value is SignalCertificateDetail | null {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactFields(value, CERTIFICATE_FIELDS)) return false;
  const fingerprints = value.fingerprints;
  const altNames = value.subjectAltNames;
  const altNameCount = value.subjectAltNameCount;
  const notBefore = timestampValue(value.notBefore);
  const notAfter = timestampValue(value.notAfter);
  if (!isRecord(fingerprints) || !hasExactFields(fingerprints, FINGERPRINT_FIELDS)) return false;
  if (
    !isNullableHex(fingerprints.md5, 32) ||
    !isNullableHex(fingerprints.sha1, 40) ||
    !isNullableHex(fingerprints.sha256, 64)
  ) {
    return false;
  }
  if (
    !Array.isArray(altNames) ||
    altNames.length > MAXIMUM_SUBJECT_ALT_NAMES ||
    new Set(altNames).size !== altNames.length ||
    !altNames.every(isDefangedCertificateName) ||
    typeof altNameCount !== "number" ||
    !Number.isInteger(altNameCount) ||
    altNameCount < altNames.length ||
    altNameCount > MAXIMUM_SUBJECT_ALT_NAME_COUNT
  ) {
    return false;
  }
  const serial = value.serialNumberHex;
  const validSerial = serial === null || (
    typeof serial === "string" && serial.length >= 1 && serial.length <= 80 && LOWER_HEX.test(serial)
  );
  if (
    !(value.countryName === null || (typeof value.countryName === "string" && /^[A-Z]{2}$/u.test(value.countryName))) ||
    !isSafeText(value.issuer, 200) ||
    !isDefangedCertificateName(value.commonName) ||
    !isNullableTimestamp(value.notBefore) ||
    !isNullableTimestamp(value.notAfter) ||
    (notBefore !== null && notAfter !== null && notBefore > notAfter) ||
    !validSerial
  ) {
    return false;
  }
  return (
    value.countryName !== null ||
    value.issuer !== null ||
    value.commonName !== null ||
    value.notBefore !== null ||
    value.notAfter !== null ||
    altNameCount > 0 ||
    serial !== null ||
    fingerprints.md5 !== null ||
    fingerprints.sha1 !== null ||
    fingerprints.sha256 !== null
  );
}

function isObservation(value: unknown, generatedAt: number): value is SignalDetailObservation {
  if (!isRecord(value) || !hasExactFields(value, OBSERVATION_FIELDS)) return false;
  const observedAt = timestampValue(value.observedAt);
  if (
    (value.source !== "URLScan" && value.source !== "CertStream") ||
    observedAt === null ||
    observedAt > generatedAt + FUTURE_SKEW_MS ||
    !isPage(value.page) ||
    !isNetwork(value.network) ||
    !isAssessment(value.assessment) ||
    !isCertificate(value.certificate)
  ) {
    return false;
  }
  if (value.source === "CertStream") {
    return value.page === null && value.network === null && value.assessment === null && value.certificate !== null;
  }
  return value.page !== null || value.network !== null || value.assessment !== null || value.certificate !== null;
}

export function parseSignalDetail(
  value: unknown,
  expected?: Pick<RadarSignal, "id" | "domain">,
): SignalDetail {
  if (!isRecord(value) || !hasExactFields(value, DETAIL_FIELDS)) {
    throw new Error("The signal detail does not match schema version 1.");
  }
  const generatedAt = timestampValue(value.generatedAt);
  const observations = value.observations;
  if (
    value.schemaVersion !== 1 ||
    value.dataset !== "signal-detail" ||
    typeof value.signalId !== "string" ||
    !IDENTIFIER.test(value.signalId) ||
    !isDefangedDomain(value.domain) ||
    generatedAt === null ||
    !Array.isArray(observations) ||
    observations.length < 1 ||
    observations.length > MAXIMUM_OBSERVATIONS ||
    !observations.every((observation) => isObservation(observation, generatedAt)) ||
    new Set(observations.map((observation) => (observation as SignalDetailObservation).source)).size !== observations.length ||
    (expected !== undefined && (value.signalId !== expected.id || value.domain !== expected.domain))
  ) {
    throw new Error("The signal detail does not match schema version 1.");
  }
  return value as SignalDetail;
}

export async function loadSignalDetail(
  signal: Pick<RadarSignal, "id" | "domain">,
  abortSignal?: AbortSignal,
): Promise<SignalDetail> {
  if (!IDENTIFIER.test(signal.id) || !isDefangedDomain(signal.domain)) {
    throw new Error("The signal detail identifier is invalid.");
  }
  const path = `/data/signals/${signal.id.slice(0, 2)}/${signal.id}.json`;
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal: abortSignal,
  });
  if (!response.ok) throw new Error(`Signal detail request failed with HTTP ${response.status}.`);
  const declaredLength = response.headers.get("Content-Length");
  if (declaredLength !== null && Number(declaredLength) > MAXIMUM_SIGNAL_DETAIL_BYTES) {
    throw new Error("The signal detail exceeds the public size limit.");
  }
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > MAXIMUM_SIGNAL_DETAIL_BYTES) {
    throw new Error("The signal detail exceeds the public size limit.");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(body);
  } catch {
    throw new Error("The signal detail is invalid JSON.");
  }
  return parseSignalDetail(decoded, signal);
}
