import type {
  RadarSignal,
  SignalAssessmentDetail,
  SignalCertificateDetail,
  SignalContextChange,
  SignalDetail,
  SignalDomainContext,
  SignalDetailObservation,
  SignalNetworkDetail,
  SignalPageDetail,
} from "../types.ts";
import { readBoundedJson } from "./boundedJson.ts";

export const MAXIMUM_SIGNAL_DETAIL_BYTES = 16 * 1024;

const MAXIMUM_OBSERVATIONS = 2;
const MAXIMUM_SUBJECT_ALT_NAMES = 12;
const MAXIMUM_SUBJECT_ALT_NAME_COUNT = 500;
const MAXIMUM_URLSCAN_CATEGORIES = 8;
const MAXIMUM_CONTEXT_CHANGES = 6;
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
const DOMAIN_CONTEXT_FIELDS = ["observedAt", "dns", "registration"];
const DNS_CONTEXT_FIELDS = ["a", "aaaa", "cname", "ns", "mx", "minimumTtl", "queriesCompleted"];
const REGISTRATION_CONTEXT_FIELDS = ["registrar", "registeredAt", "updatedAt", "expiresAt", "statuses"];
const CONTEXT_CHANGE_FIELDS = ["eventId", "observedAt", "component", "changeType", "changedFields", "source", "evidence"];
const CONTEXT_SOURCE_FIELDS = ["name", "observedAt", "referenceUrl"];
const CONTEXT_EVIDENCE_FIELDS = ["previousSha256", "currentSha256", "primaryHtmlSha256", "certificateSha256"];
const CONTEXT_CHANGED_FIELDS: Record<SignalContextChange["changeType"], readonly string[]> = {
  "first-resolving": ["a", "aaaa", "cname"],
  "stopped-resolving": ["a", "aaaa", "cname"],
  "dns-a-changed": ["a"],
  "dns-aaaa-changed": ["aaaa"],
  "dns-cname-changed": ["cname"],
  "dns-ns-changed": ["ns"],
  "dns-mx-changed": ["mx"],
  "rdap-registrar-changed": ["registrar"],
  "rdap-status-changed": ["statuses"],
  "rdap-expiry-changed": ["expiresAt"],
  "urlscan-title-changed": ["pageTitle"],
  "urlscan-redirect-changed": ["redirectedToDomain"],
  "urlscan-http-status-changed": ["httpStatus"],
  "urlscan-ip-changed": ["ipAddress"],
  "urlscan-asn-changed": ["asn"],
  "urlscan-primary-html-sha256-changed": ["primaryHtmlSha256"],
  "urlscan-certificate-fingerprint-changed": ["certificateFingerprintSha256"],
  "certificate-reissued": ["certificateFingerprintSha256", "certificateIssuer", "certificateNotBefore", "certificateNotAfter"],
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function hasExactFields(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((field) => Object.hasOwn(value, field));
}

function hasRequiredAndOptionalFields(value: Record<string, unknown>, required: string[], optional: string[]): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((field) => Object.hasOwn(value, field)) && Object.keys(value).every((field) => allowed.has(field));
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

function isBoundedUniqueList(value: unknown, maximum: number, validator: (item: unknown) => boolean): value is string[] {
  return Array.isArray(value) && value.length <= maximum && new Set(value).size === value.length && value.every(validator);
}

function isDomainContext(value: unknown, generatedAt: number): value is SignalDomainContext {
  if (!isRecord(value) || !hasExactFields(value, DOMAIN_CONTEXT_FIELDS)) return false;
  const observedAt = timestampValue(value.observedAt);
  const dns = value.dns;
  const registration = value.registration;
  if (!isRecord(dns) || !hasExactFields(dns, DNS_CONTEXT_FIELDS)) return false;
  const validMailExchange = (item: unknown) => {
    if (typeof item !== "string") return false;
    const separator = item.indexOf(" ");
    return separator > 0 && /^\d{1,5}$/u.test(item.slice(0, separator)) && isDefangedDomain(item.slice(separator + 1));
  };
  if (
    observedAt === null ||
    observedAt > generatedAt + FUTURE_SKEW_MS ||
    !isBoundedUniqueList(dns.a, 16, (item) => typeof item === "string" && isDefangedIp(item)) ||
    !isBoundedUniqueList(dns.aaaa, 16, (item) => typeof item === "string" && isDefangedIp(item)) ||
    !isBoundedUniqueList(dns.cname, 16, (item) => typeof item === "string" && isDefangedDomain(item)) ||
    !isBoundedUniqueList(dns.ns, 16, (item) => typeof item === "string" && isDefangedDomain(item)) ||
    !isBoundedUniqueList(dns.mx, 16, validMailExchange) ||
    !(dns.minimumTtl === null || (typeof dns.minimumTtl === "number" && Number.isInteger(dns.minimumTtl) && dns.minimumTtl >= 0)) ||
    typeof dns.queriesCompleted !== "number" ||
    !Number.isInteger(dns.queriesCompleted) ||
    dns.queriesCompleted < 0 ||
    dns.queriesCompleted > 5
  ) {
    return false;
  }
  if (registration === null) return true;
  if (!isRecord(registration) || !hasRequiredAndOptionalFields(registration, REGISTRATION_CONTEXT_FIELDS, ["domain"])) return false;
  return (
    (registration.domain === undefined || isDefangedDomain(registration.domain)) &&
    isSafeText(registration.registrar, 160) &&
    isNullableTimestamp(registration.registeredAt) &&
    isNullableTimestamp(registration.updatedAt) &&
    isNullableTimestamp(registration.expiresAt) &&
    isBoundedUniqueList(registration.statuses, 16, (item) => typeof item === "string" && /^[a-z\d-]{1,64}$/u.test(item))
  );
}

function isContextReference(value: unknown, component: SignalContextChange["component"]): value is string {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) return false;
    if (component === "dns") return parsed.href === "https://cloudflare-dns.com/dns-query";
    if (component === "rdap") return parsed.href === "https://data.iana.org/rdap/dns.json";
    return parsed.origin === "https://urlscan.io" && (parsed.pathname === "/" || /^\/result\/[a-f\d-]{36}\/$/iu.test(parsed.pathname));
  } catch {
    return false;
  }
}

function isContextChange(value: unknown, generatedAt: number): value is SignalContextChange {
  if (!isRecord(value) || !hasExactFields(value, CONTEXT_CHANGE_FIELDS)) return false;
  const components = {
    dns: {
      types: ["first-resolving", "stopped-resolving", "dns-a-changed", "dns-aaaa-changed", "dns-cname-changed", "dns-ns-changed", "dns-mx-changed"],
      source: "Cloudflare DNS",
    },
    rdap: {
      types: ["rdap-registrar-changed", "rdap-status-changed", "rdap-expiry-changed"],
      source: "RDAP",
    },
    urlscan: {
      types: ["urlscan-title-changed", "urlscan-redirect-changed", "urlscan-http-status-changed", "urlscan-ip-changed", "urlscan-asn-changed", "urlscan-primary-html-sha256-changed", "urlscan-certificate-fingerprint-changed", "certificate-reissued"],
      source: "URLScan",
    },
  } as const;
  const component = value.component;
  if (component !== "dns" && component !== "rdap" && component !== "urlscan") return false;
  const observedAt = timestampValue(value.observedAt);
  const source = value.source;
  const evidence = value.evidence;
  const sourceObservedAt = isRecord(source) ? timestampValue(source.observedAt) : null;
  const allowedChangedFields = typeof value.changeType === "string" && Object.hasOwn(CONTEXT_CHANGED_FIELDS, value.changeType)
    ? CONTEXT_CHANGED_FIELDS[value.changeType as SignalContextChange["changeType"]]
    : [];
  if (
    typeof value.eventId !== "string" || !/^[a-f\d]{32}$/u.test(value.eventId) ||
    observedAt === null || observedAt > generatedAt + FUTURE_SKEW_MS ||
    typeof value.changeType !== "string" || !components[component].types.some((type) => type === value.changeType) ||
    !Array.isArray(value.changedFields) || value.changedFields.length < 1 || value.changedFields.length > 32 ||
    new Set(value.changedFields).size !== value.changedFields.length ||
    !value.changedFields.every((field) => typeof field === "string" && /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(field)) ||
    !value.changedFields.every((field) => allowedChangedFields.includes(field)) ||
    !isRecord(source) || !hasExactFields(source, CONTEXT_SOURCE_FIELDS) ||
    source.name !== components[component].source || sourceObservedAt === null ||
    sourceObservedAt > observedAt + FUTURE_SKEW_MS || sourceObservedAt > generatedAt + FUTURE_SKEW_MS ||
    !isContextReference(source.referenceUrl, component) ||
    !isRecord(evidence) || !hasExactFields(evidence, CONTEXT_EVIDENCE_FIELDS) ||
    typeof evidence.previousSha256 !== "string" || !/^[a-f\d]{64}$/u.test(evidence.previousSha256) ||
    typeof evidence.currentSha256 !== "string" || !/^[a-f\d]{64}$/u.test(evidence.currentSha256) ||
    !Array.isArray(evidence.primaryHtmlSha256) || evidence.primaryHtmlSha256.length > 2 ||
    new Set(evidence.primaryHtmlSha256).size !== evidence.primaryHtmlSha256.length ||
    !evidence.primaryHtmlSha256.every((digest) => typeof digest === "string" && /^[a-f\d]{64}$/u.test(digest)) ||
    !(
      evidence.certificateSha256 === null ||
      (typeof evidence.certificateSha256 === "string" && /^[a-f\d]{64}$/u.test(evidence.certificateSha256))
    )
  ) return false;
  return component === "urlscan" || (evidence.primaryHtmlSha256.length === 0 && evidence.certificateSha256 === null);
}

export function parseSignalDetail(
  value: unknown,
  expected?: Pick<RadarSignal, "id" | "domain">,
): SignalDetail {
  if (!isRecord(value) || !hasRequiredAndOptionalFields(value, DETAIL_FIELDS, ["domainContext", "contextChanges"])) {
    throw new Error("The signal detail does not match schema version 1.");
  }
  const generatedAt = timestampValue(value.generatedAt);
  const observations = value.observations;
  const contextChanges = value.contextChanges;
  if (
    value.schemaVersion !== 1 ||
    value.dataset !== "signal-detail" ||
    typeof value.signalId !== "string" ||
    !IDENTIFIER.test(value.signalId) ||
    !isDefangedDomain(value.domain) ||
    generatedAt === null ||
    !Array.isArray(observations) ||
    observations.length > MAXIMUM_OBSERVATIONS ||
    !observations.every((observation) => isObservation(observation, generatedAt)) ||
    new Set(observations.map((observation) => (observation as SignalDetailObservation).source)).size !== observations.length ||
    (value.domainContext !== undefined && !isDomainContext(value.domainContext, generatedAt)) ||
    (contextChanges !== undefined && (
      !Array.isArray(contextChanges) || contextChanges.length < 1 || contextChanges.length > MAXIMUM_CONTEXT_CHANGES ||
      !contextChanges.every((change) => isContextChange(change, generatedAt)) ||
      new Set(contextChanges.map((change) => (change as SignalContextChange).eventId)).size !== contextChanges.length
    )) ||
    (observations.length === 0 && value.domainContext === undefined && contextChanges === undefined) ||
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
  const decoded = await readBoundedJson(response, MAXIMUM_SIGNAL_DETAIL_BYTES);
  return parseSignalDetail(decoded, signal);
}
