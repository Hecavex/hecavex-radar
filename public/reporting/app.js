/* global Blob, Option, TextEncoder, URL, crypto, document */
"use strict";

const MAX_FILES = 20;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
const DEFANGED_DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\[\.\])+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/u;
const SIGNAL_ID = /^[a-f0-9]{20}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const REVIEW_FIELDS = ["id", "signalId", "domain", "brand", "reviewState", "dispositionReason", "evidenceCodes", "ltRelevance", "reviewedAt", "modifiedAt", "expiresAt", "analystConfidence", "revoked"];

const form = document.querySelector("#pack-form");
const radarFile = document.querySelector("#radar-file");
const reviewFile = document.querySelector("#review-file");
const detailFile = document.querySelector("#detail-file");
const fileInput = document.querySelector("#evidence-files");
const candidate = document.querySelector("#candidate");
const load = document.querySelector("#load");
const status = document.querySelector("#status");
const preview = document.querySelector("#preview");
const download = document.querySelector("#download");
const clear = document.querySelector("#clear");

let loaded = null;
let currentPack = null;

function cleanText(value, maximum) {
  return Array.from(String(value ?? ""))
    .map((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code < 32 || code === 127 ? " " : character;
    })
    .join("")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, maximum);
}

function hasOnlyFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every((key) => fields.includes(key));
}

function safeText(value, maximum) {
  return typeof value === "string" && value.length > 0 && cleanText(value, maximum) === value;
}

function safeList(value, maximum, validator) {
  return Array.isArray(value) && value.length <= maximum && new Set(value).size === value.length && value.every(validator);
}

function safeUrlscanUrl(value, kind) {
  if (value === null || value === undefined) return true;
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    if (parsed.origin !== "https://urlscan.io" || parsed.username || parsed.password || parsed.search || parsed.hash) return false;
    return kind === "result"
      ? /^\/result\/[a-f0-9-]{36}\/$/u.test(parsed.pathname)
      : /^\/screenshots\/[a-f0-9-]{36}\.png$/u.test(parsed.pathname);
  } catch {
    return false;
  }
}

function hexadecimal(bytes) {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256Text(value) {
  return hexadecimal(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function readJson(input, maximum, label) {
  const file = input.files?.[0];
  if (!file || file.size <= 0 || file.size > maximum) {
    throw new Error(`${label} is missing, empty, or oversized.`);
  }
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function canonicalTime(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return null;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value ? null : parsed;
}

function selectedFiles() {
  const files = Array.from(fileInput.files || []);
  const total = files.reduce((sum, file) => sum + file.size, 0);
  if (files.length > MAX_FILES || files.some((file) => file.size > MAX_FILE_BYTES) || total > MAX_TOTAL_BYTES) {
    throw new Error("Evidence exceeds the documented local file limits.");
  }
  return files;
}

async function describeFile(file, index) {
  const content = await file.arrayBuffer();
  return {
    label: `evidence-${String(index + 1).padStart(3, "0")}`,
    bytes: file.size,
    mediaType: cleanText(file.type || "application/octet-stream", 120),
    sha256: hexadecimal(await crypto.subtle.digest("SHA-256", content)),
  };
}

async function validateArtifacts(radar, review, detail) {
  if (radar?.schemaVersion !== 2 || radar?.dataset !== "live" || !Array.isArray(radar.signals) || radar.signals.length > 2500) {
    throw new Error("Radar snapshot contract is invalid.");
  }
  if (review?.schemaVersion !== 2 || review?.dataset !== "radar-review-decisions" || !Array.isArray(review.assessments) || review.assessments.length > 2500) {
    throw new Error("Sanitized review contract is invalid.");
  }
  if (detail?.schemaVersion !== 1 || detail?.dataset !== "signal-detail" || !Array.isArray(detail.observations)) {
    throw new Error("Signal-detail contract is invalid.");
  }
  const now = new Date();
  const signals = new Map(radar.signals.map((signal) => [signal.id, signal]));
  const reviewed = [];
  for (const assessment of review.assessments) {
    const expiry = canonicalTime(assessment?.expiresAt);
    const reviewedAt = canonicalTime(assessment?.reviewedAt);
    const domain = assessment?.domain;
    const signalId = assessment?.signalId;
    if (assessment?.reviewState !== "confirmed-suspicious" || assessment?.revoked !== false || !expiry || expiry <= now || !reviewedAt) {
      continue;
    }
    if (typeof domain !== "string" || !DEFANGED_DOMAIN.test(domain) || typeof signalId !== "string" || !SIGNAL_ID.test(signalId)) {
      throw new Error("A reviewed assessment contains an unsafe indicator identity.");
    }
    if (
      !hasOnlyFields(assessment, REVIEW_FIELDS) ||
      !safeText(assessment.brand, 120) ||
      !safeText(assessment.dispositionReason, 80) ||
      !safeList(assessment.evidenceCodes, 16, (value) => safeText(value, 80)) ||
      !["lithuanian-targeting", "lithuanian-brand-relevance", "global-brand-reference", "unknown"].includes(assessment.ltRelevance) ||
      !(assessment.analystConfidence === null || (Number.isInteger(assessment.analystConfidence) && assessment.analystConfidence >= 0 && assessment.analystConfidence <= 100))
    ) throw new Error("A reviewed assessment contains fields outside the reporting contract.");
    if ((await sha256Text(domain.toLowerCase())).slice(0, 20) !== signalId) {
      throw new Error("A reviewed assessment signal identity does not match its domain.");
    }
    const signal = signals.get(signalId);
    if (!signal || signal.domain !== domain || detail.signalId !== signalId || detail.domain !== domain) {
      continue;
    }
    if (
      typeof signal.url !== "string" || !/^hxxps?:\/\//u.test(signal.url) || !signal.url.includes(domain) ||
      canonicalTime(signal.firstSeen) === null || canonicalTime(signal.lastSeen) === null ||
      !safeList(signal.sources, 3, (value) => ["CertStream", "URLScan", "HECAVEX"].includes(value)) ||
      !safeList(signal.hashes || [], 8, (value) => typeof value === "string" && SHA256.test(value)) ||
      !safeUrlscanUrl(signal.referenceUrl, "result") || !safeUrlscanUrl(signal.screenshotUrl, "screenshot") ||
      !Array.isArray(detail.observations) || detail.observations.length > 2
    ) throw new Error("The matching public signal or sidecar is outside the reporting contract.");
    reviewed.push({ assessment, signal });
  }
  if (reviewed.length !== 1) {
    throw new Error("The selected detail sidecar must match exactly one active reviewed assessment.");
  }
  return reviewed;
}

load.addEventListener("click", async () => {
  loaded = null;
  currentPack = null;
  download.disabled = true;
  candidate.disabled = true;
  candidate.replaceChildren(new Option("Validating generated artifacts...", ""));
  try {
    const radar = await readJson(radarFile, 512 * 1024, "Radar snapshot");
    const review = await readJson(reviewFile, 2 * 1024 * 1024, "Sanitized review decisions");
    const detail = await readJson(detailFile, 16 * 1024, "Signal-detail sidecar");
    const reviewed = await validateArtifacts(radar, review, detail);
    loaded = { detail, reviewed };
    const { assessment } = reviewed[0];
    candidate.replaceChildren(new Option(`${assessment.domain} · ${assessment.brand}`, assessment.signalId));
    candidate.disabled = false;
    status.textContent = "One active reviewed candidate is ready for local evidence packaging.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not validate generated artifacts.";
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  currentPack = null;
  download.disabled = true;
  if (!loaded || candidate.value !== loaded.reviewed[0].assessment.signalId) {
    status.textContent = "Load and select a valid active reviewed candidate first.";
    return;
  }
  try {
    const evidence = [];
    for (const [index, file] of selectedFiles().entries()) {
      evidence.push(await describeFile(file, index));
    }
    const { assessment, signal } = loaded.reviewed[0];
    const detail = loaded.detail;
    const urlscan = detail.observations.find((item) => item?.source === "URLScan") || null;
    const fingerprints = urlscan?.certificate?.fingerprints;
    const certificateFingerprints = fingerprints && typeof fingerprints === "object"
      ? {
          md5: typeof fingerprints.md5 === "string" && /^[a-f0-9]{32}$/u.test(fingerprints.md5) ? fingerprints.md5 : null,
          sha1: typeof fingerprints.sha1 === "string" && /^[a-f0-9]{40}$/u.test(fingerprints.sha1) ? fingerprints.sha1 : null,
          sha256: typeof fingerprints.sha256 === "string" && SHA256.test(fingerprints.sha256) ? fingerprints.sha256 : null,
        }
      : null;
    const registration = detail.domainContext?.registration;
    const registrar = safeText(registration?.registrar, 160) ? registration.registrar : null;
    const rawDns = detail.domainContext?.dns;
    const dns = rawDns && typeof rawDns === "object" ? {
      a: safeList(rawDns.a, 16, (value) => safeText(value, 80)) ? rawDns.a : [],
      aaaa: safeList(rawDns.aaaa, 16, (value) => safeText(value, 80)) ? rawDns.aaaa : [],
      cname: safeList(rawDns.cname, 16, (value) => typeof value === "string" && DEFANGED_DOMAIN.test(value)) ? rawDns.cname : [],
      ns: safeList(rawDns.ns, 16, (value) => typeof value === "string" && DEFANGED_DOMAIN.test(value)) ? rawDns.ns : [],
      mx: safeList(rawDns.mx, 16, (value) => safeText(value, 300)) ? rawDns.mx : [],
    } : null;
    const pack = {
      schemaVersion: 1,
      dataset: "radar-reviewed-reporting-evidence-pack",
      generatedAt: new Date().toISOString(),
      transmission: "none-local-browser-only",
      signalId: signal.id,
      indicator: { url: signal.url, domain: signal.domain },
      timeline: { firstSeen: signal.firstSeen, lastSeen: signal.lastSeen },
      discovery: {
        sources: signal.sources,
        discoveredVia: signal.discoveredVia || [],
        corroboratedBy: signal.corroboratedBy || [],
        evidenceTier: signal.evidenceTier,
        matchScore: signal.matchScore,
      },
      publicEvidence: {
        referenceUrl: signal.referenceUrl || null,
        screenshotUrl: signal.screenshotUrl || null,
        primaryHtmlSha256: signal.hashes || [],
        certificateFingerprints,
        host: safeText(signal.host, 160) ? signal.host : null,
        country: safeText(signal.country, 80) ? signal.country : null,
        registrar,
        dns,
      },
      assessment: {
        brand: assessment.brand,
        reviewState: assessment.reviewState,
        dispositionReason: assessment.dispositionReason,
        evidenceCodes: assessment.evidenceCodes,
        analystConfidence: assessment.analystConfidence,
        ltRelevance: assessment.ltRelevance,
        reviewedAt: assessment.reviewedAt,
        modifiedAt: assessment.modifiedAt,
        expiresAt: assessment.expiresAt,
      },
      evidence,
      reportingChannels: [
        { name: "Lithuanian NKSC phishing-site report", url: "https://www.nksc.lt/pranesti-svetaine.html" },
        ...(signal.referenceUrl ? [{ name: "Existing public URLScan report", url: signal.referenceUrl }] : []),
      ],
      boundaries: { fileContentsIncluded: false, originalFilenamesIncluded: false, reportSubmitted: false, candidateContacted: false },
    };
    currentPack = pack;
    preview.textContent = JSON.stringify(pack, null, 2);
    download.disabled = false;
    status.textContent = `Built a local reviewed-candidate pack with ${evidence.length} evidence digest${evidence.length === 1 ? "" : "s"}.`;
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not build the local manifest.";
  }
});

download.addEventListener("click", () => {
  if (!currentPack) return;
  const objectUrl = URL.createObjectURL(new Blob([`${JSON.stringify(currentPack, null, 2)}\n`], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = "radar-reviewed-reporting-evidence-pack.json";
  anchor.rel = "noopener";
  anchor.click();
  URL.revokeObjectURL(objectUrl);
});

clear.addEventListener("click", () => {
  form.reset();
  loaded = null;
  currentPack = null;
  candidate.disabled = true;
  candidate.replaceChildren(new Option("Load and validate the three public artifacts first", ""));
  preview.textContent = "A manifest has not been built.";
  download.disabled = true;
  status.textContent = "Waiting for generated public artifacts.";
});
