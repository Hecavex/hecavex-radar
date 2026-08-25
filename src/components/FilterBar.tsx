import { Check, RotateCcw, Search, Share2, SlidersHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { controlledFilterSearch, DEFAULT_FILTERS, sourceNames, uniqueValues } from "../lib/dashboard.ts";
import type { Filters, RadarSignal, SignalStatus } from "../types.ts";

const timeFilters: Array<{ value: Filters["timeRange"]; label: string }> = [
  { value: "24h", label: "24 hours" },
  { value: "3d", label: "3 days" },
  { value: "7d", label: "7 days" },
  { value: "all", label: "All retained" },
];

export function FilterBar({
  signals,
  filters,
  onChange,
}: {
  signals: RadarSignal[];
  filters: Filters;
  onChange: (filters: Filters) => void;
}) {
  const searchRef = useRef<HTMLInputElement>(null);
  const [copiedView, setCopiedView] = useState(false);
  const brands = uniqueValues(signals, "brand");
  const countries = uniqueValues(signals, "country");
  const sources = sourceNames(signals);
  const hasFilters = JSON.stringify(filters) !== JSON.stringify(DEFAULT_FILTERS);

  const update = <Key extends keyof Filters>(key: Key, value: Filters[Key]) => onChange({ ...filters, [key]: value });

  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (event.key === "/" && !target?.matches("input, textarea, select")) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener("keydown", focusSearch);
    return () => document.removeEventListener("keydown", focusSearch);
  }, []);

  const copyControlledView = async () => {
    const query = controlledFilterSearch(filters);
    const url = `${window.location.origin}${window.location.pathname}${query ? `?${query}` : ""}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopiedView(true);
      window.setTimeout(() => setCopiedView(false), 1800);
    } catch {
      setCopiedView(false);
    }
  };

  return (
    <div className="filter-shell">
      <div className="quick-filter-row">
        <span>Last seen</span>
        <div aria-label="Last-seen time window">
          {timeFilters.map((item) => (
            <button
              key={item.value}
              type="button"
              className={filters.timeRange === item.value ? "active" : undefined}
              aria-pressed={filters.timeRange === item.value}
              onClick={() => update("timeRange", item.value)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>
      <div className="search-field">
        <Search aria-hidden="true" />
        <label className="sr-only" htmlFor="signal-search">Search candidates</label>
        <input
          ref={searchRef}
          id="signal-search"
          type="search"
          placeholder="Search defanged URL, domain, brand or host..."
          value={filters.query}
          onChange={(event) => update("query", event.target.value)}
        />
        <kbd>/</kbd>
      </div>
      <div className="select-group" aria-label="Candidate filters">
        <SlidersHorizontal aria-hidden="true" />
        <label>
          <span className="sr-only">Source-reported status</span>
          <select aria-label="Source-reported status" value={filters.status} onChange={(event) => update("status", event.target.value as SignalStatus | "all")}>
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="suspected">Suspected</option>
            <option value="offline">Offline</option>
            <option value="mitigated">Mitigated</option>
            <option value="unknown">Unknown</option>
          </select>
        </label>
        <label>
          <span className="sr-only">Source</span>
          <select aria-label="Source" value={filters.source} onChange={(event) => update("source", event.target.value)}>
            <option value="all">All sources</option>
            {sources.map((source) => <option key={source} value={source}>{source}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Potential brand match</span>
          <select aria-label="Potential brand match" value={filters.brand} onChange={(event) => update("brand", event.target.value)}>
            <option value="all">All brand matches</option>
            {brands.map((brand) => <option key={brand} value={brand}>{brand}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Hosting country observed</span>
          <select aria-label="Hosting country observed" value={filters.country} onChange={(event) => update("country", event.target.value)}>
            <option value="all">All hosting countries</option>
            {countries.map((country) => <option key={country} value={country}>{country}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Minimum match score</span>
          <select
            aria-label="Minimum match score"
            value={filters.minimumMatchScore}
            onChange={(event) => update("minimumMatchScore", Number(event.target.value))}
          >
            <option value="0">Any match score</option>
            <option value="50">Match score 50+</option>
            <option value="75">Match score 75+</option>
            <option value="90">Match score 90+</option>
          </select>
        </label>
        <label>
          <span className="sr-only">Evidence</span>
          <select aria-label="Evidence" value={filters.evidence} onChange={(event) => update("evidence", event.target.value as Filters["evidence"])}>
            <option value="all">All evidence</option>
            <option value="name-only">Observed only</option>
            <option value="corroborated">Corroborated</option>
            <option value="reviewed">Analyst reviewed</option>
            <option value="screenshot">Has screenshot</option>
            <option value="urlscan">Has URLScan context</option>
            <option value="hashes">Has response hashes</option>
            <option value="certstream-only">CertStream only</option>
          </select>
        </label>
        <label>
          <span className="sr-only">Sort candidates</span>
          <select aria-label="Sort candidates" value={filters.sort} onChange={(event) => update("sort", event.target.value as Filters["sort"])}>
            <option value="last-seen-desc">Newest observation</option>
            <option value="first-seen-desc">Newest discovery</option>
            <option value="match-score-desc">Highest match score</option>
            <option value="brand-asc">Brand A-Z</option>
          </select>
        </label>
        <button className="share-filter-button" type="button" onClick={() => void copyControlledView()}>
          {copiedView ? <Check aria-hidden="true" /> : <Share2 aria-hidden="true" />}
          {copiedView ? "View copied" : "Copy filtered view"}
        </button>
        {hasFilters && (
          <button className="reset-button" type="button" onClick={() => onChange(DEFAULT_FILTERS)}>
            <RotateCcw aria-hidden="true" /> Reset
          </button>
        )}
      </div>
      <p className="filter-privacy-note">Free-text search stays in this browser and is never added to the shared URL.</p>
    </div>
  );
}
