import { RotateCcw, Search, SlidersHorizontal } from "lucide-react";
import { useEffect, useRef } from "react";

import { DEFAULT_FILTERS, sourceNames, uniqueValues } from "../lib/dashboard";
import type { Filters, RadarSignal, SignalStatus } from "../types";

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

  return (
    <div className="filter-shell">
      <div className="search-field">
        <Search aria-hidden="true" />
        <label className="sr-only" htmlFor="signal-search">Search signals</label>
        <input
          ref={searchRef}
          id="signal-search"
          type="search"
          placeholder="Search URL, domain, brand, host…"
          value={filters.query}
          onChange={(event) => update("query", event.target.value)}
        />
        <kbd>/</kbd>
      </div>
      <div className="select-group" aria-label="Signal filters">
        <SlidersHorizontal aria-hidden="true" />
        <label>
          <span className="sr-only">Status</span>
          <select value={filters.status} onChange={(event) => update("status", event.target.value as SignalStatus | "all")}>
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
          <select value={filters.source} onChange={(event) => update("source", event.target.value)}>
            <option value="all">All sources</option>
            {sources.map((source) => <option key={source} value={source}>{source}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Brand</span>
          <select value={filters.brand} onChange={(event) => update("brand", event.target.value)}>
            <option value="all">All brands</option>
            {brands.map((brand) => <option key={brand} value={brand}>{brand}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Country</span>
          <select value={filters.country} onChange={(event) => update("country", event.target.value)}>
            <option value="all">All countries</option>
            {countries.map((country) => <option key={country} value={country}>{country}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Minimum confidence score</span>
          <select
            value={filters.minimumConfidence}
            onChange={(event) => update("minimumConfidence", Number(event.target.value))}
          >
            <option value="0">Any score</option>
            <option value="50">Score 50/100 or higher</option>
            <option value="75">Score 75/100 or higher</option>
            <option value="90">Score 90/100 or higher</option>
          </select>
        </label>
        {hasFilters && (
          <button className="reset-button" type="button" onClick={() => onChange(DEFAULT_FILTERS)}>
            <RotateCcw aria-hidden="true" /> Reset
          </button>
        )}
      </div>
    </div>
  );
}
