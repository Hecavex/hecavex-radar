import {
  Download,
  ExternalLink,
  FilterX,
  GitCompareArrows,
  Network,
  Search,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  RELATION_EVIDENCE_TYPES,
  loadRelatedObservations,
  type RelatedObservationEdge,
  type RelatedObservationEvidence,
  type RelatedObservationNode,
  type RelatedObservations,
  type RelationEvidenceType,
  type RelationStrength,
} from "../lib/relatedObservations.ts";
import { formatDateTime } from "../lib/format.ts";
import type { RadarSignal } from "../types.ts";

const PAGE_SIZE = 25;

const evidenceLabels: Record<RelationEvidenceType, string> = {
  "primary-html-sha256": "Primary HTML SHA-256",
  "certificate-sha256": "Certificate SHA-256",
  "certificate-san": "Certificate name",
  "redirect-domain": "Redirect destination",
  "ip-address": "Observed IP address",
  asn: "Observed ASN",
  "dns-a": "DNS A answer",
  "dns-aaaa": "DNS AAAA answer",
  "dns-cname": "DNS CNAME answer",
  "dns-ns": "DNS nameserver",
  "dns-mx": "DNS mail exchanger",
};

type ExplorerState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "ready"; artifact: RelatedObservations };

type ExplorerSort = "strength" | "evidence" | "domain" | "cluster";

export type AssociationExplorerProps = {
  signals: readonly RadarSignal[];
  /** Omit to load Radar's public artifact; pass null to render an unavailable state. */
  artifact?: RelatedObservations | null;
  signalHref?: (signalId: string) => string;
};

function SignalEndpoint({
  node,
  signal,
  signalHref,
}: {
  node: RelatedObservationNode;
  signal: RadarSignal | undefined;
  signalHref: (signalId: string) => string;
}) {
  return (
    <a className="radar-association-endpoint" href={signalHref(node.signalId)}>
      <code>{node.domain}</code>
      <span>{signal?.brand ?? "Current row unavailable"}</span>
      <small>{signal ? `${signal.status} · score ${signal.matchScore ?? signal.confidence ?? 0}/100` : `Signal ${node.signalId}`}</small>
      <ExternalLink aria-hidden="true" />
    </a>
  );
}

function EvidenceList({ evidence }: { evidence: RelatedObservationEvidence[] }) {
  return (
    <ul className="radar-association-evidence" aria-label="Evidence shared by this pair">
      {evidence.map((item) => (
        <li key={`${item.type}:${item.value}`}>
          <span>{evidenceLabels[item.type]}</span>
          <code title={item.value}>{item.value}</code>
        </li>
      ))}
    </ul>
  );
}

function edgeStrengthRank(edge: RelatedObservationEdge): number {
  return edge.strength === "strong" ? 0 : 1;
}

export function AssociationExplorer({
  signals,
  artifact,
  signalHref = (signalId) => `/signals/${signalId}/`,
}: AssociationExplorerProps) {
  const [state, setState] = useState<ExplorerState>(() => artifact === undefined
    ? { status: "loading" }
    : artifact === null
      ? { status: "unavailable" }
      : { status: "ready", artifact });
  const [query, setQuery] = useState("");
  const [evidenceType, setEvidenceType] = useState<RelationEvidenceType | "all">("all");
  const [strength, setStrength] = useState<RelationStrength | "all">("all");
  const [brand, setBrand] = useState("all");
  const [cluster, setCluster] = useState("all");
  const [sort, setSort] = useState<ExplorerSort>("strength");
  const [page, setPage] = useState(1);

  useEffect(() => {
    if (artifact !== undefined) {
      setState(artifact === null ? { status: "unavailable" } : { status: "ready", artifact });
      return;
    }
    const controller = new AbortController();
    setState({ status: "loading" });
    void loadRelatedObservations(controller.signal).then((loaded) => {
      if (!controller.signal.aborted) setState(loaded ? { status: "ready", artifact: loaded } : { status: "unavailable" });
    });
    return () => controller.abort();
  }, [artifact]);

  const activeArtifact = state.status === "ready" ? state.artifact : null;
  const signalsById = useMemo(() => new Map(signals.map((signal) => [signal.id, signal])), [signals]);
  const nodesById = useMemo(
    () => new Map((activeArtifact?.nodes ?? []).map((node) => [node.signalId, node])),
    [activeArtifact],
  );

  const evidenceCounts = useMemo(() => {
    const counts = new Map<RelationEvidenceType, number>(RELATION_EVIDENCE_TYPES.map((type) => [type, 0]));
    for (const edge of activeArtifact?.edges ?? []) {
      for (const type of new Set(edge.evidence.map((item) => item.type))) {
        counts.set(type, (counts.get(type) ?? 0) + 1);
      }
    }
    return counts;
  }, [activeArtifact]);

  const brandOptions = useMemo(() => {
    const values = new Set<string>();
    for (const node of activeArtifact?.nodes ?? []) {
      const value = signalsById.get(node.signalId)?.brand;
      if (value) values.add(value);
    }
    return [...values].sort((left, right) => left.localeCompare(right));
  }, [activeArtifact, signalsById]);

  const clusterOptions = useMemo(() => {
    const nodeCounts = new Map<string, number>();
    for (const node of activeArtifact?.nodes ?? []) nodeCounts.set(node.clusterId, (nodeCounts.get(node.clusterId) ?? 0) + 1);
    return [...nodeCounts].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  }, [activeArtifact]);

  const filteredEdges = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const edges = (activeArtifact?.edges ?? []).filter((edge) => {
      const source = nodesById.get(edge.source);
      const target = nodesById.get(edge.target);
      if (!source || !target) return false;
      const sourceBrand = signalsById.get(edge.source)?.brand ?? "";
      const targetBrand = signalsById.get(edge.target)?.brand ?? "";
      if (strength !== "all" && edge.strength !== strength) return false;
      if (evidenceType !== "all" && !edge.evidence.some((item) => item.type === evidenceType)) return false;
      if (brand !== "all" && sourceBrand !== brand && targetBrand !== brand) return false;
      if (cluster !== "all" && source.clusterId !== cluster) return false;
      if (!needle) return true;
      return [
        source.domain,
        target.domain,
        sourceBrand,
        targetBrand,
        edge.id,
        ...edge.evidence.flatMap((item) => [item.type, evidenceLabels[item.type], item.value]),
      ].some((value) => value.toLowerCase().includes(needle));
    });

    return edges.sort((left, right) => {
      const leftSource = nodesById.get(left.source);
      const rightSource = nodesById.get(right.source);
      if (sort === "evidence") return right.evidence.length - left.evidence.length || left.id.localeCompare(right.id);
      if (sort === "domain") return (leftSource?.domain ?? "").localeCompare(rightSource?.domain ?? "") || left.id.localeCompare(right.id);
      if (sort === "cluster") return (leftSource?.clusterId ?? "").localeCompare(rightSource?.clusterId ?? "") || left.id.localeCompare(right.id);
      return edgeStrengthRank(left) - edgeStrengthRank(right) || right.evidence.length - left.evidence.length || left.id.localeCompare(right.id);
    });
  }, [activeArtifact, brand, cluster, evidenceType, nodesById, query, signalsById, sort, strength]);

  const filteredClusterCount = useMemo(() => new Set(filteredEdges.map((edge) => nodesById.get(edge.source)?.clusterId).filter(Boolean)).size, [filteredEdges, nodesById]);
  const pageCount = Math.max(1, Math.ceil(filteredEdges.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const visibleEdges = filteredEdges.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  const hasFilters = Boolean(query) || evidenceType !== "all" || strength !== "all" || brand !== "all" || cluster !== "all" || sort !== "strength";

  const resetFilters = () => {
    setQuery("");
    setEvidenceType("all");
    setStrength("all");
    setBrand("all");
    setCluster("all");
    setSort("strength");
    setPage(1);
  };

  const selectEvidence = (value: RelationEvidenceType | "all") => {
    setEvidenceType(value);
    setPage(1);
  };

  return (
    <section className="radar-tool radar-association-explorer" aria-labelledby="association-explorer-title">
      <header className="radar-tool-heading">
        <div>
          <p className="eyebrow"><Network aria-hidden="true" /> Infrastructure associations</p>
          <h2 id="association-explorer-title">Explore shared public evidence</h2>
        </div>
        <p>
          Inspect every association retained in the bounded public graph. Filter by evidence, strength, brand,
          or cluster without turning technical overlap into an attribution claim.
        </p>
      </header>

      <div className="radar-tool-notice radar-tool-notice--warning" role="note">
        <TriangleAlert aria-hidden="true" />
        <div>
          <strong>Association is not attribution</strong>
          <p>
            Shared hosting, certificates, DNS, redirects, and code can have benign or third-party explanations.
            A cluster does not identify a campaign, operator, owner, malware family, or threat actor.
          </p>
        </div>
      </div>

      {state.status === "loading" ? (
        <div className="radar-tool-empty" aria-live="polite">Loading the bounded association artifact.</div>
      ) : state.status === "unavailable" ? (
        <div className="radar-tool-empty" role="status">
          Association data is temporarily unavailable. Candidate and history datasets remain unaffected.
        </div>
      ) : activeArtifact && activeArtifact.edges.length === 0 ? (
        <div className="radar-tool-empty" role="status">
          No candidate pair meets the current shared-evidence publication rules.
        </div>
      ) : activeArtifact ? (
        <>
          <div className="radar-tool-summary radar-association-summary" aria-label="Association artifact summary">
            <div><span>Published pairs</span><strong>{activeArtifact.edges.length}</strong></div>
            <div><span>Signals linked</span><strong>{activeArtifact.nodes.length}</strong></div>
            <div><span>Evidence clusters</span><strong>{clusterOptions.length}</strong></div>
            <div>
              <span>Generated</span>
              <time dateTime={activeArtifact.generatedAt}>{formatDateTime(activeArtifact.generatedAt)} UTC</time>
            </div>
          </div>

          <div className="radar-association-facets" aria-label="Evidence facets">
            <button type="button" className={evidenceType === "all" ? "active" : ""} onClick={() => selectEvidence("all")}>
              <span>All evidence</span><strong>{activeArtifact.edges.length}</strong>
            </button>
            {RELATION_EVIDENCE_TYPES.filter((type) => (evidenceCounts.get(type) ?? 0) > 0).map((type) => (
              <button type="button" className={evidenceType === type ? "active" : ""} onClick={() => selectEvidence(type)} key={type}>
                <span>{evidenceLabels[type]}</span><strong>{evidenceCounts.get(type)}</strong>
              </button>
            ))}
          </div>

          <div className="radar-association-filters">
            <label className="radar-tool-search">
              <span>Search associations</span>
              <span><Search aria-hidden="true" /><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="Domain, evidence, brand…" /></span>
            </label>
            <label>
              <span>Evidence strength</span>
              <select value={strength} onChange={(event) => { setStrength(event.target.value as RelationStrength | "all"); setPage(1); }}>
                <option value="all">All strengths</option>
                <option value="strong">Exact strong evidence</option>
                <option value="corroborated-supporting">Corroborated supporting</option>
              </select>
            </label>
            <label>
              <span>Potential brand match</span>
              <select value={brand} onChange={(event) => { setBrand(event.target.value); setPage(1); }}>
                <option value="all">All brand matches</option>
                {brandOptions.map((value) => <option value={value} key={value}>{value}</option>)}
              </select>
            </label>
            <label>
              <span>Evidence cluster</span>
              <select value={cluster} onChange={(event) => { setCluster(event.target.value); setPage(1); }}>
                <option value="all">All clusters</option>
                {clusterOptions.map(([value, count]) => <option value={value} key={value}>{value} · {count} signals</option>)}
              </select>
            </label>
            <label>
              <span>Order</span>
              <select value={sort} onChange={(event) => { setSort(event.target.value as ExplorerSort); setPage(1); }}>
                <option value="strength">Strongest evidence</option>
                <option value="evidence">Most evidence</option>
                <option value="domain">Domain</option>
                <option value="cluster">Cluster</option>
              </select>
            </label>
            <button type="button" className="radar-tool-button" onClick={resetFilters} disabled={!hasFilters}>
              <FilterX aria-hidden="true" /> Reset filters
            </button>
          </div>

          <div className="radar-association-result-heading">
            <p><strong>{filteredEdges.length}</strong> matching associations across <strong>{filteredClusterCount}</strong> clusters</p>
            <a href="/data/related-observations.json" download><Download aria-hidden="true" /> Download published JSON</a>
          </div>

          {visibleEdges.length === 0 ? (
            <div className="radar-tool-empty">No published association matches these filters.</div>
          ) : (
            <ol className="radar-association-list">
              {visibleEdges.map((edge) => {
                const source = nodesById.get(edge.source);
                const target = nodesById.get(edge.target);
                if (!source || !target) return null;
                return (
                  <li key={edge.id}>
                    <div className="radar-association-meta">
                      <span className={`radar-association-strength radar-association-strength--${edge.strength}`}>
                        {edge.strength === "strong" ? "Exact strong evidence" : "Corroborated supporting evidence"}
                      </span>
                      <span>Cluster {source.clusterId}</span>
                      <span>{edge.evidence.length} evidence item{edge.evidence.length === 1 ? "" : "s"}</span>
                    </div>
                    <div className="radar-association-pair">
                      <SignalEndpoint node={source} signal={signalsById.get(source.signalId)} signalHref={signalHref} />
                      <GitCompareArrows aria-hidden="true" />
                      <SignalEndpoint node={target} signal={signalsById.get(target.signalId)} signalHref={signalHref} />
                    </div>
                    <EvidenceList evidence={edge.evidence} />
                  </li>
                );
              })}
            </ol>
          )}

          {pageCount > 1 ? (
            <nav className="radar-tool-pagination" aria-label="Association result pages">
              <button type="button" onClick={() => setPage(Math.max(1, safePage - 1))} disabled={safePage === 1}>Previous</button>
              <span>Page {safePage} of {pageCount}</span>
              <button type="button" onClick={() => setPage(Math.min(pageCount, safePage + 1))} disabled={safePage === pageCount}>Next</button>
            </nav>
          ) : null}

          <footer className="radar-association-boundary">
            <p>{activeArtifact.semantics}</p>
            <span>
              Suppressed before publication: {activeArtifact.suppressedEvidence.highFanoutValues} high-fanout values,
              {" "}{activeArtifact.suppressedEvidence.temporalPairs} temporal pairs. Public edge limit:
              {" "}{activeArtifact.suppressedEvidence.edgeLimit}.
            </span>
            <a href="/methodology/#publication">Read the publication boundaries</a>
          </footer>
        </>
      ) : null}
    </section>
  );
}
