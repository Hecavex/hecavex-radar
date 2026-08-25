import { ArrowLeftRight, Download, Link2, Share2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  loadRelatedObservations,
  type RelatedObservationEvidence,
  type RelatedObservationNode,
  type RelatedObservations,
} from "../lib/relatedObservations.ts";
import { formatDateTime } from "../lib/format.ts";
import type { RadarSignal } from "../types.ts";

const MAXIMUM_VISIBLE_ASSOCIATIONS = 8;

const evidenceLabels: Record<RelatedObservationEvidence["type"], string> = {
  "primary-html-sha256": "Same primary HTML SHA-256",
  "certificate-sha256": "Same certificate SHA-256",
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

type LoadState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "ready"; artifact: RelatedObservations };

function ObservationLink({
  node,
  signal,
  onSelect,
}: {
  node: RelatedObservationNode;
  signal: RadarSignal | undefined;
  onSelect: (signal: RadarSignal) => void;
}) {
  const canLink = signal?.domain === node.domain;
  if (!canLink) {
    return (
      <div className="relation-observation">
        <code>{node.domain}</code>
        <span>Current row unavailable</span>
      </div>
    );
  }
  return (
    <a className="relation-observation" href={`#signal-${node.signalId}`} onClick={() => onSelect(signal)}>
      <code>{node.domain}</code>
      <span><Link2 aria-hidden="true" /> Open signal</span>
    </a>
  );
}

export function RelatedObservationsPanel({
  signals,
  onSelect,
}: {
  signals: RadarSignal[];
  onSelect: (signal: RadarSignal) => void;
}) {
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const signalsById = useMemo(() => new Map(signals.map((signal) => [signal.id, signal])), [signals]);

  useEffect(() => {
    const controller = new AbortController();
    void loadRelatedObservations(controller.signal).then((artifact) => {
      if (!controller.signal.aborted) {
        setState(artifact ? { status: "ready", artifact } : { status: "unavailable" });
      }
    });
    return () => controller.abort();
  }, []);

  const nodesById = useMemo(
    () => new Map(state.status === "ready" ? state.artifact.nodes.map((node) => [node.signalId, node]) : []),
    [state],
  );
  const visibleEdges = state.status === "ready"
    ? state.artifact.edges.slice(0, MAXIMUM_VISIBLE_ASSOCIATIONS)
    : [];
  const clusterCount = state.status === "ready"
    ? new Set(state.artifact.nodes.map((node) => node.clusterId)).size
    : 0;

  return (
    <section className="relation-panel" aria-labelledby="related-observations-title">
      <div className="relation-heading">
        <div>
          <p className="eyebrow"><Share2 aria-hidden="true" /> Shared public evidence</p>
          <h2 id="related-observations-title">Automated associations</h2>
        </div>
        <p>
          These links show bounded evidence overlap between observations. They are associations, not campaign,
          operator, ownership, malware, or threat-actor attribution.
        </p>
      </div>

      {state.status === "loading" ? (
        <p className="relation-state" aria-live="polite">Loading bounded association data.</p>
      ) : state.status === "unavailable" ? (
        <p className="relation-state" role="status">
          Association data is temporarily unavailable. The candidate list above remains unaffected.
        </p>
      ) : state.artifact.edges.length === 0 ? (
        <div className="relation-state relation-empty" role="status">
          <strong>No current associations</strong>
          <span>No candidate pair meets the bounded shared-evidence publication rules in this snapshot.</span>
        </div>
      ) : (
        <>
          <div className="relation-summary" aria-label="Related observation summary">
            <span><strong>{state.artifact.edges.length}</strong> associations</span>
            <span><strong>{clusterCount}</strong> evidence clusters</span>
            <time dateTime={state.artifact.generatedAt}>Generated {formatDateTime(state.artifact.generatedAt)} UTC</time>
            <a href="/data/related-observations.json" download>
              <Download aria-hidden="true" /> Download JSON
            </a>
          </div>
          <ol className="relation-list">
            {visibleEdges.map((edge) => {
              const source = nodesById.get(edge.source);
              const target = nodesById.get(edge.target);
              if (!source || !target) return null;
              return (
                <li key={edge.id}>
                  <div className="relation-pair">
                    <ObservationLink node={source} signal={signalsById.get(source.signalId)} onSelect={onSelect} />
                    <span aria-hidden="true"><ArrowLeftRight /></span>
                    <ObservationLink node={target} signal={signalsById.get(target.signalId)} onSelect={onSelect} />
                  </div>
                  <div className="relation-evidence">
                    <span className={`relation-strength ${edge.strength}`}>
                      {edge.strength === "strong" ? "Exact strong evidence" : "Corroborated supporting evidence"}
                    </span>
                    <ul aria-label="Shared evidence">
                      {edge.evidence.map((evidence) => (
                        <li key={`${evidence.type}:${evidence.value}`}>
                          <span>{evidenceLabels[evidence.type]}</span>
                          <code title={evidence.value}>{evidence.value}</code>
                        </li>
                      ))}
                    </ul>
                  </div>
                </li>
              );
            })}
          </ol>
          <div className="relation-footer">
            <p>
              Showing {visibleEdges.length} of {state.artifact.edges.length} strongest published associations.
              High-fanout and temporally distant evidence is suppressed before publication.
            </p>
            <a href="/methodology/#publication">Read the evidence boundaries</a>
          </div>
        </>
      )}
    </section>
  );
}
