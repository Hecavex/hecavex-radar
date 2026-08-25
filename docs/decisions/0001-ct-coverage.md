# ADR 0001: Certificate Transparency coverage boundaries

- Status: Accepted
- Decision date: 2026-08-21
- Last reviewed: 2026-08-25
- Implementation: sampled live stream plus bounded checkpointed keyword search

## Context

Radar needs timely certificate-name leads for Lithuanian brand impersonation without claiming monitoring coverage it cannot
demonstrate. GitHub Actions is a best-effort scheduler: a run can start late, be dropped, fail before connecting, disconnect
early, or finish successfully with no matching brand. A live websocket does not provide replay after an unobserved window.

The current CertStream workflow runs at 08, 23, 38, and 53 minutes past each UTC hour. Each delivered run listens for no
more than 480 seconds. If all 96 daily runs start and complete, the theoretical maximum is 768 minutes, or 53.3% of a day.
That ceiling is not observed coverage. The public collection-health file and dated attempt rows record actual completed
windows and aggregate counts, but cannot reconstruct an event that arrived outside them.

A separate public search index can reduce some gaps without requiring a persistent service. It still has different
limitations: indexing scope and latency are controlled by the provider, a keyword query is not an enumeration of a CT log,
and a result identifier is not an RFC 9162 tree index.

## Decision

Radar keeps the sampled CertStream listener as its low-latency CT input and adds an hourly, credential-free `crt.sh`
keyword poller as a second bounded discovery path.

The indexed poller:

1. derives one conservative term from each reviewed brand entry and avoids unsafe short or ambiguous aliases;
2. rotates through six queries per run by default;
3. stores an independent monotonic result-ID checkpoint for every selected brand query;
4. limits a new query to a seven-day bootstrap and later runs to 500 rows after its checkpoint by default;
5. sends every returned hostname through the same current registry, official-domain suppression, matcher, score gate,
   defanging, archive schema, and deduplication as the live stream; and
6. writes a bounded completed, partial, or failed state before the workflow propagates an ordinary polling failure.

Both paths retain the compatible public source label `CertStream`; controlled discovery lineage distinguishes
`certstream-live` from `ct-search-api`. URLScan remains optional corroboration and is not required for a qualifying CT row
to enter the candidate snapshot.

This implementation is checkpointed replay of declared provider queries only. Radar will not describe it as complete
daily CT coverage, global CT coverage, complete brand coverage, or a durable enumeration of selected logs. The provider
may omit or delay records, query terms can miss relevant names, GitHub schedules can fail, and hard cancellation or a
failed Git push can prevent a new state from reaching the repository.

## Public evidence

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| `public/data/collection-health.json` | Timing, input, outcome, and freshness for the latest finalizable sampled live attempt | Activity between samples or continuous listener uptime |
| `data/certstream/<date>/attempts.ndjson` | Aggregate evidence for successful sampled windows, including healthy empty windows | Missed schedules, failed pre-finalizer runs, or unobserved certificates |
| `data/ct-search/state.json` | Provider, query rotation, per-query result checkpoints, timestamps, and aggregate latest-run counters | Certificate names, complete provider indexing, or CT-log tree progress |
| `data/certstream/<date>/domains.ndjson` | Defanged qualifying candidates accepted from either CT path | Proof of phishing, actor attribution, or every name processed upstream |
| `public/data/pipeline-health.json` | Sanitized current CT-search outcome/counters alongside live-stream aggregates | A combined or inflated continuous-coverage percentage |

## Consequences

Benefits:

- selected brand searches resume after ordinary workflow downtime instead of always restarting from the newest page;
- the live listener still provides lower-latency leads during delivered windows;
- both paths share one reviewed matcher, archive contract, deduplication boundary, and public source vocabulary;
- partial and failed indexed runs are observable without publishing their unpublished inputs; and
- coverage language can distinguish measured live listening from bounded indexed replay.

Limits and costs:

- `crt.sh` availability, indexing behavior, query semantics, and response size are external dependencies;
- maintaining reviewed query terms and false-positive suppression is an editorial responsibility;
- a result-ID cursor proves progress only for one declared provider query;
- the state and archive writer must remain serialized with the live collector; and
- stronger coverage claims would still require independently validated log enumeration, checkpoint/backfill semantics,
  malformed-response handling, deduplication, and public evidence for the selected log set.

## Future completeness gate

A future implementation may be described as durable selected-log coverage only after it can identify the monitored logs,
resume from verified tree checkpoints without skipping ranges, bound initial and recovery backfills, recover after an
interrupted run, deduplicate live observations, expose sanitized coverage and last-success metadata, and pass repeatable
failure/replay validation. That work is not part of the current GitHub-hosted implementation and no persistent service,
VPS collector, or TAXII endpoint is claimed here.

## Alternatives considered

### Run CertStream continuously on a persistent host

This can improve live availability, but connection continuity alone does not provide deterministic replay. It is deferred
and is not required for the current bounded implementation.

### Treat more short GitHub Actions windows as durable coverage

More windows reduce some gaps but retain scheduler uncertainty and no event replay. They remain samples.

### Treat `crt.sh` query cursors as CT-log checkpoints

Rejected. Search-result identifiers and keyword result sets do not prove RFC 9162 log position or completeness.

### Keep only the sampled listener

Operationally simple, but it permanently loses every missed window. The bounded indexed path improves recoverability for
declared terms while keeping the limitation visible.
