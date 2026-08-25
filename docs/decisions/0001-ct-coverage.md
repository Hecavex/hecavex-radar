# ADR 0001: Durable Certificate Transparency coverage

- Status: Accepted
- Decision date: 2026-08-21
- Implementation stage: Stage 02

## Context

At the time of this decision, Radar started a live CertStream listener at 02 and 32 minutes past each UTC hour. Each scheduled run was bounded to 240 seconds. If every run started on time and remained connected, that configuration observed 192 minutes per day, or 13.3% of wall-clock time. Events outside those windows were not replayed or backfilled.

The interim sampler now runs a 48-hour coverage trial at 08, 23, 38, and 53 minutes past each UTC hour, with each delivered run bounded to 480 seconds. Its theoretical ceiling is 768 minutes, or 53.3% of a day. This changes neither the decision nor the coverage claim: GitHub Actions may delay or drop schedules, and missed live events still cannot be replayed.

GitHub Actions scheduling and network delivery are best effort. A run can start late, fail before connecting, disconnect early, or complete successfully with no qualifying brand match. The signal snapshot records archive-read state. A separate bounded public health document now records the latest sampled attempt's actual connection time, aggregate input counts, outcome, scheduling delay, last success, and freshness.

One successful run reviewed on 2026-08-21 processed 83,875 messages containing 146,591 DNS names during its 240-second window and produced zero qualifying matches. That was a healthy empty result. It does not establish coverage outside the window or represent permanent collector health.

The sampled listener is useful for low-latency discovery, but it cannot be the durable source of record for Certificate Transparency coverage.

## Decision

Stage 02 will implement checkpointed Certificate Transparency log or API polling as the durable collection path. The collector will persist a monotonic checkpoint per selected log, resume from the last verified checkpoint, and backfill missed ranges within documented limits.

CertStream will remain as a low-latency discovery input. A live-stream observation may publish a qualifying candidate before the durable poller reaches the same certificate, but later ingestion must deduplicate the observation by stable certificate and hostname evidence.

Until that implementation passes coverage, replay, deduplication, and failure-recovery validation, Radar will describe the current CertStream input as sampled and will not claim complete daily certificate coverage. Latest-attempt health improves operational transparency but is not a replay checkpoint or proof of observation outside that attempt.

## Consequences

Benefits:

- missed workflow intervals can be recovered;
- coverage can be measured by log indices or equivalent provider checkpoints rather than scheduled wall-clock time;
- restarts and delayed Actions runs no longer create silent permanent gaps;
- CertStream still provides low-latency leads;
- public coverage statements can be based on recorded collector evidence.

Costs and risks:

- log selection, checkpoint storage, backfill limits, retries, and deduplication require additional implementation;
- different CT APIs expose different pagination, rate, and consistency behavior;
- the poller must handle certificate and hostname volume without publishing unsafe raw input;
- a checkpoint proves progress only for its declared log set, not all certificates globally.

## Stage 02 acceptance conditions

The durable collector is not complete until it can:

1. resume from a persisted checkpoint without skipping an unprocessed range;
2. recover after an interrupted run;
3. bound initial and recovery backfills safely;
4. deduplicate records also seen through CertStream;
5. distinguish successful-empty, partial, failed, delayed, and skipped durable collection runs (the sampled listener now provides these semantics for its latest attempt);
6. publish durable-log coverage and last-success metadata without exposing raw or quarantined observations (the sampled listener now publishes bounded latest-attempt health only);
7. document the selected logs or APIs, their limitations, and any unmonitored scope; and
8. pass repeatable validation for checkpoint advancement, replay, malformed responses, rate limiting, and atomic writes.

## Alternatives considered

### Run CertStream continuously on a persistent host

This would improve live coverage and remains a possible latency component, but connection continuity alone does not provide deterministic replay after downtime. It is not selected as the durable source of record.

### Increase the number of short GitHub Actions windows

More windows reduce some gaps but retain scheduling uncertainty and lack of replay. The current 48-hour trial measures this option as an interim sampling improvement; it is not selected as the durable source of record.

### Keep sampled collection indefinitely

This is operationally simple but incompatible with stronger coverage claims and reliable longitudinal measurement. It is acceptable only as the explicitly disclosed interim state.
