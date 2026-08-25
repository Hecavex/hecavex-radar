# Checkpointed CT search state

This directory contains the bounded, credential-free state used by the hourly
Certificate Transparency keyword poller. Each reviewed brand query has a
monotonic result identifier, last successful attempt time, and controlled
outcome. The state contains no unpublished domain names.

The poller queries the public `crt.sh` JSON search index and writes qualifying
matches through the same date-partitioned candidate archive and matcher used by
the sampled CertStream listener. The public source remains Certificate
Transparency; collection lineage distinguishes live stream observations from
search-index replay.

This is replayable coverage of the declared keyword queries, not complete
coverage of every Certificate Transparency log or certificate.
