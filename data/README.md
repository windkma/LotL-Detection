# Data layout

- external/: static threat intelligence, documentation and signature catalogs.
- raw/: immutable source logs; manifests retain URLs, commits and SHA256.
- processed/train/: real baseline, 44-column features and aligned metadata.
- processed/test/: canonical evaluation sets and their inference features.
- processed/benchmarks/: preserved protocol and historical annotation snapshot.

Ingestion uses disposable OS temporary SQLite joins, with no persistent event
layer. The current test_botsv2 CSV/JSONL contain 24 synthetic smoke-test pairs
(only 12 unique command pairs), not original BOTSv2 telemetry or independent
real ground truth. New real test mining rejects training command overlap.
See the repository README and reports/data/ for actual readiness results.
