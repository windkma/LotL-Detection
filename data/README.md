# Data layout

- external/: static catalogs and exact-hash signature evidence.
- raw/: immutable source logs; manifests retain source URLs, commits and checksums.
- processed/: final train_baseline.csv.gz, train_features.csv, aligned metadata,
  test.csv and test.jsonl; benchmark material lives under processed/benchmarks/.

Raw-to-processed ingestion uses disposable OS temporary SQLite joins. No event
partitions or persistent database indexes are retained inside data/.
The test CSV/JSONL remain synthetic smoke tests with the full evaluation schema;
production training rejects their synthetic provenance. Model fitting uses the
available real signature-eligible baseline, without a 60k/background-evidence gate.
See the repository README for commands and current data limitations.
