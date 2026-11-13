# Ready-to-use datasets

- train_baseline.csv.gz: 1,273 real Microsoft-signature-eligible process pairs,
  after execution deduplication and available held-out command exclusion.
- train_features.csv: the corresponding 1,273 x 44 numeric features.
- train_metadata.json: row-aligned identity metadata; unknown labels are preserved.
- train_baseline_provenance.json: original raw inputs, revisions, checksums,
  extraction counts and final dataset checksum.
- baseline_readiness.json: selection diagnostics.
- test.csv and test.jsonl: equivalent synthetic smoke-test events, retaining all
  evaluation columns; 26 linked pairs, 24 eligible labeled evaluation samples.
  Their synthetic provenance remains explicit and cannot enter training.
- benchmarks/: consolidated annotations, evidence and future reviewed benchmark CSVs.

This training data includes CTF/attack-emulation context and is not a certified
benign enterprise baseline. At least two distinct eligible pairs are needed;
there is no 60k/background-evidence gate. Models live under models/.
Evaluation writes inference features and aligned metadata here as needed.
Temporary process-join indexes are removed instead of becoming extra datasets.
