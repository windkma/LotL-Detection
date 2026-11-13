# LotLDetectionV2

Unsupervised LOLBin detection with 44 parent-child process features,
StandardScaler and IsolationForest. The fitted pipeline lives in
`models/detector.joblib`.

## Repository and data layout

```text
data/
  external/                       # Static threat intelligence and signature catalogs
  raw/                            # Immutable original downloads
    manifest.json                 # Source URLs, revisions and SHA256 checksums
  processed/                      # Final datasets and aligned metadata
    train_baseline.csv.gz          # 1,273 real signature-eligible process pairs
    train_features.csv             # 1,273 x 44 numeric features
    train_metadata.json            # Row-aligned identity metadata
    train_baseline_provenance.json # Raw input checksums and extraction counts
    baseline_readiness.json        # Selection diagnostics
    test.csv                      # Synthetic evaluation smoke-test records
    test.jsonl                    # Equivalent JSONL records
    benchmarks/                   # Consolidated annotations, evidence and future test CSVs
models/                           # Trained model bundles
artifacts/evaluation/             # Predictions, features, JSON and Markdown metrics
reports/                          # Training and pipeline diagnostics
src/
  data_loader.py                  # Process parsing and pairing
  enricher.py                     # ReferenceDatabase, CorpusEnricher, true 1D fastText
  features.py                     # The 44 thesis features
  model.py                        # Complete fitted pipeline and persistence
  train.py                        # Training API and CLI
  evaluate.py                     # Evaluation, prediction and metrics
  pipeline/                       # Raw ingestion, baseline selection, annotations and export
scripts/generate_annotations.py   # Optional explicit heuristic annotation
configs/dataset_sources.json      # Download source selection
tests/                            # Four focused modules plus shared in-memory fixtures
main.py                           # Compatible CLI dispatcher
```

Data has exactly three top-level directories: external, raw and processed.
Ingestion streams original JSON/JSONL/XML/EVTX/ZIP/GZIP logs and retains only
Sysmon Event ID 1 and Security Event ID 4688. Parent-child joins are scoped by
dataset and host; PID reuse selects the latest preceding creation. SQLite
indexes live in an OS temporary directory and are removed on completion or
failure. No event partitions or persistent join databases remain in data/.
The final eligible training baseline is written directly from raw logs.

## Install and test

```powershell
python -m pip install -r requirements-dev.txt
python -B -m pytest -q -p no:cacheprovider
```

Latest verification: **109 passed, 0 skipped, 0 failed**.

The unit suite has no external benchmark-data dependency. Quota, signature and
provenance validation for all five benchmark types uses pytest temporary records.
These tests do not certify the availability of real research benchmarks.
Training fixtures are generated in memory under tests; there is no separate
synthetic training JSON file in the data tree.

## Train

```powershell
python main.py train
python -m src.train --input data/processed/train_baseline.csv.gz --model models/detector.joblib
```

The default input is train_baseline.csv.gz. Training requires at least two
distinct real eligible pairs; there is no 60,000-pair or BackgroundEvidence gate.
Synthetic record provenance is still rejected, including the synthetic test
files stored in processed. Verified Microsoft signature evidence is required;
a Windows-looking executable path alone is insufficient.

The current model uses 200 IsolationForest trees, contamination=auto, seed=42,
and f7_mode=paper. Child F1-F18, parent F1-F18 and contextual F19-F26 yield
44 features. Corpus state, scaler and 1D fastText embeddings are fitted only on
training data and saved inside the model bundle. Unknown labels remain unknown;
labels are not features. Training rejects overlap with available held-out
benchmark command pairs.

## Evaluate and predict

```powershell
python main.py evaluate
python main.py evaluate --input data/processed/test.csv
python -m src.evaluate --input data/processed/test.jsonl
python main.py predict --input data/processed/test.csv
```

Evaluation defaults to data/processed/test.csv and requires no --skip-invalid.
Both test formats retain CommandLine, ParentCommandLine, Image, ParentImage,
UtcTime, IntegrityLevel, OriginalFileName, Signer, SignatureValid and Label.
Their 27 event rows link into 26 process pairs. One pair lacks a label and one
lacks signature evidence, leaving 24 evaluated samples.

The CLI prints a precision/recall/F1/FPR/confusion table to the terminal and JSON
to stdout. Reports and predictions go to artifacts/evaluation; aligned inference
features and metadata also go to processed.

The migrated test data is **synthetic smoke-test data**. Current model metrics:
precision 1.0000, recall 0.6250, F1 0.7692, FPR 0.0000; TN=16, FP=0, FN=3,
TP=5, excluded=2. These numbers do not establish real-world detection accuracy.
Reports explicitly record label_kind=synthetic_fixture.

```python
from pathlib import Path
from src.train import train_model
from src.evaluate import evaluate_model

report = train_model(Path("data/processed/train_baseline.csv.gz"),
                     Path("models/detector.joblib"), Path("data/external"))
metrics = evaluate_model(Path("data/processed/test.csv"),
                         Path("models/detector.joblib"), Path("artifacts/evaluation"))
```

## Build final datasets from raw logs

```powershell
python main.py ingest --manifest data/raw/manifest.json --chunksize 100000
# Equivalent baseline selection command:
python main.py build-baseline --manifest data/raw/manifest.json
# Compare a rebuild without replacing the current dataset:
python main.py ingest --manifest data/raw/manifest.json --output reports/data/rebuilt_baseline.csv.gz
```

The first two commands create the final baseline and refuse to overwrite an
existing dataset. Reuse the current file for model-only retraining or select a
new output path for inspection. Raw files are checksum-verified and remain
unchanged. Final provenance retains source URLs, commits, input checksums,
extraction counts and the final dataset checksum. Mirrored executions and
available held-out benchmark commands are excluded.

The current manifest contains 26 source files and 1,826,634 events. They yield
11,699 process pairs; 10,402 lack sufficient signature evidence and 24 repeated
executions are removed, leaving 1,273 training pairs. These include CTF and
attack-emulation context, with no audited clean enterprise background.
Microsoft-signed does not imply benign. Historical exact-hash catalogs do not
provide live certificate revocation checking.

`download_datasets.py --merge-csv MANIFEST` is a compatibility alias for direct
raw-to-processed export. Compressed BOTSv1 exports are streamed without an
unpacked copy. Additional manifests live under data/raw/manifests.
BOTSv2's pre-indexed archive requires an existing Splunk instance/export:

```text
python download_datasets.py --splunk-url https://YOUR-SERVER:8089 --earliest UTC_START --latest UTC_END --background-evidence AUDIT_REFERENCE
```

Set SPLUNK_TOKEN privately in the environment. The exporter verifies TLS and
preserves raw results. No Splunk instance/export is present in this workspace.

## Benchmarks and heuristic annotations

All benchmark material lives under data/processed/benchmarks/.

```powershell
python -B scripts/generate_annotations.py --manifest data/raw/manifest.json --allow-source-fallback --overwrite
python main.py build-benchmarks --manifest data/raw/manifest.json --annotations data/processed/benchmarks/annotations.csv
python main.py evaluate --benchmark all
```

These builders now stream verified pairs directly from the raw manifest. Pair
identities and actual source provenance remain intact. The five quotas are
botsv1 16/84, botsv2 8/16, botsv3 25/50, splunk_attack_data 100/75, and
mitre_eval 100/200 (suspicious/benign). The original manually labeled 674-row
set is unavailable.

The retained annotations contain 199 weak labels (91 suspicious, 108 benign-rule
matches). All 199 overlap current training commands. These are heuristic labels,
not independent ground truth. Proxy allocations preserve the actual source and
cannot be claimed as original BOTSv2/BOTSv3 telemetry. Builders report shortages
and overlap rather than padding quotas. --overwrite replaces automatic output
only and protects human reviews.

Reviewed test CSVs belong under processed/benchmarks/test_*.csv; complete weak
sets remain explicitly marked under its heuristic/ subdirectory. Evaluation
rejects overlapping training commands and marks weak metrics as rule agreement.
--benchmark all reports unavailable data and exits nonzero until valid benchmark
files exist. Passing unit tests alone does not satisfy those data requirements.
