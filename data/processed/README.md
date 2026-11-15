# Processed data

Three dataset areas:

- train/: train_baseline.csv.gz (1,273 real signature-eligible pairs),
  train_features.csv (1,273 x 44), train_metadata.json,
  train_baseline_provenance.json and baseline_readiness.json.
- test/: test_botsv2.csv and test_botsv2.jsonl (24 canonical synthetic pairs,
  8 suspicious / 16 benign), evaluate_features.csv (24 x 44)
  and evaluate_metadata.json. Future disjoint real sets use test_botsv1.csv,
  test_botsv3.csv, test_splunk_attack.csv and test_mitre.csv.
- benchmarks/: preserved protocol, annotations and readiness snapshot.

The filename test_botsv2 is a requested protocol name. Source remains synthetic
smoke-test fixtures, explicitly recorded in SourceRepo/IsSynthetic/LabelKind.
Only 12 command pairs are unique. It cannot enter production training or pass
authentic benchmark validation.

Current raw logs have zero eligible command pairs after excluding training,
so additional genuine test CSVs have not been fabricated. Mining diagnostics:
reports/data/heldout_annotations.report.json. Models remain under models/;
predictions and metrics go to artifacts/evaluation/.
