# Held-out benchmark protocol

Targets (malicious / benign): botsv1 16/84, botsv2 8/16, botsv3 25/50,
splunk_attack_data 100/75, mitre_eval 100/200. Total 674 (249/425).
These counts alone are not ground truth. No test_*.csv is synthesized to meet a quota.

Provide manual annotations as CSV with columns:
PairId,Benchmark,Label,AnnotationSource,Reviewer

PairId must refer to a real process pair rebuilt from the checksum-verified raw manifest. Benchmark
must be one of the five names above. Label is -1 or 1. AnnotationSource identifies
the evidence supporting the judgment; Reviewer records the human adjudicator.
Labels may not be derived from model predictions or a filename/ATT&CK folder.
The source repo must match the benchmark. Only Microsoft-signed eligible pairs
survive, and (ParentCommandLine,CommandLine) must be unique within each benchmark.

Run main.py build-benchmarks --annotations YOUR_ANNOTATIONS.csv. The builder
validates ALL quotas before publishing any test CSV. It records annotation
provenance and refuses to overwrite existing benchmark versions. New annotations
produce new protocol-compatible sets, not the author's original samples.

The original MITRE evaluation set in the thesis was ReaQta private telemetry.
OTRF APT29 can support a separately described benchmark, not an exact reproduction.
Without the original labels or new reviewed annotations, acceptance remains unmet.

## Automated weak labels

Run `python -B scripts/generate_annotations.py --manifest data/raw/manifest.json --allow-source-fallback --overwrite`.
The overwrite flag only replaces prior automatic output, never human reviews.
This produces `annotations.csv` with the same five-column schema, specific rule
names and Reviewer=Automated_Heuristic_Reviewer. The checksummed sidecar
`annotations.report.json` preserves each ActualSourceRepo, any SourceSubstitution,
quota deficits and command overlap with the current training dataset. Without
the fallback flag, only native source candidates are allocated.

Current result: 199 annotations (91 suspicious / 108 benign-rule matches), from
600 unique signature-eligible command pairs. BOTSv2 and BOTSv3 have no native
partitions. All 199 selected annotations overlap current training commands;
they cannot measure held-out performance of the current model. Rules abstain
on unmatched commands instead of defaulting them to benign. Command pairs and
PairIds cannot be reused across benchmark groups to pad quotas.

These are heuristic/weak labels, not independently reviewed ground truth.
Requested BOTS names with substituted sources describe proxy allocations only.
The generator returns 2 for incomplete quotas or unverified train separation.
The official builder currently writes build_report.json and exits nonzero.
No test CSVs are published until all quotas and train separation are satisfied.
Future complete weak-label sets are written under heuristic/; authentic benchmark
validation rejects automatically reviewed labels. Evaluation reports on weak
CSV inputs explicitly state that metrics measure rule agreement, and evaluation
still rejects overlapping training commands.

Builders now read raw logs directly with temporary joins. Persistent paired
partitions are not required. This directory moved under data/processed/.
