"""Validate real benchmark evidence; keep heuristic proxy sets separate."""
from __future__ import annotations
import csv
import gzip
import json
import hashlib
from pathlib import Path

from ..data_loader import DataLoader, ProcessPair, normalize_event
from .data_policy import assert_real_pair, reject_fixture_path
from ..enricher import ReferenceDatabase
from .pair_schema import PAIR_FIELDS, command_key, pair_row
from .ingestion import iter_pair_rows


BENCHMARKS = {"botsv1": (16, 84), "botsv2": (8, 16), "botsv3": (25, 50), "splunk_attack_data": (100, 75), "mitre_eval": (100, 200)}
ALLOWED_SOURCES = {"botsv1": {"splunk/botsv1"}, "botsv2": {"splunk/botsv2"}, "botsv3": {"splunk/botsv3"},
                   "splunk_attack_data": {"splunk/attack_data"}, "mitre_eval": {"OTRF/detection-hackathon-apt29", "mitre/attack-evaluations", "ReaQta/MITRE"}}


def rows(path: Path):
    csv.field_size_limit(64 * 1024 * 1024)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
        yield from csv.DictReader(stream)


def decode_pair(row: dict, source: str) -> ProcessPair:
    fields = normalize_event(row)
    return ProcessPair(DataLoader._process(fields, source, "Parent"), DataLoader._process(fields, source))


def build_benchmarks(manifest: Path, annotations: Path, output: Path, references: ReferenceDatabase, *, project: Path | None = None, chunksize: int = 100000) -> dict:
    """Require PairId/Benchmark/Label/AnnotationSource/Reviewer for each label.

    Manual judgments and explicit heuristic labels are tracked separately.
    All five sets must meet exact deduplicated quotas before any CSV is published.
    New manually annotated sets reproduce the protocol, not original thesis IDs.
    """
    reject_fixture_path(annotations)
    requested = {}
    for annotation in rows(annotations):
        if not all(annotation.get(k) for k in ("PairId", "Benchmark", "Label", "AnnotationSource", "Reviewer")):
            raise ValueError("Annotations require PairId, Benchmark, Label, AnnotationSource and Reviewer")
        if annotation["PairId"] in requested:
            raise ValueError("Duplicate/conflicting PairId annotation")
        if annotation["Benchmark"] not in BENCHMARKS or annotation["Label"] not in {"-1", "1"}:
            raise ValueError("Unknown benchmark or label")
        requested[annotation["PairId"]] = annotation
    automatic = any(a["Reviewer"] == "Automated_Heuristic_Reviewer" for a in requested.values())
    weak_report = {}
    allocations = {}
    if automatic:
        sidecar = annotations.with_suffix(".report.json")
        if not sidecar.exists():
            raise ValueError("Automated annotations require their weak-label provenance sidecar")
        weak_report = json.loads(sidecar.read_text(encoding="utf-8"))
        if weak_report.get("annotations_sha256") != hashlib.sha256(annotations.read_bytes()).hexdigest():
            raise ValueError("Automated annotation checksum mismatch")
        allocations = {a["PairId"]: a for a in weak_report["allocations"]}
    selected = {name: [] for name in BENCHMARKS}
    seen = {}
    matched = set()
    excluded_signature = 0
    duplicates = 0
    for row in (iter_pair_rows(manifest, project=project, chunksize=chunksize) if requested else []):
        annotation = requested.get(row.get("PairId"))
        if not annotation:
            continue
        name = annotation["Benchmark"]
        allocation = allocations.get(row["PairId"], {})
        proxy = automatic and weak_report.get("allow_source_fallback") and allocation.get("RequestedBenchmark") == name and allocation.get("ActualSourceRepo") == row.get("SourceRepo") and allocation.get("SourceSHA256") == row.get("SourceSHA256")
        if (row.get("SourceRepo") not in ALLOWED_SOURCES[name] and not proxy) or not row.get("SourceSHA256"):
            raise ValueError(f"Invalid source provenance for {name}")
        pair = references.enrich([decode_pair(row, str(manifest))])[0]
        assert_real_pair(pair)
        if not all((pair.parent.command_line, pair.child.command_line, pair.parent.image, pair.child.image, pair.child.utc_time)):
            raise ValueError("Incomplete real parent-child telemetry in annotation")
        matched.add(row["PairId"])
        if not pair.eligible:
            excluded_signature += 1
            continue
        key = (name, *command_key(pair))
        if key in seen:
            if seen[key] != annotation["Label"]:
                raise ValueError("Conflicting labels for duplicate benchmark command pair")
            duplicates += 1
            continue
        seen[key] = annotation["Label"]
        result = pair_row(pair)
        result.update(PairId=row["PairId"], Label=int(annotation["Label"]),
                      AnnotationSource=annotation["AnnotationSource"], Reviewer=annotation["Reviewer"])
        selected[name].append(result)
    diagnostics = {"unmatched_annotations": len(set(requested) - matched), "excluded_signature": excluded_signature, "collapsed_duplicates": duplicates,
                   "sets": {name: {"malicious": sum(r["Label"] == -1 for r in records), "benign": sum(r["Label"] == 1 for r in records)} for name, records in selected.items()}}
    diagnostics.update(label_kind="heuristic_weak_labels" if automatic else "manual_annotations", independent_ground_truth=not automatic,
                       training_overlap_annotations=weak_report.get("training_overlap_annotations") if automatic else None,
                       quota_deficits={name: {"malicious": max(0, quota[0] - diagnostics["sets"][name]["malicious"]),
                                              "benign": max(0, quota[1] - diagnostics["sets"][name]["benign"])} for name, quota in BENCHMARKS.items()})
    if automatic:
        # Requested BOTS names refer to proxy groups, never fabricated original sources.
        diagnostics["source_allocations"] = list(allocations.values())
    complete = not diagnostics["unmatched_annotations"] and all((diagnostics["sets"][name]["malicious"], diagnostics["sets"][name]["benign"]) == quota for name, quota in BENCHMARKS.items())
    diagnostics["ready"] = complete and (not automatic or weak_report.get("holdout_verified", False))
    output.mkdir(parents=True, exist_ok=True)
    (output / "build_report.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
    if not diagnostics["ready"]:
        summary = {key: diagnostics[key] for key in ("sets", "quota_deficits", "training_overlap_annotations")}
        raise ValueError("Benchmark evidence/quotas incomplete; see " + str(output / "build_report.json") + ": " + json.dumps(summary))
    if automatic:
        output = output / "heuristic"
    output.mkdir(parents=True, exist_ok=True)
    if any((output / f"test_{name}.csv").exists() for name in BENCHMARKS):
        raise FileExistsError("Benchmark outputs already exist; version them before rebuilding")
    for name, records in selected.items():
        target = output / f"test_{name}.csv"
        with target.with_suffix(".part").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=[*PAIR_FIELDS, "AnnotationSource", "Reviewer"])
            writer.writeheader()
            writer.writerows(records)
    for name in BENCHMARKS:
        target = output / f"test_{name}.csv"
        target.with_suffix(".part").replace(target)
    (output / "build_report.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
    return diagnostics


def validate_benchmark(path: Path, name: str, references: ReferenceDatabase) -> dict:
    records = list(rows(path))
    if name not in BENCHMARKS:
        raise ValueError("Unknown benchmark")
    seen = set()
    counts = {-1: 0, 1: 0}
    for row in records:
        if row.get("Reviewer") == "Automated_Heuristic_Reviewer":
            raise ValueError("Heuristic labels are not independent ground truth for authentic benchmarks")
        pair = references.enrich([decode_pair(row, str(path))])[0]
        assert_real_pair(pair)
        if pair.label not in counts or not pair.eligible or not row.get("AnnotationSource") or not row.get("Reviewer"):
            raise ValueError("Missing labels, signature evidence or manual annotation provenance")
        if row.get("SourceRepo") not in ALLOWED_SOURCES[name] or not row.get("SourceSHA256"):
            raise ValueError("Benchmark source mismatch")
        key = command_key(pair)
        if key in seen:
            raise ValueError("Duplicate benchmark commands")
        seen.add(key)
        counts[pair.label] += 1
    if (counts[-1], counts[1]) != BENCHMARKS[name]:
        raise ValueError(f"Benchmark counts do not match {BENCHMARKS[name]}")
    return {"samples": len(records), "malicious": counts[-1], "benign": counts[1]}
