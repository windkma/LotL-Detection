"""Build an unsupervised training set from available real, eligible process pairs."""
from __future__ import annotations
import csv
import gzip
import json
from pathlib import Path

from .benchmark_builder import decode_pair, rows
from .ingestion import digest, iter_manifest_pairs
from .data_policy import assert_real_pair
from ..enricher import ReferenceDatabase
from .pair_schema import PAIR_FIELDS, command_key, pair_row

MIN_TRAINING_PAIRS = 2


def build_baseline(manifest: Path, output: Path, references: ReferenceDatabase, benchmarks: Path, *, project: Path | None = None, chunksize: int = 100000) -> dict:
    """Use available real data without a minimum enterprise-baseline volume gate.

    BackgroundEvidence is diagnostic only. Unknown labels stay unknown; real
    CTF/attack-context captures are not relabeled as clean enterprise background.
    Held-out command pairs are excluded, including repetitions across sources.
    """
    heldout = {command_key(decode_pair(row, str(path))) for path in benchmarks.glob("test_*.csv") for row in rows(path)}
    counts = {"input_pairs": 0, "eligible_training": 0, "with_background_evidence": 0, "missing_background_evidence": 0, "excluded_signature": 0, "missing_identity": 0, "heldout": 0, "duplicate": 0}
    seen = set()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    temporary = output.with_suffix(".part")
    catalog = {}
    try:
        with gzip.open(temporary, "wt", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=PAIR_FIELDS)
            writer.writeheader()
            for original in iter_manifest_pairs(manifest, project, chunksize=chunksize, catalog=catalog):
                counts["input_pairs"] += 1
                pair = references.enrich([original])[0]
                assert_real_pair(pair)
                background = pair.child.metadata.get("backgroundevidence", "")
                if not background:
                    counts["missing_background_evidence"] += 1
                if not pair.eligible:
                    counts["excluded_signature"] += 1
                    continue
                if not pair.child.computer or pair.child.utc_time is None:
                    counts["missing_identity"] += 1
                    continue
                if command_key(pair) in heldout:
                    counts["heldout"] += 1
                    continue
                child = pair.child
                # Dataset namespace is intentionally absent to collapse mirrored captures.
                identity = (child.computer, child.process_guid or child.process_id, str(child.utc_time), child.image, child.command_line)
                if identity in seen:
                    counts["duplicate"] += 1
                    continue
                seen.add(identity)
                exported = pair_row(pair)
                writer.writerow(exported)
                counts["eligible_training"] += 1
                counts["with_background_evidence"] += bool(background)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    report = {**counts, "training_policy": "available_real_data", "minimum_required": MIN_TRAINING_PAIRS,
              "clean_background_verified": False, "ready": counts["eligible_training"] >= MIN_TRAINING_PAIRS}
    (output.parent / "baseline_readiness.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["ready"]:
        temporary.unlink(missing_ok=True)
        raise ValueError("Insufficient eligible training data: " + json.dumps(report))
    temporary.replace(output)
    catalog.update(output=str(output.resolve()), output_sha256=digest(output))
    output.with_name(output.name.removesuffix(".csv.gz") + "_provenance.json").write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return {**report, **catalog}


def require_production_training(pairs) -> None:
    seen = set()
    for pair in pairs:
        assert_real_pair(pair)
        if not pair.eligible:
            raise ValueError("Production training requires verified Microsoft signature evidence")
        if not pair.child.computer or pair.child.utc_time is None:
            raise ValueError("Production training requires host and creation time provenance")
        child = pair.child
        identity = (child.computer, child.process_guid or child.process_id, str(child.utc_time), child.command_line)
        if identity in seen:
            raise ValueError("Duplicated baseline execution; volume cannot be inflated")
        seen.add(identity)
    if len(seen) < MIN_TRAINING_PAIRS:
        raise ValueError(f"Training requires at least {MIN_TRAINING_PAIRS} distinct eligible pairs; found {len(seen)}")
