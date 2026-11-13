"""Generate explicit heuristic labels on verified real pairs; report quota deficits."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.enricher import ReferenceDatabase
from src.pipeline.auto_annotation import generate_annotations


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--manifest", type=Path, default=ROOT / "data/raw/manifest.json")
    cli.add_argument("--chunksize", type=int, default=100000)
    cli.add_argument("--references", type=Path, default=ROOT / "data/external")
    cli.add_argument("--output", type=Path, default=ROOT / "data/processed/benchmarks/annotations.csv")
    cli.add_argument("--allow-source-fallback", action="store_true", help="Allocate explicit proxy rows; never changes their actual source")
    cli.add_argument("--training-input", type=Path, default=ROOT / "data/processed/train_baseline.csv.gz", help="Audit overlap against the real training pairs")
    cli.add_argument("--overwrite", action="store_true", help="Replace only previous automatically generated annotations")
    args = cli.parse_args()
    try:
        report = generate_annotations(args.manifest, args.output, ReferenceDatabase(args.references), allow_source_fallback=args.allow_source_fallback, training_path=args.training_input, overwrite=args.overwrite, project=ROOT, chunksize=args.chunksize)
        print(json.dumps({k: v for k, v in report.items() if k != "allocations"}, indent=2))
        return 0 if report["quotas_complete"] and report["holdout_verified"] else 2
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
