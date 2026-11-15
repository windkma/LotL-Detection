"""Argument definitions and dispatch for data preparation commands."""
from __future__ import annotations
import argparse
from pathlib import Path
from ..enricher import ReferenceDatabase
from .cli_support import ROOT


def add_subcommands(sub) -> None:
    ingestion = sub.add_parser("ingest")
    ingestion.add_argument("--manifest", type=Path, default=ROOT / "data/raw/manifest.json")
    ingestion.add_argument("--chunksize", type=int, default=100000)
    ingestion.add_argument("--output", type=Path, default=ROOT / "data/processed/train/train_baseline.csv.gz")
    for name in ("build-baseline", "build-benchmarks"):
        task = sub.add_parser(name)
        task.add_argument("--manifest", type=Path, default=ROOT / "data/raw/manifest.json")
        task.add_argument("--chunksize", type=int, default=100000)
        task.add_argument("--references", type=Path, default=ROOT / "data/external")
        task.add_argument("--benchmarks", type=Path, default=ROOT / "data/processed/test", help="Held-out CSV directory for baseline selection; protocol/report directory when building benchmarks")
        if name == "build-baseline":
            task.add_argument("--output", type=Path, default=ROOT / "data/processed/train/train_baseline.csv.gz")
        if name == "build-benchmarks":
            task.set_defaults(benchmarks=ROOT / "data/processed/benchmarks")
            task.add_argument("--annotations", type=Path, required=True)
            task.add_argument("--test-output", type=Path, default=ROOT / "data/processed/test")


def run(args: argparse.Namespace) -> dict:
    if args.command == "ingest":
        from . import ingest_manifest
        return ingest_manifest(args.manifest, ROOT, chunksize=args.chunksize, output=args.output)
    if args.command == "build-baseline":
        from . import build_baseline
        return build_baseline(args.manifest, args.output, ReferenceDatabase(args.references), args.benchmarks, project=ROOT, chunksize=args.chunksize)
    if args.command == "build-benchmarks":
        from . import build_benchmarks
        return build_benchmarks(args.manifest, args.annotations, args.benchmarks, ReferenceDatabase(args.references), project=ROOT, chunksize=args.chunksize, test_output=args.test_output)
    raise ValueError(f"Unknown data command: {args.command}")
