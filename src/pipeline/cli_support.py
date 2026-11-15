"""Shared serialization, argument definitions and CLI error handling."""
from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]


def write_json(path: Path, content: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def add_arguments(task: argparse.ArgumentParser, command: str) -> None:
    task.set_defaults(command=command, benchmark=None)
    task.add_argument("--input", nargs="+", required=command == "predict", type=Path,
                      default=[ROOT / "data/processed/train/train_baseline.csv.gz"] if command == "train" else
                              [ROOT / "data/processed/test/test_botsv2.csv"] if command == "evaluate" else None)
    task.add_argument("--model", type=Path, default=ROOT / "models/detector.joblib")
    task.add_argument("--output", type=Path, default=ROOT / ("reports/evaluate" if command == "evaluate" else "reports/" + command))
    task.add_argument("--processed-output", type=Path, default=ROOT / "data/processed" / ("train" if command == "train" else "test"))
    task.add_argument("--assume-event-id1", action="store_true")
    task.add_argument("--skip-invalid", action="store_true")
    if command == "evaluate":
        task.add_argument("--benchmark", choices=("all", "botsv1", "botsv2", "botsv3", "splunk_attack_data", "mitre_eval"))
    if command == "train":
        task.add_argument("--references", type=Path, default=ROOT / "data/external")
        task.add_argument("--binary-dir", type=Path)
        task.add_argument("--contamination", default="auto")
        task.add_argument("--n-estimators", type=int, default=200)
        task.add_argument("--seed", type=int, default=42)
        task.add_argument("--f7-mode", choices=("statistical", "paper"), default="paper")


def execute(runner: Callable, args: argparse.Namespace) -> int:
    try:
        print(json.dumps(runner(args), ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        logging.error("%s", exc)
        return 1
