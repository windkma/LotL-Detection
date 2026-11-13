"""Ground-truth evaluation with anomalies (-1) as the positive class."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable
import argparse
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from .data_loader import DataLoader
from .enricher import ReferenceDatabase
from .model import LOLBinDetector
from .pipeline.cli_support import ROOT, add_arguments, execute, write_json


@dataclass(frozen=True)
class EvaluationResult:
    """Metrics plus denominators so undefined rates are not reported as evidence."""

    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float | None
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    evaluated_samples: int
    excluded_samples: int
    labeled_samples: int
    scored_samples: int
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["warnings"] = list(self.warnings)
        return result


class Evaluator:
    """Evaluate only labeled, eligible rows, while reporting all exclusions.

    Unknown labels are never silently assigned benign; missing predictions from
    the Microsoft-signature filter are excluded with a visible count. With no
    benign ground truth FPR is None, rather than a misleading zero.
    """

    def evaluate(self, labels: Iterable[int | None], predictions: Iterable[int | None]) -> EvaluationResult:
        labels, predictions = list(labels), list(predictions)
        if len(labels) != len(predictions):
            raise ValueError("Ground truth and predictions must have equal lengths")
        if any(value is not None and value not in {-1, 1} for value in labels + predictions):
            raise ValueError("Only -1 (anomaly), +1 (benign), or None are valid labels")
        usable = [(label, pred) for label, pred in zip(labels, predictions) if label is not None and pred is not None]
        if not usable:
            raise ValueError("No labeled, signature-eligible samples available for evaluation")
        truth = np.asarray([label for label, _ in usable])
        guessed = np.asarray([pred for _, pred in usable])
        # Order [benign, anomaly] => [[TN, FP], [FN, TP]].
        tn, fp, fn, tp = confusion_matrix(truth, guessed, labels=[1, -1]).ravel()
        warnings: list[str] = []
        if not (tn + fp):
            warnings.append("No benign ground truth: false positive rate is undefined")
        if not (tp + fn):
            warnings.append("No malicious ground truth: recall cannot measure detection ability")
        if not (tp + fp):
            warnings.append("No predicted anomalies: precision uses zero_division=0")
        return EvaluationResult(
            precision=float(precision_score(truth, guessed, pos_label=-1, zero_division=0)),
            recall=float(recall_score(truth, guessed, pos_label=-1, zero_division=0)),
            f1_score=float(f1_score(truth, guessed, pos_label=-1, zero_division=0)),
            false_positive_rate=float(fp / (fp + tn)) if fp + tn else None,
            true_positives=int(tp), false_positives=int(fp), true_negatives=int(tn), false_negatives=int(fn),
            evaluated_samples=len(usable), excluded_samples=len(labels) - len(usable),
            labeled_samples=sum(value is not None for value in labels),
            scored_samples=sum(value is not None for value in predictions), warnings=tuple(warnings),
        )


def markdown_metrics(reports: dict[str, dict]) -> str:
    """Table-11 style metrics plus counts; missing data is never a numeric score."""
    header = ["| Dataset | Precision | Recall | F1 | FPR | TN | FP | FN | TP | Excluded |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, report in reports.items():
        metrics = report.get("metrics")
        if not metrics:
            header.append(f"| {name} | unavailable | | | | | | | | |")
            continue
        rate = metrics["false_positive_rate"]
        header.append(f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1_score']:.4f} | {f'{rate:.4f}' if rate is not None else 'undefined'} | {metrics['true_negatives']} | {metrics['false_positives']} | {metrics['false_negatives']} | {metrics['true_positives']} | {metrics['excluded_samples']} |")
    note = "Weak-label rule agreement only; these labels are not independent ground truth.\n\n" if any(r.get("label_kind") == "heuristic_weak_labels" for r in reports.values()) else ""
    if any(r.get("label_kind") == "synthetic_fixture" for r in reports.values()):
        note += "Synthetic smoke-test data; metrics do not establish real-world detection accuracy.\n\n"
    return note + "\n".join(header) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "evaluate" and args.benchmark:
        from argparse import Namespace
        from src.pipeline.benchmark_builder import BENCHMARKS, validate_benchmark
        results = {}
        names = list(BENCHMARKS) if args.benchmark == "all" else [args.benchmark]
        for name in names:
            path = ROOT / "data/processed/benchmarks" / f"test_{name}.csv"
            if not path.exists():
                results[name] = {"error": "Missing authentic manually annotated benchmark"}
                continue
            try:
                validate_benchmark(path, name, ReferenceDatabase(ROOT / "data/external"))
                results[name] = run(Namespace(**{**vars(args), "benchmark": None, "input": [path], "output": args.output / name}))
            except ValueError as exc:
                results[name] = {"error": str(exc)}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "evaluation.md").write_text(markdown_metrics(results), encoding="utf-8")
        write_json(args.output / "evaluation.json", results)
        if any("error" in value for value in results.values()):
            raise ValueError("Benchmark evaluation incomplete; see " + str(args.output / "evaluation.md"))
        return results
    if not args.input:
        raise ValueError("Provide --input or --benchmark")
    loader = DataLoader(assume_event_id1=args.assume_event_id1, strict=not args.skip_invalid, production=False)
    pairs = loader.load(args.input)
    if not pairs:
        raise ValueError(f"No valid parent-child pairs. Ingestion statistics: {loader.stats}")
    args.output.mkdir(parents=True, exist_ok=True)
    detector = LOLBinDetector.load(args.model)
    if args.command == "evaluate":
        benchmark_root = (ROOT / "data/processed/benchmarks").resolve()
        if any(path.resolve().is_relative_to(benchmark_root) for path in args.input):
            validation = detector.training_report.get("baseline_validation", {})
            if validation.get("eligible_training_pairs", 0) < 2 or not validation.get("synthetic_excluded"):
                raise ValueError("Benchmark evaluation requires a model trained on eligible real data")
        detector.assert_disjoint(pairs)
    results, features, coverage = detector.predict(pairs)
    args.processed_output.mkdir(parents=True, exist_ok=True)
    features.to_csv(args.processed_output / f"{args.command}_features.csv", index=False)
    write_json(args.processed_output / f"{args.command}_metadata.json",
               {"pair_indexes": features.index.tolist(), "model_path": str(args.model.resolve())})
    report = {"coverage": coverage, "ingestion": loader.stats, "algorithm": detector.model.algorithm,
              "anomaly_score_direction": "higher is more anomalous; decision boundary = 0"}
    if any(p.child.metadata.get("reviewer") == "Automated_Heuristic_Reviewer" for p in pairs):
        report["label_kind"] = "heuristic_weak_labels"
        report["independent_ground_truth"] = False
    if any(p.child.computer.startswith(("synthetic", "fixture", "mock")) or
           str(p.child.metadata.get("issynthetic", "")).lower() in {"true", "1", "yes"} for p in pairs):
        report["label_kind"] = "synthetic_fixture"
        report["independent_ground_truth"] = False
    if args.command == "evaluate":
        labels = [None if value is None else int(value) for value in results["label"].to_numpy(dtype=object, na_value=None)]
        predictions = [None if value is None else int(value) for value in results["prediction"].to_numpy(dtype=object, na_value=None)]
        report["metrics"] = Evaluator().evaluate(labels, predictions).to_dict()
        (args.output / "evaluation.md").write_text(markdown_metrics({args.input[0].stem: report}), encoding="utf-8")
    results.to_csv(args.output / "predictions.csv", index=False)
    features.to_csv(args.output / "features.csv", index=True)
    write_json(args.output / "report.json", report)
    return report


def evaluate_model(input_path: Path, model_path: Path, output_dir: Path | None = None, *,
                   processed_output: Path | None = None, skip_invalid: bool = False,
                   assume_event_id1: bool = False) -> dict:
    """Evaluate unseen pairs, treating anomaly=-1 as positive and reporting exclusions.

    Model state is frozen. Writes predictions, numeric features, confusion counts,
    JSON and Markdown metrics. Missing ground truth never becomes a benign label.
    Synthetic smoke fixtures can be evaluated but are not real-world benchmarks.
    """
    return run(argparse.Namespace(command="evaluate", benchmark=None, input=[Path(input_path)],
        model=Path(model_path), output=Path(output_dir) if output_dir is not None else ROOT / "artifacts/evaluation",
        processed_output=Path(processed_output) if processed_output is not None else ROOT / "data/processed",
        skip_invalid=skip_invalid, assume_event_id1=assume_event_id1))


def parser(*, predict: bool = False) -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="Evaluate frozen LOLBin detector metrics" if not predict else "Predict LOLBin anomalies")
    add_arguments(cli, "predict" if predict else "evaluate")
    return cli


def main(argv: list[str] | None = None, *, predict: bool = False) -> int:
    def run_and_print(args):
        report = run(args)
        if args.command == "evaluate":
            reports = report if args.benchmark else {args.input[0].stem: report}
            print(markdown_metrics(reports), file=sys.stderr)
        return report
    return execute(run_and_print, parser(predict=predict).parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
