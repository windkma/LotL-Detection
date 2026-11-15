"""Real-data training pipeline and standalone ``python -m src.train`` CLI."""
from __future__ import annotations
import argparse
from pathlib import Path
from typing import Any
from .data_loader import DataLoader
from .enricher import ReferenceDatabase
from .model import LOLBinDetector
from .pipeline.baseline_builder import require_production_training
from .pipeline.cli_support import ROOT, add_arguments, execute, write_json
from .pipeline.pair_schema import command_key


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.input:
        raise ValueError("Provide --input for training")
    loader = DataLoader(assume_event_id1=args.assume_event_id1, strict=not args.skip_invalid, production=True)
    pairs = loader.load(args.input)
    if not pairs:
        raise ValueError(f"No valid parent-child pairs. Ingestion statistics: {loader.stats}")
    args.output.mkdir(parents=True, exist_ok=True)
    references = ReferenceDatabase(args.references)
    if args.binary_dir:
        if not args.binary_dir.is_dir():
            raise FileNotFoundError(args.binary_dir)
        references.import_pe_directory(args.binary_dir)
    contamination = "auto" if args.contamination == "auto" else float(args.contamination)
    detector = LOLBinDetector(references, f7_mode=args.f7_mode,
                               contamination=contamination,
                               n_estimators=args.n_estimators, random_state=args.seed)
    enriched_baseline = references.enrich(pairs)
    require_production_training(enriched_baseline)
    heldout_paths = list((ROOT / "data/processed/test").rglob("test_*.csv"))
    heldout_commands = {command_key(pair) for path in heldout_paths for pair in DataLoader().load(path)}
    if any(command_key(pair) in heldout_commands for pair in enriched_baseline):
        raise ValueError("Training overlaps held-out benchmark command pairs")
    detector.fit(enriched_baseline)
    detector.training_report["baseline_validation"] = {
        "eligible_training_pairs": len(enriched_baseline), "minimum_required": 2,
        "training_policy": "available_real_data", "clean_background_verified": False,
        "pairs_with_background_evidence": sum(bool(p.child.metadata.get("backgroundevidence")) for p in enriched_baseline),
        "synthetic_excluded": True, "heldout_overlap": 0}
    enriched = detector.references.enrich(pairs)
    eligible = [pair for pair in enriched if pair.eligible]
    features = detector.extractor.transform(eligible)
    args.processed_output.mkdir(parents=True, exist_ok=True)
    features.to_csv(args.processed_output / "train_features.csv", index=False)
    write_json(args.processed_output / "train_metadata.json", [
        {"dataset_id": pair.child.dataset_id, "computer": pair.child.computer,
         "process_guid": pair.child.process_guid, "label": pair.label} for pair in eligible])
    detector.save(args.model)
    report = {**detector.training_report, "ingestion": loader.stats, "model_path": str(args.model.resolve())}
    write_json(args.output / "training_report.json", report)
    return report


def train_model(input_path: Path, model_output: Path, references_dir: Path,
                contamination: float | str = "auto", n_estimators: int = 200,
                f7_mode: str = "paper", seed: int = 42, *, output_dir: Path | None = None,
                processed_output: Path | None = None, skip_invalid: bool = False,
                assume_event_id1: bool = False, binary_dir: Path | None = None) -> dict:
    """Fit the complete 44-feature pipeline on real signature-eligible pairs.

    Rejects synthetic fixtures, duplicate executions and held-out overlap. Writes
    model, numeric features, aligned metadata and a training report. Unsupervised
    fitting does not assign unknown labels or require 60,000 background pairs.
    """
    return run(argparse.Namespace(command="train", input=[Path(input_path)], model=Path(model_output),
        references=Path(references_dir), contamination=contamination, n_estimators=n_estimators,
        f7_mode=f7_mode, seed=seed, output=Path(output_dir) if output_dir is not None else ROOT / "reports/train",
        processed_output=Path(processed_output) if processed_output is not None else ROOT / "data/processed/train",
        skip_invalid=skip_invalid, assume_event_id1=assume_event_id1, binary_dir=binary_dir))


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="Train the IsolationForest LOLBin detector on real process pairs")
    add_arguments(cli, "train")
    return cli


def main(argv: list[str] | None = None) -> int:
    return execute(run, parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
