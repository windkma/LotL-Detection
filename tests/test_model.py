"""IsolationForest, persistence, metrics and CLI integration checks."""

from dataclasses import replace
import numpy as np
import pytest
from src.evaluate import Evaluator
from src.model import LOLBinDetector
import json
import subprocess
import sys
from pathlib import Path
import pandas as pd


def test_models_and_reload(tmp_path, references, history, unseen):
    detector = LOLBinDetector(references, contamination=0.1).fit(history)
    from sklearn.ensemble import IsolationForest
    assert isinstance(detector.model.pipeline.named_steps["estimator"], IsolationForest)
    before, features, report = detector.predict(unseen)
    model_path = tmp_path / "model.joblib"
    detector.save(model_path)
    loaded = LOLBinDetector.load(model_path)
    after, reloaded_features, _ = loaded.predict(unseen)
    np.testing.assert_array_equal(before["prediction"], after["prediction"])
    np.testing.assert_allclose(before["anomaly_score"], after["anomaly_score"], rtol=0, atol=0)
    np.testing.assert_array_equal(features.to_numpy(), reloaded_features.to_numpy())
    assert set(before["prediction"]) <= {-1, 1} and report["eligible_pairs"] == len(unseen)
    assert detector.model.pipeline.named_steps["scaler"].with_mean
    detector.assert_disjoint(unseen)
    with pytest.raises(ValueError, match="overlaps training"):
        detector.assert_disjoint(history)
    training_predictions, training_scores = detector.model.training_outputs()
    assert len(training_predictions) == len(history) and np.isfinite(training_scores).all()


def test_filter_and_missing_labels_remain_visible(references, history, unseen):
    detector = LOLBinDetector(references).fit(history)
    pair = unseen[0]
    excluded = replace(pair, parent=replace(pair.parent, signature_valid=None), child=replace(pair.child, signature_valid=None, label=None))
    results, features, report = detector.predict([excluded])
    assert results["prediction"].isna().all() and results["label"].isna().all()
    assert results["status"].tolist() == ["skipped_signature_evidence"]
    assert features.shape == (0, 44) and report["excluded_signature_pairs"] == 1
    with pytest.raises(ValueError, match="signature evidence"):
        LOLBinDetector(references).fit([excluded])


def test_metrics_anomaly_is_positive():
    result = Evaluator().evaluate([-1, -1, 1, 1, None, -1], [-1, 1, -1, 1, -1, None])
    assert (result.true_positives, result.false_positives, result.true_negatives, result.false_negatives) == (1, 1, 1, 1)
    assert result.precision == result.recall == result.f1_score == result.false_positive_rate == 0.5
    assert result.excluded_samples == 2
    assert Evaluator().evaluate([-1], [-1]).false_positive_rate is None
    with pytest.raises(ValueError, match="No labeled"):
        Evaluator().evaluate([None], [1])


def test_fit_ignores_ground_truth(references, history, unseen):
    a = LOLBinDetector(references, random_state=42).fit(history)
    b = LOLBinDetector(references, random_state=42).fit([replace(pair, child=replace(pair.child, label=-1)) for pair in history])
    np.testing.assert_array_equal(a.predict(unseen)[1], b.predict(unseen)[1])


def test_rejects_legacy_artifact(tmp_path, references, history):
    detector = LOLBinDetector(references).fit(history)
    detector.artifact_version = 1
    artifact = tmp_path / "legacy.joblib"
    detector.save(artifact)
    with pytest.raises(ValueError, match="Unsupported"):
        LOLBinDetector.load(artifact)


def test_cli_exposes_only_isolation_forest_options():
    from main import parser
    cli = parser()
    with pytest.raises(SystemExit):
        cli.parse_args(["train", "--input", "log.csv", "--algorithm", "other"])


def test_complete_cli_pipeline(tmp_path, history, references):
    root = Path(__file__).resolve().parents[1]
    model = tmp_path / "detector.joblib"
    # Model smoke tests may use fixtures in isolated temp storage; production train may not.
    training = [replace(pair, parent=replace(pair.parent, command_line="pytest_training_parent.exe")) for pair in history]
    LOLBinDetector(references).fit(training).save(model)
    for command, filename in [("predict", "test.csv"), ("evaluate", "test.jsonl")]:
        result = subprocess.run([sys.executable, str(root / "main.py"), command,
                                 "--input", str(root / "data" / "processed" / filename),
                                 "--model", str(model), "--output", str(tmp_path / command),
                                 "--processed-output", str(tmp_path / "processed")],
                                capture_output=True, text=True, encoding="utf-8", timeout=120)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["coverage"]["excluded_signature_pairs"] == 1
        assert report["label_kind"] == "synthetic_fixture"
        if command == "evaluate":
            assert "| Precision | Recall | F1 |" in result.stderr
    metrics = json.loads((tmp_path / "evaluate" / "report.json").read_text())["metrics"]
    assert metrics["evaluated_samples"] == 24 and metrics["excluded_samples"] == 2
    predictions = pd.read_csv(tmp_path / "evaluate" / "predictions.csv")
    features = pd.read_csv(tmp_path / "evaluate" / "features.csv")
    assert len(predictions) == 26 and features.shape == (25, 45)
    assert pd.read_csv(tmp_path / "processed" / "predict_features.csv").shape == (25, 44)


def test_default_storage_layout():
    from main import parser, ROOT
    args = parser().parse_args(["train"])
    assert args.input == [ROOT / "data/processed/train_baseline.csv.gz"]
    assert parser().parse_args(["evaluate"]).input == [ROOT / "data/processed/test.csv"]
    assert parser().parse_args(["ingest"]).manifest == ROOT / "data/raw/manifest.json"
    assert args.model == ROOT / "models" / "detector.joblib"
    assert args.processed_output == ROOT / "data" / "processed"
    assert args.output == ROOT / "reports" / "train"


def test_training_api_rejects_synthetic_input(tmp_path, test_dataset):
    from src.train import train_model
    root = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="Synthetic"):
        train_model(test_dataset, tmp_path / "model.joblib",
                    root / "data/external", output_dir=tmp_path / "reports",
                    processed_output=tmp_path / "processed")
    assert not (tmp_path / "model.joblib").exists()


def test_evaluation_api_and_standalone_cli_agree(tmp_path, references, history, unseen):
    import csv
    from src.evaluate import evaluate_model
    from src.pipeline.pair_schema import pair_row
    model_path = tmp_path / "model.joblib"
    LOLBinDetector(references).fit(history).save(model_path)
    records = [pair_row(pair) for pair in unseen]
    input_path = tmp_path / "unseen.csv"
    with input_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    api = evaluate_model(input_path, model_path, tmp_path / "api", processed_output=tmp_path / "api_features")
    result = subprocess.run([sys.executable, "-B", "-m", "src.evaluate", "--input", str(input_path),
                             "--model", str(model_path), "--output", str(tmp_path / "cli"),
                             "--processed-output", str(tmp_path / "cli_features")],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["metrics"] == api["metrics"]
    assert api["metrics"]["evaluated_samples"] == len(unseen)
    assert (tmp_path / "api/evaluation.md").exists()


@pytest.mark.parametrize("command", ["train", "evaluate"])
def test_legacy_dispatch_calls_dedicated_entrypoint(monkeypatch, command):
    import main as dispatcher
    module = getattr(dispatcher, command)
    received = []
    def entrypoint(argv):
        received.append(argv)
        return 0
    monkeypatch.setattr(module, "main", entrypoint)
    assert dispatcher.main([command, "--input", "existing.csv"]) == 0
    assert received == [["--input", "existing.csv"]]
