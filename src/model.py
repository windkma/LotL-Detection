"""Scaled anomaly estimators and an end-to-end, persistable LOLBin detector."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted

from .data_loader import ProcessPair
from .enricher import ReferenceDatabase
from .features import FEATURE_NAMES, FeatureExtractor


def pair_identity(pair: ProcessPair) -> tuple[str, ...] | None:
    """Identify a child across exports when a GUID or creation time is available."""
    child = pair.child
    if child.process_guid:
        return child.dataset_id, child.computer, child.process_guid
    if child.utc_time:
        return child.dataset_id, child.computer, child.utc_time.isoformat(), child.image.lower(), child.command_line
    return None


class AnomalyModel:
    """StandardScaler followed by IsolationForest.

    Positive anomaly_score means suspicious (negative sklearn decision_function).
    """

    def __init__(self, *, contamination: float | str = "auto", random_state: int = 42,
                 n_estimators: int = 200) -> None:
        if contamination != "auto" and not (isinstance(contamination, (int, float)) and 0 < contamination <= 0.5):
            raise ValueError("contamination must be 'auto' or in (0, 0.5]")
        if n_estimators < 1:
            raise ValueError("n_estimators must be >= 1")
        self.algorithm = "isolation_forest"
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.pipeline: Pipeline | None = None
        self._training_decisions: np.ndarray | None = None

    @staticmethod
    def _validate(matrix: Any) -> np.ndarray:
        matrix = np.asarray(matrix, dtype=np.float64)
        if matrix.ndim != 2 or matrix.shape[1] != 44 or not len(matrix) or not np.isfinite(matrix).all():
            raise ValueError("Expected a nonempty finite matrix of shape (n_samples, 44)")
        return matrix

    def fit(self, matrix: Any) -> AnomalyModel:
        matrix = self._validate(matrix)
        if len(matrix) < 2:
            raise ValueError("At least two eligible process pairs are needed for training")
        estimator = IsolationForest(n_estimators=self.n_estimators, contamination=self.contamination,
                                    random_state=self.random_state, n_jobs=-1)
        self.pipeline = Pipeline([("scaler", StandardScaler(with_mean=True, with_std=True)), ("estimator", estimator)])
        self.pipeline.fit(matrix)
        self._training_decisions = self.pipeline.decision_function(matrix)
        return self

    def predict(self, matrix: Any) -> np.ndarray:
        if self.pipeline is None:
            raise RuntimeError("AnomalyModel must be fitted first")
        return self.pipeline.predict(self._validate(matrix)).astype(int)

    def anomaly_score(self, matrix: Any) -> np.ndarray:
        if self.pipeline is None:
            raise RuntimeError("AnomalyModel must be fitted first")
        return -self.pipeline.decision_function(self._validate(matrix))

    def training_outputs(self) -> tuple[np.ndarray, np.ndarray]:
        """Return in-sample predictions and anomaly scores for training diagnostics."""
        if self._training_decisions is None:
            raise RuntimeError("AnomalyModel must be fitted first")
        return np.where(self._training_decisions < 0, -1, 1), -self._training_decisions.copy()


class LOLBinDetector:
    """Own frozen reference catalogs, corpus, embeddings, scaler and classifier.

    Fit consumes the historical corpus without labels, then filters to pairs
    with at least one verified Microsoft-signed process for estimator training.
    Predict preserves every input row, marking ineligible pairs as skipped.
    """

    ARTIFACT_VERSION = 2

    def __init__(self, references: ReferenceDatabase | None = None, *,
                 f7_mode: str = "paper", **model_options: Any) -> None:
        self.references = references if references is not None else ReferenceDatabase()
        self.extractor = FeatureExtractor(self.references, f7_mode=f7_mode)
        self.model = AnomalyModel(**model_options)
        self.training_identities: set[tuple[str, ...]] = set()
        self.training_report: dict[str, Any] = {}
        self.artifact_version = self.ARTIFACT_VERSION
        self.fitted = False

    @staticmethod
    def coverage(pairs: list[ProcessPair]) -> dict[str, int]:
        """Expose missing metadata and signature-filter coverage for audit."""
        return {
            "input_pairs": len(pairs), "eligible_pairs": sum(p.eligible for p in pairs),
            "excluded_signature_pairs": sum(not p.eligible for p in pairs),
            "missing_time_delta_pairs": sum(p.time_diff is None for p in pairs),
            "missing_original_filename_pairs": sum(not p.parent.original_file_name or not p.child.original_file_name for p in pairs),
            "unknown_signature_pairs": sum(p.parent.signature_valid is None or p.child.signature_valid is None for p in pairs),
            "labeled_pairs": sum(p.label is not None for p in pairs),
        }

    def fit(self, pairs: Iterable[ProcessPair]) -> LOLBinDetector:
        pairs = self.references.enrich(pairs)
        eligible = [p for p in pairs if p.eligible]
        if len(eligible) < 2:
            raise ValueError(f"Only {len(eligible)}/{len(pairs)} pairs have verified Microsoft signature evidence; need at least 2. Supply Signer + SignatureValid in logs or data/external/signatures.json keyed by SHA256.")
        self.extractor.fit(pairs)
        matrix = self.extractor.transform(eligible)
        self.model.fit(matrix)
        self.training_identities = {identity for p in pairs if (identity := pair_identity(p)) is not None}
        self.training_report = {
            **self.coverage(pairs), "algorithm": self.model.algorithm, "dimensions": len(FEATURE_NAMES),
            "f7_mode": self.extractor.f7_mode, "fitted_at_utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__,
            "reference_counts": {"documented_binaries": len(self.references.documentation), "lots_domains": len(self.references.lots_domains),
                                 "suspicious_extensions": len(self.references.suspicious_extensions), "hash_metadata": len(self.references.signatures)},
            "corpus": {"programs": len(self.extractor.corpus.execution_counts), "time_min": self.extractor.corpus.time_min,
                       "time_max": self.extractor.corpus.time_max, "character_ratios": self.extractor.corpus.character_ratios.tolist()},
        }
        self.fitted = True
        return self

    def assert_disjoint(self, pairs: Iterable[ProcessPair]) -> None:
        """Reject overlapping child events in evaluation, without comparing labels."""
        overlap = {identity for p in pairs if (identity := pair_identity(p)) in self.training_identities}
        if overlap:
            raise ValueError(f"Evaluation input overlaps training: {len(overlap)} child event(s). Use separate hosts, sessions or time windows.")

    def predict(self, pairs: Iterable[ProcessPair]) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, int]]:
        """Return all-row results, eligible-row features, and metadata coverage.

        Decision values are anomaly scores, not calibrated probabilities.
        """
        if not self.fitted:
            raise RuntimeError("LOLBinDetector must be fitted or loaded first")
        pairs = self.references.enrich(pairs)
        indexes = [index for index, pair in enumerate(pairs) if pair.eligible]
        features = self.extractor.transform(pairs[index] for index in indexes)
        features.index = pd.Index(indexes, name="pair_index")
        predictions = self.model.predict(features) if indexes else []
        scores = self.model.anomaly_score(features) if indexes else []
        inferred = {index: (int(pred), float(score)) for index, pred, score in zip(indexes, predictions, scores)}
        rows = []
        for index, pair in enumerate(pairs):
            prediction, score = inferred.get(index, (None, None))
            rows.append({"pair_index": index, "computer": pair.child.computer,
                         "process_guid": pair.child.process_guid, "parent_process_guid": pair.child.parent_process_guid,
                         "utc_time": pair.child.utc_time.isoformat() if pair.child.utc_time else "",
                         "image": pair.child.image, "command_line": pair.child.command_line,
                         "parent_image": pair.parent.image, "parent_command_line": pair.parent.command_line,
                         "label": pair.label, "prediction": prediction, "anomaly_score": score,
                         "status": "scored" if pair.eligible else "skipped_signature_evidence",
                         "missing_time_delta": pair.time_diff is None,
                         "unknown_parent_signature": pair.parent.signature_valid is None,
                         "unknown_child_signature": pair.child.signature_valid is None,
                         "missing_parent_original_filename": not pair.parent.original_file_name,
                         "missing_child_original_filename": not pair.child.original_file_name})
        result = pd.DataFrame(rows)
        if not result.empty:
            result["prediction"] = pd.array(result["prediction"], dtype="Int64")
            result["label"] = pd.array(result["label"], dtype="Int64")
        return result, features, self.coverage(pairs)

    def save(self, path: str | Path) -> None:
        """Persist the complete fitted system, including native fastText weights."""
        if not self.fitted:
            raise RuntimeError("Cannot save an unfitted detector")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".part")
        joblib.dump(self, temporary, compress=3)
        temporary.replace(path)

    @classmethod
    def load(cls, path: str | Path) -> LOLBinDetector:
        """Load a trusted local joblib artifact (pickle artifacts can execute code)."""
        detector = joblib.load(path)
        if not isinstance(detector, cls) or detector.artifact_version != cls.ARTIFACT_VERSION or not detector.fitted:
            raise ValueError("Unsupported or unfitted detector artifact")
        check_is_fitted(detector.model.pipeline)
        if not isinstance(detector.model.pipeline.named_steps["estimator"], IsolationForest):
            raise ValueError("Artifact must contain IsolationForest; retrain using the current pipeline")
        return detector
