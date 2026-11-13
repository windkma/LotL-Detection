"""Fail-closed provenance checks for production training and benchmark exports."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Mapping


def reject_fixture_path(path: str | Path) -> None:
    path = Path(path).resolve()
    parts = {part.lower() for part in path.parts}
    if "fixtures" in parts:
        raise ValueError(f"Synthetic fixture paths are forbidden in production data: {path}")


def reject_synthetic_record(record: Mapping[str, Any]) -> None:
    fields = {str(k).lower().replace("_", ""): str(v).lower() for k, v in record.items()}
    for name in ("computer", "hostname", "datasetid", "sourcerepo", "sourcetype"):
        if fields.get(name, "").startswith(("synthetic", "fixture", "mock")):
            raise ValueError(f"Synthetic provenance is forbidden: {name}={fields[name]}")
    if fields.get("issynthetic") in {"true", "1", "yes"}:
        raise ValueError("Synthetic records are forbidden")


def assert_real_pair(pair: Any) -> None:
    for process in (pair.parent, pair.child):
        reject_synthetic_record({**process.metadata, "Computer": process.computer, "DatasetId": process.dataset_id})
        if process.source not in {"", "memory"}:
            reject_fixture_path(process.source)
