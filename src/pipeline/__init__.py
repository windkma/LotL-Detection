"""Data engineering APIs, loaded lazily to avoid parser/enricher import cycles."""
from importlib import import_module

_EXPORTS = {
    "ingest_manifest": "ingestion",
    "build_baseline": "baseline_builder",
    "require_production_training": "baseline_builder",
    "build_benchmarks": "benchmark_builder",
    "validate_benchmark": "benchmark_builder",
    "export_csv": "dataset_export",
    "export_botsv2": "splunk_export",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)
    function = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = function
    return function
