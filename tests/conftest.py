"""Reusable explicitly synthetic Sysmon metadata and historical process pairs."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.data_loader import ProcessPair, ProcessRecord
from src.enricher import ReferenceDatabase
from src.features import FeatureExtractor


@pytest.fixture
def test_dataset() -> Path:
    return Path(__file__).resolve().parents[1] / "data/processed/test.csv"


@pytest.fixture
def references() -> ReferenceDatabase:
    return ReferenceDatabase(Path(__file__).resolve().parents[1] / "data" / "external")


@pytest.fixture
def history() -> list[ProcessPair]:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    parent = ProcessRecord(process_guid="parent", computer="training", utc_time=base,
                           image=r"C:\Windows\explorer.exe", command_line="explorer.exe",
                           original_file_name="explorer.exe", integrity_level="Medium",
                           signer="Microsoft Corporation", signature_valid=True)
    return [ProcessPair(parent, ProcessRecord(
        process_guid=f"child-{i}", parent_process_guid="parent", computer="training",
        utc_time=base + timedelta(seconds=i + 1), image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c echo hello" + (" /q" if i % 5 else ""),
        original_file_name="Cmd.Exe", integrity_level="Medium", signer="Microsoft Windows",
        signature_valid=True)) for i in range(120)]


@pytest.fixture
def extractor(references: ReferenceDatabase, history: list[ProcessPair]) -> FeatureExtractor:
    return FeatureExtractor(references, f7_mode="statistical").fit(history)


@pytest.fixture
def unseen(history: list[ProcessPair]) -> list[ProcessPair]:
    return [replace(pair, parent=replace(pair.parent, computer="heldout"),
                    child=replace(pair.child, computer="heldout", label=1)) for pair in history[:8]]
