"""Stream immutable raw logs into final datasets, using disposable disk joins."""
from __future__ import annotations
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

from ..data_loader import DataLoader, ProcessPair, normalize_event, text
from .data_policy import reject_fixture_path, reject_synthetic_record
from .pair_schema import pair_row

EVENT_FIELDS = ("DatasetId", "Computer", "EventID", "ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId", "UtcTime", "Image", "CommandLine", "ParentImage", "ParentCommandLine", "IntegrityLevel", "Hashes", "SHA256", "OriginalFileName", "Signer", "SignatureValid", "SignatureStatus", "ParentUtcTime", "ParentIntegrityLevel", "ParentSHA256", "ParentOriginalFileName", "ParentSigner", "ParentSignatureValid", "ParentSignatureStatus", "SourceRepo", "SourcePath", "SourceSHA256", "SourceRecord", "Label", "BackgroundEvidence")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def partition_name(repo: str) -> str:
    """Stable directory names for downloaded source logs."""
    known = {"splunk/botsv1": "splunk_botsv1", "splunk/botsv2": "splunk_botsv2", "splunk/botsv3": "splunk_botsv3", "splunk/attack_data": "splunk_attack_data", "OTRF/Security-Datasets": "otrf_security_datasets", "OTRF/detection-hackathon-apt29": "mitre_attack_evals"}
    return known.get(repo, re.sub(r"[^a-z0-9]+", "_", repo.lower()).strip("_"))


def manifest_project(path: Path) -> Path:
    for parent in path.resolve().parents:
        if parent.name == "raw" and parent.parent.name == "data":
            return parent.parent.parent
    return path.resolve().parent


def iter_manifest_pairs(manifest_path: Path, project: Path | None = None, *, chunksize: int = 100000, catalog: dict | None = None):
    """Verify inputs and link processes by dataset, host and GUID/PID.

    Only Sysmon 1 / Security 4688 are indexed. Each source uses a temporary
    SQLite index, removed on success, failure or generator close. No derived
    event partitions or persistent database are written into the repository.
    """
    if chunksize < 1:
        raise ValueError("chunksize must be positive")
    from .dataset_export import records
    manifest_path = Path(manifest_path)
    project = project or manifest_project(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("errors"):
        raise ValueError("Raw manifest contains unresolved download errors")
    catalog = catalog if catalog is not None else {}
    catalog.update(schema_version=2, chunksize=chunksize, revisions=manifest.get("revisions", {}),
                   manifest_sha256=digest(manifest_path), sources=[])
    groups: dict[str, list] = {}
    for entry in manifest.get("items", manifest.get("sources", [])):
        groups.setdefault(partition_name(entry["repo"]), []).append(entry)
    # Stable source order preserves alignment with existing feature/metadata rows.
    for source, items in sorted(groups.items()):
        stats = {"records": 0, "process_events": 0, "invalid": 0, "duplicates": 0, "pairs": 0, "missing_parent": 0, "negative_delta": 0}
        provenance = []
        catalog["sources"].append({"source": source, "inputs": provenance, "counts": stats})
        with TemporaryDirectory(prefix="lotl-join-") as workspace:
            connection = sqlite3.connect(Path(workspace) / "events.sqlite")
            try:
                connection.execute("CREATE TABLE events (identity TEXT PRIMARY KEY, dataset TEXT, host TEXT, guid TEXT, pid TEXT, created TEXT, payload TEXT)")
                connection.execute("CREATE INDEX guid_lookup ON events(dataset,host,guid)")
                connection.execute("CREATE INDEX pid_lookup ON events(dataset,host,pid,created)")
                for item in items:
                    path = Path(item["path"])
                    path = path if path.is_absolute() else project / path
                    reject_fixture_path(path)
                    actual = digest(path)
                    if actual != item["sha256"]:
                        raise ValueError(f"Checksum mismatch: {path}")
                    source_path = item.get("source_path", item.get("url", str(path)))
                    dataset = item.get("dataset_id") or hashlib.sha256((item["repo"] + ":" + source_path).encode()).hexdigest()[:24]
                    provenance.append({**item, "path": str(path), "sha256": actual, "dataset_id": dataset})
                    for number, (_, raw, _) in enumerate(records(path), 1):
                        stats["records"] += 1
                        if "EventID" in raw and text(raw["EventID"]) not in {"1", "4688"}:
                            continue
                        fields = normalize_event(raw)
                        reject_synthetic_record(fields)
                        event_id = text(fields.get("eventid", fields.get("eventcode", "")))
                        provider = text(fields.get("sourcename", fields.get("providername", "")))
                        if event_id not in {"1", "4688"} or event_id == "1" and provider and "sysmon" not in provider.lower():
                            continue
                        row = {name: fields.get(name.lower(), "") for name in EVENT_FIELDS}
                        row.update(DatasetId=dataset, Computer=text(fields.get("computer", fields.get("hostname", fields.get("host", "")))),
                                   EventID=event_id, SourceRepo=item["repo"], SourcePath=source_path, SourceSHA256=actual, SourceRecord=number,
                                   BackgroundEvidence=item.get("background_evidence", fields.get("backgroundevidence", "")))
                        canonical = normalize_event(row)
                        try:
                            process = DataLoader._process(canonical, str(path))
                            if not process.image or not process.command_line:
                                raise ValueError("Missing Image/CommandLine")
                        except (ValueError, TypeError):
                            stats["invalid"] += 1
                            continue
                        identity = json.dumps([dataset, process.computer, process.process_guid or (process.process_id, str(process.utc_time))])
                        try:
                            connection.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)", (identity, dataset, process.computer, process.process_guid, process.process_id,
                                               process.utc_time.isoformat() if process.utc_time else "", json.dumps(canonical)))
                        except sqlite3.IntegrityError:
                            old = json.loads(connection.execute("SELECT payload FROM events WHERE identity=?", (identity,)).fetchone()[0])
                            if any(old.get(k) != canonical.get(k) for k in ("image", "commandline", "utctime")):
                                raise ValueError(f"Conflicting process identity: {identity}")
                            stats["duplicates"] += 1
                            continue
                        stats["process_events"] += 1
                        if stats["process_events"] % chunksize == 0:
                            connection.commit()
                connection.commit()
                cursor = connection.execute("SELECT identity,payload FROM events ORDER BY rowid")
                while batch := cursor.fetchmany(chunksize):
                    for identity, payload in batch:
                        fields = json.loads(payload)
                        child = DataLoader._process(fields, source)
                        parent_data = None
                        if child.parent_process_guid:
                            parent_data = connection.execute("SELECT payload FROM events WHERE dataset=? AND host=? AND guid=? AND identity!=? LIMIT 1", (child.dataset_id, child.computer, child.parent_process_guid, identity)).fetchone()
                        elif child.parent_process_id and child.utc_time:
                            parent_data = connection.execute("SELECT payload FROM events WHERE dataset=? AND host=? AND pid=? AND created<=? AND created!='' AND identity!=? ORDER BY created DESC LIMIT 1", (child.dataset_id, child.computer, child.parent_process_id, child.utc_time.isoformat(), identity)).fetchone()
                        parent = DataLoader._process(json.loads(parent_data[0]), source) if parent_data else DataLoader._process(fields, source, "Parent")
                        if not parent.image or not parent.command_line:
                            stats["missing_parent"] += 1
                            continue
                        pair = ProcessPair(parent, child, inline_parent=not bool(parent_data))
                        if pair.time_diff is not None and pair.time_diff < 0:
                            stats["negative_delta"] += 1
                            continue
                        stats["pairs"] += 1
                        yield pair
            finally:
                connection.close()


def iter_pair_rows(manifest_path: Path, *, project: Path | None = None, chunksize: int = 100000):
    for pair in iter_manifest_pairs(manifest_path, project, chunksize=chunksize):
        yield pair_row(pair)


def ingest_manifest(manifest_path: Path, project: Path, *, chunksize: int = 100000, output: Path | None = None) -> dict:
    """Build the final eligible training CSV directly from raw telemetry."""
    from .baseline_builder import build_baseline
    from ..enricher import ReferenceDatabase
    return build_baseline(manifest_path, output or project / "data/processed/train_baseline.csv.gz",
                          ReferenceDatabase(project / "data/external"), project / "data/processed/benchmarks",
                          project=project, chunksize=chunksize)
