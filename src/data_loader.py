"""Normalize Sysmon/EDR exports and join host-scoped parent/child identities.

Parsing never executes recorded commands. JSON arrays, JSON Lines, Splunk results,
Winlogbeat event_data, XML (including namespaces), CSV and native EVTX are accepted.
Parent timestamps remain missing when only inline ParentImage/ParentCommandLine
are available; inventing a parent creation time would corrupt F23.
"""

from __future__ import annotations

import csv
import gzip
from bisect import bisect_right
import json
import ntpath
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from defusedxml import ElementTree as ET


def text(value: Any) -> str:
    """Return scalar export data as text, treating missing/NaN values as empty."""
    if value is None or str(value).strip().lower() in {"nan", "none", "null", "-"}:
        return ""
    if isinstance(value, dict):
        return text(value.get("#text", value.get("text", value.get("Value"))))
    return str(value).strip()


def key(value: str) -> str:
    """Normalize field spelling without relying on ambiguous substring matches."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def pid(value: Any) -> str:
    """Normalize decimal/hex Windows PID representations."""
    value = text(value)
    if not value:
        return ""
    try:
        return str(int(value, 16) if value.lower().startswith("0x") else int(value))
    except ValueError:
        raise ValueError(f"Invalid Windows process ID: {value}")


def normalize_event(record: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical fields for Sysmon 1 and Security-Auditing 4688; no trust inference."""
    fields = _flatten(record)
    event_id = text(fields.get("eventid", fields.get("eventcode", "")))
    if event_id == "4688" and ("newprocessid" in fields or "newprocessname" in fields):
        provider = text(fields.get("sourcename", fields.get("providername", ""))).lower()
        if provider and "security" not in provider:
            return {"eventid": "unsupported"}
        original = dict(fields)
        fields["image"] = original.get("newprocessname", original.get("image", ""))
        fields["processid"] = original.get("newprocessid", "")
        fields["parentprocessid"] = original.get("creatorprocessid", original.get("processid", ""))
        fields["parentimage"] = original.get("parentprocessname", original.get("creatorprocessname", ""))
        fields["utctime"] = original.get("utctime", original.get("systemtime", original.get("eventtime", "")))
        levels = {"S-1-16-0": "Untrusted", "S-1-16-4096": "Low", "S-1-16-8192": "Medium", "S-1-16-12288": "High", "S-1-16-16384": "System", "S-1-16-20480": "Installer"}
        fields["integritylevel"] = levels.get(text(original.get("mandatorylabel")), original.get("integritylevel", ""))
    return fields


def timestamp(value: Any) -> datetime | None:
    """Parse ISO/Sysmon timestamps, interpreting naive Sysmon timestamps as UTC."""
    value = text(value)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid process timestamp: {value!r}") from exc
    return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed).astimezone(timezone.utc)


def boolean(value: Any) -> bool | None:
    """Decode explicit signature flags; missing or unfamiliar values stay unknown."""
    value = text(value).lower()
    if value in {"true", "1", "yes", "valid", "trusted"}:
        return True
    if value in {"false", "0", "no", "invalid", "unsigned", "expired", "untrusted", "notsigned", "hashmismatch", "nottrusted"}:
        return False
    return None


def parse_label(value: Any) -> int | None:
    """Decode ground truth using -1=malicious, +1=benign (never infer labels)."""
    value = text(value).lower()
    if not value:
        return None
    if value in {"-1", "-1.0", "malicious", "anomaly", "anomalous", "attack", "lolbin"}:
        return -1
    if value in {"1", "+1", "1.0", "benign", "normal", "inlier"}:
        return 1
    raise ValueError(f"Unknown label {value!r}; use -1/malicious or 1/benign")


def sha256(value: Any) -> str:
    """Extract SHA256 from a bare hash, a Sysmon Hashes string, or a mapping."""
    if isinstance(value, Mapping):
        value = next((v for k, v in value.items() if key(k) == "sha256"), "")
    value = text(value)
    match = re.search(r"(?:SHA256\s*=\s*)?\b([0-9a-fA-F]{64})\b", value)
    return match.group(1).lower() if match else ""


@dataclass(frozen=True)
class ProcessRecord:
    """One process with explicitly observed identity, PE and signature metadata.

    signature_valid refers to validity of the signature; signer is the certificate
    subject, not the PE CompanyName. Neither Image nor CompanyName proves trust.
    """

    process_guid: str = ""
    parent_process_guid: str = ""
    utc_time: datetime | None = None
    image: str = ""
    command_line: str = ""
    integrity_level: str = ""
    sha256: str = ""
    original_file_name: str = ""
    signer: str = ""
    signature_valid: bool | None = None
    computer: str = ""
    label: int | None = None
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)
    dataset_id: str = ""
    process_id: str = ""
    parent_process_id: str = ""

    @property
    def binary_name(self) -> str:
        """Case-insensitive Windows executable basename, independent of host OS."""
        return ntpath.basename(self.image).lower()

    @property
    def microsoft_signed(self) -> bool:
        """Require an explicit valid signature and Microsoft certificate subject."""
        subject = self.signer.strip().lower()
        names = {"microsoft corporation", "microsoft windows", "microsoft windows publisher", "microsoft windows hardware compatibility publisher"}
        attributes = {k.strip(): v.strip() for k, v in re.findall(r"(?:^|[,;])\s*(cn|o)\s*=\s*([^,;]+)", subject)}
        microsoft = (attributes["o"] == "microsoft corporation" if "o" in attributes
                     else attributes.get("cn", subject) in names)
        return self.signature_valid is True and microsoft


@dataclass(frozen=True)
class ProcessPair:
    """Joined processes; label is the child's ground truth, when provided."""

    parent: ProcessRecord
    child: ProcessRecord
    inline_parent: bool = False

    @property
    def time_diff(self) -> float | None:
        """Real creation delta in seconds, or None if either timestamp is absent."""
        if self.parent.utc_time is None or self.child.utc_time is None:
            return None
        return (self.child.utc_time - self.parent.utc_time).total_seconds()

    @property
    def label(self) -> int | None:
        return self.child.label

    @property
    def eligible(self) -> bool:
        return self.parent.microsoft_signed or self.child.microsoft_signed


def _flatten(record: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten common Event/System/EventData wrappers and retain named Data fields."""
    result: dict[str, Any] = {}

    def visit(value: Any, prefix: str = "", role: str = "") -> None:
        if isinstance(value, Mapping):
            if ("@Name" in value or "Name" in value) and any(k in value for k in ("#text", "Value")):
                result[key(role + str(value.get("@Name", value.get("Name"))))] = value.get("#text", value.get("Value"))
                return
            for name, item in value.items():
                if key(name) == "provider" and isinstance(item, Mapping):
                    result["providername"] = item.get("@Name", item.get("Name", item.get("name", "")))
                elif key(name) == "host" and isinstance(item, Mapping):
                    result["computer"] = item.get("name", item.get("hostname", ""))
                    visit(item, prefix + name + ".", role)
                elif isinstance(item, Mapping) and ("#text" in item or "text" in item):
                    result[key(role + name)] = text(item)
                elif isinstance(item, (Mapping, list)):
                    visit(item, prefix + name + ".", "Parent" if key(name) in {"parent", "parentprocess"} else role)
                else:
                    result[key(role + name)] = item
                    result[key(prefix + name)] = item
        elif isinstance(value, list):
            for item in value:
                visit(item, prefix, role)

    visit(record)
    return result


class DataLoader:
    """Load several log files before joining parents, including across file boundaries.

    Event ID must be 1 unless assume_event_id1 is explicitly selected for a
    process-only EDR export. Invalid records fail with source context by default;
    strict=False counts and skips them in stats instead.
    """

    SUPPORTED = {".xml", ".json", ".jsonl", ".ndjson", ".csv", ".evtx", ".gz"}

    def __init__(self, *, assume_event_id1: bool = False, strict: bool = True, production: bool = False) -> None:
        self.assume_event_id1 = assume_event_id1
        self.strict = strict
        self.production = production
        self.stats: dict[str, int] = {}

    @staticmethod
    def _xml_record(element: Any) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for node in element.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "Data" and node.get("Name"):
                values[node.get("Name")] = node.text or ""
            elif tag in {"EventID", "Computer"}:
                values[tag] = node.text
            elif tag == "Provider":
                values["ProviderName"] = node.get("Name", "")
            elif tag == "TimeCreated":
                values["SystemTime"] = node.get("SystemTime", "")
        return values

    def _json_records(self, content: Any) -> Iterator[dict[str, Any]]:
        if isinstance(content, list):
            for record in content:
                yield from self._json_records(record)
        elif isinstance(content, dict):
            for wrapper in ("results", "records", "events"):
                if isinstance(content.get(wrapper), list):
                    yield from self._json_records(content[wrapper])
                    return
            if isinstance(content.get("result"), dict):
                yield from self._json_records(content["result"])
            elif isinstance(content.get("_raw"), str):
                raw = content["_raw"].strip()
                if raw.startswith("<"):
                    yield {**content, **self._xml_record(ET.fromstring(raw))}
                elif raw.startswith("{"):
                    yield {**content, **json.loads(raw)}
                else:
                    yield content
            else:
                yield content
        else:
            raise ValueError("Expected a JSON object or array of objects")

    def _read(self, path: Path) -> Iterator[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv" or path.name.endswith(".csv.gz"):
            csv.field_size_limit(64 * 1024 * 1024)
            opener = gzip.open if suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
                for record in csv.DictReader(stream):
                    yield from self._json_records(record)
        elif suffix == ".xml":
            for _, element in ET.iterparse(str(path), events=("end",)):
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    yield self._xml_record(element)
                    element.clear()
        elif suffix in {".jsonl", ".ndjson"}:
            with path.open(encoding="utf-8-sig") as stream:
                for number, line in enumerate(stream, 1):
                    if line.strip():
                        try:
                            yield from self._json_records(json.loads(line))
                        except ValueError as exc:
                            raise ValueError(f"{path}:{number}: {exc}") from exc
        elif suffix == ".json":
            with path.open(encoding="utf-8-sig") as stream:
                yield from self._json_records(json.load(stream))
        elif suffix == ".evtx":
            try:
                from Evtx.Evtx import Evtx
            except ImportError as exc:
                raise RuntimeError("Install python-evtx to read native EVTX") from exc
            with Evtx(str(path)) as log:
                for record in log.records():
                    yield self._xml_record(ET.fromstring(record.xml()))
        else:
            raise ValueError(f"Unsupported log format: {path}")

    @staticmethod
    def _process(fields: Mapping[str, Any], source: str, prefix: str = "") -> ProcessRecord:
        def get(*names: str) -> Any:
            return next((fields[key(prefix + name)] for name in names if text(fields.get(key(prefix + name)))), "")

        valid = boolean(get("SignatureValid", "SignatureStatus"))
        signed = boolean(get("Signed"))
        if signed is False:
            valid = False
        return ProcessRecord(
            process_guid=text(get("ProcessGuid")).lower(),
            parent_process_guid=text(get("ParentProcessGuid")).lower() if not prefix else "",
            utc_time=timestamp(get("UtcTime", "CreationUtcTime", "SystemTime")),
            image=text(get("Image", "ProcessImage", "ProcessPath")),
            command_line=text(get("CommandLine")),
            integrity_level=text(get("IntegrityLevel", "ProcessIntegrityLevel")),
            sha256=sha256(get("SHA256", "Hashes")),
            original_file_name=text(get("OriginalFileName")),
            signer=text(get("Signer", "Signature", "SignatureSubject")),
            signature_valid=valid,
            computer=text(fields.get("computer", fields.get("computername", fields.get("hostname", fields.get("host", ""))))).lower(),
            label=parse_label(get("Label", "GroundTruth")) if not prefix else None,
            source=source,
            metadata=dict(fields),
            dataset_id=text(fields.get("datasetid", "")),
            process_id=pid(get("ProcessId")),
            parent_process_id=pid(get("ParentProcessId")),
        )

    def load_records(self, records: Iterable[Mapping[str, Any]], *, source: str = "memory") -> list[ProcessPair]:
        """Parse dictionaries directly (e.g. pre-parsed EVTX or DataFrame records)."""
        return self._pair((record, source) for record in records)

    def load(self, paths: str | Path | Iterable[str | Path]) -> list[ProcessPair]:
        """Read one file, several files, or directories recursively and pair events."""
        entries = [paths] if isinstance(paths, (str, Path)) else list(paths)
        files: list[Path] = []
        for entry in entries:
            path = Path(entry)
            if self.production:
                from .pipeline.data_policy import reject_fixture_path
                reject_fixture_path(path)
            if not path.exists():
                raise FileNotFoundError(path)
            files.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() in self.SUPPORTED) if path.is_dir() else [path])
        return self._pair((r, str(p)) for p in dict.fromkeys(files) for r in self._read(p))

    def _pair(self, rows: Iterable[tuple[Mapping[str, Any], str]]) -> list[ProcessPair]:
        self.stats = {k: 0 for k in ("records", "filtered_events", "invalid_records", "duplicate_events", "missing_parents", "inline_parents", "negative_deltas", "pairs")}
        processes: dict[tuple[str, str, str], ProcessRecord] = {}
        events: list[tuple[ProcessRecord, ProcessRecord]] = []
        pid_events: dict[tuple[str, str, str], list[ProcessRecord]] = {}
        for number, (row, source) in enumerate(rows, 1):
            self.stats["records"] += 1
            try:
                fields = normalize_event(row)
                if self.production:
                    from .pipeline.data_policy import reject_synthetic_record
                    reject_synthetic_record(fields)
                event_id = text(fields.get("eventid", fields.get("eventcode", fields.get("winlogeventid", fields.get("eventcode", "")))))
                provider = text(fields.get("providername", fields.get("winlogprovidername", "")))
                if (not event_id and not self.assume_event_id1) or (event_id and event_id not in {"1", "1.0", "4688"}) or (provider and event_id != "4688" and "sysmon" not in provider.lower()):
                    self.stats["filtered_events"] += 1
                    continue
                child = self._process(fields, source)
                inline = self._process(fields, source, "Parent")
                if not child.image or not child.command_line:
                    raise ValueError("Process Creation requires nonempty Image and CommandLine")
                if not child.process_guid and not child.process_id and not (inline.image or inline.command_line):
                    raise ValueError("ProcessGuid is absent and no inline parent is available")
                identity = (child.dataset_id, child.computer, child.process_guid)
                if child.process_guid and identity in processes:
                    if child != processes[identity]:
                        # source/ground truth can differ in overlapping exports.
                        previous = processes[identity]
                        if (child.image.lower(), child.command_line, child.utc_time, child.parent_process_guid) != (previous.image.lower(), previous.command_line, previous.utc_time, previous.parent_process_guid):
                            raise ValueError(f"Conflicting ProcessGuid on host {identity}")
                    self.stats["duplicate_events"] += 1
                    continue
                if child.process_guid:
                    processes[identity] = child
                events.append((child, inline))
                if child.process_id and child.utc_time:
                    pid_events.setdefault((child.dataset_id, child.computer, child.process_id), []).append(child)
            except (ValueError, TypeError) as exc:
                self.stats["invalid_records"] += 1
                if self.strict or self.production and "Synthetic" in str(exc):
                    raise ValueError(f"{source}, record {number}: {exc}") from exc
        for history in pid_events.values():
            history.sort(key=lambda record: record.utc_time)
        pid_times = {scope: [record.utc_time for record in history] for scope, history in pid_events.items()}
        pairs: list[ProcessPair] = []
        for child, inline in events:
            parent = processes.get((child.dataset_id, child.computer, child.parent_process_guid)) if child.parent_process_guid else None
            if parent is None and not child.parent_process_guid and child.parent_process_id and child.utc_time:
                scope = (child.dataset_id, child.computer, child.parent_process_id)
                history = pid_events.get(scope, [])
                index = bisect_right(pid_times.get(scope, []), child.utc_time) - 1
                if index >= 0 and history[index] is child:
                    index -= 1
                if index >= 0:
                    parent = history[index]
            inline_parent = parent is None
            if parent is child:
                self.stats["invalid_records"] += 1
                continue
            if parent is None:
                if not (inline.image or inline.command_line):
                    self.stats["missing_parents"] += 1
                    continue
                parent = replace(inline, process_guid=child.parent_process_guid)
                self.stats["inline_parents"] += 1
            else:
                # Fill missing fields only; the actual parent event takes precedence.
                updates = {name: getattr(inline, name) for name in ("image", "command_line", "integrity_level", "sha256", "original_file_name", "signer", "signature_valid", "utc_time") if getattr(parent, name) in ("", None) and getattr(inline, name) not in ("", None)}
                parent = replace(parent, **updates)
            pair = ProcessPair(parent, child, inline_parent=inline_parent)
            if pair.time_diff is not None and pair.time_diff < 0:
                self.stats["negative_deltas"] += 1
                continue
            pairs.append(pair)
        self.stats["pairs"] = len(pairs)
        return pairs
