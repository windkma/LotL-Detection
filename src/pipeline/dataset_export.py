"""Parse immutable telemetry and export final eligible process-pair datasets."""
from __future__ import annotations

import io
import gzip
import json
import zipfile
from itertools import chain
from defusedxml import ElementTree as ET
from pathlib import Path
from typing import Iterator

from ..data_loader import DataLoader

def json_records(stream):
    """Accept JSONL, formatted JSON arrays, and single JSON objects."""
    position = stream.tell()
    head = stream.read(4096)
    stream.seek(position)
    if head.lstrip().startswith("["):
        import ijson
        binary = stream.buffer if hasattr(stream, "buffer") else io.BytesIO(stream.read().encode("utf-8"))
        yield from ijson.items(binary, "item", use_float=True)
        return
    first = stream.readline()
    if not first:
        return
    if first.lstrip().startswith("<"):
        buffer = ""
        for line in chain([first], stream):
            buffer += line
            while "</Event>" in buffer:
                event, buffer = buffer.split("</Event>", 1)
                yield DataLoader._xml_record(ET.fromstring(event + "</Event>"))
        if buffer.strip():
            yield DataLoader._xml_record(ET.fromstring(buffer))
        return
    if not first.strip():
        yield from json_records(stream)
        return
    try:
        record = json.loads(first)
    except ValueError:
        stream.seek(position)
        content = json.load(stream)
        yield from content if isinstance(content, list) else [content]
        return
    yield from record if isinstance(record, list) else [record]
    for line in stream:
        if line.strip():
            yield json.loads(line)

def records(path: Path) -> Iterator[tuple[str, dict, str]]:
    """Read JSON/XML/EVTX without executing or extracting arbitrary archive members."""
    if path.suffix.lower() == ".evtx":
        from Evtx.Evtx import Evtx
        from defusedxml import ElementTree as ET
        with Evtx(str(path)) as log:
            for record in log.records():
                raw = record.xml()
                yield "", DataLoader._xml_record(ET.fromstring(raw)), raw
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if Path(member.filename).suffix.lower() not in {".json", ".jsonl", ".log"}:
                    continue
                with archive.open(member) as binary, io.TextIOWrapper(binary, encoding="utf-8-sig") as stream:
                    for record in json_records(stream):
                        yield member.filename, record, json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    else:
        if path.suffix.lower() == ".gz":
            with gzip.open(path, "rt", encoding="utf-8-sig") as stream:
                for record in json_records(stream):
                    # Splunk JSON wrappers contain the actual XML/JSON event in _raw.
                    for event in DataLoader()._json_records(record):
                        yield "", event, json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            return
        with path.open(encoding="utf-8-sig") as stream:
            start = stream.tell()
            first = stream.readline()
            stream.seek(start)
            if first.lstrip().startswith("<"):
                from defusedxml import ElementTree as ET
                buffer = ""
                for line in stream:
                    buffer += line
                    while "</Event>" in buffer:
                        event, buffer = buffer.split("</Event>", 1)
                        raw = event + "</Event>"
                        yield "", DataLoader._xml_record(ET.fromstring(raw)), raw
                if buffer.strip():
                    raise ValueError(f"Truncated XML event in {path}")
                return
            for record in json_records(stream):
                yield "", record, json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def export_csv(manifest_path: Path, project: Path, *, chunksize: int = 100000) -> dict:
    """Compatibility entry point for direct raw-to-processed training export."""
    from .ingestion import ingest_manifest
    return ingest_manifest(manifest_path, project, chunksize=chunksize)
