"""Essential ingestion, disk joins, normalization, provenance and download checks."""

import csv
import json
import pytest
from src.data_loader import DataLoader, ProcessRecord, timestamp
import gzip
import hashlib
from pathlib import Path
from src.pipeline.ingestion import iter_manifest_pairs, ingest_manifest
from src.pipeline.dataset_export import export_csv
from src.pipeline.dataset_export import records
import io
import zipfile
from src.pipeline.dataset_export import json_records
from download_datasets import DatasetDownloader, SOURCES
from src.enricher import ReferenceDatabase


def event(guid="c", parent="p", **updates):
    return {"EventID": 1, "ProcessGuid": guid, "ParentProcessGuid": parent,
            "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c echo hi",
            "UtcTime": "2024-01-01 00:00:05.1234567", "Computer": "pc", **updates}


def test_parent_pairing_out_of_order_and_host_scope():
    rows = [event(), event("p", "", UtcTime="2024-01-01 00:00:00.1234567"),
            event("p", "", Computer="other", UtcTime="2024-01-01 00:00:03")]
    pairs = DataLoader().load_records(rows)
    assert len(pairs) == 1
    assert pairs[0].time_diff == 5
    assert pairs[0].parent.computer == "pc"
    assert not pairs[0].inline_parent


def test_inline_parent_does_not_invent_timestamp():
    pair = DataLoader().load_records([event(ParentImage=r"C:\Windows\explorer.exe", ParentCommandLine="explorer.exe")])[0]
    assert pair.time_diff is None and pair.inline_parent


def test_event_filter_and_explicit_process_only_override():
    loader = DataLoader()
    rows = [event(EventID=3, ParentImage="parent.exe"), event(EventID="", ParentImage="parent.exe")]
    assert loader.load_records(rows) == []
    assert loader.stats["filtered_events"] == 2
    assert len(DataLoader(assume_event_id1=True).load_records(rows)) == 1


@pytest.mark.parametrize("extension", ["json", "jsonl", "csv", "xml"])
def test_formats(tmp_path, extension):
    rows = [event("p", "", UtcTime="2024-01-01T00:00:00Z"), event(Hashes="SHA256=" + "ab" * 32)]
    path = tmp_path / ("log." + extension)
    if extension == "json":
        path.write_text(json.dumps({"results": rows}), encoding="utf-8")
    elif extension == "jsonl":
        path.write_text("\n".join(json.dumps({"result": row}) for row in rows), encoding="utf-8")
    elif extension == "csv":
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(r.keys() for r in rows))))
            writer.writeheader()
            writer.writerows(rows)
    else:
        from xml.sax.saxutils import escape
        events = []
        for row in rows:
            data = "".join(f'<Data Name="{k}">{escape(str(v))}</Data>' for k, v in row.items() if k not in {"EventID", "Computer"})
            events.append(f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><Computer>pc</Computer></System><EventData>{data}</EventData></Event>')
        path.write_text("<Events>" + "".join(events) + "</Events>", encoding="utf-8")
    pairs = DataLoader().load(path)
    assert len(pairs) == 1
    assert pairs[0].child.sha256 == "ab" * 32


def test_nested_dict_evtx_and_winlogbeat():
    row = {"Event": {"System": {"EventID": {"#text": "1"}, "Computer": "pc"}, "EventData": {"Data": [
        {"@Name": k, "#text": str(v)} for k, v in event(ParentImage="parent.exe").items() if k not in {"EventID", "Computer"}]}}}
    assert len(DataLoader().load_records([row])) == 1
    row = {"winlog": {"event_id": 1, "computer_name": "pc", "event_data": event(ParentImage="parent.exe")}}
    assert len(DataLoader().load_records([row])) == 1


def test_winlogbeat_host_and_nested_parent_are_not_confused():
    row = {"winlog": {"event_id": 1, "computer_name": "actual-host", "event_data": {
        "Image": r"C:\Windows\cmd.exe", "CommandLine": "cmd.exe /c hi", "ProcessGuid": "child",
        "ParentProcessGuid": "parent"}}, "Parent": {"Image": r"C:\Windows\explorer.exe", "CommandLine": "explorer.exe"}}
    pair = DataLoader().load_records([row])[0]
    assert pair.child.computer == "actual-host"
    assert pair.child.command_line == "cmd.exe /c hi"
    assert pair.parent.command_line == "explorer.exe"


def test_nested_non_sysmon_provider_is_filtered():
    row = {"Event": {"System": {"EventID": 1, "Provider": {"@Name": "OtherProvider"}},
                     "EventData": event(ParentImage="parent.exe")}}
    assert DataLoader().load_records([row]) == []


def test_duplicate_and_conflicting_guids():
    row = event(ParentImage="parent.exe")
    loader = DataLoader()
    assert len(loader.load_records([row, row])) == 1
    assert loader.stats["duplicate_events"] == 1
    with pytest.raises(ValueError, match="Conflicting"):
        loader.load_records([row, {**row, "CommandLine": "changed"}])


def test_negative_parent_delta_is_counted():
    loader = DataLoader()
    assert not loader.load_records([event("p", "", UtcTime="2024-01-02"), event()])
    assert loader.stats["negative_deltas"] == 1


def test_signatures_require_observed_validity_and_subject():
    assert ProcessRecord(signer="CN=Microsoft Windows, O=Microsoft Corporation", signature_valid=True).microsoft_signed
    assert not ProcessRecord(signer="Fake Microsoft Corporation Evil", signature_valid=True).microsoft_signed
    assert not ProcessRecord(signer="Microsoft Corporation", signature_valid=None).microsoft_signed
    assert not ProcessRecord(image=r"C:\Windows\cmd.exe").microsoft_signed


def test_strict_error_and_skip_invalid():
    with pytest.raises(ValueError, match="timestamp"):
        DataLoader().load_records([event(UtcTime="bad")])
    loader = DataLoader(strict=False)
    assert loader.load_records([event(UtcTime="bad")]) == []
    assert loader.stats["invalid_records"] == 1
    assert timestamp("2024-01-01T07:00:00+07:00") == timestamp("2024-01-01T00:00:00Z")


def test_merged_datasets_keep_reused_guids_separate():
    loader = DataLoader()
    rows = [event(DatasetId="a", ParentImage="parent-a.exe"),
            event(DatasetId="b", ParentImage="parent-b.exe", CommandLine="cmd.exe /c other")]
    pairs = loader.load_records(rows)
    assert len(pairs) == 2
    assert [p.child.dataset_id for p in pairs] == ["a", "b"]


def test_security_pid_reuse_is_time_and_host_scoped(tmp_path):
    def event(host, new_pid, parent_pid, time, command):
        return {"EventID": 4688, "Computer": host, "NewProcessId": new_pid, "ProcessId": parent_pid,
                "NewProcessName": "C:\\Windows\\cmd.exe", "CommandLine": command, "UtcTime": time}
    rows = [event("a", "0x10", "0x0", "2024-01-01T00:00:00Z", "parent-old"),
            event("b", "0x10", "0x0", "2024-01-01T00:00:00Z", "other-host"),
            event("a", "0x20", "0x10", "2024-01-01T00:00:01Z", "child-old"),
            event("a", "0x10", "0x0", "2024-01-01T00:00:02Z", "parent-new"),
            event("a", "0x21", "0x10", "2024-01-01T00:00:03Z", "child-new")]
    raw = tmp_path / "security.jsonl"
    raw.write_text("\n".join(map(json.dumps, rows)))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"repo": "real/source", "path": str(raw), "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}]}))
    pairs = list(iter_manifest_pairs(manifest, tmp_path, chunksize=1))
    assert [(p.child.command_line, p.parent.command_line) for p in pairs] == [("child-old", "parent-old"), ("child-new", "parent-new")]
    loaded = DataLoader().load_records(rows)
    assert [(p.child.command_line, p.parent.command_line) for p in loaded] == [("child-old", "parent-old"), ("child-new", "parent-new")]


def test_raw_to_final_dataset_preserves_inputs_and_filters_events(tmp_path):
    rows = [event("first", ParentImage="services.exe", ParentCommandLine="services.exe", Signer="Microsoft Windows", SignatureValid=True, Extra="a,b\nquote\""),
            event("second", ParentImage="services.exe", ParentCommandLine="services.exe", Signer="Microsoft Windows", SignatureValid=True),
            {"EventID": 13, "TargetObject": "registry-key"}]
    source = tmp_path / "log.jsonl"
    source.write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"revisions": {}, "items": [{"path": str(source), "repo": "test/repo",
        "source_path": "log.jsonl", "url": "https://example.org/log", "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]}))
    (tmp_path / "data/external").mkdir(parents=True)
    report = export_csv(manifest, tmp_path)
    assert report["sources"][0]["counts"]["records"] == 3
    assert report["sources"][0]["counts"]["process_events"] == 2
    target = tmp_path / "data/processed/train/train_baseline.csv.gz"
    with gzip.open(target, "rt", newline="", encoding="utf-8") as stream:
        exported = list(csv.DictReader(stream))
    assert len(exported) == 2 and exported[0]["EventID"] == "1"
    assert exported[0]["Label"] == ""
    assert source.read_text(encoding="utf-8").splitlines()[0] == json.dumps(rows[0])
    assert {p.name for p in (tmp_path / "data").iterdir()} == {"external", "processed"}
    assert not list(tmp_path.rglob("*.sqlite")) and not list(tmp_path.rglob("*.part"))
    original = target.read_bytes()
    with pytest.raises(FileExistsError):
        export_csv(manifest, tmp_path)
    assert target.read_bytes() == original
    provenance = json.loads((target.parent / "train_baseline_provenance.json").read_text())
    assert provenance["output_sha256"] == hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize("failure", ["checksum", "malformed_json"])
def test_failed_ingestion_cleans_temporary_index_and_partial_output(tmp_path, monkeypatch, failure):
    from functools import partial
    from tempfile import TemporaryDirectory
    from src.pipeline import ingestion
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(ingestion, "TemporaryDirectory", partial(TemporaryDirectory, dir=scratch))
    (tmp_path / "data/external").mkdir(parents=True)
    raw = tmp_path / "log.jsonl"
    raw.write_text("not-json" if failure == "malformed_json" else json.dumps(event()))
    original = raw.read_bytes()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"repo": "test/source", "path": str(raw),
        "sha256": "0" * 64 if failure == "checksum" else hashlib.sha256(original).hexdigest()}]}))
    with pytest.raises(ValueError):
        ingest_manifest(manifest, tmp_path)
    assert raw.read_bytes() == original
    assert not list(scratch.iterdir())
    assert not list((tmp_path / "data/processed").rglob("*.*"))


def test_xml_retains_system_metadata_in_raw_payload(tmp_path):
    source = tmp_path / "log.log"
    xml = '<Event><System><EventID>1</EventID><Level>4</Level></System></Event>'
    source.write_text(xml + xml)
    exported = list(records(source))
    assert len(exported) == 2
    assert exported[0][2] == xml


def test_json_record_formats_and_empty_stream():
    assert list(json_records(io.StringIO(""))) == []
    assert list(json_records(io.StringIO('\n{"a": 1}\n{"a": 2}\n'))) == [{"a": 1}, {"a": 2}]
    assert list(json_records(io.StringIO('[\n {"a": 1}\n]'))) == [{"a": 1}]
    xml = "<Event><System><EventID>1</EventID></System></Event>"
    assert len(list(json_records(io.StringIO(xml + xml)))) == 2


def test_zip_reader_does_not_extract_or_invent_labels(tmp_path):
    archive = tmp_path / "logs.zip"
    rows = [{"EventID": 1, "Image": "cmd.exe", "CommandLine": "cmd.exe /c hello",
             "ProcessGuid": "c", "ParentImage": "explorer.exe"}, {"EventID": 3}]
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../../logs.json", "\n".join(map(json.dumps, rows)))
    result = list(records(archive))
    assert len(result) == 2 and result[0][0] == "../../logs.json"
    assert "Label" not in result[0][1]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["logs.zip"]


def test_actual_xcyclopedia_schema_and_exact_hash_lookup():
    database = ReferenceDatabase()
    digest = "ab" * 32
    database.import_xcyclopedia({"comment": {"author": "strontic"}, "tool-hash": {
        "file_name": "cmd.exe", "hash_sha256": digest, "signature_status": 0,
        "signature_subject": "CN=Microsoft Windows, O=Microsoft Corporation",
        "meta_original_filename": "Cmd.Exe", "output": "Usage: cmd.exe /C /K /Q"}})
    enriched = database.enrich_process(ProcessRecord(sha256=digest))
    assert enriched.microsoft_signed and enriched.original_file_name == "Cmd.Exe"
    assert database.documentation["cmd.exe"] == {"/c", "/k", "/q"}
    assert not database.enrich_process(ProcessRecord(image="cmd.exe", sha256="cd" * 32)).microsoft_signed
    assert database.enrich_process(ProcessRecord(sha256=digest, signature_valid=False)).signature_valid is False


def test_download_size_cap_preserves_existing_file(tmp_path, monkeypatch):
    downloader = DatasetDownloader(tmp_path, tmp_path, max_bytes=4, update=True)
    target = tmp_path / "existing.json"
    target.write_bytes(b"old")

    class Response:
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def raise_for_status(self): pass
        def iter_content(self, _): yield b"oversized"

    monkeypatch.setattr(downloader.session, "get", lambda *a, **k: Response())
    with pytest.raises(ValueError, match="max-gb"):
        downloader.download("https://example.org/catalog", target)
    assert target.read_bytes() == b"old"
    assert not target.with_suffix(".json.part").exists()


def test_zip_reference_import_reads_member_without_extraction(tmp_path, monkeypatch):
    downloader = DatasetDownloader(tmp_path / "datasets", tmp_path / "refs")
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../../outside.json", json.dumps({"tool": {"file_name": "x.exe", "output": "/a"}}))
    lots = tmp_path / "lots.json"
    lots.write_text(json.dumps({"list": ["github.com"]}))
    downloader.references.mkdir()
    monkeypatch.setattr(downloader, "download", lambda url, target: archive if url.endswith(".zip") else lots)
    downloader.fetch_references()
    assert (downloader.references / "xcyclopedia.json").exists()
    assert not (tmp_path / "outside.json").exists()
