"""Deterministic weak labeling of real process pairs; never independent ground truth."""
from __future__ import annotations
import base64
import csv
import hashlib
import json
import ntpath
import re
from collections import Counter
from pathlib import Path

from ..data_loader import ProcessPair
from ..enricher import ReferenceDatabase, split_command_line
from ..features import ADS_PATTERN
from .benchmark_builder import BENCHMARKS, ALLOWED_SOURCES, TEST_FILENAMES, decode_pair, rows
from .data_policy import assert_real_pair
from .ingestion import digest, iter_pair_rows
from .pair_schema import PAIR_FIELDS, command_key, pair_row

REVIEWER = "Automated_Heuristic_Reviewer"
ANNOTATION_FIELDS = ("PairId", "Benchmark", "Label", "AnnotationSource", "Reviewer")
RULE_VERSION = "lolbin-heuristics-v2"


def classify_pair(pair: ProcessPair) -> tuple[int | None, str]:
    """Apply suspicious rules first; abstain if benign behavior is not established.

    Flags such as certutil -f and PowerShell -nop are intentionally broad per
    the requested policy. Rule matches indicate suspicious behavior, not proof
    of exploitation. Parent and child commands are both inspected.
    """
    for process in (pair.child, pair.parent):
        name = process.binary_name
        command = process.command_line.lower()
        tokens = [token.lower() for token in split_command_line(process.command_line)]
        if name == "certutil.exe" and any(flag in tokens for flag in ("-urlcache", "-split", "-f", "-decode")):
            return -1, "T1105_T1140_certutil_download_decode"
        if name == "regsvr32.exe" and ("/i:http" in command or "scrobj.dll" in command or {"/s", "/n", "/u"} <= set(tokens)):
            return -1, "T1218.010_regsvr32_scriptlet"
        if name in {"powershell.exe", "pwsh.exe"}:
            if any(token in {"-enc", "-encodedcommand"} for token in tokens):
                return -1, "T1059.001_powershell_encoded_command"
            if any(term in command for term in ("downloadstring", "downloadfile", "invoke-expression", "net.webclient")) or re.search(r"\biex\b", command):
                return -1, "T1059.001_powershell_remote_execution"
            if "-nop" in tokens or re.search(r"-(?:w|windowstyle)\s+hidden\b", command) or "bypass" in command or "assembly.load" in command:
                return -1, "T1059.001_powershell_bypass_flags"
        if name == "mshta.exe" and any(term in command for term in ("http://", "https://", "vbscript:", "javascript:", "getobject")):
            return -1, "T1218.005_mshta_script"
        if name == "rundll32.exe" and (any(term in command for term in ("appdata", "\\temp\\", "\\public\\")) or re.search(r",\s*(?:#1|entry|dllregisterserver)\b", command)):
            return -1, "T1218.011_rundll32_untrusted_export"
        if name == "wmic.exe" and re.search(r"\bprocess\s+call\s+create\b", command):
            return -1, "T1047_wmic_process_create"
        if name == "bitsadmin.exe" and any(token in {"/transfer", "/download", "/addfile"} for token in tokens):
            return -1, "T1197_bitsadmin_transfer"
        if name == "nslookup.exe" and any(re.fullmatch(r"-(?:type|querytype|q)=txt", token) for token in tokens):
            return -1, "nslookup_dns_txt_query"
        if name == "vssadmin.exe" and re.search(r"\bdelete\s+shadows\b", command):
            return -1, "vssadmin_shadow_deletion"
        if ADS_PATTERN.search(re.sub(r"https?://[^\s]+", "", command)):
            return -1, "T1564.004_alternate_data_stream"
        if any(term in command for term in ("lsass", "samsrv", "hklm\\sam", "ntds.dit")):
            return -1, "T1003_credential_target"
    # Benign is a narrow positive rule, never a default for unmatched commands.
    combined = pair.parent.command_line + " " + pair.child.command_line
    lower = combined.lower()
    if any(term in lower for term in ("http://", "https://", "\\temp\\", "\\public\\", "appdata", "^", '""', "&&", "for %", ";;")):
        return None, "abstain_unsafe_context"
    if re.search(r"(?:^|\s)(?:>|>>)|%[0-9a-fA-F]{2}", combined):
        return None, "abstain_obfuscation_or_redirection"
    if any(char in combined for char in "<>|&"):
        return None, "abstain_shell_operator"
    for process in (pair.parent, pair.child):
        for token in split_command_line(process.command_line)[1:]:
            if len(token) > 7:
                try:
                    if base64.b64encode(base64.b64decode(token, validate=True)).decode() == token:
                        return None, "abstain_encoded_token"
                except (ValueError, UnicodeError):
                    pass
    child = pair.child
    if not child.microsoft_signed or not ntpath.normpath(child.image).lower().startswith("c:\\windows\\"):
        return None, "abstain_unverified_child"
    name = child.binary_name
    command = child.command_line.lower()
    if name in {"userinit.exe", "logonui.exe", "dwm.exe", "taskhostw.exe", "runtimebroker.exe"}:
        return 1, "OS_legitimate_" + name.removesuffix(".exe")
    if name == "svchost.exe" and re.search(r"(?:^|\s)-k\s+\S+", command):
        return 1, "OS_legitimate_svchost"
    if name == "conhost.exe" and "0xffffffff" in command and "-forcev1" in command:
        return 1, "OS_legitimate_conhost"
    if name in {"whoami.exe", "hostname.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe"}:
        return 1, "OS_normal_administrative_" + name.removesuffix(".exe")
    args = [token.lower() for token in split_command_line(child.command_line)]
    if name == "cmd.exe" and len(args) == 3 and args[1] == "/c" and args[2] in {"dir", "ver"}:
        return 1, "OS_read_only_cmd_" + args[2]
    if name == "explorer.exe" and len(args) == 1:
        return 1, "OS_legitimate_explorer"
    return None, "abstain_no_positive_rule"


def _export_test_sets(directory: Path, selected: list[dict], candidates: list[dict], report: dict) -> dict:
    """Publish only complete, disjoint weak-label sets; never replace existing tests."""
    lookup = {item["PairId"]: item for item in candidates}
    result = {}
    fields = [*PAIR_FIELDS, "AnnotationSource", "Reviewer", "LabelKind", "IsSynthetic", "IndependentGroundTruth", "RequestedBenchmark"]
    for name, counts in report["sets"].items():
        target = directory / TEST_FILENAMES[name]
        status = {"filename": target.name, **counts, "state": "insufficient_candidates"}
        result[name] = status
        if counts["missing_malicious"] or counts["missing_benign"]:
            continue
        if target.exists() or target.with_suffix(".provenance.json").exists():
            status["state"] = "existing_output_preserved"
            continue
        records = []
        for annotation in selected:
            if annotation["Benchmark"] != name:
                continue
            row = {**lookup[annotation["PairId"]]["row"], "Label": annotation["Label"],
                   "AnnotationSource": annotation["AnnotationSource"], "Reviewer": REVIEWER,
                   "LabelKind": "heuristic_weak_labels", "IsSynthetic": False,
                   "IndependentGroundTruth": False, "RequestedBenchmark": name}
            records.append(row)
        directory.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".part")
        try:
            with temporary.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader(); writer.writerows(records)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        status.update(state="exported_weak_labels", samples=len(records), sha256=digest(target))
        provenance = {**status, "label_kind": "heuristic_weak_labels", "independent_ground_truth": False,
                      "training_overlap": 0, "training_sha256": report["training_sha256"],
                      "rule_version": RULE_VERSION, "source_repos": sorted({r["SourceRepo"] for r in records})}
        target.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    return result


def generate_annotations(manifest: Path, output: Path, references: ReferenceDatabase, *, allow_source_fallback: bool = False, training_path: Path | None = None, overwrite: bool = False, project: Path | None = None, chunksize: int = 100000, exclude_training: bool = False, test_output: Path | None = None) -> dict:
    """Select real IDs up to quotas; report shortages without padding or relabeling.

    Native-source sets are preferred. Optional proxy allocations retain the actual
    source in a sidecar and must never be accepted as authentic BOTS datasets.
    Identical commands and PairIds cannot be reused to satisfy multiple quotas.
    """
    if (exclude_training or test_output is not None) and (training_path is None or not training_path.is_file()):
        raise ValueError("Held-out mining requires an existing training baseline")
    if test_output is not None and not exclude_training:
        raise ValueError("Test export requires exclude_training=True")
    training_keys = {command_key(decode_pair(row, str(training_path))) for row in rows(training_path)} if training_path and training_path.exists() else None
    if exclude_training and not training_keys:
        raise ValueError("Held-out mining requires a nonempty training baseline")
    candidates = []
    counters = Counter()
    eligible_keys = set()
    inventory: dict[str, Counter] = {}
    conflicts = {}
    for row in iter_pair_rows(manifest, project=project, chunksize=chunksize):
        counters["input_pairs"] += 1
        pair = references.enrich([decode_pair(row, str(manifest))])[0]
        assert_real_pair(pair)
        if not pair.eligible:
            counters["excluded_signature"] += 1
            continue
        eligible_keys.add(command_key(pair))
        if exclude_training and command_key(pair) in training_keys:
            counters["excluded_training"] += 1
            continue
        if not all((pair.parent.command_line, pair.child.command_line, pair.parent.image, pair.child.image, pair.child.utc_time)):
            counters["incomplete_pair"] += 1
            continue
        label, rule = classify_pair(pair)
        if label is None:
            counters["abstained"] += 1
            continue
        repo = row.get("SourceRepo", "")
        key = command_key(pair)
        if (repo, key) in conflicts:
            counters["duplicates"] += 1
            continue
        conflicts[repo, key] = label
        inventory.setdefault(repo, Counter())[str(label)] += 1
        candidates.append({"PairId": row["PairId"], "repo": repo, "label": label, "rule": rule, "key": key,
                               "SourceSHA256": row["SourceSHA256"], "row": pair_row(pair)})
    candidates.sort(key=lambda c: (c["repo"], c["PairId"]))
    selected, allocations = [], []
    used_ids, used_commands = set(), set()
    actual = {name: {-1: 0, 1: 0} for name in BENCHMARKS}
    # Reserve native candidates for all groups before assigning any proxy rows.
    for proxy_pass in ((False, True) if allow_source_fallback else (False,)):
        for name, quota in BENCHMARKS.items():
            for label, target in ((-1, quota[0]), (1, quota[1])):
                for item in candidates:
                    if actual[name][label] >= target:
                        break
                    native = item["repo"] in ALLOWED_SOURCES[name]
                    if item["label"] != label or native == proxy_pass or item["PairId"] in used_ids or item["key"] in used_commands:
                        continue
                    used_ids.add(item["PairId"]); used_commands.add(item["key"])
                    actual[name][label] += 1
                    selected.append({"PairId": item["PairId"], "Benchmark": name, "Label": label,
                                     "AnnotationSource": item["rule"], "Reviewer": REVIEWER})
                    allocations.append({"PairId": item["PairId"], "RequestedBenchmark": name, "ActualSourceRepo": item["repo"],
                                        "SourceSHA256": item["SourceSHA256"], "SourceSubstitution": not native})
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not overwrite:
        raise FileExistsError("Annotations already exist; version them before regenerating")
    if output.exists() and any(row.get("Reviewer") != REVIEWER for row in rows(output)):
        raise ValueError("Refusing to overwrite human-reviewed annotations")
    temporary = output.with_suffix(".part")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=ANNOTATION_FIELDS)
        writer.writeheader(); writer.writerows(selected)
    temporary.replace(output)
    sets = {name: {"malicious": actual[name][-1], "benign": actual[name][1],
                   "missing_malicious": q[0] - actual[name][-1], "missing_benign": q[1] - actual[name][1]} for name, q in BENCHMARKS.items()}
    overlaps = sum(c["key"] in training_keys for c in candidates if c["PairId"] in used_ids) if training_keys is not None else None
    report = {"rule_version": RULE_VERSION, "label_kind": "heuristic_weak_labels", "independent_ground_truth": False,
              "training_overlap_annotations": overlaps, "holdout_verified": overlaps == 0,
              "exclude_training": exclude_training, "training_path": str(training_path.resolve()) if training_path else None,
              "training_sha256": digest(training_path) if training_keys is not None else None,
              "unique_eligible_command_pairs": len(eligible_keys),
              "heldout_eligible_command_pairs": len(eligible_keys - training_keys) if training_keys is not None else None,
              "allow_source_fallback": allow_source_fallback, "counts": dict(counters), "inventory": {k: dict(v) for k, v in inventory.items()},
              "sets": sets, "annotations": len(selected), "allocations": allocations,
              "quotas_complete": all(not s["missing_malicious"] and not s["missing_benign"] for s in sets.values()),
              "annotations_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    if test_output is not None:
        report["test_exports"] = _export_test_sets(test_output, selected, candidates, report)
        report["test_exports_complete"] = all(status["state"] == "exported_weak_labels" for status in report["test_exports"].values())
    output.with_suffix(".report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
