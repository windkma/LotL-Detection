"""Lossless canonical process-pair rows and stable evidence identifiers."""
from __future__ import annotations
import hashlib
import json
from ..data_loader import ProcessPair

PROCESS_FIELDS = ("ProcessGuid", "ProcessId", "UtcTime", "Image", "CommandLine", "IntegrityLevel", "SHA256", "OriginalFileName", "Signer", "SignatureValid")
PAIR_FIELDS = ("PairId", "DatasetId", "Computer", "EventID", "ParentProcessGuid", "ParentProcessId", *PROCESS_FIELDS,
               *("Parent" + field for field in PROCESS_FIELDS if field not in {"ProcessGuid", "ProcessId"}),
               "SourceRepo", "SourcePath", "SourceSHA256", "SourceRecord", "Label", "BackgroundEvidence")


def pair_row(pair: ProcessPair) -> dict:
    child = pair.child
    row = {"DatasetId": child.dataset_id, "Computer": child.computer, "EventID": 1,
           "ParentProcessGuid": child.parent_process_guid or pair.parent.process_guid,
           "ParentProcessId": child.parent_process_id or pair.parent.process_id,
           "Label": pair.label, "BackgroundEvidence": child.metadata.get("backgroundevidence", "")}
    attrs = ("process_guid", "process_id", "utc_time", "image", "command_line", "integrity_level", "sha256", "original_file_name", "signer", "signature_valid")
    for prefix, process in (("", child), ("Parent", pair.parent)):
        for field, attr in zip(PROCESS_FIELDS, attrs):
            value = getattr(process, attr)
            row[prefix + field] = value.isoformat() if hasattr(value, "isoformat") else value
    for field in ("SourceRepo", "SourcePath", "SourceSHA256", "SourceRecord"):
        row[field] = child.metadata.get(field.lower(), "")
    identity = [row.get(k) for k in ("DatasetId", "Computer", "ProcessGuid", "ProcessId", "UtcTime", "CommandLine", "ParentCommandLine")]
    row["PairId"] = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()
    return row


def command_key(pair: ProcessPair) -> tuple[str, str]:
    return pair.parent.command_line, pair.child.command_line
