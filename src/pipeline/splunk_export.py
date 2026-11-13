"""Export real BOTSv2 process telemetry from an existing authenticated Splunk server."""
from __future__ import annotations
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
import requests
from ..data_loader import timestamp


def export_botsv2(url: str, earliest: str, latest: str, output: Path, *, background_evidence: str = "") -> dict:
    """Read-only REST search export; credentials come only from SPLUNK_TOKEN.

    A clean time window must be externally audited. This function never infers
    benign status from the search result or attaches Microsoft signatures.
    TLS verification remains enabled. Raw JSON results are stored unchanged.
    """
    token = os.environ.get("SPLUNK_TOKEN")
    if not token:
        raise ValueError("Set SPLUNK_TOKEN for your existing Splunk server")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provide an HTTPS Splunk management endpoint without URL credentials")
    start, end = timestamp(earliest), timestamp(latest)
    if start is None or end is None or end <= start:
        raise ValueError("Provide a valid earliest/latest UTC time window")
    if output.exists():
        raise FileExistsError("Raw exports are immutable; use a new output filename")
    output.parent.mkdir(parents=True, exist_ok=True)
    search = "search index=botsv2 (EventCode=1 OR EventCode=4688 OR EventID=1 OR EventID=4688)"
    temporary = output.with_suffix(".part")
    count = 0
    with requests.post(url.rstrip("/") + "/services/search/jobs/export", headers={"Authorization": "Bearer " + token},
                       data={"search": search, "earliest_time": earliest, "latest_time": latest, "output_mode": "json"},
                       stream=True, timeout=(15, 600)) as response:
        response.raise_for_status()
        with temporary.open("wb") as stream:
            for line in response.iter_lines():
                if not line:
                    continue
                record = json.loads(line)
                if record.get("messages") and any(message.get("type") in {"ERROR", "FATAL"} for message in record["messages"]):
                    raise ValueError("Splunk search returned an error; inspect the server search job")
                if "result" in record:
                    stream.write(line + b"\n")
                    count += 1
    if not count:
        raise ValueError("Splunk returned zero process results; no raw dataset was published")
    temporary.replace(output)
    from .ingestion import digest
    item = {"repo": "splunk/botsv2", "path": str(output.resolve()), "url": url.rstrip("/") + "/services/search/jobs/export",
            "source_path": f"botsv2:{earliest}:{latest}", "sha256": digest(output), "records": count,
            "background_evidence": background_evidence, "earliest": earliest, "latest": latest}
    output.with_suffix(".manifest.json").write_text(json.dumps({"items": [item]}, indent=2), encoding="utf-8")
    return item
