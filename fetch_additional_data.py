"""Fetch real telemetry and build the final processed training dataset.

Run from any directory with Python. Sources are pinned to commit revisions per
run. Only log members are read from ZIP; no arbitrary archive extraction occurs.
Scenario metadata is retained separately and is never treated as event labels.
"""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

from download_datasets import DatasetDownloader

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "data" / "raw"


def main() -> None:
    catalog = json.loads((ROOT / "configs" / "dataset_sources.json").read_text(encoding="utf-8"))
    revisions = {}
    for entry in catalog:
        if entry["repo"] not in revisions:
            response = requests.get(f"https://api.github.com/repos/{entry['repo']}/commits/{entry['branch']}", timeout=45)
            response.raise_for_status()
            revisions[entry["repo"]] = response.json()["sha"]
    OUTPUT.mkdir(parents=True, exist_ok=True)
    report = {"revisions": revisions, "items": [], "errors": [], "note": "Unlabeled telemetry. Do not label every event malicious based on its scenario."}

    def fetch(entry):
        repo, path = entry["repo"], entry["path"]
        from src.pipeline.ingestion import partition_name
        base = OUTPUT / partition_name(repo)
        filename = revisions[repo][:12] + "_" + hashlib.sha256(path.encode()).hexdigest()[:10] + "_" + Path(path).name
        url = f"https://raw.githubusercontent.com/{repo}/{revisions[repo]}/{quote(path)}"
        if repo == "splunk/attack_data":
            url = f"https://media.githubusercontent.com/media/{repo}/{revisions[repo]}/{quote(path)}"
        downloader = DatasetDownloader(OUTPUT, ROOT / "data" / "external", max_bytes=1024**3)
        raw = downloader.download(url, base / filename)
        with raw.open("rb") as stream:
            if stream.read(50).startswith(b"version https://git-lfs.github.com/spec"):
                raise ValueError("Received Git LFS pointer instead of telemetry")
        return {**entry, "source_path": path, **downloader.inventory[-1]}, raw, base, filename

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [(entry, pool.submit(fetch, entry)) for entry in catalog]
        for entry, future in futures:
            try:
                result, raw, base, filename = future.result()
                report["items"].append(result)
                print("Downloaded:", entry["path"], flush=True)
            except Exception as exc:
                report["errors"].append({**entry, "error": str(exc)})
                print("Failed:", entry["path"], str(exc), flush=True)
            DatasetDownloader.write_json(ROOT / "data" / "raw" / "manifests" / "additional.json", report)
    from src.pipeline.ingestion import ingest_manifest
    if not report["errors"]:
        ingest_manifest(ROOT / "data/raw/manifests/additional.json", ROOT)
    print(json.dumps({"files": len(report["items"]), "bytes": sum(x["bytes"] for x in report["items"]),
                      "errors": report["errors"]}, indent=2))


if __name__ == "__main__":
    main()
