"""Fetch research sources and build passive reference catalogs.

Cloning BOTS retrieves its catalog; --bots-archives additionally fetches the
published data archives. Splunk indexes still require Splunk and EventID=1 export.
Config/rule/emulation repositories and MITRE results are identified as such and
are never presented as already labeled Sysmon telemetry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.enricher import ReferenceDatabase

ROOT = Path(__file__).resolve().parent
LOTS_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/lots-project/list.json"
XCYCLOPEDIA_URL = "https://raw.githubusercontent.com/strontic/xcyclopedia/master/output/strontic-xcyclopedia.json.zip"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    kind: str
    note: str


SOURCES = {source.name: source for source in (
    Source("botsv1", "https://github.com/splunk/botsv1", "git", "Dataset catalog; optional raw Sysmon JSON or pre-indexed archive"),
    Source("botsv2", "https://github.com/splunk/botsv2", "git", "Dataset catalog; optional Splunk archive requires export"),
    Source("botsv3", "https://github.com/splunk/botsv3", "git", "Dataset catalog; optional Splunk archive requires export"),
    Source("attack_data", "https://github.com/splunk/attack_data", "git", "Mixed telemetry; choose Sysmon Process Creation records"),
    Source("mitre", "https://github.com/attackevals/ael", "git", "Official ATT&CK Evaluations Library; results/emulations, not uniform raw Sysmon. Portal: https://mitre-engenuity.org/attackevaluations/"),
    Source("sysmon_config", "https://github.com/SwiftOnSecurity/sysmon-config", "git", "Collection configuration, not a telemetry dataset"),
    Source("lolbas", "https://github.com/LOLBAS-Project/LOLBAS", "git", "LOLBin knowledge catalog, not training telemetry"),
    Source("xcyclopedia", "https://github.com/strontic/xcyclopedia", "git", "Executable documentation and exact-hash PE/signature metadata; --references builds the catalog"),
    Source("filesec", "https://filesec.io/", "html", "Extension catalog; Appendix B offline snapshot bundled if site is unavailable"),
    Source("lots", "https://lots-project.com/", "html", "Trusted-site catalog; --references downloads the MISP LOTS list mirror"),
    Source("mordor", "https://github.com/OTRF/mordor", "git", "Security telemetry; nested archives must be unpacked before ingestion"),
    Source("security_datasets", "https://github.com/OTRF/Security-Datasets", "git", "OTRF atomic and compound recorded security telemetry; overlaps historical Mordor"),
    Source("apt29_hackathon", "https://github.com/OTRF/detection-hackathon-apt29", "git", "APT29 evaluation day1/day2 telemetry with investigation context"),
    Source("hayabusa_evtx", "https://github.com/Yamato-Security/hayabusa-sample-evtx", "git", "EVTX test collection; some samples overlap EVTX-ATTACK-SAMPLES"),
    Source("evtx_attack_samples", "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", "git", "Native EVTX telemetry accepted by DataLoader"),
    Source("atomic_red_team", "https://github.com/redcanaryco/atomic-red-team", "git", "Attack definitions, not observed telemetry; no tests are executed"),
    Source("sigma", "https://github.com/SigmaHQ/sigma", "git", "Detection rules, not observed telemetry"),
)}
BOTS_ARCHIVES = {
    "botsv1": "https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz",
    "botsv2": "https://s3.amazonaws.com/botsdataset/botsv2/botsv2_data_set.tgz",
    "botsv3": "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz",
}
BOTS1_SYSMON = "https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz"


class DatasetDownloader:
    """Stream bounded downloads, shallow clones and normalized reference imports.

    HTTP files are written atomically and inventoried with SHA256. Existing
    downloads and clones are preserved unless --update is explicitly supplied.
    Native Git LFS blobs are not downloaded by clone; fetch those separately if
    a repository uses LFS. Large archive extraction is left explicit to the user.
    """

    def __init__(self, output: Path, references: Path, *, max_bytes: int = 5 * 1024**3, update: bool = False) -> None:
        self.output, self.references = output, references
        self.max_bytes, self.update = max_bytes, update
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "LOLBin-Research-Downloader/1.0"
        retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.inventory: list[dict[str, Any]] = []

    @staticmethod
    def digest(path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else DatasetDownloader._digest_310(stream)

    @staticmethod
    def _digest_310(stream: Any) -> str:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()

    def download(self, url: str, target: Path) -> Path:
        """Fetch a file with TLS verification, retry, timeout and a per-file cap."""
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or self.update:
            temporary = target.with_suffix(target.suffix + ".part")
            try:
                with self.session.get(url, stream=True, timeout=(15, 90)) as response:
                    response.raise_for_status()
                    if int(response.headers.get("Content-Length", 0)) > self.max_bytes:
                        raise ValueError(f"Download exceeds --max-gb: {url}")
                    size = 0
                    with temporary.open("wb") as stream:
                        for chunk in response.iter_content(1024 * 1024):
                            size += len(chunk)
                            if size > self.max_bytes:
                                raise ValueError(f"Download exceeds --max-gb: {url}")
                            stream.write(chunk)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        self.inventory.append({"url": url, "path": str(target.resolve()), "bytes": target.stat().st_size,
                               "sha256": self.digest(target), "status": "downloaded_or_cached"})
        return target

    def fetch_source(self, source: Source) -> None:
        """Clone a source or save its website; record its actual role and revision."""
        canonical_name = {"botsv1": "splunk_botsv1", "botsv2": "splunk_botsv2", "botsv3": "splunk_botsv3", "attack_data": "splunk_attack_data", "security_datasets": "otrf_security_datasets", "mitre": "mitre_attack_evals", "apt29_hackathon": "mitre_attack_evals", "hayabusa_evtx": "hayabusa_samples"}.get(source.name, source.name)
        target = self.output / canonical_name
        if source.kind == "git":
            target = target / "repository"
            if shutil.which("git") is None:
                raise RuntimeError("Git is required for repository downloads")
            if target.exists():
                if not (target / ".git").exists():
                    raise ValueError(f"Destination is not a Git repository: {target}")
                origin = subprocess.run(["git", "-C", str(target), "remote", "get-url", "origin"], capture_output=True, text=True, check=True).stdout.strip()
                if origin.removesuffix(".git") != source.url.removesuffix(".git"):
                    raise ValueError(f"Existing checkout has a different origin: {target}")
                if self.update:
                    subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], check=True, timeout=3600)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                import os
                environment = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1", GIT_TERMINAL_PROMPT="0")
                subprocess.run(["git", "clone", "--depth", "1", source.url, str(target)], check=True, timeout=3600, env=environment)
            revision = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            self.inventory.append({**asdict(source), "path": str(target.resolve()), "revision": revision, "status": "cloned_or_cached"})
        else:
            self.download(source.url, target / "index.html")
            if source.name == "filesec":
                html = (target / "index.html").read_text(encoding="utf-8", errors="replace")
                extensions = {"." + match.lower() for match in re.findall(r'href=[\"\x27](?:https://filesec.io)?/([a-zA-Z0-9][a-zA-Z0-9-]{0,30})[\"\x27]', html)}
                extensions -= {".about", ".contribute", ".contact", ".privacy", ".index"}
                if not extensions:
                    raise ValueError("Filesec page schema changed: no extension links found; bundled Appendix B snapshot retained")
                existing = self.references / "filesec_extensions.json"
                previous = json.loads(existing.read_text(encoding="utf-8")) if existing.exists() else {}
                extensions.update(previous.get("extensions", []))
                self.write_json(existing, {"source": source.url, "extensions": sorted(extensions)})

    @staticmethod
    def write_json(path: Path, content: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".part")
        temporary.write_text(json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)

    def fetch_references(self) -> None:
        """Download upstream xCyclopedia JSON and the maintained MISP LOTS mirror."""
        raw = self.references / "raw"
        archive = self.download(XCYCLOPEDIA_URL, raw / "xcyclopedia.json.zip")
        with zipfile.ZipFile(archive) as bundle:
            candidates = [entry for entry in bundle.infolist() if entry.filename.endswith(".json")]
            if len(candidates) != 1 or candidates[0].file_size > self.max_bytes:
                raise ValueError("Unexpected or oversized xCyclopedia archive")
            # Read the JSON member directly; archive paths are never extracted.
            content = json.loads(bundle.read(candidates[0]).decode("utf-8-sig"))
        database = ReferenceDatabase(self.references)
        database.import_xcyclopedia(content)
        self.write_json(self.references / "xcyclopedia.json", content)
        # Keep manual documentation and signer overrides separate from upstream.
        lots = self.download(LOTS_URL, raw / "lots-project.json")
        content = json.loads(lots.read_text(encoding="utf-8"))
        if not content.get("list") or not all(isinstance(d, str) for d in content["list"]):
            raise ValueError("Unexpected LOTS catalog schema")
        self.write_json(self.references / "lots_domains.json", {**content, "source": LOTS_URL})
        self.inventory.append({"status": "references_built", "documented_binaries": len(database.documentation),
                               "hash_metadata": len(database.signatures), "lots_domains": len(content["list"])})

    def fetch_bots(self, name: str, *, raw_sysmon: bool = False) -> None:
        """Fetch BOTS archives, optionally a directly ingestible BOTSv1 Sysmon export."""
        url = BOTS1_SYSMON if raw_sysmon else BOTS_ARCHIVES[name]
        filename = unquote(Path(urlsplit(url).path).name)
        archive = self.download(url, self.output / ("splunk_" + name) / filename)
        # Gzip is streamed by ingestion; retain only the original download.



def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    cli.add_argument("--list", action="store_true", help="List source roles without downloading")
    cli.add_argument("--merge-csv", type=Path, help="Stream raw manifest directly into the final processed training dataset")
    cli.add_argument("--splunk-url", help="Existing HTTPS Splunk management endpoint for a BOTSv2 process export")
    cli.add_argument("--earliest", help="Audited background window start (ISO UTC)")
    cli.add_argument("--latest", help="Audited background window end (ISO UTC)")
    cli.add_argument("--background-evidence", default="", help="Reference identifying an audited clean scenario/time window")
    cli.add_argument("--source", choices=sorted(SOURCES), action="append", default=[])
    cli.add_argument("--all", action="store_true", help="Fetch every source; large repositories may take substantial disk space")
    cli.add_argument("--references", action="store_true", help="Build xCyclopedia and LOTS reference files")
    cli.add_argument("--bots-archives", action="store_true", help="Download published archives for selected BOTS sources")
    cli.add_argument("--botsv1-sysmon", action="store_true", help="Download the original compressed BOTSv1 Sysmon JSON export")
    cli.add_argument("--output", type=Path, default=ROOT / "data" / "raw")
    cli.add_argument("--reference-dir", type=Path, default=ROOT / "data" / "external")
    cli.add_argument("--max-gb", type=float, default=5.0, help="Per-file download/unpack bound (Git clone is not size bounded)")
    cli.add_argument("--update", action="store_true")
    args = cli.parse_args()
    if args.splunk_url:
        from src.pipeline.splunk_export import export_botsv2
        if not args.earliest or not args.latest:
            cli.error("--splunk-url requires --earliest and --latest")
        print(json.dumps(export_botsv2(args.splunk_url, args.earliest, args.latest,
                                      args.output / "splunk_botsv2" / "background_export.jsonl",
                                      background_evidence=args.background_evidence), indent=2))
        return 0
    if args.merge_csv:
        from src.pipeline.dataset_export import export_csv
        report = export_csv(args.merge_csv, ROOT)
        print(json.dumps({k: v for k, v in report.items() if k not in {"sources", "revisions"}}, indent=2))
        return 0
    if args.list or not (args.source or args.all or args.references or args.botsv1_sysmon):
        print(json.dumps([asdict(source) for source in SOURCES.values()], indent=2))
        return 0
    if args.max_gb <= 0:
        cli.error("--max-gb must be positive")
    downloader = DatasetDownloader(args.output, args.reference_dir, max_bytes=int(args.max_gb * 1024**3), update=args.update)
    errors: list[dict[str, str]] = []
    operations = [(name, lambda name=name: downloader.fetch_source(SOURCES[name])) for name in (list(SOURCES) if args.all else list(dict.fromkeys(args.source)))]
    if args.references:
        operations.append(("references", downloader.fetch_references))
    if args.botsv1_sysmon:
        operations.append(("botsv1_sysmon", lambda: downloader.fetch_bots("botsv1", raw_sysmon=True)))
    if args.bots_archives:
        operations.extend((name + "_archive", lambda name=name: downloader.fetch_bots(name)) for name in (BOTS_ARCHIVES if args.all else args.source) if name in BOTS_ARCHIVES)
    for name, operation in operations:
        logging.warning("Fetching %s", name)
        try:
            operation()
        except (OSError, ValueError, RuntimeError, requests.RequestException, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
            errors.append({"source": name, "error": str(exc)})
            logging.error("%s: %s", name, exc)
    report = {"fetched_at_utc": datetime.now(timezone.utc).isoformat(), "items": downloader.inventory, "errors": errors}
    downloader.write_json(args.output / "download_manifest.json", report)
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
