"""Training-only corpus statistics, reference metadata, and path embeddings.

All fitted state is frozen at prediction time. Hash-based signature enrichment
uses exact SHA256 matches; executable names and PE CompanyName are not a trust
source. Reference imports are passive and never launch downloaded executables.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import tempfile
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from .data_loader import ProcessPair, ProcessRecord, boolean, key, text


def split_command_line(command: str) -> list[str]:
    """Tokenize Windows quoting/backslash rules without POSIX path mangling.

    This implements argument boundary handling, not cmd/PowerShell evaluation.
    Shell metacharacters and environment variables remain literal evidence.
    """
    tokens: list[str] = []
    index, length = 0, len(command)
    while index < length:
        while index < length and command[index].isspace():
            index += 1
        if index == length:
            break
        token: list[str] = []
        quoted = False
        while index < length:
            char = command[index]
            if char.isspace() and not quoted:
                break
            if char == "\\":
                start = index
                while index < length and command[index] == "\\":
                    index += 1
                count = index - start
                if index < length and command[index] == '"':
                    token.extend("\\" * (count // 2))
                    if count % 2:
                        token.append('"')
                        index += 1
                    else:
                        quoted = not quoted
                        index += 1
                else:
                    token.extend("\\" * count)
                continue
            if char == '"':
                if quoted and index + 1 < length and command[index + 1] == '"':
                    token.append('"')
                    index += 2
                    continue
                quoted = not quoted
            else:
                token.append(char)
            index += 1
        tokens.append("".join(token))
    return tokens


def normalize_argument(argument: str) -> str:
    """Compare switch names case-insensitively, excluding attached switch values."""
    return re.split(r"[:=]", argument.lower(), maxsplit=1)[0]


def arguments(command: str) -> set[str]:
    """Return unique /switch, -switch or --switch names, excluding UNC paths."""
    return {normalize_argument(token) for token in split_command_line(command)[1:]
            if re.match(r"^(?:/(?!/)|--?)[a-zA-Z?][a-zA-Z0-9_?-]*(?::|=|$)", token)}


def character_counts(command: str) -> np.ndarray:
    """Partition Unicode characters into upper/lower/digit/space/special classes."""
    counts = np.zeros(5, dtype=np.float64)
    for char in command:
        index = 0 if char.isupper() else 1 if char.islower() else 2 if char.isdigit() else 3 if char.isspace() else 4
        counts[index] += 1
    return counts


class ReferenceDatabase:
    """Load normalized documentation, Filesec extensions, LOTS domains and hashes.

    documentation.json maps binary basenames to {arguments: [...], source: URL}.
    signatures.json maps SHA256 to {signer, signature_valid, original_file_name}.
    xcyclopedia.json may contain the upstream JSON array or hash-keyed object;
    its captured stdout/stderr is used to discover documented switches. Help
    capture is necessarily incomplete and is documented as an approximation.
    """

    def __init__(self, directory: str | Path | None = None) -> None:
        self.documentation: dict[str, set[str]] = {}
        self.suspicious_extensions: set[str] = set()
        self.lots_domains: set[str] = set()
        self.signatures: dict[str, dict[str, Any]] = {}
        self.directory = str(directory) if directory is not None else ""
        if directory is not None:
            self.load(Path(directory))

    def load(self, directory: Path) -> None:
        """Read available files; missing optional catalogs remain explicitly empty."""
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        docs = directory / "documentation.json"
        if docs.exists():
            for binary, entry in json.loads(docs.read_text(encoding="utf-8")).items():
                self.documentation[binary.lower()] = {normalize_argument(a) for a in entry["arguments"]}
        extensions = directory / "filesec_extensions.json"
        if extensions.exists():
            content = json.loads(extensions.read_text(encoding="utf-8"))
            self.suspicious_extensions = {"." + e.lower().lstrip(".") for e in (content["extensions"] if isinstance(content, dict) else content)}
        lots = directory / "lots_domains.json"
        if lots.exists():
            content = json.loads(lots.read_text(encoding="utf-8"))
            self.lots_domains = {d.lower().lstrip("*.").rstrip(".") for d in (content.get("list", content.get("domains", [])) if isinstance(content, dict) else content)}
        upstream = directory / "xcyclopedia.json"
        if upstream.exists():
            self.import_xcyclopedia(json.loads(upstream.read_text(encoding="utf-8-sig")))
        signatures = directory / "signatures.json"
        if signatures.exists():
            self.signatures.update({digest.lower(): entry for digest, entry in json.loads(signatures.read_text(encoding="utf-8")).items() if re.fullmatch(r"[0-9a-fA-F]{64}", digest)})

    def import_xcyclopedia(self, content: Any) -> None:
        """Import upstream FileName/StdOut/Signature fields, preserving unknowns."""
        records = content if isinstance(content, list) else list(content.values())
        for raw in records:
            if not isinstance(raw, dict):
                continue
            fields = {key(name): value for name, value in raw.items()}
            name = ntpath.basename(text(fields.get("filename", fields.get("name", "")))).lower()
            help_text = "\n".join(text(fields.get(k)) for k in ("stdout", "stderr", "standardoutput", "standarderror", "runtimestdout", "runtimestderr", "output"))
            if name and help_text:
                found = {normalize_argument(s) for s in re.findall(r"(?<![\w:/])(?:/(?!/)|--?)[a-zA-Z?][a-zA-Z0-9_?-]*", help_text)}
                self.documentation.setdefault(name, set()).update(found)
            digest = text(fields.get("sha256", fields.get("hashsha256", ""))).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            signature = fields.get("signature", {})
            signature = {key(k): v for k, v in signature.items()} if isinstance(signature, dict) else {}
            valid = boolean(signature.get("status", fields.get("signaturestatus")))
            # PowerShell SignatureStatus enum uses 0=Valid, unlike boolean 0.
            if isinstance(fields.get("signaturestatus"), int):
                valid = fields["signaturestatus"] == 0
            signer = text(signature.get("subject", fields.get("signaturesubject", "")))
            certificate = signature.get("signercertificate", {})
            if isinstance(certificate, dict):
                signer = signer or text(certificate.get("Subject"))
            self.signatures[digest] = {"signer": signer, "signature_valid": valid,
                                       "original_file_name": text(fields.get("originalfilename", fields.get("metaoriginalfilename", "")))}

    def enrich_process(self, process: ProcessRecord) -> ProcessRecord:
        """Fill missing fields using exact hash metadata; observed data wins."""
        entry = self.signatures.get(process.sha256, {})
        return replace(process,
                       signer=process.signer or text(entry.get("signer")),
                       signature_valid=process.signature_valid if process.signature_valid is not None else boolean(entry.get("signature_valid")),
                       original_file_name=process.original_file_name or text(entry.get("original_file_name")))

    def enrich(self, pairs: Iterable[ProcessPair]) -> list[ProcessPair]:
        return [replace(pair, parent=self.enrich_process(pair.parent), child=self.enrich_process(pair.child)) for pair in pairs]

    def import_pe_directory(self, directory: str | Path) -> int:
        """Read OriginalFilename from local PE files, indexed by computed SHA256.

        pefile cannot validate Authenticode trust. This operation never sets signer
        or signature_valid and never executes files. Existing signature data stays.
        """
        import pefile

        count = 0
        for path in Path(directory).rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".exe", ".dll", ".com", ".scr", ".cpl"}:
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                with pefile.PE(str(path), fast_load=False) as pe:
                    original = ""
                    for group in getattr(pe, "FileInfo", []):
                        for entry in group:
                            for table in getattr(entry, "StringTable", []):
                                value = table.entries.get(b"OriginalFilename", b"")
                                original = value.decode("utf-8", errors="replace").strip("\x00") or original
                    if original:
                        self.signatures.setdefault(digest, {})["original_file_name"] = original
                        count += 1
            except (pefile.PEFormatError, OSError):
                continue
        return count


class CorpusEnricher:
    """Fit per-binary execution frequencies, mean character ratios and time bounds.

    Arguments count once per process invocation, so F4 divides by invocations of
    that binary, not by the total count of all switch tokens. Shared GUID parents
    count once, preventing a prolific parent from distorting the baseline.
    """

    def __init__(self) -> None:
        self.argument_frequency: dict[str, Counter[str]] = {}
        self.execution_counts: Counter[str] = Counter()
        self.character_ratios = np.full(5, 0.2, dtype=np.float64)
        self.time_min = 0.0
        self.time_max = 0.0
        self.fitted = False

    @staticmethod
    def unique_processes(pairs: Iterable[ProcessPair]) -> list[ProcessRecord]:
        seen: set[tuple[Any, ...]] = set()
        result: list[ProcessRecord] = []
        for pair in pairs:
            for process in (pair.parent, pair.child):
                identity = (process.dataset_id, process.computer, process.process_guid) if process.process_guid else ("inline", id(process))
                if identity not in seen:
                    seen.add(identity)
                    result.append(process)
        return result

    def fit(self, pairs: Iterable[ProcessPair]) -> CorpusEnricher:
        pairs = list(pairs)
        if not pairs:
            raise ValueError("Cannot enrich an empty training corpus")
        self.argument_frequency = defaultdict(Counter)
        self.execution_counts = Counter()
        ratios: list[np.ndarray] = []
        for process in self.unique_processes(pairs):
            if not process.command_line:
                continue
            binary = process.binary_name
            self.execution_counts[binary] += 1
            self.argument_frequency[binary].update(arguments(process.command_line))
            counts = character_counts(process.command_line)
            ratios.append(counts / counts.sum())
        self.argument_frequency = dict(self.argument_frequency)
        if not ratios:
            raise ValueError("Training corpus contains no command lines")
        self.character_ratios = np.mean(ratios, axis=0)
        deltas = [p.time_diff for p in pairs if p.time_diff is not None and p.time_diff >= 0]
        self.time_min, self.time_max = (min(deltas), max(deltas)) if deltas else (0.0, 0.0)
        self.fitted = True
        return self

    def argument_is_rare(self, binary: str, argument: str) -> bool:
        if not self.fitted:
            raise RuntimeError("CorpusEnricher must be fitted first")
        total = self.execution_counts[binary.lower()]
        # An unseen argument/binary has zero historical support.
        return total == 0 or self.argument_frequency.get(binary.lower(), {}).get(argument, 0) / total < 0.01

    def normalized_time(self, delta: float | None) -> float:
        if delta is None or self.time_max <= self.time_min:
            return 0.0
        return float(np.clip((delta - self.time_min) / (self.time_max - self.time_min), 0.0, 1.0))


class ImageEmbedder:
    """A real fastText skipgram path embedding with dim=1 and subword OOV support.

    Native model bytes are embedded in joblib state so saving and reloading never
    retrains the embedding or changes the feature coordinate system.
    """

    def __init__(self) -> None:
        self.model: Any = None

    @staticmethod
    def normalize(image: str) -> str:
        return re.sub(r"\s", "%20", ntpath.normpath(image).lower()) if image else ""

    def fit(self, pairs: Iterable[ProcessPair]) -> ImageEmbedder:
        try:
            import fasttext
        except ImportError as exc:
            raise RuntimeError("Install fasttext-wheel; F19/F20 require a trained fastText model") from exc
        pairs = list(pairs)
        paths = [self.normalize(p.image) for p in CorpusEnricher.unique_processes(pairs) if p.image]
        if not paths:
            raise ValueError("No process images available for fastText training")
        with tempfile.TemporaryDirectory(prefix="lolbin-fasttext-") as folder:
            corpus = Path(folder) / "images.txt"
            # A parent/child image per line provides a co-occurrence context.
            lines = [self.normalize(pair.parent.image) + " " + self.normalize(pair.child.image) for pair in pairs]
            corpus.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.model = fasttext.train_unsupervised(str(corpus), model="skipgram", dim=1, minCount=1,
                                                     minn=2, maxn=6, bucket=50000, epoch=30,
                                                     thread=1, ws=3, loss="hs", verbose=0)
        return self

    def transform(self, image: str) -> float:
        if self.model is None:
            raise RuntimeError("ImageEmbedder must be fitted first")
        image = self.normalize(image)
        return float(self.model.get_word_vector(image)[0]) if image else 0.0

    def __getstate__(self) -> dict[str, Any]:
        if self.model is None:
            return {"native_model": None}
        with tempfile.TemporaryDirectory(prefix="lolbin-save-") as folder:
            path = Path(folder) / "image.bin"
            self.model.save_model(str(path))
            return {"native_model": path.read_bytes()}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.model = None
        if state["native_model"] is not None:
            import fasttext
            with tempfile.TemporaryDirectory(prefix="lolbin-load-") as folder:
                path = Path(folder) / "image.bin"
                path.write_bytes(state["native_model"])
                self.model = fasttext.load_model(str(path))
