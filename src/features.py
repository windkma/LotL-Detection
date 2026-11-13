"""Extract the fixed 44-dimensional representation described in thesis §5.2.3.

Order: child F1..F18, parent F1..F18, contextual F19..F26. These features
are indicators of behavior, not independent verdicts of maliciousness.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import ntpath
import re
from collections import Counter
from typing import Iterable
from urllib.parse import unquote, urlsplit

import numpy as np
import pandas as pd
from scipy.stats import chisquare

from .data_loader import ProcessPair, ProcessRecord
from .enricher import CorpusEnricher, ImageEmbedder, ReferenceDatabase, arguments, character_counts, split_command_line


COMMAND_FEATURES = (
    "no_documentation", "documented_usage", "undocumented_usage", "anomalous_argument",
    "potential_obfuscation", "potential_hex", "char_ratio_deviation", "remote_code",
    "potentially_untrusted_code", "suspicious_extension", "untrusted_hostname",
    "url_encoding", "one_hostname_one_path", "web_remote_keywords", "potential_encoding",
    "dump_related_string", "multiple_filesystem_paths", "ads_syntax",
)
CONTEXT_FEATURES = (
    "F19_parent_image", "F20_child_image", "F21_parent_filename_mismatch",
    "F22_child_filename_mismatch", "F23_time_delta", "F24_parent_integrity",
    "F25_child_integrity", "F26_invalid_signature",
)
FEATURE_NAMES = tuple(f"{role}_F{i}_{name}" for role in ("child", "parent")
                      for i, name in enumerate(COMMAND_FEATURES, 1)) + CONTEXT_FEATURES

# File types executable directly or through a script processor; excluded from F10.
EXECUTABLE_EXTENSIONS = frozenset({".exe", ".dll", ".com", ".scr", ".cpl", ".hta", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".wsf", ".wsh"})
INTEGRITY_LEVELS = {name.lower(): index for index, name in enumerate(("Untrusted", "Low", "Medium", "High", "System", "Installer"), 1)}
URL_PATTERN = re.compile(r"\bhttps?://[^\s\"'<>|]+", re.IGNORECASE)
UNC_PATTERN = re.compile(r'"((?:\\\\|//)[^"\r\n]+)"|(?<![:\w/])((?:\\\\|//)[^\s"\x27<>|]+)')
LOCAL_PATTERN = re.compile(r'"((?:[a-zA-Z]:[\\/]|%[^%]+%[\\/])[^"\r\n]*)"|((?:[a-zA-Z]:[\\/]|%[^%]+%[\\/])[^\s"\x27<>|&,;]*)')
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN_PATTERN = re.compile(r"(?<![\w@\\/.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w.-])")
ADS_PATTERN = re.compile(r"[A-Za-z0-9_.-]+\.[A-Za-z0-9]+:[A-Za-z0-9_.-]+(?:\.[A-Za-z0-9]+)?")


def shannon_entropy(value: str) -> float:
    """Empirical Shannon entropy in bits per character, as requested in F15."""
    if not value:
        return 0.0
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in Counter(value).values())


class FeatureExtractor:
    """Fit once on history, then featurize both training and unseen process pairs.

    f7_mode='statistical' marks p<0.05; 'paper' intentionally reproduces the
    inverted p>0.05 condition printed on thesis page 22. Laplace smoothing avoids
    undefined chi-square statistics when a character class was absent in history.
    Unknown PE filenames yield mismatch=0; unknown signatures conservatively
    yield F26=1. Missing context is also exposed in pipeline coverage reports.
    """

    def __init__(self, references: ReferenceDatabase, *, f7_mode: str = "paper",
                 privileged_directories: Iterable[str] = ("C:\\Windows", "%windir%", "%systemroot%")) -> None:
        if f7_mode not in {"statistical", "paper"}:
            raise ValueError("f7_mode must be 'statistical' or 'paper'")
        self.references = references
        self.f7_mode = f7_mode
        self.privileged_directories = tuple(ntpath.normpath(p).lower().rstrip("\\/") for p in privileged_directories)
        self.corpus = CorpusEnricher()
        self.embedder = ImageEmbedder()
        self.fitted = False

    def fit(self, pairs: Iterable[ProcessPair]) -> FeatureExtractor:
        pairs = list(pairs)
        self.corpus.fit(pairs)
        self.embedder.fit(pairs)
        self.fitted = True
        return self

    @staticmethod
    def _locations(command: str) -> tuple[list[str], list[str], list[str]]:
        urls = [m.group().rstrip(").,;") for m in URL_PATTERN.finditer(command)]
        # Remove URLs before looking for drive paths; URL paths must not count as local.
        without_urls = URL_PATTERN.sub(" ", command)
        uncs = [(m.group(1) or m.group(2)).rstrip(").,;") for m in UNC_PATTERN.finditer(without_urls)]
        locals_ = [m.group(1) or m.group(2) for m in LOCAL_PATTERN.finditer(UNC_PATTERN.sub(" ", without_urls))]
        return urls, uncs, locals_

    @staticmethod
    def _extension(path: str) -> str:
        if path.lower().startswith(("http://", "https://")):
            try:
                path = urlsplit(path).path
            except ValueError:
                return ""
        return ntpath.splitext(unquote(path).rstrip("\"'.,;)"))[1].lower()

    def _protected(self, path: str) -> bool:
        path = ntpath.normpath(path).lower()
        return any(path == root or path.startswith(root + "\\") for root in self.privileged_directories)

    def _hostnames(self, command: str, urls: list[str], uncs: list[str]) -> set[str]:
        hosts: set[str] = set()
        for url in urls:
            try:
                host = urlsplit(url).hostname
                if host:
                    hosts.add(host.lower().rstrip("."))
            except ValueError:
                continue
        for path in uncs:
            host = re.split(r"[\\/]", path.lstrip("\\/"), maxsplit=1)[0]
            hosts.add(host.lower())
        for match in IP_PATTERN.finditer(command):
            try:
                hosts.add(str(ipaddress.IPv4Address(match.group())))
            except ipaddress.AddressValueError:
                pass
        # Bare DNS names are useful too. Exclude all known file suffixes and paths.
        file_extensions = EXECUTABLE_EXTENSIONS | self.references.suspicious_extensions | {".txt", ".log", ".json", ".xml", ".csv", ".bin", ".dat", ".png", ".jpg", ".pdf"}
        remaining = URL_PATTERN.sub(" ", command)
        remaining = LOCAL_PATTERN.sub(" ", remaining)
        remaining = UNC_PATTERN.sub(" ", remaining)
        remaining = re.sub(r'^\s*(?:"[^"]*"|[^\s]+)', " ", remaining, count=1)
        file_extensions = file_extensions - {".com"}
        for match in DOMAIN_PATTERN.finditer(remaining):
            host = match.group().lower()
            if ntpath.splitext(host)[1] not in file_extensions:
                hosts.add(host)
        return hosts

    def _untrusted_host(self, host: str) -> bool:
        try:
            address = ipaddress.ip_address(host)
            # Globally routable IPv4; exclude private, loopback, multicast/reserved.
            return address.version == 4 and address.is_global and not address.is_multicast
        except ValueError:
            return any(host == domain or host.endswith("." + domain) for domain in self.references.lots_domains)

    def _ratio_deviation(self, command: str) -> int:
        observed = character_counts(command)
        if not observed.sum():
            return 0
        probabilities = self.corpus.character_ratios + 1e-9
        probabilities /= probabilities.sum()
        expected = probabilities * observed.sum()
        p_value = float(chisquare(observed, f_exp=expected).pvalue)
        return int(p_value > 0.05 if self.f7_mode == "paper" else p_value < 0.05)

    def command_features(self, process: ProcessRecord) -> np.ndarray:
        """Return F1..F18 for one process, using frozen historical statistics."""
        if not self.fitted:
            raise RuntimeError("FeatureExtractor must be fitted before extraction")
        command = process.command_line
        lower = command.lower()
        switches = arguments(command)
        documented = self.references.documentation.get(process.binary_name)
        status = [1, 0, 0] if documented is None else [0, int(switches <= documented), int(not switches <= documented)]
        urls, uncs, local_paths = self._locations(command)
        hosts = self._hostnames(command, urls, uncs)
        tokens = split_command_line(command)
        paths = urls + uncs + local_paths
        # Also consider bare/relative code filenames for F9.
        relative_code = [token for token in tokens if self._extension(token) in EXECUTABLE_EXTENSIONS
                         and token not in paths and not token.lower().startswith(("http://", "https://", "\\\\", "//"))]
        # An unqualified executable name resolves via Image; do not flag the
        # launcher itself merely because argv[0] omits its protected full path.
        if tokens and relative_code and relative_code[0] == tokens[0] and process.image:
            relative_code[0] = process.image
        code_paths = [path for path in paths + relative_code if self._extension(path) in EXECUTABLE_EXTENSIONS]
        extensions = {"." + match.group(1).lower() for match in re.finditer(r"\.([a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)(?=$|[\s\"'/:?&#,;)=])", command)}
        encoded = False
        for token in command.split():
            if len(token) <= 7:
                continue
            try:
                encoded = base64.b64encode(base64.b64decode(token, validate=True)).decode("ascii") == token
            except (ValueError, binascii.Error):
                encoded = False
            if encoded or shannon_entropy(token) > 7.0:
                encoded = True
                break
        values = status + [
            int(any(self.corpus.argument_is_rare(process.binary_name, switch) for switch in switches)),
            int(any(item in lower for item in ("^", '\"\"', "set", "&&", "&&for", "for %", ";;"))),
            int(bool(re.search(r"0x[0-9a-fA-F]{8,}|(?<![0-9a-fA-F])[0-9a-fA-F]{9,}(?![0-9a-fA-F])", command))),
            self._ratio_deviation(command),
            int(any(self._extension(path) in EXECUTABLE_EXTENSIONS for path in urls + uncs)),
            int(any(not self._protected(path) for path in code_paths)),
            int(bool(extensions & (self.references.suspicious_extensions - EXECUTABLE_EXTENSIONS))),
            int(any(self._untrusted_host(host) for host in hosts)),
            int(bool(re.search(r"%[0-9a-fA-F]{2}", command))),
            int(len(hosts) == 1 and len(local_paths) == 1),
            int(any(word in lower for word in ("http", "www.", ".com", "html", "tcp", "udp"))),
            int(encoded),
            int(any(word in lower for word in ("lsass", "samsrv", "hklm\\sam", "winlogon", "netlogon", "kerberos.dll", "dump", ".bin", "ntds"))),
            int(len(local_paths) + len(uncs) >= 2),
            int(bool(ADS_PATTERN.search(URL_PATTERN.sub(" ", command)))),
        ]
        return np.asarray(values, dtype=np.float64)

    @staticmethod
    def filename_mismatch(process: ProcessRecord) -> int:
        """Compare known OriginalFilename to Image and the invoked executable."""
        original = ntpath.basename(process.original_file_name).lower()
        if not original:
            return 0
        names = [process.binary_name] if process.image else []
        tokens = split_command_line(process.command_line)
        if tokens:
            invoked = ntpath.basename(tokens[0]).lower()
            # The .exe suffix is optional when invoking a Windows executable.
            names.append(invoked + ".exe" if not ntpath.splitext(invoked)[1] and original.endswith(".exe") else invoked)
        return int(any(name != original for name in names))

    def extract(self, pair: ProcessPair) -> np.ndarray:
        """Extract one finite float64 vector in the public FEATURE_NAMES order."""
        if not self.fitted:
            raise RuntimeError("FeatureExtractor must be fitted before extraction")
        parent, child = pair.parent, pair.child
        context = np.asarray([
            self.embedder.transform(parent.image), self.embedder.transform(child.image),
            self.filename_mismatch(parent), self.filename_mismatch(child),
            self.corpus.normalized_time(pair.time_diff),
            INTEGRITY_LEVELS.get(parent.integrity_level.lower(), -1),
            INTEGRITY_LEVELS.get(child.integrity_level.lower(), -1),
            int(not (parent.microsoft_signed and child.microsoft_signed)),
        ], dtype=np.float64)
        result = np.concatenate((self.command_features(child), self.command_features(parent), context))
        if result.shape != (44,) or not np.isfinite(result).all():
            raise ValueError("Feature extraction produced an invalid 44-dimensional vector")
        return result

    def transform(self, pairs: Iterable[ProcessPair]) -> pd.DataFrame:
        """Produce a named feature matrix; empty input retains its 44-column schema."""
        rows = [self.extract(pair) for pair in pairs]
        return pd.DataFrame(rows, columns=FEATURE_NAMES, dtype=np.float64)
