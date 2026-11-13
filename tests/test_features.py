"""Behavioral cases for all 26 feature IDs and their 44-column representation."""

from dataclasses import replace

import numpy as np
import pytest

from src.data_loader import ProcessPair, ProcessRecord
from src.enricher import CorpusEnricher, arguments, split_command_line
from src.features import FEATURE_NAMES, shannon_entropy


def process(command, image=r"C:\Windows\System32\cmd.exe"):
    return ProcessRecord(image=image, command_line=command)


@pytest.mark.parametrize(("feature", "command"), [
    (4, "cmd.exe /never-seen"),
    (5, "cmd.exe /c c^alc.exe && echo done"),
    (6, "cmd.exe 0x0123456789abcdef"),
    (7, "cmd.exe " + "9" * 300),
    (8, "cmd.exe /c https://example.org/a.dll"),
    (8, r"cmd.exe /c \\server\share\run.ps1"),
    (8, r'cmd.exe /c "\\server\Shared Folder\run.ps1"'),
    (9, r"cmd.exe /c C:\Users\Public\run.ps1"),
    (9, r"cmd.exe /c C:\WindowsEvil\run.exe"),
    (9, r"cmd.exe /c C:\Windows\..\Temp\run.exe"),
    (10, "cmd.exe /c invoice.docm"),
    (11, "cmd.exe https://raw.githubusercontent.com/a"),
    (11, "cmd.exe https://8.8.8.8/a"),
    (11, "cmd.exe github.com"),
    (12, "cmd.exe https://example.org/a%20b"),
    (13, r"cmd.exe https://example.org/a C:\Temp\a.txt"),
    (13, r"cmd.exe example.com C:\Temp\a.txt"),
    (14, "cmd.exe tcp://example.org"),
    (15, "cmd.exe SQBFAFgAIAAxAA=="),
    (16, r"cmd.exe /c reg save HKLM\SAM C:\Temp\sam.bin"),
    (17, 'cmd.exe /c copy "C:\\Program Files\\a.txt" "D:\\Backup\\a.txt"'),
    (18, r"cmd.exe /c C:\Temp\foo.txt:bar.exe"),
])
def test_positive_command_features(extractor, feature, command):
    assert extractor.command_features(process(command))[feature - 1] == 1


def test_documentation_one_hot_and_known_switches(extractor):
    for cmd, image, expected in [
        ("unknown.exe /a", r"C:\unknown.exe", [1, 0, 0]),
        ("cmd.exe /c echo hi", r"C:\Windows\System32\cmd.exe", [0, 1, 0]),
        ("cmd.exe /nonexistent", r"C:\Windows\System32\cmd.exe", [0, 0, 1]),
    ]:
        assert extractor.command_features(process(cmd, image))[:3].tolist() == expected


@pytest.mark.parametrize(("feature", "command"), [
    (4, "cmd.exe /c hi"), (5, "cmd.exe /c echo hello"), (6, "cmd.exe abc123"),
    (8, "cmd.exe https://example.org/a.txt"), (9, r"cmd.exe /c C:\Windows\run.exe"),
    (10, "cmd.exe /c run.ps1"), (11, "cmd.exe http://10.1.2.3/a"),
    (11, "cmd.exe https://github.com.attacker.example/a"),
    (11, "cmd.exe http://127.0.0.1/a"), (12, "cmd.exe %TEMP%"),
    (13, r"cmd.exe https://example.org/a https://another.org/b C:\a.txt"),
    (14, "cmd.exe /c echo hello"), (15, "cmd.exe short"),
    (16, "cmd.exe /c echo hello"), (17, r"cmd.exe C:\a.txt"),
    (18, r"cmd.exe https://example.org/file.exe:8080"),
])
def test_negative_command_features(extractor, feature, command):
    assert extractor.command_features(process(command))[feature - 1] == 0


def test_context_vector_order_and_missing_values(extractor, history):
    pair = history[0]
    pair = replace(pair, parent=replace(pair.parent, image=r"C:\Temp\renamed.exe", command_line="renamed.exe"),
                   child=replace(pair.child, integrity_level="System", signature_valid=False))
    vector = extractor.extract(pair)
    assert vector.shape == (44,) and len(FEATURE_NAMES) == 44 and np.isfinite(vector).all()
    assert set(vector[:36]) <= {0, 1}
    assert vector[36] == extractor.embedder.transform(pair.parent.image)
    assert vector[37] == extractor.embedder.transform(pair.child.image)
    assert vector[38:].tolist() == [1, 0, 0, 3, 5, 1]
    pair = ProcessPair(ProcessRecord(image="p.exe"), ProcessRecord(image="c.exe"))
    assert extractor.extract(pair)[38:].tolist() == [0, 0, 0, -1, -1, 1]


def test_f7_paper_mode_reproduces_inverted_condition(extractor):
    command = "cmd.exe " + "9" * 300
    assert extractor.command_features(process(command))[6] == 1
    extractor.f7_mode = "paper"
    assert extractor.command_features(process(command))[6] == 0


def test_argument_frequency_denominator_and_frozen_state(history):
    corpus = CorpusEnricher().fit(history)
    assert corpus.execution_counts["cmd.exe"] == 120
    assert corpus.execution_counts["explorer.exe"] == 1
    assert not corpus.argument_is_rare("cmd.exe", "/q")
    assert corpus.argument_is_rare("cmd.exe", "/unknown")
    assert corpus.normalized_time(999999) == 1
    assert corpus.normalized_time(-1) == 0
    assert CorpusEnricher().fit([history[0]]).normalized_time(1) == 0


def test_windows_paths_and_argument_values():
    command = r'"C:\Program Files\tool.exe" /i:https://example.org/a -x=1 "C:\Some Folder\a.txt"'
    assert split_command_line(command) == [r"C:\Program Files\tool.exe", "/i:https://example.org/a", "-x=1", r"C:\Some Folder\a.txt"]
    assert arguments(command) == {"/i", "-x"}


def test_entropy_encryption_branch(extractor):
    # Latin extended letters avoid whitespace and supply >128 distinct symbols.
    token = "".join(chr(i) for i in range(0x100, 0x200))
    assert shannon_entropy(token) > 7
    assert extractor.command_features(process("cmd.exe " + token))[14] == 1


def test_true_fasttext_nonconstant_oov_and_no_refit(extractor, history):
    assert extractor.embedder.model.get_dimension() == 1
    values = [extractor.embedder.transform(p) for p in [r"C:\Windows\explorer.exe", r"C:\Windows\System32\cmd.exe", r"C:\new\unseen.exe"]]
    assert np.isfinite(values).all() and len(set(values)) > 1
    previous = dict(extractor.corpus.execution_counts)
    extractor.transform(history[:1])
    assert dict(extractor.corpus.execution_counts) == previous
