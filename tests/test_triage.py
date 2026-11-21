import json

import pefile
import pytest
import yara

from triage.__main__ import RULES, main
from triage.analyze import analyze_pe, entropy, verdict_for
from triage.synthetic import CODE, LOADER_IMPORTS, NORMAL_IMPORTS, WX, PESpec, Section, _patterned, _random, build_pe, samples

SAMPLES = samples()
RULESET = yara.compile(filepath=str(RULES))


def triage(blob: bytes):
    return analyze_pe(pefile.PE(data=blob))


def checks(blob: bytes) -> set[str]:
    return {f.check for f in triage(blob).findings}


def yara_hits(blob: bytes) -> set[str]:
    return {m.rule for m in RULESET.match(data=blob)}


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"A" * 100) == 0.0
    assert entropy(bytes(range(256)) * 4) == pytest.approx(8.0)


@pytest.mark.parametrize("name, low, high", [
    ("benign-app.exe", 0, 0),
    ("installer-style.exe", 1, 29),     # noted, not flagged
    ("crypter-style.exe", 60, 100),     # caught with no packer names at all
    ("upx-style.exe", 60, 100),
    ("protector-style.exe", 60, 100),
])
def test_sample_scores(name, low, high):
    assert low <= triage(SAMPLES[name][0]).score <= high


def test_upx_style_findings():
    assert checks(SAMPLES["upx-style.exe"][0]) >= {
        "packer_section_names", "high_entropy_code", "writable_executable", "empty_on_disk",
        "entry_point_unusual_section", "loader_only_imports"}


def test_protector_style_findings():
    found = checks(SAMPLES["protector-style.exe"][0])
    assert {"packer_section_names", "tls_callbacks", "entry_point_unusual_section"} <= found
    assert "VMProtect" in triage(SAMPLES["protector-style.exe"][0]).findings[0].detail


def test_crypter_style_is_caught_generically():
    found = checks(SAMPLES["crypter-style.exe"][0])
    assert "packer_section_names" not in found
    assert {"high_entropy_code", "loader_only_imports", "encrypted_overlay"} <= found


def test_no_imports_and_entry_point_outside_code():
    blob = build_pe(PESpec([Section(".text", _patterned(0x1000), CODE), Section(".data", _random(0x1000, 9), 0xC0000040)],
                           imports={}, entry_section=".data"))
    found = checks(blob)
    assert {"no_imports", "entry_point_not_code", "high_entropy_data"} <= found


def test_normal_program_with_full_imports_is_not_loader_only():
    blob = build_pe(PESpec([Section(".text", _patterned(0x1000), CODE)], NORMAL_IMPORTS))
    assert "loader_only_imports" not in checks(blob)


def test_verdict_thresholds():
    assert (verdict_for(0), verdict_for(30), verdict_for(60)) == (
        "no strong signs of packing", "suspicious: review", "likely packed or protected")


# ---------- YARA agrees with the Python checks ----------

def test_yara_benign_has_no_hits():
    assert yara_hits(SAMPLES["benign-app.exe"][0]) == set()


def test_yara_installer_only_overlay():
    assert yara_hits(SAMPLES["installer-style.exe"][0]) == {"Encrypted_Overlay"}


@pytest.mark.parametrize("name", ["upx-style.exe", "protector-style.exe", "crypter-style.exe"])
def test_yara_combined_rule_fires_on_packed_samples(name):
    assert "Likely_Packed_Or_Protected" in yara_hits(SAMPLES[name][0])


def test_yara_section_names_only_where_names_exist():
    assert "Packer_Section_Names" in yara_hits(SAMPLES["upx-style.exe"][0])
    assert "Packer_Section_Names" not in yara_hits(SAMPLES["crypter-style.exe"][0])


def test_yara_writable_executable():
    blob = build_pe(PESpec([Section(".text", _patterned(0x1000), WX)], LOADER_IMPORTS))
    assert "Writable_Executable_Section" in yara_hits(blob)


# ---------- CLI ----------

def test_cli_scan_json_and_exit_code(tmp_path, capsys):
    assert main(["samples", str(tmp_path)]) == 0
    (tmp_path / "notes.txt").write_text("not a PE file")
    capsys.readouterr()
    assert main(["scan", str(tmp_path), "--json", "--yara", "--min-score", "60"]) == 1  # 1 = something flagged
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert sorted(r["path"].rsplit("/", 1)[-1] for r in rows) == ["crypter-style.exe", "protector-style.exe", "upx-style.exe"]
    assert all("Likely_Packed_Or_Protected" in r["yara"] for r in rows)


def test_cli_clean_folder_exits_zero(tmp_path):
    (tmp_path / "app.exe").write_bytes(SAMPLES["benign-app.exe"][0])
    assert main(["scan", str(tmp_path)]) == 0
