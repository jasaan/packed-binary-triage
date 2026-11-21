"""Static triage of Windows PE files for signs of packing, encryption (crypters) and protectors.

Packing hides code from static analysis and signature scanning (MITRE ATT&CK T1027.002,
Software Packing). It isn't proof of malice: installers, games and licensed commercial
software are often packed or protected. This tool explains *why* a file looks packed so an
analyst can decide what to do next (detonate, unpack, check signer and prevalence).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pefile

HIGH_ENTROPY = 7.2  # compressed or encrypted data sits near 8.0; compiled code is usually 5.5-6.8

# Section names left by common packers and protectors (lower-cased).
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    "pec2": "PECompact", "pecompact2": "PECompact", ".pec": "PECompact",
    ".mew": "MEW", ".fsg": "FSG", ".perplex": "Perplex", ".yp": "Y0da Protector", ".obsidium": "Obsidium",
}
# A stub that resolves the real imports at runtime only needs a handful of loader functions.
LOADER_FUNCS = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress",
                "getmodulehandlea", "getmodulehandlew", "virtualalloc", "virtualprotect", "ldrloaddll"}

SCN_EXECUTE, SCN_WRITE, SCN_CODE = 0x20000000, 0x80000000, 0x20

TECHNIQUE = "T1027.002 Software Packing"


@dataclass
class Finding:
    check: str
    points: int
    detail: str


@dataclass
class Result:
    path: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    technique: str = TECHNIQUE

    def to_dict(self) -> dict:
        return asdict(self)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _name(section) -> str:
    return section.Name.rstrip(b"\0").decode("latin-1")


def _is_exec(section) -> bool:
    return bool(section.Characteristics & (SCN_EXECUTE | SCN_CODE))


def verdict_for(score: int) -> str:
    if score >= 60:
        return "likely packed or protected"
    if score >= 30:
        return "suspicious: review"
    return "no strong signs of packing"


def analyze_pe(pe: pefile.PE, path: str = "") -> Result:
    findings: list[Finding] = []
    context: list[str] = []
    secs = list(pe.sections)
    info = [{"name": _name(s), "entropy": round(entropy(s.get_data()), 2), "raw_size": s.SizeOfRawData,
             "virtual_size": s.Misc_VirtualSize, "exec": _is_exec(s), "write": bool(s.Characteristics & SCN_WRITE)}
            for s in secs]

    # 1. Packer / protector section names
    tools = sorted({PACKER_SECTIONS[i["name"].lower()] for i in info if i["name"].lower() in PACKER_SECTIONS})
    if tools:
        names = [i["name"] for i in info if i["name"].lower() in PACKER_SECTIONS]
        findings.append(Finding("packer_section_names", 35, f"Section names {names} are left by {', '.join(tools)}."))

    # 2. High entropy: compressed or encrypted content
    hot_exec = [i for i in info if i["exec"] and i["entropy"] >= HIGH_ENTROPY]
    hot_other = [i for i in info if not i["exec"] and i["entropy"] >= HIGH_ENTROPY and i["name"].lower() != ".rsrc"]
    if hot_exec:
        findings.append(Finding("high_entropy_code", 30, "Executable section(s) look compressed or encrypted: "
                                + ", ".join(f"{i['name']} ({i['entropy']})" for i in hot_exec)
                                + f". Compiled code is usually below {HIGH_ENTROPY}."))
    elif hot_other:
        findings.append(Finding("high_entropy_data", 15, "Data section(s) look compressed or encrypted: "
                                + ", ".join(f"{i['name']} ({i['entropy']})" for i in hot_other) + "."))

    # 3. Writable + executable sections (code that rewrites itself in memory)
    wx = [i["name"] for i in info if i["exec"] and i["write"]]
    if wx:
        findings.append(Finding("writable_executable", 20, f"Section(s) {wx} are both writable and executable, "
                                "typical of a stub that unpacks code in place."))

    # 4. Section that is empty on disk but large in memory (unpacked into at runtime)
    hollow = [i["name"] for i in info if i["raw_size"] == 0 and i["virtual_size"] >= 0x1000]
    if hollow:
        findings.append(Finding("empty_on_disk", 15, f"Section(s) {hollow} are empty on disk but reserve memory, "
                                "where unpacked code is usually written."))

    # 5. Entry point location
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_sec = next((s for s in secs if s.contains_rva(ep)), None)
    first_exec = next((s for s in secs if _is_exec(s)), None)
    if ep_sec is None:
        findings.append(Finding("entry_point_outside_sections", 25, f"Entry point 0x{ep:x} is outside every section."))
    elif not _is_exec(ep_sec):
        findings.append(Finding("entry_point_not_code", 25, f"Entry point is in non-executable section {_name(ep_sec)}."))
    elif first_exec is not None and ep_sec is not first_exec:
        findings.append(Finding("entry_point_unusual_section", 15, f"Entry point is in {_name(ep_sec)}, not the first "
                                f"code section ({_name(first_exec)}): typical of an unpacking stub added to the file."))

    # 6. Imports
    imports = [(e.dll.decode("latin-1").lower(), (imp.name or b"").decode("latin-1").lower())
               for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for imp in e.imports]
    funcs = {f for _, f in imports if f}
    if not imports:
        findings.append(Finding("no_imports", 20, "No import table: the file must find every API itself at runtime."))
    elif len(funcs) < 10 and funcs & LOADER_FUNCS:
        findings.append(Finding("loader_only_imports", 20, f"Only {len(funcs)} imported functions, including "
                                f"{sorted(funcs & LOADER_FUNCS)}: enough to load the real imports after unpacking."))

    # 7. Overlay (data appended after the last section)
    overlay_at = pe.get_overlay_data_start_offset()
    size = len(pe.__data__)
    if overlay_at is not None:
        overlay = pe.__data__[overlay_at:]
        ent = entropy(overlay)
        share = len(overlay) / size
        if ent >= HIGH_ENTROPY and share >= 0.10:
            findings.append(Finding("encrypted_overlay", 15, f"{len(overlay):,} bytes ({share:.0%} of the file) are "
                                    f"appended after the last section with entropy {ent:.2f}: an encrypted or "
                                    "compressed payload. Installers do this too."))
        else:
            context.append(f"Overlay of {len(overlay):,} bytes (entropy {ent:.2f}).")

    # 8. TLS callbacks (code that runs before the entry point; used for anti-debugging)
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None and tls.struct.AddressOfCallBacks:
        findings.append(Finding("tls_callbacks", 10, "TLS callbacks run code before the entry point, a common "
                                "place for protector anti-debugging checks."))

    # Context that doesn't change the score
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
        context.append("Has an Authenticode signature (not verified here): check the signer before deciding.")
    if any(i["name"].lower() == ".rsrc" and i["entropy"] >= HIGH_ENTROPY for i in info):
        context.append("High-entropy resources (often compressed images or embedded installers).")

    score = min(100, sum(f.points for f in findings))
    return Result(path, score, verdict_for(score), findings, context, info)


def analyze_file(path: Path) -> Result:
    data = Path(path).read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as err:
        raise ValueError(f"{path}: not a PE file ({err})") from err
    try:
        return analyze_pe(pe, str(path))
    finally:
        pe.close()
