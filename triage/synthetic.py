"""Build small, inert Windows PE files for tests and demos.

The files have valid headers, section tables, import tables and (optionally) TLS
callbacks, but their sections hold patterned or random bytes, not code. Nothing here
packs, encrypts or protects a real program, and nothing generated can do anything if
run. They exist so the detections can be tested without shipping real malware or packers.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_BASE = 0x400000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
HEADERS_SIZE = 0x400

CODE = 0x60000020  # code | execute | read
RDATA = 0x40000040  # initialized data | read
DATA = 0xC0000040  # initialized data | read | write
WX = 0xE0000060  # code | initialized data | execute | read | write


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int
    virtual_size: int | None = None  # defaults to len(data); set larger to mimic an unpack-into-memory section


@dataclass
class PESpec:
    sections: list[Section]
    imports: dict[str, list[str]] = field(default_factory=dict)
    entry_section: str = ".text"
    entry_offset: int = 0
    overlay: bytes = b""
    tls_callbacks: int = 0


def _build_idata(imports: dict[str, list[str]], va: int) -> bytes:
    """Import directory, lookup tables, address tables, hint/name entries and DLL names."""
    dlls = list(imports)
    desc_size = 20 * (len(dlls) + 1)
    thunks = [4 * (len(imports[d]) + 1) for d in dlls]
    ilt_off = desc_size
    iat_off = ilt_off + sum(thunks)
    names_off = iat_off + sum(thunks)

    hint_names = bytearray()
    hn_rva: dict[tuple[str, str], int] = {}
    for d in dlls:
        for fn in imports[d]:
            hn_rva[(d, fn)] = va + names_off + len(hint_names)
            entry = struct.pack("<H", 0) + fn.encode() + b"\0"
            hint_names += entry + (b"\0" if len(entry) % 2 else b"")
    dll_off = names_off + len(hint_names)
    dll_names = bytearray()
    dll_rva = {}
    for d in dlls:
        dll_rva[d] = va + dll_off + len(dll_names)
        dll_names += d.encode() + b"\0"

    out = bytearray()
    ilt, iat = bytearray(), bytearray()
    for d in dlls:
        out += struct.pack("<IIIII", va + ilt_off + len(ilt), 0, 0, dll_rva[d], va + iat_off + len(iat))
        for fn in imports[d]:
            ilt += struct.pack("<I", hn_rva[(d, fn)])
            iat += struct.pack("<I", hn_rva[(d, fn)])
        ilt += b"\0" * 4
        iat += b"\0" * 4
    out += b"\0" * 20
    return bytes(out + ilt + iat + hint_names + dll_names)


def build_pe(spec: PESpec) -> bytes:
    sections = list(spec.sections)
    # Lay out user sections first so the import/TLS sections' addresses are known.
    layout = []
    va, raw = SECTION_ALIGN, HEADERS_SIZE
    for s in sections:
        vsize = s.virtual_size or max(len(s.data), 1)
        rsize = _align(len(s.data), FILE_ALIGN) if s.data else 0
        layout.append([s, va, vsize, raw if rsize else 0, rsize])
        va += _align(vsize, SECTION_ALIGN)
        raw += rsize

    data_dirs = [(0, 0)] * 16
    if spec.imports:
        idata = _build_idata(spec.imports, va)
        s = Section(".idata", idata, DATA)
        rsize = _align(len(idata), FILE_ALIGN)
        layout.append([s, va, len(idata), raw, rsize])
        data_dirs[1] = (va, 20 * (len(spec.imports) + 1))
        iat_start = 20 * (len(spec.imports) + 1) + sum(4 * (len(f) + 1) for f in spec.imports.values())
        data_dirs[12] = (va + iat_start, sum(4 * (len(f) + 1) for f in spec.imports.values()))
        va += _align(len(idata), SECTION_ALIGN)
        raw += rsize

    if spec.tls_callbacks:
        # TLS directory (24 bytes), an index slot, then the callback array (VAs, null-terminated).
        tls_va = va
        cb_targets = [IMAGE_BASE + layout[0][1] + 0x10 * i for i in range(spec.tls_callbacks)]
        callbacks_va = IMAGE_BASE + tls_va + 28
        tls = struct.pack("<IIIIII", 0, 0, IMAGE_BASE + tls_va + 24, callbacks_va, 0, 0) + b"\0" * 4
        tls += b"".join(struct.pack("<I", t) for t in cb_targets) + b"\0" * 4
        s = Section(".tls", tls, DATA)
        rsize = _align(len(tls), FILE_ALIGN)
        layout.append([s, va, len(tls), raw, rsize])
        data_dirs[9] = (tls_va, 24)
        va += _align(len(tls), SECTION_ALIGN)
        raw += rsize

    size_of_image = va
    entry = next(L for L in layout if L[0].name == spec.entry_section)
    entry_rva = entry[1] + spec.entry_offset
    code_size = sum(L[4] for L in layout if L[0].characteristics & 0x20)

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, len(layout), 0x5F000000, 0, 0, 0xE0, 0x0102)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, code_size, 0, 0, entry_rva, layout[0][1], layout[0][1], IMAGE_BASE, SECTION_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0, 0, size_of_image, HEADERS_SIZE, 0, 2, 0x8140,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"".join(struct.pack("<II", *d) for d in data_dirs)
    table = b"".join(
        struct.pack("<8sIIIIIIHHI", s.name.encode()[:8], vsize, sva, rsize, rptr, 0, 0, 0, 0, s.characteristics)
        for s, sva, vsize, rptr, rsize in layout
    )
    header = bytes(dos) + b"PE\0\0" + coff + opt + table
    assert len(header) <= HEADERS_SIZE, "too many sections for the header size"
    out = bytearray(header.ljust(HEADERS_SIZE, b"\0"))
    for s, _sva, _vsize, _rptr, rsize in layout:
        if rsize:
            out += s.data.ljust(rsize, b"\0")
    return bytes(out + spec.overlay)


# ---------- sample set ----------

def _random(n: int, seed: int) -> bytes:
    return random.Random(seed).randbytes(n)


def _patterned(n: int) -> bytes:
    # Low-entropy filler shaped a little like compiled code (repeating prologue/epilogue-like bytes).
    chunk = bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x8B, 0x45, 0x08, 0x5F, 0x5E, 0x5B, 0xC9, 0xC3, 0xCC])
    return (chunk * (n // len(chunk) + 1))[:n]


NORMAL_IMPORTS = {
    "KERNEL32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc", "HeapFree",
                     "GetProcessHeap", "GetModuleHandleW", "GetCommandLineW", "ExitProcess", "Sleep"],
    "USER32.dll": ["MessageBoxW", "GetWindowTextW", "SetWindowTextW"],
    "ADVAPI32.dll": ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"],
}
LOADER_IMPORTS = {"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect", "ExitProcess"]}


def samples() -> dict[str, tuple[bytes, str]]:
    """name -> (file bytes, what it imitates)."""
    text = Section(".text", _patterned(0x3000), CODE)
    rdata = Section(".rdata", b"Contoso Utility\0Version 1.0\0" * 40, RDATA)
    data = Section(".data", b"\0" * 0x200, DATA)
    return {
        "benign-app.exe": (
            build_pe(PESpec([text, rdata, data], NORMAL_IMPORTS)),
            "Ordinary compiled program: normal sections, low entropy, full import table.",
        ),
        "upx-style.exe": (
            build_pe(PESpec(
                [Section("UPX0", b"", WX, virtual_size=0x8000), Section("UPX1", _random(0x2800, 1), WX),
                 Section(".rsrc", b"\0" * 0x200, RDATA)],
                LOADER_IMPORTS, entry_section="UPX1", entry_offset=0x2600)),
            "UPX-style layout: empty section that expands in memory, compressed section, loader-only imports.",
        ),
        "protector-style.exe": (
            build_pe(PESpec(
                [text, rdata, Section(".vmp0", _random(0x1000, 2), CODE), Section(".vmp1", _random(0x3000, 3), CODE)],
                {"KERNEL32.dll": ["GetModuleHandleA", "GetProcAddress", "VirtualAlloc"]},
                entry_section=".vmp1", entry_offset=0x100, tls_callbacks=2)),
            "Protector-style layout: virtualization-protector section names, entry point in the last section, TLS callbacks.",
        ),
        "crypter-style.exe": (
            build_pe(PESpec(
                [Section(".text", _random(0x1800, 4), WX), Section(".data", b"\0" * 0x200, DATA)],
                LOADER_IMPORTS, overlay=_random(0x6000, 5))),
            "Crypter-style layout: normal section names but encrypted-looking code, loader-only imports, large encrypted overlay.",
        ),
        "installer-style.exe": (
            build_pe(PESpec([text, rdata, data], NORMAL_IMPORTS, overlay=_random(0x4000, 6))),
            "Installer-style layout: ordinary program with a large compressed payload appended (common and usually benign).",
        ),
    }


def write_samples(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, (blob, _desc) in samples().items():
        p = out_dir / name
        p.write_bytes(blob)
        paths.append(p)
    return paths
