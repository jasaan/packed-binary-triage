# packed-binary-triage

**Explainable static triage of Windows executables for packing, crypters and protectors** ([MITRE ATT&CK T1027.002, Software Packing](https://attack.mitre.org/techniques/T1027/002/)), with matching YARA rules and a Microsoft Defender for Endpoint hunt to find candidates.

Packers, crypters and protectors hide a program's real code until it runs, which defeats signature scanning and slows analysis. Attackers use them on nearly every commodity payload. So do installers, games and licensed commercial software. A useful triage tool therefore doesn't just say "packed": it says **why**, so an analyst can decide quickly whether to detonate, unpack or move on.

```
$ python -m triage scan samples/crypter-style.exe

samples/crypter-style.exe
  score 85/100: likely packed or protected  [T1027.002 Software Packing]
  +30  high_entropy_code: Executable section(s) look compressed or encrypted: .text (7.97). Compiled code is usually below 7.2.
  +20  writable_executable: Section(s) ['.text'] are both writable and executable, typical of a stub that unpacks code in place.
  +20  loader_only_imports: Only 4 imported functions, including ['getprocaddress', 'loadlibrarya', 'virtualprotect']: enough to load the real imports after unpacking.
  +15  encrypted_overlay: 24,576 bytes (75% of the file) are appended after the last section with entropy 7.99: an encrypted or compressed payload. Installers do this too.
```

That file has ordinary section names, so name-based rules miss it. The structural checks don't.

## What it checks

| Check | Points | Why it matters |
|---|---|---|
| Packer / protector section names | 35 | `UPX0/1`, `.aspack`, `.themida`, `.vmp0/1`, `.MPRESS1`, `PEC2`, `.enigma1` and others name the tool outright. |
| High-entropy code section | 30 | Compiled code sits around 5.5–6.8 bits per byte; compressed or encrypted data approaches 8. |
| Writable **and** executable section | 20 | A stub that decrypts or decompresses code in place needs to write where it executes. |
| Section empty on disk, large in memory | 15 | Space reserved for the unpacked code (the classic UPX layout). |
| Entry point in an unusual place | 15–25 | Outside every section, in a data section, or in a code section other than the first: where an added stub lives. |
| No imports, or loader-only imports | 20 | A stub needs only `LoadLibrary` + `GetProcAddress` (plus `VirtualProtect`/`VirtualAlloc`) to rebuild the real import table after unpacking. |
| Encrypted overlay | 15 | A large high-entropy payload appended after the last section. Crypters do this; so do installers, which is why it scores low on its own. |
| TLS callbacks | 10 | Code that runs before the entry point, a favourite place for protector anti-debugging checks. |

Scores add up to a maximum of 100: **60+** likely packed or protected, **30–59** suspicious (review), below 30 no strong signs. Context that shouldn't move the score (an Authenticode signature, high-entropy resources) is listed as a note.

## YARA rules

[`rules/packed.yar`](rules/packed.yar) has the same logic for scanners and EDR/sandbox pipelines that take YARA:

`Packer_Section_Names` · `High_Entropy_Executable_Section` · `Writable_Executable_Section` · `Loader_Only_Imports` · `Encrypted_Overlay` · **`Likely_Packed_Or_Protected`** (any two of the above; the one to alert on)

```bash
yara -r rules/packed.yar /path/to/files
python -m triage scan /path/to/files --yara      # or both together
```

## Finding candidates: Defender for Endpoint hunt

[`hunts/unsigned-rare-exe-user-paths.kql`](hunts/unsigned-rare-exe-user-paths.kql) finds executables that are **unsigned (or untrusted), started from user-writable folders, seen on three or fewer of your devices, and rare worldwide** (`FileProfile()` global prevalence). Those are the files worth pulling and triaging. A self-checking test with an attack row and four near misses (signed, Program Files, allow-listed, common across the estate) is in [`unsigned-rare-exe-user-paths.test.kql`](hunts/unsigned-rare-exe-user-paths.test.kql). Paste it into any Azure Data Explorer cluster; it should return `PASS`.

The workflow: **hunt** for rare unsigned executables → **collect** the file (Defender "Collect file" or Live Response) → **triage** it here → detonate or unpack what scores high, and add the hash/signer to the hunt's allow list when it's legitimate.

## Test samples are synthetic and inert

There are no real malware samples or packers in this repo. [`triage/synthetic.py`](triage/synthetic.py) builds small PE files at test time with valid headers, section tables, import tables and TLS directories, but sections filled with random or patterned bytes instead of code. Nothing generated can do anything if run. They imitate five layouts:

| Sample | Imitates | Triage score | YARA |
|---|---|---|---|
| `benign-app.exe` | ordinary compiled program | 0 | none |
| `installer-style.exe` | program + compressed payload appended | 15 | `Encrypted_Overlay` only |
| `crypter-style.exe` | normal names, encrypted code, loader-only imports, encrypted overlay | 85 | combined rule |
| `upx-style.exe` | UPX layout | 100 | combined rule |
| `protector-style.exe` | VMProtect-style sections, TLS callbacks | 100 | combined rule |

```bash
python -m triage samples samples/   # write them out to try the tools
```

Because they're built to *look* packed, some antivirus products may flag the generated files. That's the point, but generate them somewhere your AV won't quarantine them. They're excluded from git.

## Limits

- Static structure only. A well-made protector can look ordinary on disk, and a custom packer won't have a known section name. Behaviour (memory allocations, self-modifying code) and detonation catch what this doesn't.
- Packed isn't malicious. Always weigh signer, prevalence and context. The score is for prioritising analyst time, not for blocking.
- 32- and 64-bit PE files are both parsed by `pefile`; the synthetic samples are 32-bit.

## Use

```bash
pip install -e ".[dev]"
python -m triage scan PATH [PATH ...] [--json] [--min-score 60] [--yara]
```

Exit code 1 means at least one file scored 60 or more, so it can gate a pipeline. `--json` prints one object per file for a SIEM or notebook.

```bash
ruff check . && pytest -q    # 21 tests: Python checks, YARA rules and CLI, all on the synthetic samples
```

Built with Claude; designed, reviewed and tested by me.

## License

MIT
