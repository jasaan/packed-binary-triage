"""triage: score Windows executables for signs of packing, crypters and protectors.

    python -m triage scan PATH [PATH ...] [--json] [--min-score N] [--yara]
    python -m triage samples OUT_DIR      # write the inert synthetic test samples
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyze import analyze_file
from .synthetic import samples, write_samples

RULES = Path(__file__).resolve().parent.parent / "rules" / "packed.yar"


def _files(paths: list[Path]):
    for p in paths:
        if p.is_dir():
            yield from (f for f in sorted(p.rglob("*")) if f.is_file())
        else:
            yield p


def _yara_matches(path: Path) -> list[str]:
    try:
        import yara
    except ImportError:
        return ["(yara-python not installed)"]
    if not hasattr(_yara_matches, "rules"):
        _yara_matches.rules = yara.compile(filepath=str(RULES))
    return [m.rule for m in _yara_matches.rules.match(str(path))]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="triage", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Score PE files (directories are scanned recursively)")
    s.add_argument("paths", type=Path, nargs="+")
    s.add_argument("--json", action="store_true", help="One JSON object per file")
    s.add_argument("--min-score", type=int, default=0, help="Only show files scoring at least this")
    s.add_argument("--yara", action="store_true", help="Also run rules/packed.yar")
    s = sub.add_parser("samples", help="Write the inert synthetic samples used by the tests")
    s.add_argument("out", type=Path)
    a = p.parse_args(argv)

    if a.cmd == "samples":
        for path in write_samples(a.out):
            print(f"{path}  {samples()[path.name][1]}")
        return 0

    flagged = 0
    for f in _files(a.paths):
        try:
            r = analyze_file(f)
        except ValueError:
            continue  # not a PE file; skip quietly when scanning folders
        if r.score < a.min_score:
            continue
        flagged += r.score >= 60
        yara_hits = _yara_matches(f) if a.yara else None
        if a.json:
            print(json.dumps(r.to_dict() | ({"yara": yara_hits} if yara_hits is not None else {})))
            continue
        print(f"\n{f}\n  score {r.score}/100: {r.verdict}  [{r.technique}]")
        for fd in r.findings:
            print(f"  +{fd.points:<3} {fd.check}: {fd.detail}")
        for c in r.context:
            print(f"  note: {c}")
        if yara_hits is not None:
            print(f"  yara: {', '.join(yara_hits) or 'no matches'}")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
