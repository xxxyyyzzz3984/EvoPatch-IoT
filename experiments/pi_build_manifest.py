#!/usr/bin/env python3
"""Summarize Raspberry Pi BusyBox stripped build outputs."""

from __future__ import annotations

import argparse
import csv
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_ROOT / "busybox_unstripped_dataset"
LOCAL_OUT = PROJECT_ROOT / "raspi_build_results"
ARCHES = ["aarch64", "arm", "mips", "mipsel", "x86_64"]


def target_versions() -> list[str]:
    return sorted(p.name for p in DATASET_DIR.iterdir() if p.is_dir() and p.name.startswith("busybox-"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def file_brief(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        proc = subprocess.run(["file", str(path)], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        return ""
    return ""


def build_rows(local_out: Path, archs: Sequence[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for version in target_versions():
        for arch in archs:
            binary = local_out / version / f"busybox-{arch}-stripped"
            status_file = local_out / "logs" / version / f"{arch}.status"
            log_file = local_out / "logs" / version / f"{arch}.log"
            status = read_text(status_file) or "MISSING"
            if binary.exists() and binary.stat().st_size > 0 and status == "OK":
                result = "OK"
            elif status != "MISSING":
                result = "FAIL"
            else:
                result = "MISSING"
            rows.append(
                {
                    "version": version,
                    "arch": arch,
                    "result": result,
                    "status": status,
                    "binary_path": str(binary),
                    "binary_size": str(binary.stat().st_size if binary.exists() else 0),
                    "log_path": str(log_file),
                    "log_size": str(log_file.stat().st_size if log_file.exists() else 0),
                    "file_brief": file_brief(binary) if result == "OK" else "",
                }
            )
    return rows


def write_report(rows: list[dict[str, str]], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "stripped_manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    ok = sum(1 for r in rows if r["result"] == "OK")
    fail = sum(1 for r in rows if r["result"] == "FAIL")
    missing = sum(1 for r in rows if r["result"] == "MISSING")
    by_arch = {arch: sum(1 for r in rows if r["arch"] == arch and r["result"] == "OK") for arch in ARCHES}
    by_version = {}
    for r in rows:
        by_version.setdefault(r["version"], 0)
        if r["result"] == "OK":
            by_version[r["version"]] += 1
    complete_versions = sum(1 for v in by_version.values() if v == len(ARCHES))

    report = out_dir / "BUILD_STATUS.md"
    lines = [
        "# Raspberry Pi BusyBox Stripped Build Status",
        "",
        f"- Generated at: {datetime.now().isoformat(timespec='seconds')}",
        f"- Target versions: {len(by_version)}",
        f"- Target binaries: {total}",
        f"- OK binaries: {ok}",
        f"- Failed binaries: {fail}",
        f"- Missing binaries: {missing}",
        f"- Complete 5-arch versions: {complete_versions}",
        "",
        "## OK By Architecture",
        "",
    ]
    for arch in ARCHES:
        lines.append(f"- {arch}: {by_arch[arch]}")
    lines.extend(["", "## Incomplete Versions", ""])
    incomplete = [(v, c) for v, c in by_version.items() if c != len(ARCHES)]
    if incomplete:
        for version, count in incomplete[:80]:
            lines.append(f"- {version}: {count}/{len(ARCHES)} OK")
    else:
        lines.append("- None")
    lines.extend(["", "## Recent Failures", ""])
    failures = [r for r in rows if r["result"] == "FAIL"]
    if failures:
        for r in failures[-80:]:
            lines.append(f"- {r['version']} {r['arch']}: {r['status']}")
    else:
        lines.append("- None")
    lines.append("")
    report.write_text("\n".join(lines), encoding="utf-8")
    return manifest, report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-out", type=Path, default=LOCAL_OUT)
    parser.add_argument("--archs", nargs="+", default=ARCHES)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    rows = build_rows(args.local_out, args.archs)
    manifest, report = write_report(rows, args.local_out)
    print(f"manifest={manifest}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
