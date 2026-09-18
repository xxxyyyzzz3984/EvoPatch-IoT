#!/usr/bin/env python3
"""Run Raspberry Pi BusyBox builds version-by-version with resume support.

This wrapper keeps the disk-saving behavior in pi_compile_orchestrator.py:
after each version is built, outputs and logs are downloaded locally and the
remote per-version artifacts are removed. The wrapper adds resumability and a
single append-only batch log for long Raspberry Pi runs.
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_ROOT / "busybox_unstripped_dataset"
LOCAL_OUT = PROJECT_ROOT / "raspi_build_results"
ARCHES = ["aarch64", "arm", "mips", "mipsel", "x86_64"]


def target_versions() -> list[str]:
    return sorted(p.name for p in DATASET_DIR.iterdir() if p.is_dir() and p.name.startswith("busybox-"))


def is_done(version: str, arch: str, local_out: Path) -> bool:
    binary = local_out / version / f"busybox-{arch}-stripped"
    status = local_out / "logs" / version / f"{arch}.status"
    if not binary.exists() or binary.stat().st_size <= 0:
        return False
    if not status.exists():
        return False
    return status.read_text(errors="replace").strip() == "OK"


def missing_arches(version: str, archs: Sequence[str], local_out: Path) -> list[str]:
    return [arch for arch in archs if not is_done(version, arch, local_out)]


def append_state(path: Path, row: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "time",
                "version",
                "archs",
                "status",
                "returncode",
                "elapsed_sec",
                "note",
            ],
        )
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions", nargs="+", default=["target57"], help="Version names, or target57.")
    parser.add_argument("--archs", nargs="+", default=ARCHES)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--local-out", type=Path, default=LOCAL_OUT)
    parser.add_argument("--log-dir", type=Path, default=PROJECT_ROOT / "raspi_build_results" / "batch_logs")
    parser.add_argument("--password-env", default="PI_SSH_PASSWORD")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.versions == ["target57"]:
        versions = target_versions()
    else:
        versions = list(args.versions)

    run_id = args.run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    batch_log = args.log_dir / f"pi_batch_{run_id}.log"
    state_csv = args.log_dir / "pi_batch_state.csv"

    with batch_log.open("a", encoding="utf-8", errors="replace") as log:
        log.write(f"## batch_start {datetime.now().isoformat()} versions={len(versions)} archs={' '.join(args.archs)}\n")
        log.flush()
        for version in versions:
            todo = missing_arches(version, args.archs, args.local_out)
            if not todo:
                note = "all requested arches already have OK stripped binaries"
                log.write(f"## skip {version}: {note}\n")
                log.flush()
                append_state(
                    state_csv,
                    {
                        "time": datetime.now().isoformat(),
                        "version": version,
                        "archs": " ".join(args.archs),
                        "status": "SKIP",
                        "returncode": "0",
                        "elapsed_sec": "0",
                        "note": note,
                    },
                )
                continue

            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "experiments" / "pi_compile_orchestrator.py"),
                "--versions",
                version,
                "--archs",
                *todo,
                "--jobs",
                str(args.jobs),
                "--local-out",
                str(args.local_out),
            ]
            log.write(f"## build_start {datetime.now().isoformat()} version={version} archs={' '.join(todo)}\n")
            log.write(f"## command {' '.join(cmd)}\n")
            log.flush()
            if args.dry_run:
                rc = 0
                elapsed = 0.0
                status = "DRY_RUN"
            else:
                start = time.time()
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(PROJECT_ROOT),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    env=os.environ.copy(),
                    text=True,
                )
                rc = proc.wait()
                elapsed = time.time() - start
                remaining = missing_arches(version, args.archs, args.local_out)
                status = "OK" if rc == 0 and not remaining else "PARTIAL_OR_FAIL"
                if remaining:
                    log.write(f"## remaining {version}: {' '.join(remaining)}\n")

            log.write(f"## build_done {datetime.now().isoformat()} version={version} rc={rc} elapsed_sec={elapsed:.1f} status={status}\n")
            log.flush()
            append_state(
                state_csv,
                {
                    "time": datetime.now().isoformat(),
                    "version": version,
                    "archs": " ".join(todo),
                    "status": status,
                    "returncode": str(rc),
                    "elapsed_sec": f"{elapsed:.1f}",
                    "note": "",
                },
            )
        log.write(f"## batch_done {datetime.now().isoformat()}\n")
    print(f"batch_log={batch_log}")
    print(f"state_csv={state_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
