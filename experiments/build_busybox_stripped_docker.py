#!/usr/bin/env python3
"""Safe Docker preflight/helper for future BusyBox stripped builds.

Default mode only performs preflight checks. It does not pull images or install
packages because Docker Desktop may store image layers outside this project.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = PROJECT_ROOT / "busybox_sources_codes"
DEFAULT_OUT = PROJECT_ROOT / "experiments" / "artifacts" / "docker_stripped_builds"
DEFAULT_LOG = PROJECT_ROOT / "experiments" / "runs" / "docker_build_preflight.json"


def run_cmd(args: Sequence[str], timeout: int = 120) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", (exc.stderr or "") + f"\nTIMEOUT after {timeout}s"


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--image", default="evobin-iot-busybox-builder:local")
    parser.add_argument("--version", action="append", help="BusyBox version directory name, e.g. busybox-1.37.0")
    parser.add_argument("--arch", action="append", default=[], help="Target architecture. Repeatable.")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--allow-pull", action="store_true", help="Allow Docker image pull/build steps after storage is confirmed.")
    parser.add_argument("--execute", action="store_true", help="Actually run Docker commands after preflight.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    docker = shutil.which("docker")
    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "sources": str(args.sources),
        "out": str(args.out),
        "image": args.image,
        "requested_versions": args.version or [],
        "requested_arches": args.arch or [],
        "docker_path": docker,
        "allow_pull": bool(args.allow_pull),
        "execute": bool(args.execute),
        "status": "preflight",
        "notes": [],
        "commands": [],
    }
    if not docker:
        result["status"] = "blocked"
        result["notes"].append("Docker was not found in PATH. No build was attempted.")
        write_json(args.log, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2
    code, stdout, stderr = run_cmd([docker, "--version"], timeout=30)
    result["docker_version_rc"] = code
    result["docker_version"] = (stdout or stderr).strip()
    if not args.execute:
        result["status"] = "preflight_only"
        result["notes"].append("Use --execute to run Docker commands. Use --allow-pull only after confirming Docker storage is not on the system disk.")
        write_json(args.log, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if not args.allow_pull:
        result["status"] = "blocked"
        result["notes"].append("Execution requested but --allow-pull was not set. Refusing to pull/build images implicitly.")
        write_json(args.log, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 3
    result["status"] = "not_implemented"
    result["notes"].append("Docker command generation is reserved for the next step after confirming local Docker storage and target cross-toolchains.")
    write_json(args.log, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
