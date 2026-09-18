#!/usr/bin/env python3
"""Run Ghidra headless feature extraction on aligned BusyBox stripped binaries.

This script is the next engineering step after the symbol-label and anonymous
statistics baselines.  It keeps unstripped binaries as label anchors only and
extracts model-facing features from stripped binaries with Ghidra headless.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STRIPPED = PROJECT_ROOT / "busybox_stripped_dataset"
DEFAULT_UNSTRIPPED = PROJECT_ROOT / "busybox_unstripped_dataset"
DEFAULT_GHIDRA = PROJECT_ROOT / "ghidra"
DEFAULT_EXPERIMENTS = PROJECT_ROOT / "experiments"
GHIDRA_SCRIPT_DIR = DEFAULT_EXPERIMENTS / "ghidra_scripts"
RUNS_DIR = DEFAULT_EXPERIMENTS / "runs"

BINARY_RE = re.compile(r"^busybox-(?P<arch>.+?)-(?P<kind>stripped|unstripped)$")


def now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def version_tuple(version: str) -> Tuple[int, ...]:
    raw = version.replace("busybox-", "")
    parts: List[int] = []
    for item in raw.split("."):
        match = re.match(r"\d+", item)
        parts.append(int(match.group(0)) if match else 0)
    return tuple(parts)


def short_version(version: str) -> str:
    return version.replace("busybox-", "")


def binary_id(version: str, arch: str) -> str:
    return f"{version}-{arch}-stripped"


def parse_csv_list(raw: Optional[str]) -> Optional[set]:
    if not raw:
        return None
    return {item.strip() for item in raw.split(",") if item.strip()}


def write_json(path: Path, obj: object) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def write_csv(path: Path, rows: Iterable[dict], fieldnames: Sequence[str]) -> int:
    ensure_dir(path.parent)
    count = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def run_cmd(args: Sequence[str], timeout: int, env: Optional[dict] = None,
            cwd: Optional[Path] = None) -> Tuple[int, str, str, float]:
    start = time.time()
    try:
        proc = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, time.time() - start
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr + f"\nTIMEOUT after {timeout}s", time.time() - start
    except FileNotFoundError as exc:
        return 127, "", str(exc), time.time() - start


class RunContext:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.status_path = run_dir / "status_events.jsonl"
        ensure_dir(run_dir)
        ensure_dir(run_dir / "features")
        ensure_dir(run_dir / "summaries")
        ensure_dir(run_dir / "logs")

    def setup_logging(self) -> None:
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(self.run_dir / "run.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    def event(self, step: str, status: str, **extra: object) -> None:
        row = {"timestamp": datetime.now().isoformat(timespec="seconds"), "step": step, "status": status, **extra}
        with self.status_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    @contextmanager
    def step(self, name: str) -> Iterator[None]:
        start = time.time()
        logging.info("START %s", name)
        self.event(name, "started")
        try:
            yield
        except Exception as exc:
            duration = time.time() - start
            logging.exception("FAILED %s", name)
            self.event(name, "failed", duration_sec=round(duration, 3), error=str(exc))
            raise
        else:
            duration = time.time() - start
            logging.info("END %s (%.2fs)", name, duration)
            self.event(name, "completed", duration_sec=round(duration, 3))


def discover_dataset(stripped_dir: Path, unstripped_dir: Path) -> List[dict]:
    rows = []
    if not stripped_dir.exists():
        raise FileNotFoundError(f"Stripped dataset not found: {stripped_dir}")

    unstripped_index = {}
    if unstripped_dir.exists():
        for version_dir in sorted(unstripped_dir.iterdir(), key=lambda p: version_tuple(p.name)):
            if not version_dir.is_dir() or not version_dir.name.startswith("busybox-"):
                continue
            for item in version_dir.iterdir():
                if not item.is_file():
                    continue
                match = BINARY_RE.match(item.name)
                if match and match.group("kind") == "unstripped":
                    unstripped_index[(version_dir.name, match.group("arch"))] = item

    for version_dir in sorted(stripped_dir.iterdir(), key=lambda p: version_tuple(p.name)):
        if not version_dir.is_dir() or not version_dir.name.startswith("busybox-"):
            continue
        for item in sorted(version_dir.iterdir(), key=lambda p: p.name):
            if not item.is_file():
                continue
            match = BINARY_RE.match(item.name)
            if not match or match.group("kind") != "stripped":
                continue
            arch = match.group("arch")
            unstripped_path = unstripped_index.get((version_dir.name, arch))
            rows.append({
                "binary_id": binary_id(version_dir.name, arch),
                "version": version_dir.name,
                "version_short": short_version(version_dir.name),
                "arch": arch,
                "stripped_path": str(item),
                "stripped_size": item.stat().st_size,
                "unstripped_path": str(unstripped_path) if unstripped_path else "",
                "has_unstripped_label": int(unstripped_path is not None),
                "label_status": "paired_unstripped" if unstripped_path else "stripped_only",
            })
    return rows


def filter_manifest(rows: Sequence[dict], versions: Optional[set], archs: Optional[set], limit: int) -> List[dict]:
    selected = []
    for row in rows:
        version = str(row["version"])
        version_short = str(row["version_short"])
        arch = str(row["arch"])
        if versions and version not in versions and version_short not in versions:
            continue
        if archs and arch not in archs:
            continue
        selected.append(dict(row))
    selected.sort(key=lambda r: (version_tuple(str(r["version"])), str(r["arch"])))
    if limit > 0:
        selected = selected[:limit]
    return selected


def parse_java_major(output: str) -> Optional[int]:
    first = output.splitlines()[0] if output.splitlines() else ""
    match = re.search(r'version "([0-9]+)(?:\.([0-9]+))?', first)
    if not match:
        return None
    major = int(match.group(1))
    if major == 1 and match.group(2):
        return int(match.group(2))
    return major


def ghidra_env(java_home: Optional[Path]) -> dict:
    env = os.environ.copy()
    if java_home:
        env["JAVA_HOME"] = str(java_home)
    return env


def detect_environment(run_dir: Path, ghidra_dir: Path, java_home: Optional[Path], preflight_timeout: int) -> dict:
    analyze = ghidra_dir / "support" / "analyzeHeadless.bat"
    env = ghidra_env(java_home)

    java_cmd = str((java_home / "bin" / "java.exe") if java_home else shutil.which("java") or "java")
    java_rc, java_out, java_err, _ = run_cmd([java_cmd, "-version"], timeout=20, env=env)
    java_version_text = (java_out or java_err).strip()
    java_major = parse_java_major(java_version_text)

    headless_rc = 127
    headless_out = ""
    headless_err = ""
    if analyze.exists():
        headless_rc, headless_out, headless_err, _ = run_cmd([str(analyze), "-version"], timeout=preflight_timeout, env=env)

    headless_text = (headless_out + "\n" + headless_err).strip()
    headless_lower = headless_text.lower()
    jdk_missing = (
        "could not be found" in headless_lower
        or "failed to find a supported jdk" in headless_lower
        or "jdk 21+" in headless_lower
    )
    # analyzeHeadless does not support a real "-version" option.  With a valid
    # JDK it prints usage and exits with rc=1, so readiness is based on Java and
    # absence of LaunchSupport/JDK errors rather than a zero return code.
    ready = analyze.exists() and java_major is not None and java_major >= 21 and not jdk_missing
    notes = []
    if not analyze.exists():
        notes.append("Ghidra analyzeHeadless.bat was not found.")
    if java_major is None:
        notes.append("Could not parse Java version from PATH/JAVA_HOME.")
    elif java_major < 21:
        notes.append("Ghidra requires JDK 21+; current Java major version appears to be %d." % java_major)
    if analyze.exists() and jdk_missing:
        notes.append("Ghidra headless preflight failed; configure JAVA_HOME or pass --java-home with a JDK 21+ directory.")

    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "run_dir": str(run_dir),
        "platform": platform.platform(),
        "python_executable": sys.executable,
        "python_version": sys.version.replace("\n", " "),
        "ghidra": {
            "ghidra_dir": str(ghidra_dir),
            "analyze_headless": str(analyze),
            "analyze_headless_exists": analyze.exists(),
            "headless_preflight_rc": headless_rc,
            "headless_preflight_first_lines": "\n".join(headless_text.splitlines()[:8]),
            "ready": ready,
        },
        "java": {
            "java_cmd": java_cmd,
            "java_rc": java_rc,
            "java_major": java_major,
            "java_version_first_lines": "\n".join(java_version_text.splitlines()[:4]),
            "java_home_arg": str(java_home) if java_home else "",
            "java_home_env": env.get("JAVA_HOME", ""),
        },
        "notes": notes,
    }
    write_json(run_dir / "environment.json", result)
    return result


def output_paths(run_dir: Path, row: dict) -> Tuple[Path, Path]:
    version = str(row["version"])
    bid = str(row["binary_id"])
    feature_path = run_dir / "features" / version / f"{bid}.jsonl"
    summary_path = run_dir / "summaries" / version / f"{bid}.summary.json"
    return feature_path, summary_path


def build_ghidra_command(analyze: Path, project_root: Path, row: dict, feature_path: Path,
                         summary_path: Path, max_tokens: int, max_functions: int,
                         analysis_timeout: int) -> List[str]:
    bid = str(row["binary_id"])
    project_name = "ghidra_" + re.sub(r"[^A-Za-z0-9_]+", "_", bid)
    return [
        str(analyze),
        str(project_root),
        project_name,
        "-import",
        str(row["stripped_path"]),
        "-analysisTimeoutPerFile",
        str(analysis_timeout),
        "-scriptPath",
        str(GHIDRA_SCRIPT_DIR),
        "-postScript",
        "ExportFunctionFeatures.java",
        str(feature_path),
        str(summary_path),
        bid,
        str(row["version"]),
        str(row["arch"]),
        str(row["stripped_path"]),
        str(max_tokens),
        str(max_functions),
        "-deleteProject",
    ]


def run_extraction(args: argparse.Namespace, ctx: RunContext, rows: Sequence[dict], env_info: dict) -> List[dict]:
    analyze = args.ghidra / "support" / "analyzeHeadless.bat"
    project_root = ctx.run_dir / "ghidra_projects"
    ensure_dir(project_root)
    env = ghidra_env(args.java_home)
    statuses = []

    if not env_info["ghidra"]["ready"]:
        logging.warning("Ghidra is not ready; skipping extraction. See environment.json for details.")
        return statuses

    for index, row in enumerate(rows, start=1):
        feature_path, summary_path = output_paths(ctx.run_dir, row)
        status = {
            "binary_id": row["binary_id"],
            "version": row["version"],
            "arch": row["arch"],
            "stripped_path": row["stripped_path"],
            "feature_path": str(feature_path),
            "summary_path": str(summary_path),
            "status": "not_started",
            "return_code": "",
            "duration_sec": "",
            "message": "",
        }
        if feature_path.exists() and summary_path.exists() and not args.force:
            status.update({"status": "exists", "message": "existing feature output reused"})
            statuses.append(status)
            continue

        ensure_dir(feature_path.parent)
        ensure_dir(summary_path.parent)
        if args.force:
            for path in [feature_path, summary_path]:
                if path.exists():
                    path.unlink()

        cmd = build_ghidra_command(
            analyze=analyze,
            project_root=project_root,
            row=row,
            feature_path=feature_path,
            summary_path=summary_path,
            max_tokens=args.max_tokens,
            max_functions=args.max_functions_per_binary,
            analysis_timeout=args.analysis_timeout,
        )
        logging.info("Ghidra extraction %d/%d: %s %s", index, len(rows), row["version"], row["arch"])
        ctx.event("extract_binary", "started", binary_id=row["binary_id"], index=index, total=len(rows))
        rc, stdout, stderr, duration = run_cmd(cmd, timeout=args.timeout, env=env, cwd=PROJECT_ROOT)

        stdout_log = ctx.run_dir / "logs" / (str(row["binary_id"]) + ".stdout.txt")
        stderr_log = ctx.run_dir / "logs" / (str(row["binary_id"]) + ".stderr.txt")
        stdout_log.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_log.write_text(stderr, encoding="utf-8", errors="replace")

        status["return_code"] = rc
        status["duration_sec"] = round(duration, 3)
        if rc == 0 and feature_path.exists() and summary_path.exists():
            status.update({"status": "completed", "message": "feature extraction completed"})
            ctx.event("extract_binary", "completed", binary_id=row["binary_id"], duration_sec=round(duration, 3))
        else:
            message = (stderr or stdout).strip().replace("\r", " ").replace("\n", " ")[:800]
            status.update({"status": "failed", "message": message})
            ctx.event("extract_binary", "failed", binary_id=row["binary_id"], duration_sec=round(duration, 3), error=message)
            if args.stop_on_error:
                statuses.append(status)
                break
        statuses.append(status)
        write_csv(ctx.run_dir / "ghidra_status.csv", statuses, GHIDRA_STATUS_FIELDS)
    return statuses


def merge_features(run_dir: Path, statuses: Sequence[dict]) -> Optional[Path]:
    completed = [Path(str(row["feature_path"])) for row in statuses if row.get("status") in {"completed", "exists"}]
    if not completed:
        return None
    merged = run_dir / "function_features.jsonl"
    with merged.open("w", encoding="utf-8", newline="\n") as out:
        for path in completed:
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="replace") as src:
                for line in src:
                    out.write(line)
    return merged


def summarize_manifest(rows: Sequence[dict]) -> dict:
    versions = sorted({str(r["version"]) for r in rows}, key=version_tuple)
    archs = sorted({str(r["arch"]) for r in rows})
    paired = sum(1 for r in rows if int(r["has_unstripped_label"]) == 1)
    by_arch = {}
    for arch in archs:
        items = [r for r in rows if r["arch"] == arch]
        by_arch[arch] = {
            "stripped_binaries": len(items),
            "paired_unstripped": sum(1 for r in items if int(r["has_unstripped_label"]) == 1),
            "stripped_only": sum(1 for r in items if int(r["has_unstripped_label"]) == 0),
        }
    return {
        "versions": len(versions),
        "version_min": versions[0] if versions else "",
        "version_max": versions[-1] if versions else "",
        "architectures": archs,
        "stripped_binaries": len(rows),
        "paired_unstripped_binaries": paired,
        "stripped_only_binaries": len(rows) - paired,
        "by_arch": by_arch,
    }


GHIDRA_STATUS_FIELDS = [
    "binary_id", "version", "arch", "stripped_path", "feature_path", "summary_path",
    "status", "return_code", "duration_sec", "message",
]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripped-dataset", type=Path, default=DEFAULT_STRIPPED)
    parser.add_argument("--unstripped-dataset", type=Path, default=DEFAULT_UNSTRIPPED)
    parser.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
    parser.add_argument("--java-home", type=Path, default=None, help="JDK 21+ home directory for Ghidra.")
    parser.add_argument("--experiments-dir", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--run-id", default="ghidra_" + now_id())
    parser.add_argument("--versions", default="", help="Comma-separated BusyBox versions, e.g. 1.37.0,busybox-1.36.1.")
    parser.add_argument("--archs", default="", help="Comma-separated architectures, e.g. x86_64,arm,mips.")
    parser.add_argument("--limit", type=int, default=0, help="Limit selected binaries; 0 means no limit.")
    parser.add_argument("--dry-run", action="store_true", help="Write manifests and environment only; do not run Ghidra.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing per-binary feature outputs.")
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--merge-jsonl", action="store_true", help="Concatenate completed per-binary outputs into function_features.jsonl.")
    parser.add_argument("--timeout", type=int, default=900, help="Wall-clock timeout per binary for analyzeHeadless.")
    parser.add_argument("--analysis-timeout", type=int, default=300, help="Ghidra analysis timeout per imported file.")
    parser.add_argument("--preflight-timeout", type=int, default=30)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--max-functions-per-binary", type=int, default=0, help="Debug cap passed to Ghidra script; 0 means all.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    run_dir = args.experiments_dir / "runs" / args.run_id
    ctx = RunContext(run_dir)
    ctx.setup_logging()
    logging.info("Output run: %s", run_dir)

    try:
        with ctx.step("discover_aligned_dataset"):
            all_rows = discover_dataset(args.stripped_dataset, args.unstripped_dataset)
            selected_rows = filter_manifest(
                all_rows,
                versions=parse_csv_list(args.versions),
                archs=parse_csv_list(args.archs),
                limit=args.limit,
            )
            manifest_fields = [
                "binary_id", "version", "version_short", "arch", "stripped_path",
                "stripped_size", "unstripped_path", "has_unstripped_label", "label_status",
            ]
            write_csv(run_dir / "aligned_binaries_all.csv", all_rows, manifest_fields)
            write_csv(run_dir / "aligned_binaries_selected.csv", selected_rows, manifest_fields)
            summary = {"all": summarize_manifest(all_rows), "selected": summarize_manifest(selected_rows)}
            write_json(run_dir / "alignment_summary.json", summary)
            logging.info("Discovered %d stripped binaries; selected %d", len(all_rows), len(selected_rows))
            logging.info("Paired unstripped labels: %d / %d", summary["all"]["paired_unstripped_binaries"], summary["all"]["stripped_binaries"])

        with ctx.step("detect_environment"):
            env_info = detect_environment(run_dir, args.ghidra, args.java_home, args.preflight_timeout)
            logging.info("Ghidra ready: %s", env_info["ghidra"]["ready"])
            for note in env_info.get("notes", []):
                logging.warning(note)

        statuses: List[dict] = []
        if args.dry_run:
            logging.info("Dry-run requested; skipping Ghidra execution.")
        else:
            with ctx.step("ghidra_extract_features"):
                statuses = run_extraction(args, ctx, selected_rows, env_info)
                write_csv(run_dir / "ghidra_status.csv", statuses, GHIDRA_STATUS_FIELDS)
                logging.info("Ghidra completed=%d failed=%d exists=%d",
                             sum(1 for r in statuses if r["status"] == "completed"),
                             sum(1 for r in statuses if r["status"] == "failed"),
                             sum(1 for r in statuses if r["status"] == "exists"))
            if args.merge_jsonl:
                with ctx.step("merge_feature_jsonl"):
                    merged = merge_features(run_dir, statuses)
                    logging.info("Merged JSONL: %s", merged if merged else "no completed outputs")
    except Exception:
        logging.exception("Ghidra feature extraction pipeline failed")
        return 1
    logging.info("Ghidra feature extraction pipeline finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
