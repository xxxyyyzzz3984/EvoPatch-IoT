#!/usr/bin/env python3
"""Run reproducible BusyBox firmware-binary baseline experiments.

This first pipeline is deliberately standard-library only. It creates a real
experiment scaffold: inventory, labels, stripped-artifact attempts, baseline
experiments, logs, and result files under experiments/runs/<run_id>/.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import gzip
import hashlib
import json
import logging
import math
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "busybox_unstripped_dataset"
DEFAULT_SOURCES = PROJECT_ROOT / "busybox_sources_codes"
DEFAULT_EXPERIMENTS = PROJECT_ROOT / "experiments"

ARCH_RE = re.compile(r"^busybox-(?P<arch>.+?)-unstripped$")
SYMBOL_RE = re.compile(r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
COMPILER_SUFFIX_RE = re.compile(r"(\.constprop\.\d+|\.isra\.\d+|\.part\.\d+|\.cold(?:\.\d+)?|\.localalias(?:\.\d+)?)$")
RUNTIME_PREFIXES = (
    "__", "_ITM_", "_Unwind_", "_GLOBAL_", "deregister_tm_clones",
    "register_tm_clones", "frame_dummy", "call_weak_fn",
)


def now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_cmd(args: Sequence[str], timeout: int = 120) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr + f"\nTIMEOUT after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


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


def write_csv_gz(path: Path, rows: Iterable[dict], fieldnames: Sequence[str]) -> int:
    ensure_dir(path.parent)
    count = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def version_tuple(version: str) -> Tuple[int, ...]:
    raw = version.replace("busybox-", "")
    parts: List[int] = []
    for part in raw.split("."):
        match = re.match(r"\d+", part)
        parts.append(int(match.group(0)) if match else 0)
    return tuple(parts)


def cmp_version_tuple(version: str, width: int = 3) -> Tuple[int, ...]:
    parts = list(version_tuple(version))
    while len(parts) < width:
        parts.append(0)
    return tuple(parts[:width])


def normalize_func_name(name: str) -> str:
    name = name.strip()
    if "@" in name:
        name = name.split("@", 1)[0]
    previous = None
    while previous != name:
        previous = name
        name = COMPILER_SUFFIX_RE.sub("", name)
    return name


def is_analysis_func(name: str, size: int, ndx: str) -> bool:
    if not name or size <= 0 or ndx in {"UND", "ABS", "COM"}:
        return False
    if name.startswith(".") or name.startswith("$"):
        return False
    if name in {"_start", "init", "fini", "_init", "_fini"}:
        return False
    if any(name.startswith(prefix) for prefix in RUNTIME_PREFIXES):
        return False
    return True


def parse_arch_from_name(path: Path) -> str:
    match = ARCH_RE.match(path.name)
    return match.group("arch") if match else "unknown"


def parse_readelf_header(output: str) -> Dict[str, str]:
    fields = {}
    mapping = {"Class": "elf_class", "Data": "endian", "Type": "elf_type", "Machine": "machine", "Entry point address": "entry"}
    for line in output.splitlines():
        if ":" not in line:
            continue
        left, right = line.split(":", 1)
        key = left.strip()
        if key in mapping:
            fields[mapping[key]] = right.strip()
    return fields


def parse_sections(output: str) -> Dict[str, object]:
    names = []
    for line in output.splitlines():
        if not line.lstrip().startswith("["):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[1]
        if name == "]" and len(parts) > 2:
            name = parts[2]
        if name.startswith("."):
            names.append(name)
    name_set = set(names)
    debug_count = sum(1 for n in names if n.startswith(".debug"))
    return {
        "section_count": len(names),
        "has_symtab": ".symtab" in name_set,
        "has_strtab": ".strtab" in name_set,
        "has_debug": debug_count > 0,
        "debug_section_count": debug_count,
    }


def extract_symbols(readelf: str, binary: Path, version: str, arch: str) -> List[dict]:
    code, stdout, stderr = run_cmd([readelf, "-sW", str(binary)], timeout=180)
    if code != 0 and not stdout:
        raise RuntimeError(f"readelf -sW failed for {binary}: {stderr.strip()[:400]}")
    rows = []
    for line in stdout.splitlines():
        match = SYMBOL_RE.match(line)
        if not match:
            continue
        value_hex, size_raw, typ, bind, vis, ndx, name = match.groups()
        if typ != "FUNC":
            continue
        try:
            size = int(size_raw)
            value = int(value_hex, 16)
        except ValueError:
            continue
        norm = normalize_func_name(name)
        rows.append({
            "version": version,
            "arch": arch,
            "binary_name": binary.name,
            "address": value,
            "size": size,
            "type": typ,
            "bind": bind,
            "visibility": vis,
            "section_index": ndx,
            "name": name.strip(),
            "norm_name": norm,
            "analysis_func": int(is_analysis_func(norm, size, ndx)),
        })
    return rows


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * p
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return float(ordered[low])
    frac = pos - low
    return float(ordered[low] * (1 - frac) + ordered[high] * frac)


def safe_mean(values: Sequence[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


class RunContext:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.status_path = run_dir / "status_events.jsonl"
        ensure_dir(run_dir)
        ensure_dir(run_dir / "results")

    def setup_logging(self) -> None:
        log_path = self.run_dir / "run.log"
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
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


def detect_environment(run_dir: Path) -> dict:
    tools = {}
    for tool in ["python", "readelf", "objdump", "strip", "objcopy", "docker", "make", "gcc", "apply_patch"]:
        path = shutil.which(tool)
        info = {"path": path, "available": bool(path)}
        if path:
            code, stdout, stderr = run_cmd([path, "--version"], timeout=20)
            first = (stdout or stderr).splitlines()[0] if (stdout or stderr).splitlines() else ""
            info.update({"version_rc": code, "version_first_line": first})
        tools[tool] = info
    notes = []
    if tools.get("apply_patch", {}).get("available") and tools["apply_patch"].get("version_rc") != 0:
        notes.append("apply_patch exists but returned a non-zero status in this shell; file creation used controlled project-local writes.")
    if not tools.get("docker", {}).get("available"):
        notes.append("Docker was not found in PATH; Docker-based BusyBox compilation was not attempted in this run.")
    env = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "run_dir": str(run_dir),
        "platform": platform.platform(),
        "python_executable": sys.executable,
        "python_version": sys.version.replace("\n", " "),
        "tools": tools,
        "notes": notes,
    }
    write_json(run_dir / "environment.json", env)
    return env


def source_inventory(source_dir: Path, run_dir: Path) -> dict:
    rows = []
    if source_dir.exists():
        children = [p for p in source_dir.iterdir() if p.is_dir() and p.name.startswith("busybox-")]
        for child in sorted(children, key=lambda p: version_tuple(p.name)):
            rows.append({
                "version": child.name,
                "path": str(child),
                "has_makefile": int((child / "Makefile").exists()),
                "has_config": int((child / ".config").exists()),
            })
    write_csv(run_dir / "source_manifest.csv", rows, ["version", "path", "has_makefile", "has_config"])
    return {"source_dir": str(source_dir), "version_count": len(rows)}


def collect_manifest(dataset_dir: Path, run_dir: Path, readelf: str, compute_sha256: bool) -> Tuple[List[dict], Dict[Tuple[str, str], Path]]:
    manifest = []
    binary_paths = {}
    version_dirs = [p for p in dataset_dir.iterdir() if p.is_dir() and p.name.startswith("busybox-")]
    version_dirs.sort(key=lambda p: version_tuple(p.name))
    for version_dir in version_dirs:
        for binary in sorted(version_dir.iterdir(), key=lambda p: p.name):
            if not binary.is_file() or not binary.name.startswith("busybox-"):
                continue
            arch = parse_arch_from_name(binary)
            header_rc, header_out, header_err = run_cmd([readelf, "-h", str(binary)], timeout=60)
            sec_rc, sec_out, sec_err = run_cmd([readelf, "-SW", str(binary)], timeout=60)
            header_fields = parse_readelf_header(header_out) if (header_rc == 0 or header_out) else {"readelf_header_error": header_err.strip()[:300]}
            section_fields = parse_sections(sec_out) if (sec_rc == 0 or sec_out) else {"readelf_section_error": sec_err.strip()[:300]}
            row = {
                "version": version_dir.name,
                "version_tuple": ".".join(str(x) for x in cmp_version_tuple(version_dir.name)),
                "arch": arch,
                "binary_name": binary.name,
                "path": str(binary),
                "size_bytes": binary.stat().st_size,
                "sha256": sha256_file(binary) if compute_sha256 else "",
                **header_fields,
                **section_fields,
            }
            manifest.append(row)
            binary_paths[(version_dir.name, arch)] = binary
    fieldnames = [
        "version", "version_tuple", "arch", "binary_name", "path", "size_bytes", "sha256",
        "elf_class", "endian", "elf_type", "machine", "entry", "section_count",
        "has_symtab", "has_strtab", "has_debug", "debug_section_count",
        "readelf_header_error", "readelf_section_error",
    ]
    write_csv(run_dir / "binary_manifest.csv", manifest, fieldnames)
    return manifest, binary_paths


def extract_all_symbols(manifest: Sequence[dict], run_dir: Path, readelf: str) -> Tuple[List[dict], Dict[Tuple[str, str], List[dict]], Dict[Tuple[str, str], dict]]:
    all_rows: List[dict] = []
    by_binary: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    stats_by_binary: Dict[Tuple[str, str], dict] = {}
    for index, item in enumerate(manifest, start=1):
        binary = Path(str(item["path"]))
        version = str(item["version"])
        arch = str(item["arch"])
        logging.info("Extracting function symbols %d/%d: %s %s", index, len(manifest), version, arch)
        rows = extract_symbols(readelf, binary, version, arch)
        by_binary[(version, arch)].extend(rows)
        all_rows.extend(rows)
        sizes = [int(r["size"]) for r in rows if int(r["analysis_func"]) == 1]
        stats_by_binary[(version, arch)] = {
            "version": version,
            "arch": arch,
            "func_symbols": len(rows),
            "analysis_funcs": len(sizes),
            "func_size_mean": round(safe_mean(sizes), 3),
            "func_size_median": round(statistics.median(sizes), 3) if sizes else 0.0,
            "func_size_p90": round(percentile(sizes, 0.90), 3),
            "func_size_p99": round(percentile(sizes, 0.99), 3),
        }
    fieldnames = [
        "version", "arch", "binary_name", "address", "size", "type", "bind", "visibility",
        "section_index", "name", "norm_name", "analysis_func",
    ]
    write_csv_gz(run_dir / "function_symbols.csv.gz", all_rows, fieldnames)
    stat_rows = [stats_by_binary[k] for k in sorted(stats_by_binary, key=lambda x: (version_tuple(x[0]), x[1]))]
    write_csv(run_dir / "function_symbol_stats.csv", stat_rows,
              ["version", "arch", "func_symbols", "analysis_funcs", "func_size_mean", "func_size_median", "func_size_p90", "func_size_p99"])
    return all_rows, by_binary, stats_by_binary


def attempt_strip_dataset(manifest: Sequence[dict], run_dir: Path, strip_tool: Optional[str], force: bool) -> List[dict]:
    out_root = DEFAULT_EXPERIMENTS / "artifacts" / "stripped_dataset"
    rows = []
    for item in manifest:
        version = str(item["version"])
        arch = str(item["arch"])
        src = Path(str(item["path"]))
        dst_dir = out_root / version
        dst = dst_dir / f"busybox-{arch}-stripped"
        ensure_dir(dst_dir)
        row = {
            "version": version, "arch": arch, "src": str(src), "dst": str(dst),
            "status": "not_attempted", "return_code": "", "src_size": src.stat().st_size,
            "dst_size": "", "message": "",
        }
        if not strip_tool:
            row.update({"status": "skipped", "message": "strip tool not available"})
            rows.append(row)
            continue
        if dst.exists() and not force:
            row.update({"status": "exists", "dst_size": dst.stat().st_size, "message": "existing output reused"})
            rows.append(row)
            continue
        if dst.exists() and force:
            dst.unlink()
        code, stdout, stderr = run_cmd([strip_tool, "-o", str(dst), str(src)], timeout=120)
        message = (stderr or stdout).strip().replace("\r", " ").replace("\n", " ")[:500]
        row["return_code"] = code
        if code == 0 and dst.exists():
            row.update({"status": "success", "dst_size": dst.stat().st_size, "message": message})
        else:
            if dst.exists():
                try:
                    dst.unlink()
                except OSError:
                    pass
            row.update({"status": "failed", "message": message})
        rows.append(row)
    write_csv(run_dir / "strip_status.csv", rows,
              ["version", "arch", "src", "dst", "status", "return_code", "src_size", "dst_size", "message"])
    return rows


def topk_by_size(query_size: int, candidates_sorted: Sequence[Tuple[int, str, dict]], k: int) -> List[dict]:
    sizes = [item[0] for item in candidates_sorted]
    pos = bisect.bisect_left(sizes, query_size)
    left = pos - 1
    right = pos
    result: List[Tuple[int, int, dict]] = []
    while len(result) < k and (left >= 0 or right < len(candidates_sorted)):
        if left < 0:
            size, _, rec = candidates_sorted[right]
            result.append((abs(size - query_size), right, rec))
            right += 1
        elif right >= len(candidates_sorted):
            size, _, rec = candidates_sorted[left]
            result.append((abs(size - query_size), left, rec))
            left -= 1
        else:
            left_size = candidates_sorted[left][0]
            right_size = candidates_sorted[right][0]
            if abs(left_size - query_size) <= abs(right_size - query_size):
                _, _, rec = candidates_sorted[left]
                result.append((abs(left_size - query_size), left, rec))
                left -= 1
            else:
                _, _, rec = candidates_sorted[right]
                result.append((abs(right_size - query_size), right, rec))
                right += 1
    result.sort(key=lambda x: (x[0], x[1]))
    return [r[2] for r in result[:k]]


def exp_cross_arch_size_retrieval(by_binary: Dict[Tuple[str, str], List[dict]], run_dir: Path) -> List[dict]:
    results = []
    for version in sorted({k[0] for k in by_binary}, key=version_tuple):
        archs = sorted([arch for v, arch in by_binary if v == version])
        for src_arch in archs:
            queries = [r for r in by_binary[(version, src_arch)] if int(r["analysis_func"]) == 1]
            for dst_arch in archs:
                if src_arch == dst_arch:
                    continue
                candidates = [r for r in by_binary[(version, dst_arch)] if int(r["analysis_func"]) == 1]
                if not queries or not candidates:
                    continue
                relevant_names = {str(r["norm_name"]) for r in candidates}
                eval_queries = [q for q in queries if str(q["norm_name"]) in relevant_names]
                if not eval_queries:
                    continue
                candidates_sorted = sorted(((int(r["size"]), str(r["norm_name"]), r) for r in candidates), key=lambda t: (t[0], t[1], int(t[2]["address"])))
                candidate_name_counts = Counter(str(r["norm_name"]) for r in candidates)
                hits1 = hits5 = hits10 = 0
                mrr10 = 0.0
                random_hit1 = random_hit5 = random_hit10 = 0.0
                for query in eval_queries:
                    name = str(query["norm_name"])
                    top = topk_by_size(int(query["size"]), candidates_sorted, 10)
                    top_names = [str(r["norm_name"]) for r in top]
                    hits1 += int(name in top_names[:1])
                    hits5 += int(name in top_names[:5])
                    hits10 += int(name in top_names[:10])
                    for rank, top_name in enumerate(top_names[:10], start=1):
                        if top_name == name:
                            mrr10 += 1.0 / rank
                            break
                    rel = candidate_name_counts[name]
                    n = len(candidates)
                    random_hit1 += min(1.0, rel / n)
                    random_hit5 += min(1.0, (5 * rel) / n)
                    random_hit10 += min(1.0, (10 * rel) / n)
                n_query = len(eval_queries)
                results.append({
                    "version": version, "src_arch": src_arch, "dst_arch": dst_arch,
                    "queries": n_query, "candidates": len(candidates),
                    "hit_at_1": round(hits1 / n_query, 6),
                    "hit_at_5": round(hits5 / n_query, 6),
                    "hit_at_10": round(hits10 / n_query, 6),
                    "mrr_at_10": round(mrr10 / n_query, 6),
                    "random_hit_at_1_expected": round(random_hit1 / n_query, 6),
                    "random_hit_at_5_expected": round(random_hit5 / n_query, 6),
                    "random_hit_at_10_expected": round(random_hit10 / n_query, 6),
                })
    write_csv(run_dir / "results" / "cross_arch_size_retrieval.csv", results,
              ["version", "src_arch", "dst_arch", "queries", "candidates", "hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "random_hit_at_1_expected", "random_hit_at_5_expected", "random_hit_at_10_expected"])
    return results


def binary_classification_features(stats_by_binary: Dict[Tuple[str, str], dict], manifest: Sequence[dict]) -> Dict[Tuple[str, str], dict]:
    manifest_by_key = {(str(r["version"]), str(r["arch"])): r for r in manifest}
    features = {}
    for key, stats in stats_by_binary.items():
        item = manifest_by_key.get(key, {})
        features[key] = {
            "size_mb": float(item.get("size_bytes", 0)) / (1024 * 1024),
            "func_symbols": float(stats.get("func_symbols", 0)),
            "analysis_funcs": float(stats.get("analysis_funcs", 0)),
            "func_size_mean": float(stats.get("func_size_mean", 0)),
            "func_size_median": float(stats.get("func_size_median", 0)),
            "func_size_p90": float(stats.get("func_size_p90", 0)),
            "func_size_p99": float(stats.get("func_size_p99", 0)),
            "section_count": float(item.get("section_count", 0) or 0),
            "debug_section_count": float(item.get("debug_section_count", 0) or 0),
        }
    return features


def cve_2021_42386_label(version: str) -> Optional[int]:
    vt = cmp_version_tuple(version)
    if (1, 16, 0) <= vt <= (1, 33, 1):
        return 1
    if vt >= (1, 34, 0):
        return 0
    return None


def standardize(train_rows: List[dict], test_rows: List[dict], feature_names: Sequence[str]) -> Tuple[List[List[float]], List[List[float]]]:
    means = []
    stds = []
    for name in feature_names:
        vals = [float(r[name]) for r in train_rows]
        mean = safe_mean(vals)
        var = safe_mean([(v - mean) ** 2 for v in vals])
        std = math.sqrt(var) if var > 0 else 1.0
        means.append(mean)
        stds.append(std)
    train_x = [[(float(r[name]) - means[i]) / stds[i] for i, name in enumerate(feature_names)] for r in train_rows]
    test_x = [[(float(r[name]) - means[i]) / stds[i] for i, name in enumerate(feature_names)] for r in test_rows]
    return train_x, test_x


def nearest_centroid_predict(train_rows: List[dict], test_rows: List[dict], feature_names: Sequence[str]) -> List[int]:
    train_x, test_x = standardize(train_rows, test_rows, feature_names)
    by_label: Dict[int, List[List[float]]] = defaultdict(list)
    for row, x in zip(train_rows, train_x):
        by_label[int(row["label"])].append(x)
    centroids = {}
    for label, xs in by_label.items():
        centroids[label] = [safe_mean([x[i] for x in xs]) for i in range(len(feature_names))]
    preds = []
    for x in test_x:
        best_label = 0
        best_dist = float("inf")
        for label, centroid in centroids.items():
            dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(x, centroid)))
            if dist < best_dist:
                best_dist = dist
                best_label = label
        preds.append(int(best_label))
    return preds


def classification_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict:
    tp = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 1)
    tn = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 0)
    fp = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 0)
    total = len(y_true)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n": total, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round((tp + tn) / total, 6) if total else 0.0,
        "precision": round(precision, 6), "recall": round(recall, 6), "f1": round(f1, 6),
    }


def exp_cve_patch_state_proxy(stats_by_binary: Dict[Tuple[str, str], dict], manifest: Sequence[dict], run_dir: Path) -> List[dict]:
    features_by_key = binary_classification_features(stats_by_binary, manifest)
    rows = []
    for (version, arch), feats in features_by_key.items():
        label = cve_2021_42386_label(version)
        if label is not None:
            rows.append({"version": version, "arch": arch, "label": label, **feats})
    feature_names = ["size_mb", "func_symbols", "analysis_funcs", "func_size_mean", "func_size_median", "func_size_p90", "func_size_p99", "section_count", "debug_section_count"]
    results = []
    for heldout in sorted({r["arch"] for r in rows}):
        train = [r for r in rows if r["arch"] != heldout]
        test = [r for r in rows if r["arch"] == heldout]
        if not train or not test or len({r["label"] for r in train}) < 2:
            continue
        preds = nearest_centroid_predict(train, test, feature_names)
        y_true = [int(r["label"]) for r in test]
        results.append({
            "cve": "CVE-2021-42386", "heldout_arch": heldout,
            "train_binaries": len(train), "test_binaries": len(test),
            **classification_metrics(y_true, preds),
        })
    write_csv(run_dir / "results" / "cve_2021_42386_patch_state_proxy.csv", results,
              ["cve", "heldout_arch", "train_binaries", "test_binaries", "n", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1"])
    return results


def roc_auc(labels: Sequence[int], scores: Sequence[float]) -> float:
    pairs = sorted(zip(scores, labels), key=lambda x: x[0])
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.0
    rank_sum = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            if pairs[k][1] == 1:
                rank_sum += avg_rank
        i = j + 1
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def average_precision(labels: Sequence[int], scores: Sequence[float]) -> float:
    pairs = sorted(zip(scores, labels), key=lambda x: x[0], reverse=True)
    total_pos = sum(labels)
    if total_pos == 0:
        return 0.0
    tp = 0
    ap = 0.0
    for idx, (_, label) in enumerate(pairs, start=1):
        if label == 1:
            tp += 1
            ap += tp / idx
    return ap / total_pos


def size_map(records: Sequence[dict]) -> Dict[str, int]:
    result = {}
    for r in records:
        if int(r["analysis_func"]) != 1:
            continue
        name = str(r["norm_name"])
        size = int(r["size"])
        if name not in result or size > result[name]:
            result[name] = size
    return result


def changed_scores(old_map: Dict[str, int], new_map: Dict[str, int]) -> Dict[str, float]:
    scores = {}
    for name in set(old_map) & set(new_map):
        old = old_map[name]
        new = new_map[name]
        scores[name] = abs(new - old) / max(old, new, 1)
    return scores


def exp_version_change_transfer(by_binary: Dict[Tuple[str, str], List[dict]], run_dir: Path) -> List[dict]:
    threshold = 0.05
    min_abs_delta = 16
    versions = sorted({v for v, _ in by_binary}, key=version_tuple)
    results = []
    for old_v, new_v in zip(versions, versions[1:]):
        archs = sorted({arch for v, arch in by_binary if v in {old_v, new_v}})
        archs = [a for a in archs if (old_v, a) in by_binary and (new_v, a) in by_binary]
        if len(archs) < 2:
            continue
        maps = {}
        for arch in archs:
            old_map = size_map(by_binary[(old_v, arch)])
            new_map = size_map(by_binary[(new_v, arch)])
            maps[arch] = (old_map, new_map, changed_scores(old_map, new_map))
        for src_arch in archs:
            for dst_arch in archs:
                if src_arch == dst_arch:
                    continue
                src_old, src_new, src_scores = maps[src_arch]
                dst_old, dst_new, dst_scores = maps[dst_arch]
                labels = []
                scores = []
                for name in set(src_scores) & set(dst_scores):
                    dst_abs = abs(dst_new[name] - dst_old[name])
                    label = int(dst_scores[name] >= threshold and dst_abs >= min_abs_delta)
                    labels.append(label)
                    scores.append(src_scores[name])
                if len(labels) < 20 or len(set(labels)) < 2:
                    continue
                results.append({
                    "old_version": old_v, "new_version": new_v,
                    "src_arch": src_arch, "dst_arch": dst_arch,
                    "functions": len(labels),
                    "positive_changed_rate": round(sum(labels) / len(labels), 6),
                    "roc_auc": round(roc_auc(labels, scores), 6),
                    "average_precision": round(average_precision(labels, scores), 6),
                    "threshold_rel": threshold,
                    "threshold_abs_bytes": min_abs_delta,
                })
    write_csv(run_dir / "results" / "version_change_transfer.csv", results,
              ["old_version", "new_version", "src_arch", "dst_arch", "functions", "positive_changed_rate", "roc_auc", "average_precision", "threshold_rel", "threshold_abs_bytes"])
    return results


def exp_cve_awk_patch_probe(by_binary: Dict[Tuple[str, str], List[dict]], run_dir: Path) -> List[dict]:
    old_v = "busybox-1.33.1"
    new_v = "busybox-1.34.0"
    rows = []
    for arch in sorted({arch for v, arch in by_binary if v in {old_v, new_v}}):
        if (old_v, arch) not in by_binary or (new_v, arch) not in by_binary:
            continue
        old_map = size_map(by_binary[(old_v, arch)])
        new_map = size_map(by_binary[(new_v, arch)])
        names = sorted({n for n in set(old_map) | set(new_map) if "awk" in n.lower()})
        for name in names:
            old_size = old_map.get(name)
            new_size = new_map.get(name)
            if old_size is None:
                status = "appeared"
                abs_delta = new_size or 0
                rel_delta = 1.0
            elif new_size is None:
                status = "removed"
                abs_delta = old_size
                rel_delta = 1.0
            else:
                abs_delta = abs(new_size - old_size)
                rel_delta = abs_delta / max(old_size, new_size, 1)
                status = "changed" if abs_delta > 0 else "unchanged"
            rows.append({
                "cve": "CVE-2021-42386", "old_version": old_v, "new_version": new_v,
                "arch": arch, "function": name,
                "old_size": old_size if old_size is not None else "",
                "new_size": new_size if new_size is not None else "",
                "abs_delta": abs_delta, "rel_delta": round(rel_delta, 6), "status": status,
            })
    rows.sort(key=lambda r: (r["arch"], -float(r["rel_delta"]), r["function"]))
    write_csv(run_dir / "results" / "cve_2021_42386_awk_patch_probe.csv", rows,
              ["cve", "old_version", "new_version", "arch", "function", "old_size", "new_size", "abs_delta", "rel_delta", "status"])
    return rows


def aggregate_results(manifest: Sequence[dict], symbols: Sequence[dict], strip_rows: Sequence[dict],
                      retrieval: Sequence[dict], patch_state: Sequence[dict],
                      change_transfer: Sequence[dict], awk_probe: Sequence[dict],
                      source_summary: dict, env: dict) -> dict:
    arch_counts = Counter(str(r["arch"]) for r in manifest)
    version_count = len({str(r["version"]) for r in manifest})
    retrieval_summary = {}
    if retrieval:
        for metric in ["hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10"]:
            retrieval_summary[f"mean_{metric}"] = round(safe_mean([float(r[metric]) for r in retrieval]), 6)
    patch_summary = {}
    if patch_state:
        for metric in ["accuracy", "precision", "recall", "f1"]:
            patch_summary[f"mean_{metric}"] = round(safe_mean([float(r[metric]) for r in patch_state]), 6)
    change_summary = {}
    if change_transfer:
        for metric in ["roc_auc", "average_precision", "positive_changed_rate"]:
            change_summary[f"mean_{metric}"] = round(safe_mean([float(r[metric]) for r in change_transfer]), 6)
    return {
        "dataset": {
            "binaries": len(manifest),
            "versions": version_count,
            "arch_counts": dict(sorted(arch_counts.items())),
            "function_symbol_rows": len(symbols),
            "analysis_function_rows": sum(1 for r in symbols if int(r["analysis_func"]) == 1),
        },
        "sources": source_summary,
        "strip": {
            "success": sum(1 for r in strip_rows if r["status"] == "success"),
            "failed": sum(1 for r in strip_rows if r["status"] == "failed"),
            "existing": sum(1 for r in strip_rows if r["status"] == "exists"),
            "skipped": sum(1 for r in strip_rows if r["status"] == "skipped"),
        },
        "environment_notes": {
            "docker_available": bool(env["tools"].get("docker", {}).get("available")),
            "readelf_available": bool(env["tools"].get("readelf", {}).get("available")),
            "strip_available": bool(env["tools"].get("strip", {}).get("available")),
            "notes": env.get("notes", []),
        },
        "experiments": {
            "cross_arch_size_retrieval": {"directed_pairs": len(retrieval), **retrieval_summary},
            "cve_2021_42386_patch_state_proxy": {"heldout_arch_runs": len(patch_state), **patch_summary},
            "version_change_transfer": {"directed_transition_runs": len(change_transfer), **change_summary},
            "cve_2021_42386_awk_patch_probe": {
                "rows": len(awk_probe),
                "changed_or_appeared_removed": sum(1 for r in awk_probe if r["status"] != "unchanged"),
            },
        },
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--experiments-dir", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--run-id", default=now_id())
    parser.add_argument("--compute-sha256", action="store_true")
    parser.add_argument("--force-strip", action="store_true")
    parser.add_argument("--skip-strip", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    run_dir = args.experiments_dir / "runs" / args.run_id
    ctx = RunContext(run_dir)
    ctx.setup_logging()
    logging.info("Run directory: %s", run_dir)
    try:
        with ctx.step("detect_environment"):
            env = detect_environment(run_dir)
            readelf = env["tools"].get("readelf", {}).get("path")
            strip_tool = env["tools"].get("strip", {}).get("path")
            if not readelf:
                raise RuntimeError("readelf is required for this pipeline")
        with ctx.step("source_inventory"):
            source_summary = source_inventory(args.sources, run_dir)
            logging.info("Source versions discovered: %s", source_summary["version_count"])
        with ctx.step("binary_manifest"):
            manifest, _ = collect_manifest(args.dataset, run_dir, str(readelf), args.compute_sha256)
            logging.info("Binaries discovered: %d", len(manifest))
        with ctx.step("extract_function_symbols"):
            symbols, by_binary, stats_by_binary = extract_all_symbols(manifest, run_dir, str(readelf))
            logging.info("Function symbol rows: %d", len(symbols))
        with ctx.step("strip_artifacts"):
            if args.skip_strip:
                strip_rows = []
                write_csv(run_dir / "strip_status.csv", [], ["version", "arch", "src", "dst", "status", "return_code", "src_size", "dst_size", "message"])
                logging.info("Stripping skipped by flag")
            else:
                strip_rows = attempt_strip_dataset(manifest, run_dir, str(strip_tool) if strip_tool else None, args.force_strip)
                logging.info("Stripping successes: %d", sum(1 for r in strip_rows if r["status"] == "success"))
        with ctx.step("experiment_cross_arch_size_retrieval"):
            retrieval = exp_cross_arch_size_retrieval(by_binary, run_dir)
        with ctx.step("experiment_cve_patch_state_proxy"):
            patch_state = exp_cve_patch_state_proxy(stats_by_binary, manifest, run_dir)
        with ctx.step("experiment_version_change_transfer"):
            change_transfer = exp_version_change_transfer(by_binary, run_dir)
        with ctx.step("experiment_cve_awk_patch_probe"):
            awk_probe = exp_cve_awk_patch_probe(by_binary, run_dir)
        with ctx.step("aggregate_results"):
            summary = aggregate_results(manifest, symbols, strip_rows, retrieval, patch_state, change_transfer, awk_probe, source_summary, env)
            write_json(run_dir / "results_summary.json", summary)
            logging.info("Summary: %s", json.dumps(summary, ensure_ascii=False, sort_keys=True))
    except Exception:
        logging.exception("Pipeline failed")
        return 1
    logging.info("Pipeline completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
