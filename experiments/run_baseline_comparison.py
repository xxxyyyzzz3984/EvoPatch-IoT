#!/usr/bin/env python3
"""Fast unified baseline comparison for BusyBox cross-architecture retrieval.

The baselines in this script use stripped-compatible anonymous features:
function size, relative address rank, and local size-shape statistics. Function
names are used only as ground truth for evaluation, never as input features.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import gzip
import json
import logging
import math
import shutil
import sys
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = PROJECT_ROOT / "experiments" / "runs"
FEATURE_NAMES = ["log_size", "rel_addr", "rank_pct", "local_log_mean", "local_log_delta"]
FEATURE_SCALES = [1.0, 0.20, 0.20, 1.0, 1.0]
REPRESENTATIVE_VERSIONS = {
    "busybox-1.11.0",
    "busybox-1.14.0",
    "busybox-1.21.0",
    "busybox-1.28.4",
    "busybox-1.30.1",
    "busybox-1.33.1",
    "busybox-1.34.0",
    "busybox-1.37.0",
}


def now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def version_tuple(version: str) -> Tuple[int, ...]:
    raw = version.replace("busybox-", "")
    parts = []
    for item in raw.split("."):
        try:
            parts.append(int(item))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


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


class RunContext:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.status_path = out_dir / "status_events.jsonl"
        ensure_dir(out_dir)

    def setup_logging(self) -> None:
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(self.out_dir / "run.log", encoding="utf-8")
        fh.setFormatter(formatter)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(sh)

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
            logging.exception("FAILED %s", name)
            self.event(name, "failed", duration_sec=round(time.time() - start, 3), error=str(exc))
            raise
        else:
            duration = time.time() - start
            logging.info("END %s (%.2fs)", name, duration)
            self.event(name, "completed", duration_sec=round(duration, 3))


def latest_success_run() -> Path:
    candidates = []
    for run in RUNS_DIR.iterdir():
        if run.is_dir() and (run / "function_symbols.csv.gz").exists() and (run / "binary_manifest.csv").exists():
            candidates.append(run)
    if not candidates:
        raise FileNotFoundError("No previous pipeline run with function_symbols.csv.gz found")
    return sorted(candidates, key=lambda p: p.name)[-1]


def read_manifest(run_dir: Path) -> List[dict]:
    with (run_dir / "binary_manifest.csv").open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def mean_std(values: Sequence[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 1.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var) if var > 1e-9 else 1.0


def load_analysis_functions(run_dir: Path) -> Tuple[Dict[Tuple[str, str], List[dict]], Dict[Tuple[str, str], dict]]:
    by_binary: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    with gzip.open(run_dir / "function_symbols.csv.gz", "rt", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("analysis_func") != "1":
                continue
            name = row.get("norm_name", "")
            if not name:
                continue
            try:
                address = int(row["address"])
                size = int(row["size"])
            except ValueError:
                continue
            if size <= 0:
                continue
            by_binary[(row["version"], row["arch"])].append(
                {"version": row["version"], "arch": row["arch"], "name": name, "address": address, "size": size}
            )
    stats = {}
    for key, rows in by_binary.items():
        rows.sort(key=lambda r: (r["address"], r["size"], r["name"]))
        if not rows:
            continue
        min_addr = rows[0]["address"]
        max_addr = max(r["address"] + r["size"] for r in rows)
        span = max(max_addr - min_addr, 1)
        logs = [math.log1p(r["size"]) for r in rows]
        for idx, rec in enumerate(rows):
            left = max(0, idx - 2)
            right = min(len(rows), idx + 3)
            local_mean = sum(logs[left:right]) / max(right - left, 1)
            log_size = logs[idx]
            rec["feature"] = [
                log_size,
                (rec["address"] - min_addr) / span,
                idx / max(len(rows) - 1, 1),
                local_mean,
                log_size - local_mean,
            ]
        dims = list(zip(*(r["feature"] for r in rows)))
        means = []
        stds = []
        for values in dims:
            m, s = mean_std(values)
            means.append(m)
            stds.append(s)
        stats[key] = {"means": means, "stds": stds, "count": len(rows)}
    return by_binary, stats


def choose_versions(by_binary: Dict[Tuple[str, str], List[dict]], mode: str) -> List[str]:
    versions = sorted({v for v, _ in by_binary}, key=version_tuple)
    if mode == "full":
        return versions
    selected = [v for v in versions if v in REPRESENTATIVE_VERSIONS]
    if selected:
        return selected
    step = max(1, len(versions) // 8)
    return versions[::step]


def write_splits(out_dir: Path, versions: Sequence[str], archs: Sequence[str]) -> dict:
    sorted_versions = sorted(versions, key=version_tuple)
    train = [v for v in sorted_versions if version_tuple(v) <= (1, 30, 1)]
    val = [v for v in sorted_versions if (1, 31, 0) <= version_tuple(v) <= (1, 33, 2)]
    test = [v for v in sorted_versions if version_tuple(v) >= (1, 34, 0)]
    splits = {
        "version_range_split": {"train": train, "validation": val, "test": test},
        "leave_one_arch": {arch: {"test_arch": arch, "train_arches": [a for a in archs if a != arch]} for arch in archs},
        "representative_versions": sorted(REPRESENTATIVE_VERSIONS, key=version_tuple),
    }
    write_json(out_dir / "splits.json", splits)
    return splits


def sampled_queries(queries: Sequence[dict], max_queries: int) -> List[dict]:
    if max_queries <= 0 or len(queries) <= max_queries:
        return list(queries)
    step = len(queries) / max_queries
    return [queries[int(i * step)] for i in range(max_queries)]


def transform_feature(feature: Sequence[float], method: str, src_stats: dict, dst_stats: dict) -> List[float]:
    if method in {"SizeStat", "ShapeStat"}:
        return list(feature)
    # Distribution calibration uses anonymous per-binary feature statistics only.
    out = []
    for x, sm, ss, dm, ds in zip(feature, src_stats["means"], src_stats["stds"], dst_stats["means"], dst_stats["stds"]):
        out.append(dm + ((x - sm) / ss) * ds)
    return out


def distance(a: Sequence[float], b: Sequence[float], dims: Sequence[int]) -> float:
    total = 0.0
    for idx in dims:
        total += ((a[idx] - b[idx]) / FEATURE_SCALES[idx]) ** 2
    return total


def build_candidate_index(candidates: Sequence[dict]) -> List[Tuple[float, int, dict]]:
    rows = [(rec["feature"][0], idx, rec) for idx, rec in enumerate(candidates)]
    rows.sort(key=lambda x: (x[0], x[1]))
    return rows


def topk_window(query_feature: Sequence[float], candidates_sorted: Sequence[Tuple[float, int, dict]], dims: Sequence[int], window: int, k: int) -> List[dict]:
    primary = [item[0] for item in candidates_sorted]
    pos = bisect.bisect_left(primary, query_feature[0])
    left = max(0, pos - window)
    right = min(len(candidates_sorted), pos + window + 1)
    target_width = min(len(candidates_sorted), 2 * window + 1)
    if right - left < target_width:
        missing = target_width - (right - left)
        left = max(0, left - missing)
        right = min(len(candidates_sorted), right + missing)
    scored = []
    for _, _, rec in candidates_sorted[left:right]:
        scored.append((distance(query_feature, rec["feature"], dims), rec["address"], rec["name"], rec))
    scored.sort(key=lambda x: (x[0], x[1], x[2]))
    return [x[3] for x in scored[:k]]


def evaluate_pair(method: str, version: str, src_arch: str, dst_arch: str,
                  by_binary: Dict[Tuple[str, str], List[dict]], stats: Dict[Tuple[str, str], dict],
                  window: int, max_queries: int) -> Optional[dict]:
    queries = by_binary.get((version, src_arch), [])
    candidates = by_binary.get((version, dst_arch), [])
    if not queries or not candidates:
        return None
    candidate_names = {r["name"] for r in candidates}
    eval_queries = [q for q in queries if q["name"] in candidate_names]
    eval_queries = sampled_queries(eval_queries, max_queries)
    if not eval_queries:
        return None
    dims = [0] if method == "SizeStat" else [0, 1, 2, 3, 4]
    candidate_index = build_candidate_index(candidates)
    src_stats = stats[(version, src_arch)]
    dst_stats = stats[(version, dst_arch)]
    hits1 = hits5 = hits10 = 0
    mrr10 = 0.0
    inspected_sum = 0
    for query in eval_queries:
        q_feat = transform_feature(query["feature"], method, src_stats, dst_stats)
        top = topk_window(q_feat, candidate_index, dims, window, 10)
        names = [r["name"] for r in top]
        target = query["name"]
        hits1 += int(target in names[:1])
        hits5 += int(target in names[:5])
        hits10 += int(target in names[:10])
        rank = None
        for idx, name in enumerate(names, start=1):
            if name == target:
                rank = idx
                mrr10 += 1.0 / idx
                break
        inspected_sum += rank if rank is not None else 11
    n = len(eval_queries)
    return {
        "method": method,
        "version": version,
        "src_arch": src_arch,
        "dst_arch": dst_arch,
        "queries": n,
        "candidates": len(candidates),
        "hit_at_1": round(hits1 / n, 6),
        "hit_at_5": round(hits5 / n, 6),
        "hit_at_10": round(hits10 / n, 6),
        "mrr_at_10": round(mrr10 / n, 6),
        "mean_inspected_at_10": round(inspected_sum / n, 6),
    }


def summarize(rows: Sequence[dict]) -> List[dict]:
    by_method: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_method[row["method"]].append(row)
    summary = []
    for method, items in sorted(by_method.items()):
        total_q = sum(int(r["queries"]) for r in items)
        entry = {"method": method, "pairs": len(items), "queries": total_q}
        for metric in ["hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "mean_inspected_at_10"]:
            macro = sum(float(r[metric]) for r in items) / len(items)
            weighted = sum(float(r[metric]) * int(r["queries"]) for r in items) / max(total_q, 1)
            entry[f"macro_{metric}"] = round(macro, 6)
            entry[f"weighted_{metric}"] = round(weighted, 6)
        summary.append(entry)
    return summary


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-run", type=Path, default=None)
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--window", type=int, default=64)
    parser.add_argument("--max-queries", type=int, default=400)
    parser.add_argument("--run-id", default="baseline_" + now_id())
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    input_run = args.input_run or latest_success_run()
    out_dir = RUNS_DIR / args.run_id
    ctx = RunContext(out_dir)
    ctx.setup_logging()
    logging.info("Input run: %s", input_run)
    logging.info("Output run: %s", out_dir)
    try:
        with ctx.step("copy_environment_notes"):
            source_env = input_run / "environment.json"
            env = json.loads(source_env.read_text(encoding="utf-8")) if source_env.exists() else {}
            env["baseline_runner"] = {
                "mode": args.mode,
                "window": args.window,
                "max_queries": args.max_queries,
                "input_run": str(input_run),
                "methods": ["SizeStat", "ShapeStat", "DistCalibratedShape"],
                "notes": [
                    "Baselines use names only as ground-truth labels, not as input features.",
                    "Function boundaries currently come from unstripped labels; stripped multiarch extraction is the next engineering step.",
                    "DistCalibratedShape uses anonymous per-binary feature distribution calibration.",
                ],
            }
            write_json(out_dir / "environment.json", env)
        with ctx.step("load_data"):
            manifest = read_manifest(input_run)
            by_binary, stats = load_analysis_functions(input_run)
            versions = sorted({v for v, _ in by_binary}, key=version_tuple)
            archs = sorted({a for _, a in by_binary})
            logging.info("Loaded %d manifest rows and %d function groups", len(manifest), len(by_binary))
        with ctx.step("write_splits"):
            splits = write_splits(out_dir, versions, archs)
            logging.info("Version split sizes: train=%d val=%d test=%d",
                         len(splits["version_range_split"]["train"]),
                         len(splits["version_range_split"]["validation"]),
                         len(splits["version_range_split"]["test"]))
        with ctx.step("evaluate_baselines"):
            eval_versions = choose_versions(by_binary, args.mode)
            methods = ["SizeStat", "ShapeStat", "DistCalibratedShape"]
            max_queries = args.max_queries if args.mode == "quick" else 0
            rows = []
            total_pairs = 0
            for version in eval_versions:
                archs_v = sorted([arch for v, arch in by_binary if v == version])
                for src_arch in archs_v:
                    for dst_arch in archs_v:
                        if src_arch == dst_arch:
                            continue
                        total_pairs += 1
                        for method in methods:
                            row = evaluate_pair(method, version, src_arch, dst_arch, by_binary, stats, args.window, max_queries)
                            if row:
                                rows.append(row)
                        if total_pairs % 20 == 0:
                            logging.info("Evaluated %d directed arch-version pairs", total_pairs)
            fields = ["method", "version", "src_arch", "dst_arch", "queries", "candidates", "hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "mean_inspected_at_10"]
            write_csv(out_dir / "baseline_pair_results.csv", rows, fields)
            summary = summarize(rows)
            summary_fields = [
                "method", "pairs", "queries",
                "macro_hit_at_1", "weighted_hit_at_1",
                "macro_hit_at_5", "weighted_hit_at_5",
                "macro_hit_at_10", "weighted_hit_at_10",
                "macro_mrr_at_10", "weighted_mrr_at_10",
                "macro_mean_inspected_at_10", "weighted_mean_inspected_at_10",
            ]
            write_csv(out_dir / "baseline_summary.csv", summary, summary_fields)
            write_json(out_dir / "baseline_summary.json", {"input_run": str(input_run), "mode": args.mode, "window": args.window, "max_queries": max_queries, "pair_rows": len(rows), "summary": summary})
            logging.info("Baseline summary: %s", json.dumps(summary, ensure_ascii=False, sort_keys=True))
    except Exception:
        logging.exception("Baseline comparison failed")
        return 1
    logging.info("Baseline comparison completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
