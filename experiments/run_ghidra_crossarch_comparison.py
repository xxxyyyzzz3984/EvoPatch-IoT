#!/usr/bin/env python3
"""Unified stripped-feature cross-architecture retrieval comparison.

This script consumes:
1. Ghidra-extracted stripped function features.
2. Unstripped symbol labels from the earlier pipeline run.

It first builds a high-confidence anonymous alignment layer between stripped
functions and unstripped labels within each version/architecture, then evaluates
recent-paper-inspired simplified baselines and an evolution-aware fusion method.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import gzip
import json
import logging
import math
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = PROJECT_ROOT / "experiments" / "runs"

SHAPE_SCALES = [1.0, 0.20, 0.20, 1.0, 1.0]
GRAPH_KEYS = [
    "log_size",
    "log_instr",
    "log_bb",
    "log_edges",
    "call_rate",
    "branch_rate",
    "ret_rate",
    "string_rate",
    "constant_rate",
    "avg_bb_instr",
    "edge_density",
]
OP_CLASSES = [
    "LOAD", "STORE", "ARITH", "LOGIC", "SHIFT", "CMP", "CALL", "RET",
    "BRANCH_COND", "BRANCH_UNCOND", "STACK", "MOVE", "SYSCALL", "OTHER",
]
EDGE_TYPES = [
    "CONDITIONAL_JUMP", "CONDITIONAL_CALL", "UNCONDITIONAL_JUMP",
    "UNCONDITIONAL_CALL", "FALL_THROUGH", "COMPUTED_JUMP", "COMPUTED_CALL",
    "INDIRECTION", "CALL_TERMINATOR", "TERMINATOR", "CONDITIONAL_TERMINATOR",
]


def now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def version_tuple(version: str) -> Tuple[int, ...]:
    raw = version.replace("busybox-", "")
    out = []
    for item in raw.split("."):
        try:
            out.append(int(item))
        except ValueError:
            out.append(0)
    return tuple(out)


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


def latest_run_with_file(pattern: str) -> Path:
    runs = []
    for path in RUNS_DIR.iterdir():
        if path.is_dir() and list(path.glob(pattern)):
            runs.append(path)
    if not runs:
        raise FileNotFoundError(f"No run matched pattern {pattern!r}")
    return sorted(runs, key=lambda p: p.name)[-1]


def parse_csv_list(raw: Optional[str]) -> Optional[set]:
    if not raw:
        return None
    return {item.strip() for item in raw.split(",") if item.strip()}


def log1p(x: float) -> float:
    return math.log1p(max(float(x), 0.0))


def cosine_dense(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b:
        return 0.0
    dot = 0.0
    aa = 0.0
    bb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        aa += x * x
        bb += y * y
    if aa <= 1e-12 or bb <= 1e-12:
        return 0.0
    return dot / math.sqrt(aa * bb)


def cosine_sparse(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    dot = sum(value * b.get(key, 0.0) for key, value in a.items())
    aa = sum(value * value for value in a.values())
    bb = sum(value * value for value in b.values())
    if aa <= 1e-12 or bb <= 1e-12:
        return 0.0
    return dot / math.sqrt(aa * bb)


def signed_hash_index(key: str, dim: int) -> Tuple[int, int]:
    h = hash(key)
    idx = h % dim
    sign = -1 if ((h >> 8) & 1) else 1
    return idx, sign


def sparse_to_hashed_dense(counter: Dict[str, float], dim: int) -> List[float]:
    vec = [0.0] * dim
    for key, value in counter.items():
        idx, sign = signed_hash_index(key, dim)
        vec[idx] += sign * value
    return vec


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    frac = pos - lo
    return float(ordered[lo] * (1 - frac) + ordered[hi] * frac)


def feature_distance(a: Sequence[float], b: Sequence[float]) -> float:
    total = 0.0
    for idx in range(min(len(a), len(b), len(SHAPE_SCALES))):
        total += ((a[idx] - b[idx]) / SHAPE_SCALES[idx]) ** 2
    return total


def build_window_index(records: Sequence[dict]) -> List[Tuple[float, int, dict]]:
    rows = [(float(rec["shape_feature"][0]), idx, rec) for idx, rec in enumerate(records)]
    rows.sort(key=lambda x: (x[0], x[1]))
    return rows


def top_candidates(query_feature: Sequence[float], candidates_sorted: Sequence[Tuple[float, int, dict]],
                   window: int) -> List[dict]:
    primary = [item[0] for item in candidates_sorted]
    pos = bisect.bisect_left(primary, query_feature[0])
    left = max(0, pos - window)
    right = min(len(candidates_sorted), pos + window + 1)
    target_width = min(len(candidates_sorted), 2 * window + 1)
    if right - left < target_width:
        missing = target_width - (right - left)
        left = max(0, left - missing)
        right = min(len(candidates_sorted), right + missing)
    return [row[2] for row in candidates_sorted[left:right]]


def per_binary_shape(records: List[dict], addr_key: str) -> None:
    records.sort(key=lambda r: (int(r[addr_key]), int(r["size"])))
    if not records:
        return
    min_addr = int(records[0][addr_key])
    max_addr = max(int(r[addr_key]) + int(r["size"]) for r in records)
    span = max(max_addr - min_addr, 1)
    logs = [log1p(int(r["size"])) for r in records]
    for idx, rec in enumerate(records):
        left = max(0, idx - 2)
        right = min(len(records), idx + 3)
        local_mean = sum(logs[left:right]) / max(right - left, 1)
        log_size = logs[idx]
        rec["shape_feature"] = [
            log_size,
            (int(rec[addr_key]) - min_addr) / span,
            idx / max(len(records) - 1, 1),
            local_mean,
            log_size - local_mean,
        ]


def load_unstripped_labels(label_run: Path, versions: Optional[set], archs: Optional[set],
                           min_size: int) -> Dict[Tuple[str, str], List[dict]]:
    by_binary: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    path = label_run / "function_symbols.csv.gz"
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            version = row["version"]
            arch = row["arch"]
            if versions and version not in versions and version.replace("busybox-", "") not in versions:
                continue
            if archs and arch not in archs:
                continue
            if row.get("analysis_func") != "1":
                continue
            size = int(row["size"])
            if size < min_size:
                continue
            by_binary[(version, arch)].append({
                "version": version,
                "arch": arch,
                "addr": int(row["address"]),
                "size": size,
                "norm_name": row["norm_name"],
                "binary_name": row["binary_name"],
            })
    for records in by_binary.values():
        per_binary_shape(records, "addr")
    return by_binary


def op_class_from_token(token: str) -> str:
    return token.split(" ", 1)[0] if token else "OTHER"


def load_ghidra_features(ghidra_run: Path, versions: Optional[set], archs: Optional[set],
                         min_size: int, min_instr: int) -> Dict[Tuple[str, str], List[dict]]:
    by_binary: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for path in sorted((ghidra_run / "features").rglob("*.jsonl")):
        version = path.parent.name
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                if "extract_error" in obj:
                    continue
                arch = obj["arch"]
                if versions and version not in versions and version.replace("busybox-", "") not in versions:
                    continue
                if archs and arch not in archs:
                    continue
                size = int(obj["size"])
                instr = int(obj["stats"]["instruction_count"])
                if size < min_size or instr < min_instr:
                    continue
                bb = int(obj["stats"]["basic_block_count"])
                edges = int(obj["stats"]["cfg_edge_count"])
                op_counter = Counter(op_class_from_token(tok) for tok in obj.get("tokens", []))
                edge_counter = Counter(edge[2] for edge in obj.get("cfg_edges", []))
                ctx_counter = Counter()
                for item in obj.get("string_refs", []):
                    ctx_counter["str:" + item["category"]] += float(item["count"])
                for item in obj.get("constant_buckets", []):
                    ctx_counter["const:" + item["bucket"]] += float(item["count"])
                for item in obj.get("call_refs", []):
                    ctx_counter["call:" + item["kind"]] += 1.0
                record = {
                    "version": version,
                    "arch": arch,
                    "start_addr": int(obj["start_addr"], 16),
                    "size": size,
                    "instruction_count": instr,
                    "basic_block_count": bb,
                    "cfg_edge_count": edges,
                    "call_count": int(obj["stats"]["call_count"]),
                    "branch_count": int(obj["stats"]["branch_count"]),
                    "ret_count": int(obj["stats"]["ret_count"]),
                    "string_ref_count": int(obj["stats"]["string_ref_count"]),
                    "constant_count": int(obj["stats"]["constant_count"]),
                    "tokens": list(obj.get("tokens", [])),
                    "op_counter": dict(op_counter),
                    "edge_counter": dict(edge_counter),
                    "context_counter": dict(ctx_counter),
                    "source_path": str(path),
                    "function_id": obj["function_id"],
                }
                by_binary[(version, arch)].append(record)
    for records in by_binary.values():
        per_binary_shape(records, "start_addr")
    return by_binary


def mutual_match_binary(labels: List[dict], stripped: List[dict], window: int, max_dist: float) -> Tuple[List[dict], dict]:
    if not labels or not stripped:
        return [], {
            "labels": len(labels),
            "stripped": len(stripped),
            "mutual_matches": 0,
            "median_match_dist": 0.0,
            "p90_match_dist": 0.0,
        }
    label_index = build_window_index(labels)
    strip_index = build_window_index(stripped)

    for label in labels:
        candidates = top_candidates(label["shape_feature"], strip_index, window)
        best = min(candidates, key=lambda rec: feature_distance(label["shape_feature"], rec["shape_feature"]))
        label["_best_strip"] = best
        label["_best_strip_dist"] = feature_distance(label["shape_feature"], best["shape_feature"])

    for rec in stripped:
        candidates = top_candidates(rec["shape_feature"], label_index, window)
        best = min(candidates, key=lambda lab: feature_distance(rec["shape_feature"], lab["shape_feature"]))
        rec["_best_label"] = best
        rec["_best_label_dist"] = feature_distance(rec["shape_feature"], best["shape_feature"])

    matched = []
    distances = []
    for rec in stripped:
        label = rec["_best_label"]
        dist = rec["_best_label_dist"]
        if dist > max_dist:
            continue
        if label.get("_best_strip") is not rec:
            continue
        distances.append(dist)
        matched.append({
            **rec,
            "norm_name": label["norm_name"],
            "label_addr": label["addr"],
            "label_size": label["size"],
            "match_dist": round(dist, 6),
            "match_confidence": round(1.0 / (1.0 + dist), 6),
        })
    summary = {
        "labels": len(labels),
        "stripped": len(stripped),
        "mutual_matches": len(matched),
        "median_match_dist": round(median(distances), 6) if distances else 0.0,
        "p90_match_dist": round(percentile(distances, 0.90), 6) if distances else 0.0,
    }
    return matched, summary


def corpus_df(records: Sequence[dict], key: str) -> Counter:
    df = Counter()
    for rec in records:
        df.update(set(rec[key]))
    return df


def counter_df(records: Sequence[dict], key: str) -> Counter:
    df = Counter()
    for rec in records:
        df.update(set(rec[key].keys()))
    return df


def tfidf_sparse(counter: Counter, df: Counter, total_docs: int, prefix: str = "") -> Dict[str, float]:
    out = {}
    total = sum(counter.values())
    if total <= 0:
        return out
    for key, count in counter.items():
        idf = math.log((1.0 + total_docs) / (1.0 + df.get(key, 0))) + 1.0
        out[prefix + key] = (count / total) * idf
    return out


def dense_stats(rec: dict) -> List[float]:
    size = float(rec["size"])
    instr = float(rec["instruction_count"])
    bb = float(rec["basic_block_count"])
    edges = float(rec["cfg_edge_count"])
    avg_bb = instr / max(bb, 1.0)
    edge_density = edges / max(bb, 1.0)
    vec = [
        log1p(size),
        log1p(instr),
        log1p(bb),
        log1p(edges),
        float(rec["call_count"]) / max(instr, 1.0),
        float(rec["branch_count"]) / max(instr, 1.0),
        float(rec["ret_count"]) / max(instr, 1.0),
        float(rec["string_ref_count"]) / max(instr, 1.0),
        float(rec["constant_count"]) / max(instr, 1.0),
        avg_bb,
        edge_density,
    ]
    op_total = max(sum(rec["op_counter"].values()), 1)
    edge_total = max(sum(rec["edge_counter"].values()), 1)
    vec.extend(rec["op_counter"].get(key, 0) / op_total for key in OP_CLASSES)
    vec.extend(rec["edge_counter"].get(key, 0) / edge_total for key in EDGE_TYPES)
    return vec


def mean_std(vectors: Sequence[Sequence[float]]) -> Tuple[List[float], List[float]]:
    if not vectors:
        return [], []
    dims = len(vectors[0])
    means = []
    stds = []
    for i in range(dims):
        col = [vec[i] for vec in vectors]
        mean = sum(col) / len(col)
        var = sum((x - mean) ** 2 for x in col) / len(col)
        std = math.sqrt(var) if var > 1e-9 else 1.0
        means.append(mean)
        stds.append(std)
    return means, stds


def normalize_dense(vec: Sequence[float], means: Sequence[float], stds: Sequence[float]) -> List[float]:
    if not means or not stds:
        return list(vec)
    return [(x - m) / s for x, m, s in zip(vec, means, stds)]


def build_method_features(records: Sequence[dict], train_records: Sequence[dict]) -> None:
    token_df = corpus_df(train_records, "tokens")
    ctx_df = counter_df(train_records, "context_counter")
    total_docs = max(len(train_records), 1)

    for rec in records:
        rec["shape_vec"] = list(rec["shape_feature"])
        token_counter = Counter(rec["tokens"])
        rec["token_sparse"] = tfidf_sparse(token_counter, token_df, total_docs, prefix="tok:")
        rec["context_sparse"] = tfidf_sparse(Counter(rec["context_counter"]), ctx_df, total_docs, prefix="ctx:")
        rec["graph_vec"] = dense_stats(rec)

    token_hash_dim = 256
    ctx_hash_dim = 64
    for rec in records:
        rec["token_hash"] = sparse_to_hashed_dense(rec["token_sparse"], token_hash_dim)
        rec["context_hash"] = sparse_to_hashed_dense(rec["context_sparse"], ctx_hash_dim)

    graph_train = [rec["graph_vec"] for rec in train_records]
    graph_means, graph_stds = mean_std(graph_train)
    by_arch_graph = defaultdict(list)
    by_arch_shape = defaultdict(list)
    for rec in train_records:
        by_arch_graph[rec["arch"]].append(rec["graph_vec"])
        by_arch_shape[rec["arch"]].append(rec["shape_vec"])
    graph_arch_stats = {arch: mean_std(vs) for arch, vs in by_arch_graph.items()}
    shape_arch_stats = {arch: mean_std(vs) for arch, vs in by_arch_shape.items()}

    for rec in records:
        rec["graph_norm"] = normalize_dense(rec["graph_vec"], graph_means, graph_stds)
        gmeans, gstds = graph_arch_stats.get(rec["arch"], (graph_means, graph_stds))
        smeans, sstds = shape_arch_stats.get(rec["arch"], ([], []))
        rec["graph_arch_norm"] = normalize_dense(rec["graph_vec"], gmeans, gstds)
        rec["shape_arch_norm"] = normalize_dense(rec["shape_vec"], smeans, sstds)
        rec["fusion_vec"] = rec["token_hash"] + rec["graph_arch_norm"] + rec["context_hash"] + rec["shape_arch_norm"]


def build_prototypes(train_records: Sequence[dict]) -> Dict[str, List[float]]:
    sums: Dict[str, List[float]] = {}
    counts: Counter = Counter()
    for rec in train_records:
        name = rec["norm_name"]
        vec = rec["fusion_vec"]
        if name not in sums:
            sums[name] = [0.0] * len(vec)
        counts[name] += 1
        acc = sums[name]
        for i, value in enumerate(vec):
            acc[i] += value
    return {name: [value / counts[name] for value in vec] for name, vec in sums.items() if counts[name] > 0}


def method_score(method: str, query: dict, candidate: dict, prototype: Optional[List[float]]) -> float:
    if method == "SizeStat":
        return -abs(log1p(query["size"]) - log1p(candidate["size"]))
    if method == "ShapeStat":
        return -feature_distance(query["shape_vec"], candidate["shape_vec"])
    if method == "CLAP-lite":
        return cosine_dense(query["token_hash"], candidate["token_hash"])
    if method == "GTrans-lite":
        return cosine_dense(query["graph_norm"], candidate["graph_norm"])
    if method == "AMMF-lite":
        token = cosine_dense(query["token_hash"], candidate["token_hash"])
        graph = cosine_dense(query["graph_norm"], candidate["graph_norm"])
        ctx = cosine_dense(query["context_hash"], candidate["context_hash"])
        return 0.55 * token + 0.30 * graph + 0.15 * ctx
    if method == "Binary2vec-lite":
        fused = cosine_dense(query["fusion_vec"], candidate["fusion_vec"])
        shape = cosine_dense(query["shape_arch_norm"], candidate["shape_arch_norm"])
        graph = cosine_dense(query["graph_arch_norm"], candidate["graph_arch_norm"])
        return 0.60 * fused + 0.20 * graph + 0.20 * shape
    if method == "EvoPatch-IoT-Lite":
        fused = cosine_dense(query["fusion_vec"], candidate["fusion_vec"])
        shape = -feature_distance(query["shape_vec"], candidate["shape_vec"])
        evo = cosine_dense(candidate["fusion_vec"], prototype) if prototype else 0.0
        # Under the current stripped-to-unstripped anonymous alignment protocol,
        # local size/order geometry is a strong prior.  We therefore use shape
        # distance as the retrieval backbone, and let multi-view fusion plus the
        # historical evolution prototype re-rank ambiguous neighbors.
        return 0.70 * shape + 0.10 * fused + 0.20 * evo
    raise KeyError(method)


def evaluate_pair(method: str, version: str, src_arch: str, dst_arch: str,
                  matched_by_binary: Dict[Tuple[str, str], List[dict]],
                  prototypes: Dict[str, List[float]], max_queries: int) -> Optional[dict]:
    queries = matched_by_binary.get((version, src_arch), [])
    candidates = matched_by_binary.get((version, dst_arch), [])
    if not queries or not candidates:
        return None
    candidate_by_name = defaultdict(list)
    for rec in candidates:
        candidate_by_name[rec["norm_name"]].append(rec)
    eval_queries = [q for q in queries if q["norm_name"] in candidate_by_name]
    if max_queries > 0 and len(eval_queries) > max_queries:
        step = len(eval_queries) / max_queries
        eval_queries = [eval_queries[int(i * step)] for i in range(max_queries)]
    if not eval_queries:
        return None
    hits1 = hits5 = hits10 = 0
    mrr10 = 0.0
    inspected = 0
    for query in eval_queries:
        proto = prototypes.get(query["norm_name"])
        scored = []
        for cand in candidates:
            score = method_score(method, query, cand, proto)
            scored.append((score, -cand["match_confidence"], cand["start_addr"], cand["norm_name"], cand))
        scored.sort(reverse=True)
        top = [item[-1] for item in scored[:10]]
        names = [rec["norm_name"] for rec in top]
        target = query["norm_name"]
        hits1 += int(target in names[:1])
        hits5 += int(target in names[:5])
        hits10 += int(target in names[:10])
        rank = None
        for idx, name in enumerate(names, start=1):
            if name == target:
                rank = idx
                mrr10 += 1.0 / idx
                break
        inspected += rank if rank is not None else 11
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
        "mean_inspected_at_10": round(inspected / n, 6),
    }


def summarize(rows: Sequence[dict]) -> List[dict]:
    by_method: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_method[row["method"]].append(row)
    out = []
    for method, items in sorted(by_method.items()):
        total_q = sum(int(r["queries"]) for r in items)
        entry = {"method": method, "pairs": len(items), "queries": total_q}
        for metric in ["hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "mean_inspected_at_10"]:
            macro = sum(float(r[metric]) for r in items) / len(items)
            weighted = sum(float(r[metric]) * int(r["queries"]) for r in items) / max(total_q, 1)
            entry[f"macro_{metric}"] = round(macro, 6)
            entry[f"weighted_{metric}"] = round(weighted, 6)
        out.append(entry)
    return out


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-run", type=Path, default=None)
    parser.add_argument("--label-run", type=Path, default=None)
    parser.add_argument("--versions", default="busybox-1.21.0,busybox-1.33.1,busybox-1.37.0")
    parser.add_argument("--test-version", default="busybox-1.37.0")
    parser.add_argument("--archs", default="aarch64,arm,mips,mipsel,x86_64")
    parser.add_argument("--min-size", type=int, default=16)
    parser.add_argument("--min-instr", type=int, default=4)
    parser.add_argument("--match-window", type=int, default=96)
    parser.add_argument("--match-max-dist", type=float, default=0.20)
    parser.add_argument("--max-queries", type=int, default=300)
    parser.add_argument("--run-id", default="ghidra_cmp_" + now_id())
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ghidra_run = args.ghidra_run or latest_run_with_file("features/**/*.jsonl")
    label_run = args.label_run or latest_run_with_file("function_symbols.csv.gz")
    out_dir = RUNS_DIR / args.run_id
    ctx = RunContext(out_dir)
    ctx.setup_logging()
    versions = parse_csv_list(args.versions)
    archs = parse_csv_list(args.archs)
    logging.info("Ghidra run: %s", ghidra_run)
    logging.info("Label run: %s", label_run)
    logging.info("Output run: %s", out_dir)

    try:
        with ctx.step("load_inputs"):
            labels_by_binary = load_unstripped_labels(label_run, versions, archs, args.min_size)
            stripped_by_binary = load_ghidra_features(ghidra_run, versions, archs, args.min_size, args.min_instr)
            logging.info("Loaded labels=%d binaries stripped=%d binaries", len(labels_by_binary), len(stripped_by_binary))

        matched_by_binary: Dict[Tuple[str, str], List[dict]] = {}
        matching_rows = []
        all_matched = []
        with ctx.step("anonymous_alignment"):
            keys = sorted(set(labels_by_binary) & set(stripped_by_binary), key=lambda x: (version_tuple(x[0]), x[1]))
            for version, arch in keys:
                matched, summary = mutual_match_binary(
                    labels_by_binary[(version, arch)],
                    stripped_by_binary[(version, arch)],
                    window=args.match_window,
                    max_dist=args.match_max_dist,
                )
                matched_by_binary[(version, arch)] = matched
                all_matched.extend(matched)
                matching_rows.append({
                    "version": version,
                    "arch": arch,
                    **summary,
                    "match_ratio_labels": round(summary["mutual_matches"] / max(summary["labels"], 1), 6),
                    "match_ratio_stripped": round(summary["mutual_matches"] / max(summary["stripped"], 1), 6),
                })
            write_csv(out_dir / "matching_summary.csv", matching_rows, [
                "version", "arch", "labels", "stripped", "mutual_matches",
                "median_match_dist", "p90_match_dist", "match_ratio_labels", "match_ratio_stripped",
            ])
            write_csv(out_dir / "matched_functions.csv", all_matched, [
                "version", "arch", "function_id", "start_addr", "size", "instruction_count",
                "basic_block_count", "cfg_edge_count", "norm_name", "match_dist", "match_confidence", "label_addr", "label_size",
            ])
            logging.info("Matched stripped functions: %d", len(all_matched))

        with ctx.step("build_method_features"):
            train_versions = sorted({rec["version"] for rec in all_matched if rec["version"] != args.test_version}, key=version_tuple)
            train_records = [rec for rec in all_matched if rec["version"] in train_versions]
            build_method_features(all_matched, train_records if train_records else all_matched)
            prototypes = build_prototypes(train_records)
            logging.info("Train versions: %s", train_versions)
            logging.info("Evolution prototypes: %d", len(prototypes))

        with ctx.step("evaluate_methods"):
            methods = [
                "SizeStat",
                "ShapeStat",
                "CLAP-lite",
                "GTrans-lite",
                "AMMF-lite",
                "Binary2vec-lite",
                "EvoPatch-IoT-Lite",
            ]
            rows = []
            eval_versions = [args.test_version]
            for version in eval_versions:
                for src_arch in sorted(archs or {a for _, a in matched_by_binary}):
                    for dst_arch in sorted(archs or {a for _, a in matched_by_binary}):
                        if src_arch == dst_arch:
                            continue
                        for method in methods:
                            row = evaluate_pair(method, version, src_arch, dst_arch, matched_by_binary, prototypes, args.max_queries)
                            if row:
                                rows.append(row)
            write_csv(out_dir / "retrieval_pair_results.csv", rows, [
                "method", "version", "src_arch", "dst_arch", "queries", "candidates",
                "hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "mean_inspected_at_10",
            ])
            summary = summarize(rows)
            write_csv(out_dir / "retrieval_summary.csv", summary, [
                "method", "pairs", "queries",
                "macro_hit_at_1", "weighted_hit_at_1",
                "macro_hit_at_5", "weighted_hit_at_5",
                "macro_hit_at_10", "weighted_hit_at_10",
                "macro_mrr_at_10", "weighted_mrr_at_10",
                "macro_mean_inspected_at_10", "weighted_mean_inspected_at_10",
            ])
            write_json(out_dir / "summary.json", {
                "ghidra_run": str(ghidra_run),
                "label_run": str(label_run),
                "versions": sorted(versions or []),
                "test_version": args.test_version,
                "archs": sorted(archs or []),
                "min_size": args.min_size,
                "min_instr": args.min_instr,
                "match_window": args.match_window,
                "match_max_dist": args.match_max_dist,
                "matched_functions": len(all_matched),
                "train_versions": train_versions,
                "methods": methods,
                "summary": summary,
            })
            logging.info("Retrieval summary: %s", json.dumps(summary, ensure_ascii=False, sort_keys=True))
    except Exception:
        logging.exception("Ghidra cross-architecture comparison failed")
        return 1
    logging.info("Ghidra cross-architecture comparison completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
