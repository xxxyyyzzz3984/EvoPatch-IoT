#!/usr/bin/env python3
"""Reproducible experiments added for the PC-26060119 major revision.

The script reconstructs only the already aligned functions from archived Ghidra
artifacts.  It does not rerun disassembly.  Temporal experiments fit feature
statistics and historical prototypes using versions strictly earlier than the
version under test.
"""
from __future__ import annotations

import csv
import json
import math
import os
import platform
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import matplotlib.pyplot as plt
import numpy as np
import psutil
import torch
from scipy.stats import wilcoxon


ROOT = Path(__file__).resolve().parents[1]
PAPER_DIR = Path(__file__).resolve().parent
RUN_DIR = ROOT / "experiments" / "runs" / "codes_all57_eval_full_plus_vex_ex_20260419"
GHIDRA_DIR = ROOT / "experiments" / "runs" / "ghidra_eval_all57_20260419_bg"
OUT_DIR = PAPER_DIR / "revision_results"
FIG_DIR = PAPER_DIR / "figures"
ARCHS = ["aarch64", "arm", "mips", "mipsel", "x86_64"]
MIN_SIZE = 16
MIN_INSTR = 4
MAX_QUERIES = 300
SEED = 20260817
FIXED_WEIGHTS = (0.70, 0.10, 0.20)
VALIDATION_START = (1, 27, 0)
VALIDATION_END = (1, 29, 3)
TEST_START = (1, 30, 0)

import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_ghidra_crossarch_comparison import (  # noqa: E402
    build_method_features,
    build_prototypes,
    op_class_from_token,
    per_binary_shape,
    version_tuple,
)


def write_csv(path: Path, rows: Iterable[dict], fieldnames: Sequence[str] | None = None) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def normalize_rows(matrix: torch.Tensor) -> torch.Tensor:
    return matrix / torch.linalg.norm(matrix, dim=1, keepdim=True).clamp_min(1e-12)


def tensor_from(records: List[dict], key: str, device: str) -> torch.Tensor:
    return torch.tensor([record[key] for record in records], dtype=torch.float32, device=device)


def load_alignment_index() -> Tuple[List[dict], Dict[str, dict], set[str]]:
    rows = list(csv.DictReader((RUN_DIR / "matched_functions.csv").open("r", encoding="utf-8", newline="")))
    by_id = {row["function_id"]: row for row in rows}
    versions = {row["version"] for row in rows}
    return rows, by_id, versions


def reconstruct_matched_records() -> Tuple[List[dict], Dict[Tuple[str, str], List[dict]]]:
    alignment_rows, aligned_by_id, versions = load_alignment_index()
    recovered: Dict[str, dict] = {}
    feature_paths = sorted((GHIDRA_DIR / "features").rglob("*.jsonl"))

    for path_index, path in enumerate(feature_paths, start=1):
        version = path.parent.name
        if version not in versions:
            continue
        binary_records: List[dict] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                obj = json.loads(line)
                if "extract_error" in obj:
                    continue
                size = int(obj["size"])
                instr = int(obj["stats"]["instruction_count"])
                if size < MIN_SIZE or instr < MIN_INSTR:
                    continue
                op_counter = Counter(op_class_from_token(token) for token in obj.get("tokens", []))
                edge_counter = Counter(edge[2] for edge in obj.get("cfg_edges", []))
                context_counter = Counter()
                for item in obj.get("string_refs", []):
                    context_counter["str:" + item["category"]] += float(item["count"])
                for item in obj.get("constant_buckets", []):
                    context_counter["const:" + item["bucket"]] += float(item["count"])
                for item in obj.get("call_refs", []):
                    context_counter["call:" + item["kind"]] += 1.0
                stats = obj["stats"]
                binary_records.append(
                    {
                        "version": version,
                        "arch": obj["arch"],
                        "start_addr": int(obj["start_addr"], 16),
                        "size": size,
                        "instruction_count": instr,
                        "basic_block_count": int(stats["basic_block_count"]),
                        "cfg_edge_count": int(stats["cfg_edge_count"]),
                        "call_count": int(stats["call_count"]),
                        "branch_count": int(stats["branch_count"]),
                        "ret_count": int(stats["ret_count"]),
                        "string_ref_count": int(stats["string_ref_count"]),
                        "constant_count": int(stats["constant_count"]),
                        "tokens": list(obj.get("tokens", [])),
                        "op_counter": dict(op_counter),
                        "edge_counter": dict(edge_counter),
                        "context_counter": dict(context_counter),
                        "function_id": obj["function_id"],
                    }
                )
        per_binary_shape(binary_records, "start_addr")
        for record in binary_records:
            aligned = aligned_by_id.get(record["function_id"])
            if aligned is None:
                continue
            record.update(
                {
                    "norm_name": aligned["norm_name"],
                    "match_dist": float(aligned["match_dist"]),
                    "match_confidence": float(aligned["match_confidence"]),
                    "label_addr": int(aligned["label_addr"]),
                    "label_size": int(aligned["label_size"]),
                }
            )
            recovered[record["function_id"]] = record
        if path_index % 50 == 0:
            print(f"reconstructed {len(recovered):,} aligned functions from {path_index} feature files", flush=True)

    missing = [row["function_id"] for row in alignment_rows if row["function_id"] not in recovered]
    if missing:
        raise RuntimeError(f"Could not reconstruct {len(missing)} aligned functions; first={missing[0]}")

    records = [recovered[row["function_id"]] for row in alignment_rows]
    by_binary: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for record in records:
        by_binary[(record["version"], record["arch"])].append(record)
    return records, dict(by_binary)


def evaluation_queries(queries: List[dict], candidates: List[dict]) -> List[dict]:
    candidate_names = {record["norm_name"] for record in candidates}
    selected = [query for query in queries if query["norm_name"] in candidate_names]
    if len(selected) > MAX_QUERIES:
        step = len(selected) / MAX_QUERIES
        selected = [selected[int(index * step)] for index in range(MAX_QUERIES)]
    return selected


def metrics_from_scores(scores: torch.Tensor, query_names: List[str], candidate_names: List[str]) -> dict:
    top_k = min(10, scores.shape[1])
    indices = torch.topk(scores, k=top_k, dim=1, largest=True, sorted=True).indices.cpu().numpy()
    hits1 = hits5 = hits10 = 0
    reciprocal_rank = 0.0
    inspected = 0
    for row_index, query_name in enumerate(query_names):
        names = [candidate_names[column] for column in indices[row_index]]
        rank = next((rank for rank, name in enumerate(names, start=1) if name == query_name), None)
        hits1 += int(rank is not None and rank <= 1)
        hits5 += int(rank is not None and rank <= 5)
        hits10 += int(rank is not None and rank <= 10)
        reciprocal_rank += 1.0 / rank if rank is not None else 0.0
        inspected += rank if rank is not None else 11
    count = len(query_names)
    return {
        "queries": count,
        "hit_at_1": hits1 / count,
        "hit_at_5": hits5 / count,
        "hit_at_10": hits10 / count,
        "mrr_at_10": reciprocal_rank / count,
        "mean_inspected_at_10": inspected / count,
    }


def evaluate_pair(
    version: str,
    source_arch: str,
    target_arch: str,
    by_binary: Dict[Tuple[str, str], List[dict]],
    prototypes: Dict[str, List[float]],
    configurations: Dict[str, Tuple[float, float, float]],
    device: str,
) -> Tuple[List[dict], int, int]:
    candidates = by_binary.get((version, target_arch), [])
    queries = evaluation_queries(by_binary.get((version, source_arch), []), candidates)
    if not queries or not candidates:
        return [], 0, 0

    q_shape = tensor_from(queries, "shape_vec", device)
    c_shape = tensor_from(candidates, "shape_vec", device)
    shape_scales = torch.tensor([1.0, 0.20, 0.20, 1.0, 1.0], dtype=torch.float32, device=device)
    shape_score = -((((q_shape[:, None, :] - c_shape[None, :, :]) / shape_scales) ** 2).sum(dim=2))

    q_fused = normalize_rows(tensor_from(queries, "fusion_vec", device))
    c_fused = normalize_rows(tensor_from(candidates, "fusion_vec", device))
    fused_score = q_fused @ c_fused.T

    prototype_vectors = []
    prototype_count = 0
    dimension = len(candidates[0]["fusion_vec"])
    for query in queries:
        prototype = prototypes.get(query["norm_name"])
        if prototype is None:
            prototype_vectors.append([0.0] * dimension)
        else:
            prototype_vectors.append(prototype)
            prototype_count += 1
    prototype_tensor = torch.tensor(prototype_vectors, dtype=torch.float32, device=device)
    norms = torch.linalg.norm(prototype_tensor, dim=1, keepdim=True)
    available = norms.squeeze(1) > 1e-12
    prototype_tensor = prototype_tensor / norms.clamp_min(1e-12)
    prototype_score = prototype_tensor @ c_fused.T
    prototype_score[~available] = 0.0

    query_names = [record["norm_name"] for record in queries]
    candidate_names = [record["norm_name"] for record in candidates]
    rows = []
    for configuration, weights in configurations.items():
        geometry_weight, fusion_weight, prototype_weight = weights
        scores = (
            geometry_weight * shape_score
            + fusion_weight * fused_score
            + prototype_weight * prototype_score
        )
        metrics = metrics_from_scores(scores, query_names, candidate_names)
        rows.append(
            {
                "configuration": configuration,
                "geometry_weight": geometry_weight,
                "fusion_weight": fusion_weight,
                "prototype_weight": prototype_weight,
                "test_version": version,
                "src_arch": source_arch,
                "dst_arch": target_arch,
                "candidates": len(candidates),
                "prototype_queries": prototype_count,
                **metrics,
            }
        )
    return rows, len(queries), prototype_count


def summarize_pair_rows(rows: List[dict]) -> List[dict]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["configuration"]].append(row)
    output = []
    metrics = ["hit_at_1", "hit_at_5", "hit_at_10", "mrr_at_10", "mean_inspected_at_10"]
    for configuration, items in grouped.items():
        total_queries = sum(int(item["queries"]) for item in items)
        total_proto = sum(int(item["prototype_queries"]) for item in items)
        entry = {
            "configuration": configuration,
            "geometry_weight": items[0]["geometry_weight"],
            "fusion_weight": items[0]["fusion_weight"],
            "prototype_weight": items[0]["prototype_weight"],
            "versions": len({item["test_version"] for item in items}),
            "pairs": len(items),
            "queries": total_queries,
            "prototype_coverage": total_proto / max(total_queries, 1),
        }
        for metric in metrics:
            entry[f"weighted_{metric}"] = sum(float(item[metric]) * int(item["queries"]) for item in items) / max(total_queries, 1)
            entry[f"macro_{metric}"] = sum(float(item[metric]) for item in items) / len(items)
        output.append(entry)
    return output


def grid_configurations() -> Dict[str, Tuple[float, float, float]]:
    configurations = {}
    for geometry in range(11):
        for fusion in range(11 - geometry):
            prototype = 10 - geometry - fusion
            weights = (geometry / 10.0, fusion / 10.0, prototype / 10.0)
            name = f"w_{weights[0]:.1f}_{weights[1]:.1f}_{weights[2]:.1f}"
            configurations[name] = weights
    return configurations


def ablation_configurations() -> Dict[str, Tuple[float, float, float]]:
    return {
        "Full (0.70/0.10/0.20)": FIXED_WEIGHTS,
        "Geometry only": (1.0, 0.0, 0.0),
        "Fusion only": (0.0, 1.0, 0.0),
        "Prototype only": (0.0, 0.0, 1.0),
        "Without geometry": (0.0, 1.0 / 3.0, 2.0 / 3.0),
        "Without fusion": (7.0 / 9.0, 0.0, 2.0 / 9.0),
        "Without prototype": (7.0 / 8.0, 1.0 / 8.0, 0.0),
    }


def run_temporal_experiments(records: List[dict], by_binary: Dict[Tuple[str, str], List[dict]], device: str) -> Tuple[List[dict], List[dict], List[dict], List[dict]]:
    versions = sorted({record["version"] for record in records}, key=version_tuple)
    validation_versions = [
        version for version in versions if VALIDATION_START <= version_tuple(version) <= VALIDATION_END
    ]
    test_versions = [version for version in versions if version_tuple(version) >= TEST_START]
    evaluation_versions = validation_versions + test_versions
    validation_rows: List[dict] = []
    test_rows: List[dict] = []

    for index, test_version in enumerate(evaluation_versions, start=1):
        earlier = [record for record in records if version_tuple(record["version"]) < version_tuple(test_version)]
        current = [record for record in records if record["version"] == test_version]
        if not earlier:
            continue
        print(
            f"temporal {index}/{len(evaluation_versions)} {test_version}: "
            f"train={len(earlier):,}, test={len(current):,}",
            flush=True,
        )
        build_method_features(earlier + current, earlier)
        prototypes = build_prototypes(earlier)
        configurations = grid_configurations() if test_version in validation_versions else ablation_configurations()
        destination = validation_rows if test_version in validation_versions else test_rows
        for source_arch in ARCHS:
            for target_arch in ARCHS:
                if source_arch == target_arch:
                    continue
                pair_rows, _, _ = evaluate_pair(
                    test_version,
                    source_arch,
                    target_arch,
                    by_binary,
                    prototypes,
                    configurations,
                    device,
                )
                destination.extend(pair_rows)
        if device == "cuda":
            torch.cuda.empty_cache()

    validation_summary = summarize_pair_rows(validation_rows)
    validation_summary.sort(
        key=lambda row: (
            -row["weighted_hit_at_10"],
            -row["weighted_hit_at_1"],
            -row["weighted_mrr_at_10"],
        )
    )
    for rank, row in enumerate(validation_summary, start=1):
        row["validation_rank"] = rank
    test_summary = summarize_pair_rows(test_rows)
    test_summary.sort(key=lambda row: -row["weighted_hit_at_10"])
    return validation_rows, validation_summary, test_rows, test_summary


def paired_statistics(rows: List[dict], method_a: str, method_b: str, method_key: str, prefix: str) -> List[dict]:
    keyed: Dict[Tuple[str, str, str, str], dict] = {}
    for row in rows:
        method = row[method_key]
        if method not in {method_a, method_b}:
            continue
        key = (row["test_version"], row["src_arch"], row["dst_arch"], method)
        keyed[key] = row

    metric_names = ["hit_at_1", "hit_at_10", "mrr_at_10"]
    rng = np.random.default_rng(SEED)
    output = []
    for metric in metric_names:
        paired = []
        version_blocks: Dict[str, List[Tuple[float, float, int]]] = defaultdict(list)
        versions = sorted({key[0] for key in keyed}, key=version_tuple)
        for version in versions:
            for source_arch in ARCHS:
                for target_arch in ARCHS:
                    if source_arch == target_arch:
                        continue
                    key_a = (version, source_arch, target_arch, method_a)
                    key_b = (version, source_arch, target_arch, method_b)
                    if key_a not in keyed or key_b not in keyed:
                        continue
                    row_a = keyed[key_a]
                    row_b = keyed[key_b]
                    value_a = float(row_a[metric])
                    value_b = float(row_b[metric])
                    queries = int(row_a["queries"])
                    paired.append(value_a - value_b)
                    version_blocks[version].append((value_a, value_b, queries))

        differences = np.asarray(paired, dtype=float)
        test = wilcoxon(differences, zero_method="wilcox", alternative="two-sided", method="auto")
        block_values = []
        block_weights = []
        for version in versions:
            items = version_blocks[version]
            total = sum(item[2] for item in items)
            difference = sum((item[0] - item[1]) * item[2] for item in items) / max(total, 1)
            block_values.append(difference)
            block_weights.append(total)
        block_values = np.asarray(block_values, dtype=float)
        block_weights = np.asarray(block_weights, dtype=float)
        bootstrap = np.empty(20000, dtype=float)
        for iteration in range(len(bootstrap)):
            indices = rng.integers(0, len(block_values), size=len(block_values))
            bootstrap[iteration] = np.average(block_values[indices], weights=block_weights[indices])
        ci_low, ci_high = np.quantile(bootstrap, [0.025, 0.975])
        output.append(
            {
                "analysis": prefix,
                "metric": metric,
                "method_a": method_a,
                "method_b": method_b,
                "pairs": len(differences),
                "versions": len(block_values),
                "weighted_mean_difference": np.average(block_values, weights=block_weights),
                "median_pair_difference": float(np.median(differences)),
                "positive_pairs": int(np.sum(differences > 0)),
                "tied_pairs": int(np.sum(differences == 0)),
                "negative_pairs": int(np.sum(differences < 0)),
                "wilcoxon_statistic": float(test.statistic),
                "wilcoxon_p_two_sided": float(test.pvalue),
                "bootstrap_95_ci_low": float(ci_low),
                "bootstrap_95_ci_high": float(ci_high),
                "bootstrap_iterations": len(bootstrap),
            }
        )
    return output


def load_original_pair_rows() -> List[dict]:
    path = RUN_DIR / "retrieval_pair_results_all57.csv"
    return list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))


def make_revision_figure(
    validation_summary: List[dict],
    test_summary: List[dict],
    original_rows: List[dict],
    output_path: Path,
) -> None:
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5})
    navy = "#17324D"
    teal = "#1F8A70"
    orange = "#E07A3F"
    sand = "#E8D8B5"
    fig, axes = plt.subplots(2, 2, figsize=(10.5, 7.1), constrained_layout=True)

    preferred_order = [
        "Geometry only",
        "Fusion only",
        "Prototype only",
        "Without geometry",
        "Without fusion",
        "Without prototype",
        "Full (0.70/0.10/0.20)",
    ]
    by_name = {row["configuration"]: row for row in test_summary}
    labels = [label for label in preferred_order if label in by_name]
    positions = np.arange(len(labels))
    width = 0.36
    axes[0, 0].bar(
        positions - width / 2,
        [by_name[label]["weighted_hit_at_1"] for label in labels],
        width,
        color=navy,
        label="Hit@1",
    )
    axes[0, 0].bar(
        positions + width / 2,
        [by_name[label]["weighted_hit_at_10"] for label in labels],
        width,
        color=teal,
        label="Hit@10",
    )
    axes[0, 0].set_xticks(positions, [label.replace("Without ", "w/o ") for label in labels], rotation=28, ha="right")
    axes[0, 0].set_ylim(0, 0.65)
    axes[0, 0].set_ylabel("Weighted retrieval rate")
    axes[0, 0].set_title("(a) Direct component ablation on recent held-out versions", loc="left", fontweight="bold")
    axes[0, 0].legend(frameon=False, ncol=2, loc="upper left")
    axes[0, 0].grid(axis="y", alpha=0.2)

    x_values = []
    y_values = []
    colors = []
    for row in validation_summary:
        geometry = float(row["geometry_weight"])
        fusion = float(row["fusion_weight"])
        prototype = float(row["prototype_weight"])
        x_values.append(fusion + 0.5 * prototype)
        y_values.append(math.sqrt(3.0) * prototype / 2.0)
        colors.append(float(row["weighted_hit_at_10"]))
    scatter = axes[0, 1].scatter(x_values, y_values, c=colors, cmap="YlGnBu", s=42, edgecolor="white", linewidth=0.35)
    fixed_x = FIXED_WEIGHTS[1] + 0.5 * FIXED_WEIGHTS[2]
    fixed_y = math.sqrt(3.0) * FIXED_WEIGHTS[2] / 2.0
    axes[0, 1].scatter([fixed_x], [fixed_y], marker="*", s=150, color=orange, edgecolor="black", linewidth=0.5)
    axes[0, 1].annotate(
        "Eq. (11)",
        xy=(fixed_x, fixed_y),
        xytext=(fixed_x + 0.10, fixed_y + 0.07),
        arrowprops={"arrowstyle": "-", "color": orange, "lw": 0.9},
        ha="left",
        va="bottom",
    )
    axes[0, 1].plot([0, 1, 0.5, 0], [0, 0, math.sqrt(3) / 2, 0], color=navy, linewidth=0.8)
    axes[0, 1].text(-0.03, -0.035, "Geometry", ha="left", va="top")
    axes[0, 1].text(1.03, -0.035, "Fusion", ha="right", va="top")
    axes[0, 1].text(0.5, math.sqrt(3) / 2 + 0.035, "Prototype", ha="center", va="bottom")
    axes[0, 1].set_xticks([])
    axes[0, 1].set_yticks([])
    axes[0, 1].set_title("(b) Validation-only coefficient sweep", loc="left", fontweight="bold")
    colorbar = fig.colorbar(scatter, ax=axes[0, 1], fraction=0.045, pad=0.02)
    colorbar.set_label("Weighted Hit@10")

    original_by_key = defaultdict(dict)
    for row in original_rows:
        if row["method"] in {"EvoPatch-IoT", "ShapeStat"}:
            key = (row["test_version"], row["src_arch"], row["dst_arch"])
            original_by_key[key][row["method"]] = float(row["hit_at_10"])
    differences = [values["EvoPatch-IoT"] - values["ShapeStat"] for values in original_by_key.values() if len(values) == 2]
    axes[1, 0].hist(differences, bins=31, color=navy, alpha=0.9, edgecolor="white", linewidth=0.35)
    axes[1, 0].axvline(0, color=orange, linestyle="--", linewidth=1.1)
    axes[1, 0].axvline(np.mean(differences), color=teal, linewidth=1.2, label=f"mean={np.mean(differences):.3f}")
    axes[1, 0].set_xlabel("Pair-level Hit@10 difference")
    axes[1, 0].set_ylabel("Directed architecture pairs")
    axes[1, 0].set_title("(c) EvoPatch-IoT minus geometry-only baseline", loc="left", fontweight="bold")
    axes[1, 0].legend(frameon=False)
    axes[1, 0].grid(axis="y", alpha=0.2)

    full_rows = [row for row in test_summary if row["configuration"] == "Full (0.70/0.10/0.20)"]
    geometry_rows = [row for row in test_summary if row["configuration"] == "Geometry only"]
    if full_rows and geometry_rows:
        full = full_rows[0]
        geometry = geometry_rows[0]
        metric_labels = ["Hit@1", "Hit@5", "Hit@10", "MRR@10"]
        full_values = [full["weighted_hit_at_1"], full["weighted_hit_at_5"], full["weighted_hit_at_10"], full["weighted_mrr_at_10"]]
        geometry_values = [geometry["weighted_hit_at_1"], geometry["weighted_hit_at_5"], geometry["weighted_hit_at_10"], geometry["weighted_mrr_at_10"]]
        x = np.arange(len(metric_labels))
        axes[1, 1].plot(x, geometry_values, marker="o", color=orange, linewidth=2, label="Geometry only")
        axes[1, 1].plot(x, full_values, marker="o", color=teal, linewidth=2, label="Full temporal")
        axes[1, 1].fill_between(x, geometry_values, full_values, color=sand, alpha=0.55)
        axes[1, 1].set_xticks(x, metric_labels)
        axes[1, 1].set_ylim(0, 0.65)
        axes[1, 1].set_ylabel("Weighted score")
        axes[1, 1].set_title("(d) Historical-only evaluation (versions 1.30--1.37)", loc="left", fontweight="bold")
        axes[1, 1].legend(frameon=False)
        axes[1, 1].grid(axis="y", alpha=0.2)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    fig.savefig(output_path.with_suffix(".png"), dpi=300, bbox_inches="tight")
    plt.close(fig)


def hardware_info() -> dict:
    gpu = {}
    try:
        line = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ],
            text=True,
        ).strip().splitlines()[0]
        name, memory_mib, driver = [item.strip() for item in line.split(",")]
        gpu = {"name": name, "memory_mib": int(memory_mib), "driver": driver}
    except Exception as exc:  # pragma: no cover - depends on local driver
        gpu = {"error": str(exc)}
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpu_count": psutil.cpu_count(logical=True),
        "physical_cpu_count": psutil.cpu_count(logical=False),
        "ram_gib": psutil.virtual_memory().total / (1024**3),
        "python": platform.python_version(),
        "torch": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
        "gpu": gpu,
    }


def main() -> int:
    if os.environ.get("PYTHONHASHSEED") != "0":
        raise RuntimeError("Run with PYTHONHASHSEED=0 for deterministic hashed features")
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda":
        torch.cuda.manual_seed_all(SEED)
        torch.cuda.reset_peak_memory_stats()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    process = psutil.Process()
    records, by_binary = reconstruct_matched_records()
    reconstruction_seconds = time.perf_counter() - started
    print(f"reconstruction complete: {len(records):,} records in {reconstruction_seconds:.1f}s", flush=True)

    experiment_started = time.perf_counter()
    validation_rows, validation_summary, test_rows, test_summary = run_temporal_experiments(records, by_binary, device)
    experiment_seconds = time.perf_counter() - experiment_started

    original_rows = load_original_pair_rows()
    original_significance = paired_statistics(
        original_rows,
        "EvoPatch-IoT",
        "ShapeStat",
        "method",
        "original_leave_one_version_out",
    )
    temporal_significance = paired_statistics(
        test_rows,
        "Full (0.70/0.10/0.20)",
        "Geometry only",
        "configuration",
        "historical_only_recent_test",
    )
    significance = original_significance + temporal_significance

    write_csv(OUT_DIR / "weight_sweep_pair_results.csv", validation_rows)
    write_csv(OUT_DIR / "weight_sweep_summary.csv", validation_summary)
    write_csv(OUT_DIR / "temporal_ablation_pair_results.csv", test_rows)
    write_csv(OUT_DIR / "temporal_ablation_summary.csv", test_summary)
    write_csv(OUT_DIR / "paired_significance.csv", significance)

    make_revision_figure(
        validation_summary,
        test_summary,
        original_rows,
        FIG_DIR / "fig8_revision_analysis.pdf",
    )

    fixed_grid_name = "w_0.7_0.1_0.2"
    fixed_validation = next(row for row in validation_summary if row["configuration"] == fixed_grid_name)
    best_validation = validation_summary[0]
    memory_info = process.memory_info()
    profile = {
        "seed": SEED,
        "device": device,
        "matched_functions": len(records),
        "validation_versions": sorted({row["test_version"] for row in validation_rows}, key=version_tuple),
        "test_versions": sorted({row["test_version"] for row in test_rows}, key=version_tuple),
        "weight_grid_points": len(validation_summary),
        "reconstruction_seconds": reconstruction_seconds,
        "temporal_experiment_seconds": experiment_seconds,
        "total_seconds": time.perf_counter() - started,
        "process_rss_gib": memory_info.rss / (1024**3),
        "process_peak_working_set_gib": getattr(memory_info, "peak_wset", memory_info.rss) / (1024**3),
        "cuda_peak_allocated_gib": torch.cuda.max_memory_allocated() / (1024**3) if device == "cuda" else 0.0,
        "cuda_peak_reserved_gib": torch.cuda.max_memory_reserved() / (1024**3) if device == "cuda" else 0.0,
        "fixed_weight_validation_rank": fixed_validation["validation_rank"],
        "fixed_weight_validation_hit_at_10": fixed_validation["weighted_hit_at_10"],
        "best_validation_configuration": best_validation["configuration"],
        "best_validation_hit_at_10": best_validation["weighted_hit_at_10"],
        "hardware": hardware_info(),
    }
    write_json(OUT_DIR / "revision_experiment_profile.json", profile)
    write_json(
        OUT_DIR / "revision_experiment_manifest.json",
        {
            "protocol": "Historical prototypes and feature statistics use only BusyBox versions strictly earlier than each target version.",
            "fixed_weights": FIXED_WEIGHTS,
            "validation_range": ["busybox-1.27.0", "busybox-1.29.3"],
            "held_out_recent_range": ["busybox-1.30.0", "busybox-1.37.0"],
            "max_queries_per_directed_pair": MAX_QUERIES,
            "bootstrap_iterations": 20000,
            "artifacts": [
                "weight_sweep_pair_results.csv",
                "weight_sweep_summary.csv",
                "temporal_ablation_pair_results.csv",
                "temporal_ablation_summary.csv",
                "paired_significance.csv",
                "revision_experiment_profile.json",
            ],
        },
    )
    print(json.dumps(profile, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
