from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patheffects as pe
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
PAPER_DIR = Path(__file__).resolve().parent
FIG_DIR = PAPER_DIR / "figures"
LABEL_RUN = ROOT / "experiments" / "runs" / "20260417_225234"
FULL_RUN = ROOT / "experiments" / "runs" / "codes_all57_eval_full_plus_vex_ex_20260419"
GHIDRA_RUN = ROOT / "experiments" / "runs" / "ghidra_eval_all57_20260419_bg"

ARCH_ORDER = ["aarch64", "arm", "mips", "mipsel", "x86_64"]
ARCH_LABELS = ["AArch64", "ARM", "MIPS", "MIPSEL", "x86_64"]
METHOD_LABELS = {
    "SizeStat": "Size-only",
    "ShapeStat": "Geometry-only",
    "CLAP": "CLAP-style",
    "ISSTA 2024": "TSC-Fusion",
    "GTrans": "GTrans-style",
    "BAR 2024": "SCG-Fusion",
    "AMMF": "AMMF",
    "Cybersecurity 2025": "AMV",
    "Binary2vec": "Binary2vec-style",
    "Array 2025": "Prototype-Fusion",
    "VEXIR2Vec 2023": "VexIR2Vec-style",
    "Ex2Vec 2025": "Ex2Vec-style",
    "EvoPatch-IoT": "EvoPatch-IoT",
}


def ensure_dirs() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def save(fig: plt.Figure, name: str) -> None:
    fig.tight_layout()
    fig.savefig(FIG_DIR / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(FIG_DIR / f"{name}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def setup_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Serif",
            "font.size": 9,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "figure.dpi": 160,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def fig1_placeholder() -> None:
    fig, ax = plt.subplots(figsize=(7.0, 3.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    rect = plt.Rectangle(
        (0.04, 0.08),
        0.92,
        0.84,
        fill=False,
        edgecolor="#8d99ae",
        linewidth=1.5,
        linestyle="--",
    )
    ax.add_patch(rect)
    ax.axis("off")
    save(fig, "fig1_placeholder")


def fig2_dataset_overview() -> None:
    manifest = read_csv(LABEL_RUN / "binary_manifest.csv")
    func_stats = read_csv(LABEL_RUN / "function_symbol_stats.csv")
    alignment = json.loads((GHIDRA_RUN / "alignment_summary.json").read_text(encoding="utf-8"))
    matching = read_csv(FULL_RUN / "matching_summary.csv")

    unstripped_counts = {arch: 0 for arch in ARCH_ORDER}
    for row in manifest:
        unstripped_counts[row["arch"]] += 1
    stripped_counts = {arch: alignment["all"]["by_arch"][arch]["stripped_binaries"] for arch in ARCH_ORDER}

    analysis_counts = {arch: 0 for arch in ARCH_ORDER}
    for row in func_stats:
        analysis_counts[row["arch"]] += int(row["analysis_funcs"])

    recovered = []
    for path in (GHIDRA_RUN / "summaries").rglob("*.summary.json"):
        obj = json.loads(path.read_text(encoding="utf-8"))
        recovered.append(int(obj["function_count"]))

    match_ratio_labels = defaultdict(list)
    match_ratio_stripped = defaultdict(list)
    for row in matching:
        arch = row["arch"]
        match_ratio_labels[arch].append(float(row["match_ratio_labels"]))
        match_ratio_stripped[arch].append(float(row["match_ratio_stripped"]))

    x = np.arange(len(ARCH_ORDER))
    fig, axes = plt.subplots(2, 2, figsize=(7.1, 5.6))
    ax = axes[0, 0]
    ax.bar(x - 0.16, [unstripped_counts[a] for a in ARCH_ORDER], width=0.32, color="#355070", label="Unstripped")
    ax.bar(x + 0.16, [stripped_counts[a] for a in ARCH_ORDER], width=0.32, color="#6d597a", label="Stripped")
    ax.set_xticks(x, ARCH_LABELS, rotation=20)
    ax.set_ylim(0, 70)
    ax.set_ylabel("Binary Count")
    ax.set_title("(a) Binary Coverage by Architecture")
    ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 0.98), fontsize=7)

    ax = axes[0, 1]
    vals = [analysis_counts[a] / 1000.0 for a in ARCH_ORDER]
    ax.bar(x, vals, color=["#0f4c5c", "#2c7da0", "#468faf", "#61a5c2", "#89c2d9"])
    ax.set_xticks(x, ARCH_LABELS, rotation=20)
    ax.set_ylabel("Analysis Functions (K)")
    ax.set_title("(b) Labeled Analysis Functions")

    ax = axes[1, 0]
    ax.hist(recovered, bins=18, color="#bc4749", edgecolor="white")
    ax.axvline(np.mean(recovered), color="#1d3557", linestyle="--", linewidth=1.2, label=f"Mean={np.mean(recovered):.0f}")
    ax.set_xlabel("Recovered Functions per Stripped Binary")
    ax.set_ylabel("Frequency")
    ax.set_title("(c) Ghidra-Recovered Function Distribution")
    ax.legend(frameon=False)

    ax = axes[1, 1]
    label_means = [np.mean(match_ratio_labels[a]) for a in ARCH_ORDER]
    strip_means = [np.mean(match_ratio_stripped[a]) for a in ARCH_ORDER]
    ax.bar(x - 0.16, label_means, width=0.32, color="#3a5a40", label="Match/Labels")
    ax.bar(x + 0.16, strip_means, width=0.32, color="#a3b18a", label="Match/Stripped")
    ax.set_xticks(x, ARCH_LABELS, rotation=20)
    ax.set_ylim(0, 0.33)
    ax.set_ylabel("Average Ratio")
    ax.set_title("(d) Anonymous Mutual-Match Ratios")
    ax.legend(frameon=False, loc="upper right")

    save(fig, "fig2_dataset_overview")


def fig3_overall_comparison() -> None:
    rows = read_csv(FULL_RUN / "retrieval_summary_all57.csv")
    rows.sort(key=lambda r: float(r["weighted_hit_at_10"]), reverse=True)
    methods = [r["method"] for r in rows]
    method_labels = [METHOD_LABELS.get(method, method) for method in methods]
    hit1 = [float(r["weighted_hit_at_1"]) for r in rows]
    hit10 = [float(r["weighted_hit_at_10"]) for r in rows]
    colors = ["#c1121f" if m == "EvoPatch-IoT" else "#669bbc" for m in methods]

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 4.4))
    y = np.arange(len(methods))
    ax = axes[0]
    ax.barh(y, hit1, color=colors)
    ax.set_yticks(y, method_labels)
    ax.invert_yaxis()
    ax.set_xlabel("Weighted Hit@1")
    ax.set_title("(a) Weighted Hit@1")
    ax.grid(axis="x", alpha=0.2)

    ax = axes[1]
    ax.barh(y, hit10, color=colors)
    ax.set_yticks(y, method_labels)
    ax.invert_yaxis()
    ax.set_xlabel("Weighted Hit@10")
    ax.set_title("(b) Weighted Hit@10")
    ax.grid(axis="x", alpha=0.2)

    save(fig, "fig3_overall_comparison")


def fig4_version_trend() -> None:
    rows = read_csv(FULL_RUN / "retrieval_version_summary_all57.csv")
    selected = ["EvoPatch-IoT", "ShapeStat", "Array 2025", "Binary2vec"]
    by_method = {m: [] for m in selected}
    versions = []
    for row in rows:
        if row["method"] == "EvoPatch-IoT":
            versions.append(row["test_version"].replace("busybox-", ""))
    versions = versions[:57]
    for method in selected:
        for row in rows:
            if row["method"] == method:
                by_method[method].append(float(row["weighted_hit_at_10"]))

    fig, ax = plt.subplots(figsize=(7.1, 3.2))
    x = np.arange(len(versions))
    ax.axvspan(-0.5, 14.5, color="#f1faee", alpha=0.9)
    ax.axvspan(14.5, 41.5, color="#f8f9fa", alpha=1.0)
    ax.axvspan(41.5, 56.5, color="#fff3b0", alpha=0.45)
    palette = {
        "EvoPatch-IoT": "#c1121f",
        "ShapeStat": "#1d3557",
        "Array 2025": "#457b9d",
        "Binary2vec": "#6c757d",
    }
    for method in selected:
        ax.plot(
            x,
            by_method[method],
            label=METHOD_LABELS.get(method, method),
            linewidth=2.0 if method == "EvoPatch-IoT" else 1.4,
            color=palette[method],
            marker="o" if method == "EvoPatch-IoT" else None,
            markersize=2.2,
        )
    ax.set_xlim(-0.5, len(versions) - 0.5)
    ax.set_ylim(0.30, 0.78)
    tick_pos = list(range(0, len(versions), 4))
    if tick_pos[-1] != len(versions) - 1:
        tick_pos.append(len(versions) - 1)
    ax.set_xticks(tick_pos, [versions[i] for i in tick_pos], rotation=35, ha="right")
    ax.set_ylabel("Weighted Hit@10")
    ax.set_title("Version-Wise Cross-Architecture Retrieval Trend")
    ax.legend(frameon=False, ncol=2, loc="upper right")
    ax.grid(axis="y", alpha=0.2)
    save(fig, "fig4_version_trend")


def build_pair_matrix(method: str, metric: str) -> np.ndarray:
    rows = read_csv(FULL_RUN / "retrieval_pair_results_all57.csv")
    mat = np.full((len(ARCH_ORDER), len(ARCH_ORDER)), np.nan)
    grouped = defaultdict(list)
    for row in rows:
        if row["method"] != method:
            continue
        grouped[(row["src_arch"], row["dst_arch"])].append(float(row[metric]))
    for i, src in enumerate(ARCH_ORDER):
        for j, dst in enumerate(ARCH_ORDER):
            if src == dst:
                continue
            vals = grouped[(src, dst)]
            mat[i, j] = float(np.mean(vals))
    return mat


def annotate_heatmap(ax: plt.Axes, mat: np.ndarray, fmt: str = "{:.2f}", contrast: str = "mean") -> None:
    finite = mat[np.isfinite(mat)]
    mean_value = float(np.mean(finite)) if finite.size else 0.0
    max_value = float(np.max(finite)) if finite.size else 1.0
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            if np.isnan(mat[i, j]):
                continue
            if contrast == "magma":
                color = "black" if mat[i, j] >= 0.68 * max_value else "white"
            else:
                color = "white" if mat[i, j] > mean_value else "black"
            stroke = "black" if color == "white" else "white"
            ax.text(
                j,
                i,
                fmt.format(mat[i, j]),
                ha="center",
                va="center",
                fontsize=7,
                color=color,
                path_effects=[pe.withStroke(linewidth=1.1, foreground=stroke)],
            )


def fig5_arch_heatmap() -> None:
    ours = build_pair_matrix("EvoPatch-IoT", "hit_at_10")
    shape = build_pair_matrix("ShapeStat", "hit_at_10")
    gain = ours - shape

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 3.4))

    ax = axes[0]
    im = ax.imshow(ours, cmap="YlGnBu", vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(ARCH_LABELS)), ARCH_LABELS, rotation=35, ha="right")
    ax.set_yticks(range(len(ARCH_LABELS)), ARCH_LABELS)
    ax.set_title("(a) EvoPatch-IoT Mean Hit@10")
    annotate_heatmap(ax, ours)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax = axes[1]
    im = ax.imshow(gain, cmap="RdYlGn", vmin=-0.05, vmax=0.12)
    ax.set_xticks(range(len(ARCH_LABELS)), ARCH_LABELS, rotation=35, ha="right")
    ax.set_yticks(range(len(ARCH_LABELS)), ARCH_LABELS)
    ax.set_title("(b) Gain over Geometry-only")
    annotate_heatmap(ax, gain, "{:+.02f}")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    save(fig, "fig5_arch_heatmap")


def fig6_patch_case_study() -> None:
    proxy = read_csv(LABEL_RUN / "results" / "cve_2021_42386_patch_state_proxy.csv")
    probe = read_csv(LABEL_RUN / "results" / "cve_2021_42386_awk_patch_probe.csv")

    proxy.sort(key=lambda r: ARCH_ORDER.index(r["heldout_arch"]))
    archs = [r["heldout_arch"] for r in proxy]
    acc = [float(r["accuracy"]) for r in proxy]
    f1 = [float(r["f1"]) for r in proxy]

    selected_funcs = ["awk_printf", "awk_main", "awk_exit", "awk_split", "awk_getline", "awk_sub"]
    heat = np.zeros((len(ARCH_ORDER), len(selected_funcs)))
    for i, arch in enumerate(ARCH_ORDER):
        for j, func in enumerate(selected_funcs):
            row = next((r for r in probe if r["arch"] == arch and r["function"] == func), None)
            heat[i, j] = float(row["rel_delta"]) if row else 0.0

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 3.4), gridspec_kw={"width_ratios": [1.05, 1.0]})
    x = np.arange(len(archs))
    ax = axes[0]
    ax.bar(x - 0.16, acc, width=0.32, color="#1d3557", label="Accuracy")
    ax.bar(x + 0.16, f1, width=0.32, color="#e63946", label="F1")
    ax.set_xticks(x, [a.upper() if a != "aarch64" else "AArch64" for a in archs], rotation=20)
    ax.set_ylim(0.70, 1.02)
    ax.set_ylabel("Score")
    ax.set_title("(a) Patch-State Proxy", pad=8)
    ax.legend(frameon=False)
    ax.grid(axis="y", alpha=0.2)

    ax = axes[1]
    im = ax.imshow(heat, cmap="magma", vmin=0.0, vmax=float(np.max(heat)))
    ax.set_aspect("auto")
    ax.set_xticks(range(len(selected_funcs)), selected_funcs, rotation=28, ha="right")
    ax.set_yticks(range(len(ARCH_LABELS)), ARCH_LABELS)
    ax.tick_params(axis="x", labelsize=7)
    ax.set_title("(b) AWK Relative Size Delta", pad=8)
    annotate_heatmap(ax, heat, "{:.02f}", contrast="magma")
    fig.colorbar(im, ax=ax, fraction=0.038, pad=0.10)

    save(fig, "fig6_patch_case_study")


def fig7_efficiency_failure() -> None:
    match = read_csv(FULL_RUN / "matching_summary.csv")
    status = read_csv(GHIDRA_RUN / "ghidra_status.csv")
    pair_rows = read_csv(FULL_RUN / "retrieval_pair_results_all57.csv")

    match_ratio = defaultdict(list)
    for row in match:
        match_ratio[row["arch"]].append(float(row["match_ratio_stripped"]))

    time_mean = defaultdict(list)
    for row in status:
        if row["status"] == "completed":
            time_mean[row["arch"]].append(float(row["duration_sec"]))

    src_hit = defaultdict(list)
    dst_hit = defaultdict(list)
    for row in pair_rows:
        if row["method"] != "EvoPatch-IoT":
            continue
        src_hit[row["src_arch"]].append(float(row["hit_at_10"]))
        dst_hit[row["dst_arch"]].append(float(row["hit_at_10"]))

    ratios = [float(np.mean(match_ratio[a])) for a in ARCH_ORDER]
    times = [float(np.mean(time_mean[a])) for a in ARCH_ORDER]
    src_vals = [float(np.mean(src_hit[a])) for a in ARCH_ORDER]
    dst_vals = [float(np.mean(dst_hit[a])) for a in ARCH_ORDER]

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 3.2))
    x = np.arange(len(ARCH_ORDER))

    ax = axes[0]
    bars = ax.bar(x, times, width=0.6, color="#adb5bd", label="Extraction Time (s)")
    ax.set_xticks(x, ARCH_LABELS, rotation=20)
    ax.set_ylabel("Mean Extraction Time (s)")
    ax.set_title("(a) Extraction Cost and Match Ratio")
    ax.grid(axis="y", alpha=0.2)
    ax2 = ax.twinx()
    line = ax2.plot(
        x,
        ratios,
        color="#c1121f",
        marker="o",
        linewidth=1.8,
        markersize=4.2,
        label="Match/Stripped",
        zorder=2,
    )
    ax2.set_ylabel("Average Match/Stripped")
    ax2.set_ylim(0.15, 0.43)
    legend = ax.legend(
        [bars, line[0]],
        ["Extraction Time (s)", "Match/Stripped"],
        loc="upper center",
        bbox_to_anchor=(0.54, 0.98),
        frameon=True,
        fancybox=False,
        framealpha=0.95,
    )
    legend.get_frame().set_facecolor("white")
    legend.get_frame().set_edgecolor("white")

    ax = axes[1]
    ax.bar(x - 0.16, src_vals, width=0.32, color="#457b9d", label="As Source")
    ax.bar(x + 0.16, dst_vals, width=0.32, color="#e63946", label="As Target")
    ax.set_xticks(x, ARCH_LABELS, rotation=20)
    ax.set_ylabel("Mean Hit@10")
    ax.set_ylim(0.20, 0.62)
    ax.set_title("(b) Directional Retrieval Asymmetry")
    ax.legend(frameon=False, loc="upper right")
    ax.grid(axis="y", alpha=0.2)

    save(fig, "fig7_efficiency_failure")


def main() -> None:
    ensure_dirs()
    setup_style()
    fig1_placeholder()
    fig2_dataset_overview()
    fig3_overall_comparison()
    fig4_version_trend()
    fig5_arch_heatmap()
    fig6_patch_case_study()
    fig7_efficiency_failure()
    print(f"Generated figures under {FIG_DIR}")


if __name__ == "__main__":
    main()
