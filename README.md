# EvoPatch-IoT

Reproducibility code for **EvoPatch-IoT: Evolution-Aware Cross-Architecture Vulnerability Retrieval and Patch-State Profiling for BusyBox-Based IoT Firmware**.

This repository contains the source code for dataset preparation, stripped-binary feature extraction, anonymous alignment, cross-architecture retrieval, baseline comparison, and the paper's revision-analysis scripts.

## Repository scope

This is a code-only release. The following items are intentionally not committed:

- BusyBox source archives and compiled binaries.
- Stripped and unstripped dataset files.
- Ghidra distributions, JDKs, Docker images, and other third-party tools.
- Generated Ghidra features, experiment runs, logs, CSV/JSON results, and caches.

BusyBox and Ghidra remain subject to their own licenses. Install or download them separately before running the corresponding pipeline.

## Dataset

The benchmark is an original dataset created by the authors. We collected different official BusyBox releases and compiled 57 versions one by one for five architecture targets: AArch64, ARM, MIPS, MIPSEL, and x86_64. Both stripped and unstripped artifacts are retained where the build is available, together with manifests and build information.

Download the dataset from the Science Data Bank record:

<https://cstr.cn/31253.11.sciencedb.34638>

The dataset is not mirrored in this Git repository. After downloading it, keep the data on a local data disk and pass its paths to the scripts, or place the extracted directories at the repository root as `busybox_stripped_dataset/` and `busybox_unstripped_dataset/`.

## Layout

```text
codes/
  Unified method registry and the all-version comparison runner.
experiments/
  Dataset inventory, stripping, Ghidra extraction, alignment, and evaluation.
paper-tools/
  Optional figure-generation and revision-analysis scripts; they expect generated runs.
```

## Requirements

- Python 3.10 or newer.
- Python packages for the comparison and paper-analysis stages: `numpy`, `scipy`, `matplotlib`, `psutil`, and `torch`.
- A JDK 21 or newer and a separately installed Ghidra release for headless feature extraction.
- GNU binutils or Docker with suitable cross-architecture tools only when rebuilding or stripping binaries locally.

The baseline inventory stage uses Python's standard library. GPU acceleration is optional; CUDA is used automatically by the comparison runner when an available PyTorch CUDA installation is detected.

Example setup on Windows PowerShell:

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install numpy scipy matplotlib psutil torch
```

## Reproduction workflow

1. Download and unpack the original dataset from Science Data Bank. Do not commit the unpacked directories.

2. Inspect the local toolchain and dataset using the standard-library pipeline:

```powershell
python .\\experiments\\run_pipeline.py --help
python .\\experiments\\run_pipeline.py --dataset <path-to-unstripped-dataset> --experiments-dir <path-to-local-experiments>
```

3. Generate anonymous features from stripped binaries with Ghidra. The dry run creates the manifest and checks the external toolchain without launching analysis:

```powershell
python .\\experiments\\ghidra_feature_extract.py `
  --stripped-dataset <path-to-stripped-dataset> `
  --unstripped-dataset <path-to-unstripped-dataset> `
  --ghidra <path-to-ghidra> `
  --java-home <path-to-jdk-21-or-newer> `
  --experiments-dir <path-to-local-experiments> `
  --dry-run
```

Remove `--dry-run` for extraction. Use `--versions`, `--archs`, and `--limit` for a small smoke test before launching the full 57-version job. Extraction writes only to the selected `--experiments-dir`.

4. Run the unified cross-architecture comparison after the feature and label runs are available:

```powershell
python .\\experiments\\run_ghidra_crossarch_comparison.py --help
python .\\codes\\run_all57_comparison.py --help
```

The all-version runner reads `codes/configs/all57_current_bg.json`. Set its `ghidra_run` and `label_run` values to the relative paths of the generated runs before starting the full evaluation. Use `--device cpu` when CUDA is unavailable.

5. The scripts in `paper-tools/` reproduce the manuscript's revision sweeps and figures after the corresponding generated runs have been created. They do not contain the data or result files themselves.

## Reproducibility notes

Function names and unstripped symbols are used only as offline identity labels and are not emitted as model-facing features. The stripped-side feature exporter records anonymous instruction, CFG, call, string-category, constant-bucket, and layout statistics. Generated artifacts can be large, so the repository keeps them outside version control and records the required input/output locations instead.

## Citation and contact

When using the code or dataset, please cite the EvoPatch-IoT paper and the Science Data Bank dataset record. For questions about the release, please use the GitHub issue tracker or contact the corresponding authors listed in the paper.
