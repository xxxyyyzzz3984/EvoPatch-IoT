# BusyBox unified comparison code

This directory is the reproducible entry point for the BusyBox cross-architecture comparison study. It contains code only; the dataset and generated Ghidra runs are external inputs.

## Goal

Put our method and all implemented comparison methods under one directory and keep the interface stable for later GitHub sync.

## Current method registry

- Implemented now: SizeStat, ShapeStat, CLAP, ISSTA 2024, GTrans, BAR 2024, AMMF, Cybersecurity 2025, Binary2vec, Array 2025, EvoPatch-IoT, VEXIR2Vec 2023, Ex2Vec 2025.
- No pending methods remain in the current unified registry.

## Data source

- Download the original 57-version, five-architecture dataset from Science Data Bank: <https://cstr.cn/31253.11.sciencedb.34638>.
- Generate the Ghidra feature and label runs locally before invoking the all-version runner.
- Do not commit binaries, feature JSONL files, logs, or result CSV/JSON files.

## Files in this directory

- `methods/registry.py`: method registry and scoring hooks.
- `configs/all57_current_bg.json`: reproducible config template; update its run paths after generating local artifacts.
- `run_all57_comparison.py`: unified runner entry.
- `status_summary.py`: quick status checker for the all57 feature source.

## Repro commands

Check coverage:

```powershell
python .\codes\status_summary.py
```

GPU or CPU full run:

```powershell
python .\codes\run_all57_comparison.py --run-id codes_all57_eval_full --device auto
```

Small smoke run:

```powershell
python .\codes\run_all57_comparison.py --run-id codes_all57_eval_smoke --max-test-versions 1 --max-queries-override 5 --device cuda
```

## Paper-ready outputs

The full runner writes:

- `matching_summary.csv`
- `matched_functions.csv`
- `retrieval_pair_results_all57.csv`
- `retrieval_version_summary_all57.csv`
- `retrieval_best_by_version.csv`
- `retrieval_summary_all57.csv`
- `retrieval_ranking_all57.csv`
- `method_catalog.csv`
- `version_coverage.csv`
- `codes_all57_summary.json`

## Reproducibility notes

- The current implemented methods are unified stripped-compatible reproductions under one protocol, not paper-by-paper full reimplementations.
- Method names are fixed so later GitHub sync and result tables stay stable.
- The registry is currently fully implemented under the unified protocol.
