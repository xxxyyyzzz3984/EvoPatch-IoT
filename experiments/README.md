# EvoPatch-IoT Experiment Code

This directory contains the reproducible experiment pipeline for the BusyBox-based IoT firmware binary analysis project. It contains scripts only; the original data release is hosted separately.

The pipeline is dependency-light:

- It uses only Python standard-library modules.
- It does not download pretrained models.
- It writes generated data, logs, and results under `experiments/`.
- It uses the original `busybox_unstripped_dataset/` binaries as offline label sources after the dataset is downloaded from <https://cstr.cn/31253.11.sciencedb.34638>.

Run:

```powershell
python .\experiments\run_pipeline.py
```

Outputs are stored in:

```text
experiments/runs/<run_id>/
```

Important files:

- `run.log`: human-readable execution log.
- `status_events.jsonl`: step-level status events.
- `environment.json`: detected tools and host information.
- `binary_manifest.csv`: ELF-level binary inventory.
- `function_symbols.csv.gz`: function-symbol labels extracted from unstripped binaries.
- `strip_status.csv`: attempted stripped-binary generation status.
- `results_summary.json`: compact result summary.
- `results/*.csv`: per-experiment result tables.

Current environment notes are recorded in each run. On this workstation, Docker was not detected in PATH during initial probing, and the available MinGW `strip`/`objdump` are not full multi-architecture tools.

## Ghidra stripped feature extraction

After `busybox_unstripped_dataset/` and `busybox_stripped_dataset/` are aligned, use Ghidra headless to extract stripped-compatible function features:

```powershell
python .\experiments\ghidra_feature_extract.py --dry-run
python .\experiments\ghidra_feature_extract.py --versions 1.37.0 --archs x86_64 --limit 1 --merge-jsonl
```

If Ghidra cannot find a supported JDK automatically, pass a JDK 21+ directory:

```powershell
python .\experiments\ghidra_feature_extract.py --java-home C:\Path\To\jdk-21 --versions 1.37.0 --archs x86_64 --limit 1
```

Important outputs:

- `aligned_binaries_all.csv`: all stripped binaries and their optional unstripped label anchor.
- `aligned_binaries_selected.csv`: the subset selected for this run.
- `alignment_summary.json`: version/architecture pairing statistics.
- `features/<version>/<binary_id>.jsonl`: per-function anonymous instruction/CFG/call/string-category features.
- `summaries/<version>/<binary_id>.summary.json`: per-binary Ghidra extraction summary.
- `ghidra_status.csv`: per-binary execution status for resumable runs.

The Ghidra exporter is implemented as a native Java GhidraScript (`experiments/ghidra_scripts/ExportFunctionFeatures.java`) and does not emit ground-truth function names, source paths, DWARF paths, or unstripped symbols as model features.

## Ghidra cross-architecture comparison

After extracting stripped features, run the unified comparison script:

```powershell
python .\experiments\run_ghidra_crossarch_comparison.py `
  --ghidra-run .\experiments\runs\ghidra_eval_v1210_v1331_v1370_20260419 `
  --label-run .\experiments\runs\20260417_225234 `
  --versions busybox-1.21.0,busybox-1.33.1,busybox-1.37.0 `
  --test-version busybox-1.37.0 `
  --archs aarch64,arm,mips,mipsel,x86_64
```

Current methods:

- `SizeStat`: size-only weak baseline.
- `ShapeStat`: anonymous local-shape baseline.
- `CLAP-lite`: token-semantic stripped baseline.
- `GTrans-lite`: graph-structure stripped baseline.
- `AMMF-lite`: multi-feature fusion stripped baseline.
- `Binary2vec-lite`: globally fused embedding baseline.
- `EvoPatch-IoT-Lite`: shape-backbone plus fusion and historical evolution prototype.

These `*-lite` methods are simplified reproductions of the corresponding recent method families under a unified stripped-binary protocol. They preserve the core modeling bias of each family, but they are not full paper-for-paper reimplementations.

Outputs include:

- `matching_summary.csv`: stripped-to-unstripped anonymous alignment statistics.
- `matched_functions.csv`: high-confidence stripped functions assigned to normalized function IDs.
- `retrieval_pair_results.csv`: per architecture-pair retrieval metrics on the held-out version.
- `retrieval_summary.csv`: macro/weighted aggregate table for all methods.
