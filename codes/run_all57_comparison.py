#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import torch
except Exception:
    torch = None

from codes.methods.registry import ALL_METHODS, IMPLEMENTED_METHODS, PENDING_METHODS, score_method
from experiments.run_ghidra_crossarch_comparison import (
    build_method_features,
    build_prototypes,
    load_ghidra_features,
    load_unstripped_labels,
    mutual_match_binary,
    summarize,
    version_tuple,
    write_csv,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Unified all-version BusyBox comparison runner.')
    parser.add_argument('--config', type=Path, default=PROJECT_ROOT / 'codes' / 'configs' / 'all57_current_bg.json')
    parser.add_argument('--run-id', default='codes_all57_eval')
    parser.add_argument('--max-test-versions', type=int, default=0, help='Debug cap; 0 means all selected versions.')
    parser.add_argument('--max-queries-override', type=int, default=0, help='Optional override for max queries per arch pair.')
    parser.add_argument('--device', choices=['auto', 'cpu', 'cuda'], default='auto')
    return parser.parse_args()


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def load_ghidra_status_rows(ghidra_run: Path) -> List[dict]:
    return list(csv.DictReader((ghidra_run / 'ghidra_status.csv').open('r', encoding='utf-8', newline='')))


def completed_versions(ghidra_run: Path, arch_count: int) -> List[str]:
    rows = load_ghidra_status_rows(ghidra_run)
    per_version: Dict[str, int] = defaultdict(int)
    for row in rows:
        if row['status'] == 'completed':
            per_version[row['version']] += 1
    return sorted([version for version, count in per_version.items() if count >= arch_count], key=version_tuple)


def select_versions(config: dict, ghidra_run: Path) -> List[str]:
    mode = config.get('versions_mode', 'completed_only')
    explicit = list(config.get('explicit_versions', []))
    arch_count = len(config.get('archs', [])) or 5
    if explicit:
        return sorted(explicit, key=version_tuple)
    if mode == 'completed_only':
        return completed_versions(ghidra_run, arch_count)
    feature_root = ghidra_run / 'features'
    versions = [path.name for path in feature_root.iterdir() if path.is_dir()]
    return sorted(versions, key=version_tuple)


def choose_device(device_arg: str) -> str:
    if device_arg == 'cpu':
        return 'cpu'
    if device_arg == 'cuda':
        if torch is None or not torch.cuda.is_available():
            raise RuntimeError('CUDA was requested but torch.cuda is unavailable')
        return 'cuda'
    if torch is not None and torch.cuda.is_available():
        return 'cuda'
    return 'cpu'


def normalize_rows_torch(matrix: 'torch.Tensor') -> 'torch.Tensor':
    norms = torch.linalg.norm(matrix, dim=1, keepdim=True).clamp_min(1e-12)
    return matrix / norms


def tensor_from_records(records: List[dict], key: str, device: str) -> 'torch.Tensor':
    return torch.tensor([rec[key] for rec in records], dtype=torch.float32, device=device)


def evaluate_pair_registry_fast(method_specs: List, version: str, src_arch: str, dst_arch: str,
                                matched_by_binary: Dict[tuple, List[dict]], prototypes: Dict[str, List[float]],
                                max_queries: int, device: str) -> List[dict]:
    if torch is None:
        raise RuntimeError('torch is required for accelerated evaluation')
    queries = matched_by_binary.get((version, src_arch), [])
    candidates = matched_by_binary.get((version, dst_arch), [])
    if not queries or not candidates:
        return []
    candidate_by_name = defaultdict(list)
    for rec in candidates:
        candidate_by_name[rec['norm_name']].append(rec)
    eval_queries = [q for q in queries if q['norm_name'] in candidate_by_name]
    if max_queries > 0 and len(eval_queries) > max_queries:
        step = len(eval_queries) / max_queries
        eval_queries = [eval_queries[int(i * step)] for i in range(max_queries)]
    if not eval_queries:
        return []

    q_sizes = torch.tensor([rec['size'] for rec in eval_queries], dtype=torch.float32, device=device)
    c_sizes = torch.tensor([rec['size'] for rec in candidates], dtype=torch.float32, device=device)
    q_log_sizes = torch.log1p(q_sizes)
    c_log_sizes = torch.log1p(c_sizes)

    q_shape = tensor_from_records(eval_queries, 'shape_vec', device)
    c_shape = tensor_from_records(candidates, 'shape_vec', device)
    shape_scales = torch.tensor([1.0, 0.20, 0.20, 1.0, 1.0], dtype=torch.float32, device=device).view(1, 1, -1)
    shape_score = -((((q_shape[:, None, :] - c_shape[None, :, :]) / shape_scales) ** 2).sum(dim=2))

    q_token = normalize_rows_torch(tensor_from_records(eval_queries, 'token_hash', device))
    c_token = normalize_rows_torch(tensor_from_records(candidates, 'token_hash', device))
    q_graph = normalize_rows_torch(tensor_from_records(eval_queries, 'graph_norm', device))
    c_graph = normalize_rows_torch(tensor_from_records(candidates, 'graph_norm', device))
    q_graph_arch = normalize_rows_torch(tensor_from_records(eval_queries, 'graph_arch_norm', device))
    c_graph_arch = normalize_rows_torch(tensor_from_records(candidates, 'graph_arch_norm', device))
    q_context = normalize_rows_torch(tensor_from_records(eval_queries, 'context_hash', device))
    c_context = normalize_rows_torch(tensor_from_records(candidates, 'context_hash', device))
    q_shape_arch = normalize_rows_torch(tensor_from_records(eval_queries, 'shape_arch_norm', device))
    c_shape_arch = normalize_rows_torch(tensor_from_records(candidates, 'shape_arch_norm', device))
    q_fused = normalize_rows_torch(tensor_from_records(eval_queries, 'fusion_vec', device))
    c_fused = normalize_rows_torch(tensor_from_records(candidates, 'fusion_vec', device))

    token_score = q_token @ c_token.T
    graph_score = q_graph @ c_graph.T
    graph_arch_score = q_graph_arch @ c_graph_arch.T
    context_score = q_context @ c_context.T
    shape_arch_score = q_shape_arch @ c_shape_arch.T
    fused_score = q_fused @ c_fused.T
    size_score = -(q_log_sizes[:, None] - c_log_sizes[None, :]).abs()

    score_mats = {
        'size_stat': size_score,
        'shape_stat': shape_score,
        'clap': token_score,
        'issta_2024': 0.60 * token_score + 0.25 * shape_arch_score + 0.15 * context_score,
        'gtrans': graph_score,
        'bar_2024': 0.40 * shape_arch_score + 0.35 * context_score + 0.25 * graph_arch_score,
        'ammf': 0.55 * token_score + 0.30 * graph_score + 0.15 * context_score,
        'cybersecurity_2025': 0.45 * fused_score + 0.20 * token_score + 0.20 * graph_arch_score + 0.15 * context_score,
        'binary2vec': 0.60 * fused_score + 0.20 * graph_arch_score + 0.20 * shape_arch_score,
        'vexir2vec_2023': 0.40 * graph_arch_score + 0.35 * token_score + 0.20 * shape_arch_score + 0.05 * context_score,
        'ex2vec_2025': 0.35 * token_score + 0.30 * graph_arch_score + 0.20 * context_score + 0.15 * shape_arch_score,
    }

    candidate_conf = [float(rec['match_confidence']) for rec in candidates]
    candidate_addr = [int(rec['start_addr']) for rec in candidates]
    candidate_name = [rec['norm_name'] for rec in candidates]
    out = []
    for spec in method_specs:
        hits1 = hits5 = hits10 = 0
        mrr10 = 0.0
        inspected = 0
        for qi, query in enumerate(eval_queries):
            if spec.method_id == 'array_2025':
                proto = prototypes.get(query['norm_name'])
                if proto:
                    proto_vec = normalize_rows_torch(torch.tensor([proto], dtype=torch.float32, device=device))[0]
                    proto_score = c_fused @ proto_vec
                else:
                    proto_score = torch.zeros(len(candidates), dtype=torch.float32, device=device)
                scores = (0.50 * fused_score[qi] + 0.25 * shape_arch_score[qi] + 0.25 * proto_score).detach().cpu().tolist()
            elif spec.method_id == 'evopatch_iot':
                proto = prototypes.get(query['norm_name'])
                if proto:
                    proto_vec = normalize_rows_torch(torch.tensor([proto], dtype=torch.float32, device=device))[0]
                    proto_score = c_fused @ proto_vec
                else:
                    proto_score = torch.zeros(len(candidates), dtype=torch.float32, device=device)
                scores = (0.70 * shape_score[qi] + 0.10 * fused_score[qi] + 0.20 * proto_score).detach().cpu().tolist()
            else:
                scores = score_mats[spec.method_id][qi].detach().cpu().tolist()

            ordered = sorted(
                range(len(candidates)),
                key=lambda ci: (scores[ci], -candidate_conf[ci], candidate_addr[ci], candidate_name[ci]),
                reverse=True,
            )[:10]
            names = [candidate_name[ci] for ci in ordered]
            target = query['norm_name']
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
        out.append({
            'method_id': spec.method_id,
            'method': spec.display_name,
            'test_version': version,
            'src_arch': src_arch,
            'dst_arch': dst_arch,
            'queries': n,
            'candidates': len(candidates),
            'hit_at_1': round(hits1 / n, 6),
            'hit_at_5': round(hits5 / n, 6),
            'hit_at_10': round(hits10 / n, 6),
            'mrr_at_10': round(mrr10 / n, 6),
            'mean_inspected_at_10': round(inspected / n, 6),
        })
    return out


def evaluate_pair_registry(method_id: str, method_name: str, version: str, src_arch: str, dst_arch: str,
                           matched_by_binary: Dict[tuple, List[dict]], prototypes: Dict[str, List[float]],
                           max_queries: int) -> Optional[dict]:
    queries = matched_by_binary.get((version, src_arch), [])
    candidates = matched_by_binary.get((version, dst_arch), [])
    if not queries or not candidates:
        return None
    candidate_by_name = defaultdict(list)
    for rec in candidates:
        candidate_by_name[rec['norm_name']].append(rec)
    eval_queries = [q for q in queries if q['norm_name'] in candidate_by_name]
    if max_queries > 0 and len(eval_queries) > max_queries:
        step = len(eval_queries) / max_queries
        eval_queries = [eval_queries[int(i * step)] for i in range(max_queries)]
    if not eval_queries:
        return None

    hits1 = hits5 = hits10 = 0
    mrr10 = 0.0
    inspected = 0
    for query in eval_queries:
        proto = prototypes.get(query['norm_name'])
        scored = []
        for cand in candidates:
            score = score_method(method_id, query, cand, proto)
            scored.append((score, -cand['match_confidence'], cand['start_addr'], cand['norm_name'], cand))
        scored.sort(reverse=True)
        top = [item[-1] for item in scored[:10]]
        names = [rec['norm_name'] for rec in top]
        target = query['norm_name']
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
        'method_id': method_id,
        'method': method_name,
        'test_version': version,
        'src_arch': src_arch,
        'dst_arch': dst_arch,
        'queries': n,
        'candidates': len(candidates),
        'hit_at_1': round(hits1 / n, 6),
        'hit_at_5': round(hits5 / n, 6),
        'hit_at_10': round(hits10 / n, 6),
        'mrr_at_10': round(mrr10 / n, 6),
        'mean_inspected_at_10': round(inspected / n, 6),
    }


def summarize_by_version(rows: List[dict]) -> List[dict]:
    grouped: Dict[tuple, List[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row['test_version'], row['method'])].append(row)
    out = []
    for (test_version, method), items in sorted(grouped.items(), key=lambda x: (version_tuple(x[0][0]), x[0][1])):
        total_q = sum(int(r['queries']) for r in items)
        entry = {
            'test_version': test_version,
            'method': method,
            'pairs': len(items),
            'queries': total_q,
        }
        for metric in ['hit_at_1', 'hit_at_5', 'hit_at_10', 'mrr_at_10', 'mean_inspected_at_10']:
            macro = sum(float(r[metric]) for r in items) / len(items)
            weighted = sum(float(r[metric]) * int(r['queries']) for r in items) / max(total_q, 1)
            entry[f'macro_{metric}'] = round(macro, 6)
            entry[f'weighted_{metric}'] = round(weighted, 6)
        out.append(entry)
    return out


def build_method_catalog_rows() -> List[dict]:
    return [
        {
            'method_id': spec.method_id,
            'display_name': spec.display_name,
            'status': spec.status,
            'family': spec.family,
            'note': spec.note,
        }
        for spec in ALL_METHODS
    ]


def build_version_coverage_rows(ghidra_status_rows: List[dict], selected_versions: List[str], expected_arches: int) -> List[dict]:
    by_version: Dict[str, Dict[str, int]] = {}
    for version in selected_versions:
        by_version[version] = defaultdict(int)
    for row in ghidra_status_rows:
        version = row['version']
        if version not in by_version:
            continue
        by_version[version]['total_rows'] += 1
        by_version[version][f"status_{row['status']}"] += 1
    out = []
    for version in sorted(selected_versions, key=version_tuple):
        stats = by_version[version]
        completed = int(stats.get('status_completed', 0))
        out.append({
            'version': version,
            'expected_arches': expected_arches,
            'completed_binaries': completed,
            'total_status_rows': int(stats.get('total_rows', 0)),
            'is_complete': int(completed >= expected_arches),
        })
    return out


def build_overall_ranking_rows(summary_rows: List[dict]) -> List[dict]:
    implemented = [row for row in summary_rows if row.get('status') == 'implemented']
    ordered = sorted(
        implemented,
        key=lambda row: (
            -float(row['weighted_hit_at_1']),
            -float(row['weighted_hit_at_10']),
            -float(row['weighted_mrr_at_10']),
            float(row['weighted_mean_inspected_at_10']),
            row['method'],
        ),
    )
    out = []
    for rank, row in enumerate(ordered, start=1):
        out.append({
            'rank': rank,
            'method': row['method'],
            'weighted_hit_at_1': row['weighted_hit_at_1'],
            'weighted_hit_at_5': row['weighted_hit_at_5'],
            'weighted_hit_at_10': row['weighted_hit_at_10'],
            'weighted_mrr_at_10': row['weighted_mrr_at_10'],
            'weighted_mean_inspected_at_10': row['weighted_mean_inspected_at_10'],
        })
    return out


def build_best_by_version_rows(version_summary_rows: List[dict]) -> List[dict]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for row in version_summary_rows:
        grouped[row['test_version']].append(row)
    out = []
    for version in sorted(grouped, key=version_tuple):
        best = sorted(
            grouped[version],
            key=lambda row: (
                -float(row['weighted_hit_at_1']),
                -float(row['weighted_hit_at_10']),
                -float(row['weighted_mrr_at_10']),
                float(row['weighted_mean_inspected_at_10']),
                row['method'],
            ),
        )[0]
        out.append({
            'test_version': version,
            'best_method': best['method'],
            'weighted_hit_at_1': best['weighted_hit_at_1'],
            'weighted_hit_at_5': best['weighted_hit_at_5'],
            'weighted_hit_at_10': best['weighted_hit_at_10'],
            'weighted_mrr_at_10': best['weighted_mrr_at_10'],
            'weighted_mean_inspected_at_10': best['weighted_mean_inspected_at_10'],
        })
    return out


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    ghidra_run = PROJECT_ROOT / config['ghidra_run']
    label_run = PROJECT_ROOT / config['label_run']
    archs = list(config['archs'])
    ghidra_status_rows = load_ghidra_status_rows(ghidra_run)
    versions = select_versions(config, ghidra_run)
    device = choose_device(args.device)
    if args.max_test_versions > 0:
        versions = versions[:args.max_test_versions]
    out_dir = PROJECT_ROOT / 'experiments' / 'runs' / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f'Using ghidra_run={ghidra_run}')
    print(f'Using label_run={label_run}')
    print(f'Using device={device}')
    print(f'Selected versions={len(versions)}')

    labels_by_binary = load_unstripped_labels(label_run, set(versions), set(archs), int(config['min_size']))
    stripped_by_binary = load_ghidra_features(ghidra_run, set(versions), set(archs), int(config['min_size']), int(config['min_instr']))

    matched_by_binary: Dict[tuple, List[dict]] = {}
    matching_rows = []
    all_matched: List[dict] = []
    keys = sorted(set(labels_by_binary) & set(stripped_by_binary), key=lambda x: (version_tuple(x[0]), x[1]))
    for version, arch in keys:
        matched, summary = mutual_match_binary(
            labels_by_binary[(version, arch)],
            stripped_by_binary[(version, arch)],
            window=int(config['match_window']),
            max_dist=float(config['match_max_dist']),
        )
        matched_by_binary[(version, arch)] = matched
        all_matched.extend(matched)
        matching_rows.append({
            'version': version,
            'arch': arch,
            **summary,
            'match_ratio_labels': round(summary['mutual_matches'] / max(summary['labels'], 1), 6),
            'match_ratio_stripped': round(summary['mutual_matches'] / max(summary['stripped'], 1), 6),
        })

    print(f'Aligned matched functions={len(all_matched)}')
    build_method_features(all_matched, all_matched)

    pair_rows: List[dict] = []
    for idx, test_version in enumerate(versions, start=1):
        print(f'[{idx}/{len(versions)}] evaluating {test_version}', flush=True)
        train_records = [rec for rec in all_matched if rec['version'] != test_version]
        prototypes = build_prototypes(train_records)
        for src_arch in archs:
            for dst_arch in archs:
                if src_arch == dst_arch:
                    continue
                rows = evaluate_pair_registry_fast(
                    IMPLEMENTED_METHODS,
                        test_version,
                        src_arch,
                        dst_arch,
                        matched_by_binary,
                        prototypes,
                        int(args.max_queries_override) if args.max_queries_override > 0 else int(config['max_queries']),
                        device,
                    )
                pair_rows.extend(rows)

    summary_rows = summarize(pair_rows)
    for row in summary_rows:
        row['status'] = 'implemented'
    for spec in PENDING_METHODS:
        summary_rows.append({
            'method': spec.display_name,
            'pairs': 0,
            'queries': 0,
            'status': 'pending',
            'macro_hit_at_1': '',
            'weighted_hit_at_1': '',
            'macro_hit_at_5': '',
            'weighted_hit_at_5': '',
            'macro_hit_at_10': '',
            'weighted_hit_at_10': '',
            'macro_mrr_at_10': '',
            'weighted_mrr_at_10': '',
            'macro_mean_inspected_at_10': '',
            'weighted_mean_inspected_at_10': '',
        })

    version_summary_rows = summarize_by_version(pair_rows)
    method_catalog_rows = build_method_catalog_rows()
    version_coverage_rows = build_version_coverage_rows(ghidra_status_rows, versions, len(archs))
    overall_ranking_rows = build_overall_ranking_rows(summary_rows)
    best_by_version_rows = build_best_by_version_rows(version_summary_rows)
    notes = [
        'Implemented methods are unified stripped-compatible reproductions under one protocol.',
        'Do not claim paper-for-paper full reimplementation for the implemented baselines without further engineering.',
    ]
    if PENDING_METHODS:
        notes.insert(1, 'If pending methods exist, they remain reserved in the registry until implemented.')

    write_csv(out_dir / 'matching_summary.csv', matching_rows, [
        'version', 'arch', 'labels', 'stripped', 'mutual_matches',
        'median_match_dist', 'p90_match_dist', 'match_ratio_labels', 'match_ratio_stripped',
    ])
    write_csv(out_dir / 'matched_functions.csv', all_matched, [
        'version', 'arch', 'function_id', 'start_addr', 'size', 'instruction_count',
        'basic_block_count', 'cfg_edge_count', 'norm_name', 'match_dist', 'match_confidence', 'label_addr', 'label_size',
    ])
    write_csv(out_dir / 'retrieval_pair_results_all57.csv', pair_rows, [
        'method_id', 'method', 'test_version', 'src_arch', 'dst_arch', 'queries', 'candidates',
        'hit_at_1', 'hit_at_5', 'hit_at_10', 'mrr_at_10', 'mean_inspected_at_10',
    ])
    write_csv(out_dir / 'retrieval_version_summary_all57.csv', version_summary_rows, [
        'test_version', 'method', 'pairs', 'queries',
        'macro_hit_at_1', 'weighted_hit_at_1',
        'macro_hit_at_5', 'weighted_hit_at_5',
        'macro_hit_at_10', 'weighted_hit_at_10',
        'macro_mrr_at_10', 'weighted_mrr_at_10',
        'macro_mean_inspected_at_10', 'weighted_mean_inspected_at_10',
    ])
    write_csv(out_dir / 'retrieval_best_by_version.csv', best_by_version_rows, [
        'test_version', 'best_method',
        'weighted_hit_at_1', 'weighted_hit_at_5',
        'weighted_hit_at_10', 'weighted_mrr_at_10',
        'weighted_mean_inspected_at_10',
    ])
    write_csv(out_dir / 'retrieval_summary_all57.csv', summary_rows, [
        'method', 'pairs', 'queries', 'status',
        'macro_hit_at_1', 'weighted_hit_at_1',
        'macro_hit_at_5', 'weighted_hit_at_5',
        'macro_hit_at_10', 'weighted_hit_at_10',
        'macro_mrr_at_10', 'weighted_mrr_at_10',
        'macro_mean_inspected_at_10', 'weighted_mean_inspected_at_10',
    ])
    write_csv(out_dir / 'retrieval_ranking_all57.csv', overall_ranking_rows, [
        'rank', 'method',
        'weighted_hit_at_1', 'weighted_hit_at_5',
        'weighted_hit_at_10', 'weighted_mrr_at_10',
        'weighted_mean_inspected_at_10',
    ])
    write_csv(out_dir / 'method_catalog.csv', method_catalog_rows, [
        'method_id', 'display_name', 'status', 'family', 'note',
    ])
    write_csv(out_dir / 'version_coverage.csv', version_coverage_rows, [
        'version', 'expected_arches', 'completed_binaries', 'total_status_rows', 'is_complete',
    ])
    write_json(out_dir / 'codes_all57_summary.json', {
        'generated_at': datetime.now().isoformat(timespec='seconds'),
        'config': config,
        'ghidra_run': str(ghidra_run),
        'label_run': str(label_run),
        'device': device,
        'versions': versions,
        'implemented_methods': [item.display_name for item in IMPLEMENTED_METHODS],
        'pending_methods': [item.display_name for item in PENDING_METHODS],
        'method_catalog': method_catalog_rows,
        'version_coverage': version_coverage_rows,
        'matched_functions': len(all_matched),
        'pair_rows': len(pair_rows),
        'summary_rows': summary_rows,
        'overall_ranking': overall_ranking_rows,
        'best_by_version': best_by_version_rows,
        'notes': notes,
    })
    print(json.dumps({'out_dir': str(out_dir), 'versions': len(versions), 'pair_rows': len(pair_rows)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
