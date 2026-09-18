from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence


@dataclass(frozen=True)
class MethodSpec:
    method_id: str
    display_name: str
    status: str
    family: str
    note: str


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


def feature_distance(a: Sequence[float], b: Sequence[float], scales: Sequence[float]) -> float:
    total = 0.0
    for idx in range(min(len(a), len(b), len(scales))):
        total += ((a[idx] - b[idx]) / scales[idx]) ** 2
    return total


SHAPE_SCALES = [1.0, 0.20, 0.20, 1.0, 1.0]

ALL_METHODS: List[MethodSpec] = [
    MethodSpec('size_stat', 'SizeStat', 'implemented', 'weak_baseline', 'Size-only weak baseline.'),
    MethodSpec('shape_stat', 'ShapeStat', 'implemented', 'weak_baseline', 'Anonymous local-shape baseline.'),
    MethodSpec('clap', 'CLAP', 'implemented', 'token_semantics', 'Unified stripped-compatible CLAP-style token-semantic reproduction.'),
    MethodSpec('issta_2024', 'ISSTA 2024', 'implemented', 'token_shape_fusion', 'Token, context, and calibrated local-shape fusion under the stripped protocol.'),
    MethodSpec('gtrans', 'GTrans', 'implemented', 'graph_structure', 'Unified stripped-compatible graph-structure reproduction.'),
    MethodSpec('bar_2024', 'BAR 2024', 'implemented', 'retrieval_fusion', 'Context, graph, and shape retrieval fusion under the stripped protocol.'),
    MethodSpec('ammf', 'AMMF', 'implemented', 'multi_feature_fusion', 'Unified stripped-compatible multi-feature fusion reproduction.'),
    MethodSpec('cybersecurity_2025', 'Cybersecurity 2025', 'implemented', 'multi_view_embedding', 'Unified stripped-compatible multi-view retrieval baseline inspired by recent cybersecurity venue work.'),
    MethodSpec('binary2vec', 'Binary2vec', 'implemented', 'global_embedding', 'Unified stripped-compatible global embedding reproduction.'),
    MethodSpec('array_2025', 'Array 2025', 'implemented', 'prototype_fusion', 'Prototype-aware retrieval fusion under the stripped protocol.'),
    MethodSpec('evopatch_iot', 'EvoPatch-IoT', 'implemented', 'ours', 'Our method: shape-backbone retrieval with fusion and historical evolution priors.'),
    MethodSpec('vexir2vec_2023', 'VEXIR2Vec 2023', 'implemented', 'ir_peephole_embedding', 'Unified stripped-compatible VEXIR2Vec-style IR-normalized peephole and CFG embedding reproduction.'),
    MethodSpec('ex2vec_2025', 'Ex2Vec 2025', 'implemented', 'execution_aware_embedding', 'Unified stripped-compatible Ex2Vec-style execution-aware token and CFG fusion reproduction.'),
]

METHOD_BY_ID: Dict[str, MethodSpec] = {item.method_id: item for item in ALL_METHODS}
IMPLEMENTED_METHODS: List[MethodSpec] = [item for item in ALL_METHODS if item.status == 'implemented']
PENDING_METHODS: List[MethodSpec] = [item for item in ALL_METHODS if item.status != 'implemented']


def get_method(method_id: str) -> MethodSpec:
    if method_id not in METHOD_BY_ID:
        raise KeyError(f'Unknown method_id: {method_id}')
    return METHOD_BY_ID[method_id]


def score_method(method_id: str, query: dict, candidate: dict, prototype: Optional[List[float]]) -> float:
    token = cosine_dense(query.get('token_hash', []), candidate.get('token_hash', []))
    graph = cosine_dense(query.get('graph_norm', []), candidate.get('graph_norm', []))
    graph_arch = cosine_dense(query.get('graph_arch_norm', []), candidate.get('graph_arch_norm', []))
    context = cosine_dense(query.get('context_hash', []), candidate.get('context_hash', []))
    shape = -feature_distance(query.get('shape_vec', []), candidate.get('shape_vec', []), SHAPE_SCALES)
    shape_arch = cosine_dense(query.get('shape_arch_norm', []), candidate.get('shape_arch_norm', []))
    fused = cosine_dense(query.get('fusion_vec', []), candidate.get('fusion_vec', []))
    proto = cosine_dense(candidate.get('fusion_vec', []), prototype or []) if prototype else 0.0

    if method_id == 'size_stat':
        return -abs(log1p(query['size']) - log1p(candidate['size']))
    if method_id == 'shape_stat':
        return shape
    if method_id == 'clap':
        return token
    if method_id == 'issta_2024':
        return 0.60 * token + 0.25 * shape_arch + 0.15 * context
    if method_id == 'gtrans':
        return graph
    if method_id == 'bar_2024':
        return 0.40 * shape_arch + 0.35 * context + 0.25 * graph_arch
    if method_id == 'ammf':
        return 0.55 * token + 0.30 * graph + 0.15 * context
    if method_id == 'cybersecurity_2025':
        return 0.45 * fused + 0.20 * token + 0.20 * graph_arch + 0.15 * context
    if method_id == 'binary2vec':
        return 0.60 * fused + 0.20 * graph_arch + 0.20 * shape_arch
    if method_id == 'vexir2vec_2023':
        return 0.40 * graph_arch + 0.35 * token + 0.20 * shape_arch + 0.05 * context
    if method_id == 'ex2vec_2025':
        return 0.35 * token + 0.30 * graph_arch + 0.20 * context + 0.15 * shape_arch
    if method_id == 'array_2025':
        return 0.50 * fused + 0.25 * shape_arch + 0.25 * proto
    if method_id == 'evopatch_iot':
        return 0.70 * shape + 0.10 * fused + 0.20 * proto
    raise KeyError(method_id)
