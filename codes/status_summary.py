#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_config() -> dict:
    path = PROJECT_ROOT / 'codes' / 'configs' / 'all57_current_bg.json'
    return json.loads(path.read_text(encoding='utf-8'))


def main() -> int:
    config = load_config()
    ghidra_run = PROJECT_ROOT / config['ghidra_run']
    rows = list(csv.DictReader((ghidra_run / 'ghidra_status.csv').open('r', encoding='utf-8', newline='')))
    arch_count = len(config.get('archs', [])) or 5
    by_status = Counter(row['status'] for row in rows)
    by_version = Counter(row['version'] for row in rows if row['status'] == 'completed')
    completed_versions = sorted([version for version, count in by_version.items() if count >= arch_count])
    summary = {
        'ghidra_run': str(ghidra_run),
        'completed_binaries': by_status.get('completed', 0),
        'total_binaries': len(rows),
        'completed_versions': completed_versions,
        'completed_version_count': len(completed_versions),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
