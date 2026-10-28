"""只读汇总性能日志；仅输出固定路由和阶段，不回显任意日志内容。"""
from collections import defaultdict, deque
import json
import math
from pathlib import Path
import uuid

from .performance import STAGES

ROUTES = frozenset({'/api/v1/access/me', '/api/v1/scans', '/api/v1/search/boxes',
    '/api/v1/search/boxes/{record_id}',
    'background:inventory-execution',
    '/api/v1/scans/inbound', '/api/v1/scans/outbound', '/api/v1/scans/transfer',
    '/api/v1/scans/inbound/validate', '/api/v1/inventory-executions/{record_id}',
    '/api/v1/inventory-executions/{record_id}/prepare', '/api/v1/inventory-executions/{record_id}/execute',
    '/api/v1/inventory-executions/{record_id}/dispatch', '/api/v1/inventory-executions/{record_id}/progress',
    '/auth/feishu/callback', '/auth/feishu/start', '/auth/logout', '/api/v1/sync/status'})


def percentiles(values):
    values = sorted(values)
    return {'p50_ms': round(values[(len(values)-1)//2], 3),
            'p95_ms': round(values[math.ceil(len(values)*0.95)-1], 3), 'maximum_ms': round(values[-1], 3)}


def number(value):
    return type(value) in (int, float) and 0 <= value <= 604800000 and math.isfinite(value)


def summarize(path, *, max_lines=10000, request_id=None):
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError('INVALID_PERFORMANCE_LINE_LIMIT')
    selected = str(uuid.UUID(request_id)) if request_id is not None else None
    path = Path(path)
    if path.stat().st_size > 50000000:
        raise ValueError('PERFORMANCE_LOG_TOO_LARGE')
    with path.open(encoding='utf-8-sig', errors='replace') as stream:
        lines = deque(stream, maxlen=max_lines)
    groups, seen, invalid, duplicates = defaultdict(list), set(), 0, 0
    for line in lines:
        if 'performance=' not in line: continue
        if len(line) > 16384:
            invalid += 1
            continue
        try:
            row = json.loads(line.split('performance=', 1)[1])
            key = str(uuid.UUID(row['request_id']))
            if not (number(row['duration_ms']) and type(row['status']) is int and 100 <= row['status'] <= 599
                    and isinstance(row['stages'], dict) and row['stages'] and set(row['stages']) <= STAGES):
                raise ValueError('INVALID_PERFORMANCE_ENTRY')
            for stage in row['stages'].values():
                if not (type(stage['calls']) is int and 1 <= stage['calls'] <= 10000000
                        and type(stage['failures']) is int and 0 <= stage['failures'] <= stage['calls']
                        and number(stage['elapsed_ms'])):
                    raise ValueError('INVALID_PERFORMANCE_ENTRY')
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            invalid += 1
            continue
        if selected is not None and key != selected: continue
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        route = row.get('route')
        groups[route if isinstance(route, str) and route in ROUTES else 'other'].append(row)
    result = []
    for route, rows in sorted(groups.items()):
        stages = {}
        for name in sorted(STAGES):
            parts = [row['stages'][name] for row in rows if name in row['stages']]
            if parts:
                stages[name] = {'sampled_requests': len(parts), 'calls': sum(p['calls'] for p in parts),
                    'failed_calls': sum(p['failures'] for p in parts),
                    **percentiles([p['elapsed_ms'] for p in parts])}
        result.append({'route': route, 'requests': len(rows),
                       **percentiles([row['duration_ms'] for row in rows]), 'stages': stages})
    return {'read_only': True, 'requests': len(seen), 'routes': result, 'invalid_entries': invalid,
            'duplicate_entries': duplicates, 'lines_scanned': len(lines), 'max_lines': max_lines,
            'nested_stage_times_are_not_additive': True}
