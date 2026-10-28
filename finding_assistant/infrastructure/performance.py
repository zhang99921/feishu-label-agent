"""请求内分段计时：固定阶段名、调用数及失败数，不收集参数或异常内容。"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from threading import Lock
import time

STAGES = frozenset({'authorize', 'local_session', 'login_identity', 'native_permission', 'feishu_http', 'oauth_http',
    'related_read', 'schema_check', 'flow_write', 'position_allocation', 'inventory_prepare',
    'inventory_execute', 'inventory_write', 'readback', 'reconcile', 'postgresql'})
_current = ContextVar('finding_performance', default=None)


class Trace:
    def __init__(self):
        self._values, self._lock = {}, Lock()

    def add(self, stage, elapsed, failed):
        with self._lock:
            row = self._values.setdefault(stage, {'calls': 0, 'elapsed_ms': 0.0, 'failures': 0})
            row['calls'] += 1
            row['elapsed_ms'] += elapsed
            row['failures'] += int(failed)

    def snapshot(self):
        with self._lock:
            return {name: {**value, 'elapsed_ms': round(value['elapsed_ms'], 3)}
                    for name, value in sorted(self._values.items())}


@contextmanager
def request_trace():
    trace = Trace()
    token = _current.set(trace)
    try:
        yield trace
    finally:
        _current.reset(token)


@contextmanager
def span(stage):
    if stage not in STAGES:
        raise ValueError('INVALID_PERFORMANCE_STAGE')
    trace = _current.get()
    if trace is None:
        yield
        return
    started, failed = time.perf_counter(), False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        try:
            trace.add(stage, (time.perf_counter() - started) * 1000, failed)
        except Exception:
            pass  # 观测失败不得替代业务结果、抹去原异常或诱发重试。


def timed(stage):
    if stage not in STAGES:
        raise ValueError('INVALID_PERFORMANCE_STAGE')

    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            with span(stage):
                return function(*args, **kwargs)
        return measured
    return decorate
