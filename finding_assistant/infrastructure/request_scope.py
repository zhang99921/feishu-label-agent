"""仅在单次 HTTP 请求内复用成功的身份及字段结构；不缓存业务记录。"""
from contextlib import contextmanager
from contextvars import ContextVar
from threading import RLock

_current = ContextVar('finding_request_scope', default=None)


class RequestScope:
    def __init__(self):
        self.values = {}
        self.lock = RLock()


def current_scope():
    return _current.get()


@contextmanager
def request_scope():
    scope = RequestScope()
    token = _current.set(scope)
    try:
        yield scope
    finally:
        _current.reset(token)
        with scope.lock:
            scope.values.clear()
