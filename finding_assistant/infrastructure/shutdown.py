"""进程停止信号转为等待事件；不改变数据库或业务状态。"""
from contextlib import contextmanager
import signal
import threading


@contextmanager
def intake_shutdown():
    """SIGTERM/Windows SIGBREAK请求收尾；Ctrl+C保留原KeyboardInterrupt行为。"""
    stopping = threading.Event()
    previous = {}

    def stop(signum, frame):
        stopping.set()

    try:
        if threading.current_thread() is threading.main_thread():
            for name in ('SIGTERM', 'SIGBREAK'):
                number = getattr(signal, name, None)
                if number is not None:
                    previous[number] = signal.signal(number, stop)
        yield stopping
    finally:
        for number, old in previous.items():
            signal.signal(number, old)
