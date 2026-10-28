"""HTTP与接收进程的限量日志；配置解析不访问文件系统。"""
from copy import copy
from dataclasses import dataclass
import logging
from .log_archives import ArchivedFileHandler
from pathlib import Path
import sys
import time

LOG_KEYS = ('FINDING_ASSISTANT_LOG_DIR', 'FINDING_ASSISTANT_LOG_MAX_BYTES', 'FINDING_ASSISTANT_LOG_BACKUPS',
            'FINDING_ASSISTANT_LOG_RETENTION_DAYS')


@dataclass(frozen=True)
class LogConfig:
    directory: str
    max_bytes: int
    backups: int
    retention_days: int = 30

    @classmethod
    def from_values(cls, values):
        directory = values.get(LOG_KEYS[0], 'logs')
        try:
            if not isinstance(directory, str) or any(ord(c) < 32 for c in directory):
                raise ValueError
            maximum = int(values.get(LOG_KEYS[1], '10485760'))
            backups = int(values.get(LOG_KEYS[2], '5'))
            retention = int(values.get(LOG_KEYS[3], '30'))
            if not 1048576 <= maximum <= 104857600 or not 1 <= backups <= 10 or not 1 <= retention <= 3650:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError('INVALID_RUNTIME_LOG_CONFIGURATION') from None
        # 空目录显式禁用文件日志；控制台仍保留固定格式的运行信息。
        return cls(directory.strip(), maximum, backups, retention)


class RuntimeFormatter(logging.Formatter):
    converter = time.gmtime

    def format(self, record):
        record = copy(record)
        # 不沿用其他handler缓存的异常原文，也不输出可能包含HTTP凭据的堆栈。
        record.exc_text = None
        message = super().format(record)
        encoded = message.encode('utf-8', errors='backslashreplace')
        if len(encoded) > 16384:
            return encoded[:16384].decode('utf-8', errors='ignore') + ' [truncated]'
        return message

    def formatException(self, exc_info):
        kind = exc_info[0]
        return 'exception_type=' + (kind.__name__ if isinstance(kind, type) else 'unknown')

    def formatStack(self, stack_info):
        return 'stack_omitted'


class RuntimeFileHandler(ArchivedFileHandler):
    def handleError(self, record):
        # 文件写满、目录失去权限等故障不递归写日志，不回显原始异常或请求。
        if not getattr(self, '_failure_reported', False):
            self._failure_reported = True
            try:
                sys.stderr.write('RUNTIME_LOG_WRITE_FAILED; check log storage\n')
            except (OSError, ValueError):
                pass


def configure_logging(component, values):
    """仅配置本服务的日志，不将httpx等库的URL/请求日志写入运行文件。"""
    if component not in ('http', 'intake', 'sync'):
        raise ValueError('INVALID_LOG_COMPONENT')
    config = LogConfig.from_values(values)
    formatter = RuntimeFormatter('%(asctime)sZ %(levelname)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')
    handlers = []
    try:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        handlers.append(console)
        if config.directory:
            directory = Path(config.directory)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            file = RuntimeFileHandler(directory / (component + '.log'), maxBytes=config.max_bytes,
                                      backupCount=config.backups, retention_days=config.retention_days,
                                      encoding='utf-8', errors='backslashreplace')
            file.setFormatter(formatter)
            handlers.append(file)
    except (OSError, ValueError):
        for handler in handlers:
            handler.close()
        raise ValueError('RUNTIME_LOG_STORAGE_UNAVAILABLE') from None
    logger = logging.getLogger('finding_assistant.' + component)
    # 同一进程重复装配时只替换本模块创建的handler，不重复输出或泄漏文件句柄。
    for old in list(logger.handlers):
        if getattr(old, '_finding_runtime_handler', False):
            logger.removeHandler(old)
            old.close()
    for handler in handlers:
        handler._finding_runtime_handler = True
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    # 身份诊断不属于http子树，显式接入同一组脱敏文件/控制台handler。
    identity = logging.getLogger('finding_assistant.identity')
    owned = [h for h in identity.handlers if getattr(h, '_finding_runtime_handler', False)]
    if component == 'http' or not owned:
        for handler in owned:
            identity.removeHandler(handler)  # handler仍由组件logger拥有，不在这里重复close。
        for handler in handlers:
            identity.addHandler(handler)
        identity.setLevel(logging.INFO)
        identity.propagate = False
    for name in ('httpx', 'httpcore'):
        logging.getLogger(name).setLevel(logging.WARNING)
    return logger
