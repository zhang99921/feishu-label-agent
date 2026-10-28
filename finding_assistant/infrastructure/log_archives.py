"""组件日志按UTC日期/大小压缩归档；只清理本组件格式严格匹配的旧归档。"""
from datetime import datetime, timedelta, timezone
import gzip
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import os
import re
import shutil
import time
import uuid


class ArchivedFileHandler(RotatingFileHandler):
    def __init__(self, filename, *args, retention_days=30, **kwargs):
        path = Path(filename)
        if path.is_symlink():
            raise ValueError('LOG_SYMLINK_REFUSED')
        self.component = path.stem
        if self.component not in ('http', 'sync', 'intake'):
            raise ValueError('INVALID_LOG_COMPONENT')
        self.retention_days = retention_days
        self.archive_root = path.parent / 'archive' / self.component
        modified = path.stat().st_mtime if path.exists() and path.stat().st_size else time.time()
        self.active_day = datetime.fromtimestamp(modified, timezone.utc).date()
        self.next_day = self.active_day
        self.last_pruned_day = None
        self.next_archive_retry = 0
        super().__init__(filename, *args, **kwargs)

    def shouldRollover(self, record):
        self.next_day = datetime.fromtimestamp(record.created, timezone.utc).date()
        if self.next_day != self.active_day:
            return True
        return super().shouldRollover(record)

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        source = Path(self.baseFilename)
        if source.exists() and source.stat().st_size:
            folder = self.archive_root / self.active_day.isoformat()
            # 归档目录不能通过符号链接把日志写到其他位置。
            for directory in (self.archive_root.parent, self.archive_root, folder):
                if directory.is_symlink():
                    raise OSError('LOG_ARCHIVE_SYMLINK_REFUSED')
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            archive = folder / f'{self.component}-{stamp}-{uuid.uuid4().hex}.log.gz'
            temporary = archive.with_suffix('.tmp')
            try:
                with source.open('rb') as incoming, temporary.open('xb') as outgoing:
                    with gzip.GzipFile(fileobj=outgoing, mode='wb', filename='', mtime=0) as compressed:
                        shutil.copyfileobj(incoming, compressed)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                temporary.replace(archive)
                # 归档完整落盘后才截断活跃日志；失败时原文件继续保留。
                with source.open('w', encoding=self.encoding):
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        self.active_day = self.next_day
        if not self.delay:
            self.stream = self._open()

    def prune(self, today):
        if not self.archive_root.exists():
            return
        if self.archive_root.is_symlink() or self.archive_root.parent.is_symlink():
            raise OSError('LOG_ARCHIVE_SYMLINK_REFUSED')
        root = self.archive_root.resolve()
        cutoff = today - timedelta(days=self.retention_days - 1)
        pattern = re.compile(re.escape(self.component) + r'-\d{8}T\d{12}Z-[0-9a-f]{32}\.log\.gz')
        for folder in self.archive_root.iterdir():
            if folder.is_symlink() or not folder.is_dir() or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', folder.name):
                continue
            try:
                day = datetime.strptime(folder.name, '%Y-%m-%d').date()
            except ValueError:
                continue
            if day >= cutoff:
                continue
            for archive in folder.iterdir():
                if archive.is_symlink() or not archive.is_file() or not pattern.fullmatch(archive.name):
                    continue
                resolved = archive.resolve()
                if resolved.parent != folder.resolve() or not resolved.is_relative_to(root):
                    raise OSError('LOG_ARCHIVE_OUTSIDE_ROOT')
                archive.unlink()
            # 不递归删除，也不删除未知文件；空日期目录可保留。

    def emit(self, record):
        try:
            today = datetime.fromtimestamp(record.created, timezone.utc).date()
            if time.monotonic() >= self.next_archive_retry:
                if self.shouldRollover(record):
                    self.doRollover()
                if self.last_pruned_day != today:
                    self.prune(today)
                    self.last_pruned_day = today
        except Exception:
            # 归档/清理失败不能丢掉当前事件：回退追加原活跃文件，并报告固定告警。
            self.handleError(record)
            self.next_archive_retry = time.monotonic() + 60
        logging.FileHandler.emit(self, record)
