"""持续接收流水的运行控制；临时故障退避后重新读取，不执行库存写入。"""
import logging
import threading

import psycopg

from finding_assistant.adapters.feishu.existing_forms import SourceUnavailable
from .scan_ingestion import ScanIngestion

LOG = logging.getLogger('finding_assistant.intake')


def run_intake(reader, repository, *, watch=False, wait=None, stop_requested=None):
    if wait is None:
        wait = threading.Event().wait
    interval = reader.config.poll_seconds
    failures = 0
    while True:
        if stop_requested is not None and stop_requested():
            LOG.info('intake_status=stopped inventory_posting_enabled=false')
            return
        phase = 'database_check'
        try:
            repository.ready()
            phase = 'source_read'
            # 整轮远端读取完整后才登记；中途数据库失败的旧项由唯一键防重。
            records = list(reader.records())
            ingestion = ScanIngestion(repository, reader.app_token, reader.config.scan_table_id,
                                     include_blank_status=reader.config.include_blank_status)
            counts = ingestion.run(records)
        except (SourceUnavailable, ValueError, psycopg.OperationalError, psycopg.InterfaceError) as error:
            # 迁移缺失、校验和冲突属于配置问题，不能无限重试或自动修复。
            if phase == 'database_check' and isinstance(error, ValueError):
                raise
            if not watch:
                raise
            failures += 1
            # 5分钟封顶，但不短于已配置的常规轮询间隔；连续故障不忙循环。
            delay = min(interval * 2 ** min(failures - 1, 8), max(300, interval))
            origin = 'database' if isinstance(error, psycopg.Error) else 'source'
            LOG.error('intake_status=retry source=%s failure_count=%s retry_in_seconds=%s inventory_posting_enabled=false',
                      origin, failures, delay)
        else:
            failures = 0
            delay = interval
            LOG.info('intake_counts=%s inventory_posting_enabled=false', counts)
        if not watch:
            return
        if wait(delay):
            LOG.info('intake_status=stopped inventory_posting_enabled=false')
            return
