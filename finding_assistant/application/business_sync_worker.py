"""同步进程：一轮完成后再等待，不重叠拉取；日志不记录业务内容和异常原文。"""
import logging
import time

LOG = logging.getLogger('finding_assistant.sync')


def check_interval(values):
    """0关闭；正数至少60秒，避免把全副本核验误配成高频忙循环。"""
    raw = values.get('FINDING_ASSISTANT_REPLICA_CHECK_SECONDS', '0')
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal():
        raise ValueError('INVALID_REPLICA_CHECK_INTERVAL')
    value = int(raw)
    if value != 0 and not 60 <= value <= 604800:
        raise ValueError('INVALID_REPLICA_CHECK_INTERVAL')
    return value


def run_sync(sync, reader, *, watch, wait, stop_requested, checker=None, check_seconds=0, monotonic=time.monotonic):
    if type(check_seconds) is not int or (check_seconds != 0 and not 60 <= check_seconds <= 604800):
        raise ValueError('INVALID_REPLICA_CHECK_INTERVAL')
    if check_seconds and not callable(checker):
        raise ValueError('REPLICA_CHECKER_REQUIRED')
    failures = 0
    next_check = monotonic()
    while not stop_requested():
        eligible = True
        try:
            result = sync.sync_once(reader)
            eligible = result['outcome'] != 'BUSY'
            metrics = result.get('metrics', {})
            LOG.info('business_sync=%s duration_seconds=%s records=%s pages=%s max_page_records=%s mode=%s reused=%s changed_fetch=%s feishu_written=false',
                     result['outcome'], metrics.get('duration_seconds'), metrics.get('record_count'),
                     metrics.get('record_pages'), metrics.get('max_page_records'), metrics.get('sync_mode'),
                     metrics.get('reused_records'), metrics.get('changed_records_fetched'))
            failures = 0
        except Exception:
            LOG.error('business_sync=FAILED previous_complete_replica_retained=true')
            failures += 1
            if not watch:
                raise
        if eligible and check_seconds and not stop_requested() and monotonic() >= next_check:
            try:
                inspected = checker()
                if not isinstance(inspected, dict) or type(inspected.get('healthy')) is not bool:
                    raise ValueError('INVALID_REPLICA_CHECK_RESULT')
                if inspected['healthy'] and (inspected.get('content', {}).get('digest_verified') is not True
                        or inspected.get('content', {}).get('index_values_verified') is not True):
                    raise ValueError('CONTENT_CHECK_NOT_CONFIRMED')
                # 不记录字段值、原异常或回调提供的任意文案；详细问题码由手动巡检查看。
                if inspected['healthy']:
                    LOG.info('replica_check=HEALTHY content_verified=true feishu_checked=false repairs_executed=false')
                else:
                    LOG.error('replica_check=INCONSISTENT manual_replica_check_required=true repairs_executed=false')
            except Exception:
                # 巡检故障独立于同步重试：不把已成功的同步改成失败，不停止watch。
                LOG.error('replica_check=UNAVAILABLE manual_replica_check_required=true repairs_executed=false')
            finally:
                # 从本轮核验完成时计时，不补跑错过的历史时段，进程内串行执行。
                next_check = monotonic() + check_seconds
        if not watch or stop_requested():
            break
        # 失败退避最高15分钟；下一轮仍从头完整校验，不公开半个版本。
        wait(min(900, sync.config.interval * 2 ** min(failures, 4)))
