"""有界后台执行入口；执行计划持久化，调度与会话仅保存在当前进程。"""
from finding_assistant.security.native_access import verified_authorize
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import logging
import json
import time
import uuid
from threading import BoundedSemaphore, RLock
from types import SimpleNamespace

from finding_assistant.application.workflow import Conflict
from finding_assistant.infrastructure.request_scope import request_scope
from finding_assistant.infrastructure.performance import request_trace
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable

LOG = logging.getLogger('finding_assistant.http.background')


class BackgroundInventory:
    """单HTTP进程内最多八个任务；库存层仍通过数据库锁防止并行写。"""
    def __init__(self, execution, capacity=8):
        if type(capacity) is not int or not 1 <= capacity <= 64:
            raise ValueError('INVALID_DISPATCH_CAPACITY')
        self.execution = execution
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='inventory')
        self.slots = BoundedSemaphore(capacity)
        self.lock = RLock()
        self.jobs = {}
        self.finished = OrderedDict()
        self.closed = False

    def submit(self, session_id, record_id):
        # 包括流水归属、原始输入指纹和当前动作权限；不接受客户端角色。
        identity, _, submission, row = self.execution._source(session_id, record_id)
        key = submission.source_key
        if row and row['state'] == 'SUCCEEDED':
            return self._result(key, 'COMPLETED')
        with self.lock:
            if self.closed:
                raise AuthorizationUnavailable('background execution is unavailable')
            if key in self.jobs:
                if self.jobs[key] == 'PREPARING':
                    raise Conflict('execution admission is in progress')
                return self._result(key, self.jobs[key])
            if not self.slots.acquire(blocking=False):
                raise AuthorizationUnavailable('background queue is full')
            self.jobs[key] = 'PREPARING'
        try:
            if row is None:
                self.execution.prepare(session_id, record_id)
            result = self._result(key, 'QUEUED')
            # 在启动线程之前提交受理审计；失败时计划保留，调用方可重新提交。
            with self.execution.repository.operations.connection() as db:
                self.execution.repository.operations._audit(db, 'BACKGROUND_EXECUTION', 'QUEUED',
                    identity, submission.action, key=uuid.UUID(result['task_id']))
            with self.lock:
                if self.closed:
                    raise AuthorizationUnavailable('background execution is unavailable')
                self.jobs[key] = 'QUEUED'
                actor = SimpleNamespace(open_id=identity.open_id, tenant_key=identity.tenant_key)
                future = self.pool.submit(self._run, session_id, record_id, key, actor, submission.action, result['task_id'])
                future.add_done_callback(lambda done: self._done(key, done))
            return result
        except Exception:
            with self.lock:
                self.jobs.pop(key, None)
            self.slots.release()
            raise

    def _run(self, session_id, record_id, key, actor, action, task_id):
        with self.lock:
            self.jobs[key] = 'RUNNING'
        outcome = 'UNCONFIRMED'
        started = time.perf_counter()
        with request_trace() as timing:
            try:
                # 不继承受理请求中的鉴权/结构复用，轮到执行时重新校验登录与权限。
                with request_scope():
                    result = self.execution.execute(session_id, record_id)
                if result.get('state') == 'SUCCEEDED':
                    outcome = 'COMPLETED'
            except Exception:
                # 未知写入由原执行器保留；不重试、不打印异常及会话。
                try:
                    with self.execution.repository.operations.connection() as db:
                        self.execution.repository.operations._audit(db, 'BACKGROUND_EXECUTION',
                            'UNCONFIRMED', actor, action, key=uuid.UUID(task_id))
                except Exception:
                    pass
            finally:
                with self.lock:
                    self.jobs[key] = outcome
        try:
            # task_id关联审计；每次执行另生成编号，防止续跑被汇总器当作重复日志。
            LOG.info('background_execution task_id=%s outcome=%s', task_id, outcome)
            stages = timing.snapshot()
            if stages:
                LOG.info('performance=%s', json.dumps({'request_id': uuid.uuid4().hex, 'task_id': task_id,
                    'route': 'background:inventory-execution', 'status': 200 if outcome == 'COMPLETED' else 503,
                    'duration_ms': round((time.perf_counter()-started)*1000,3), 'stages': stages},
                    separators=(',', ':'), sort_keys=True))
        except Exception:
            pass  # 计时/日志故障不得改变库存结果或占用队列容量。

    def _done(self, key, future):
        with self.lock:
            state = self.jobs.pop(key, 'UNCONFIRMED')
            if not future.cancelled() and future.exception() is not None:
                state = 'UNCONFIRMED'
            self.finished[key] = 'NOT_SCHEDULED' if future.cancelled() else state
            self.finished.move_to_end(key)
            while len(self.finished) > 128:
                self.finished.popitem(last=False)
        self.slots.release()

    def _result(self, key, dispatch_state):
        result = self.execution.repository.summary(key)
        if result.get('state') == 'SUCCEEDED':
            dispatch_state = 'COMPLETED'
        return {**result, 'task_id': result.get('execution_id'), 'dispatch_state': dispatch_state,
                'poll_after_seconds': 5,
                'resume_required': result.get('state') == 'PREPARED' and
                    dispatch_state in ('NOT_SCHEDULED', 'UNCONFIRMED'),
                'review_required': result.get('state') == 'RECONCILE' or dispatch_state == 'UNCONFIRMED'}

    def progress(self, session_id, record_id):
        self.execution.access._id(record_id)
        identity = verified_authorize(self.execution.gate, session_id, 'QUERY')
        # 与现有库存执行入口一致：未验证普通账号行列范围前，不绕过原生可见性。
        self.execution.access.reader._complete_scope(identity)
        repo = self.execution.repository
        key = repo.base + ':' + repo.scan_table + ':' + record_id
        row = repo.row(key)
        if row is None:
            return {'found': False, 'inventory_posted': False}
        if row['tenant_key'] != identity.tenant_key or row['open_id'] != identity.open_id:
            raise AccessDenied('execution belongs to another operator')
        with self.lock:
            state = self.jobs.get(key, self.finished.get(key, 'NOT_SCHEDULED'))
        return self._result(key, state)

    def close(self):
        with self.lock:
            self.closed = True
        # 等待当前执行结束；排队任务保留持久化计划，重启后须重新提交。
        self.pool.shutdown(wait=True, cancel_futures=True)
