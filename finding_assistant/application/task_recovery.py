"""原账号管理员的只读核查及原任务续办；不修补未知写、不修改冻结计划。"""
import hashlib
import hmac
import json
from finding_assistant.application.workflow import Conflict
from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.native_access import verified_authorize


class TaskRecovery:
    def __init__(self, tasks):
        self.tasks = tasks
        self.engine = tasks.service.inventory_execution

    def _authorized(self, sid, task_id):
        actor = verified_authorize(self.tasks.service.gate, sid, 'ADMIN')
        if actor.permission != 'full_access':
            raise AccessDenied('management permission required')
        self.engine.access.reader._complete_scope(actor)
        row = self.tasks.store.row(task_id, actor)
        self.tasks._check_scope(row)
        if row['state'] != 'REVIEW':
            raise Conflict('task does not require review')
        return actor, row

    def inspect(self, sid, task_id):
        actor, row = self._authorized(sid, task_id)
        return self._inspect(sid, actor, row)

    def _inspect(self, sid, actor, row):
        report = {'task_id': str(row['task_id']), 'record_id': row['record_id'],
                  'can_continue': False, 'steps': [], 'read_only': True,
                  'atomic_remote_snapshot': False, 'reason': 'SOURCE_WRITE_REQUIRES_MANUAL_REVIEW'}
        evidence = [str(row['updated_at']), row['fingerprint'], row['record_id']]
        if row['record_id']:
            _, source, submission, execution = self.engine._source(sid, row['record_id'])
            if execution is not None:
                plan = execution['plan']
                self.engine.access.validate_plan(actor, plan)
                self.engine.access.verify_rows(actor, plan)
                stored = self.engine.repository.steps(submission.source_key)
                observations = {}
                for role in ('BOX', 'DETAIL'):
                    selected = [s['specification'] for s in stored if s['kind'] == role]
                    if selected:
                        observations[role] = self.engine.access.get_many(actor, role, [s['record_id'] for s in selected])
                ledger_steps = [s['specification'] for s in stored if s['kind'] == 'LEDGER']
                ledgers = self.engine.access.ledgers(actor, ledger_steps) if ledger_steps else {}
                evidence += [str(execution['updated_at']), execution['fingerprint'], source['fields'], plan]
                all_after = True
                status_after = False
                for entry in stored:
                    step = entry['specification']
                    records = (ledgers[step['fields']['事务号']] if step['kind'] == 'LEDGER' else
                               [source] if step['kind'] == 'STATUS' else [observations[step['kind']][step['record_id']]])
                    current = records[0] if len(records) == 1 else None
                    after = current is not None and self.engine.access.verify(current, step['after'], step['types'])
                    before = (not records if step['kind'] == 'LEDGER' else
                              current is not None and self.engine.access.verify(current, step['before'], step['types']))
                    receipt_ok = not entry['remote_record_id'] or (current is not None and current['record_id'] == entry['remote_record_id'])
                    state = entry['state']
                    if len(records) > 1 or not receipt_ok:
                        result = 'RECEIPT_CONFLICT'
                    elif after and (state in ('CONFIRMED', 'RUNNING', 'UNKNOWN') or (state == 'PENDING' and before)):
                        result = 'AFTER_CONFIRMED'
                    elif state == 'PENDING' and before:
                        result = 'PENDING_NOT_SENT'
                    else:
                        result = 'MANUAL_RECONCILIATION_REQUIRED'
                    report['steps'].append({'ordinal': entry['ordinal'], 'kind': step['kind'],
                                            'local_state': state, 'observation': result})
                    evidence += [entry['ordinal'], state, entry['remote_record_id'], records]
                    if step['kind'] == 'STATUS':
                        status_after = after
                    else:
                        all_after = all_after and after
                blocked = any(s['observation'] not in ('AFTER_CONFIRMED', 'PENDING_NOT_SENT') for s in report['steps'])
                # 流水已完成而库存未全部匹配时，不把原计划重新执行当作修复。
                report['can_continue'] = bool(stored) and not blocked and (not status_after or all_after)
                report['reason'] = 'ORIGINAL_PLAN_CONTINUATION_AVAILABLE' if report['can_continue'] else 'MANUAL_RECONCILIATION_REQUIRED'
            else:
                report['reason'] = 'FROZEN_PLAN_MISSING'
        report['review_fingerprint'] = hashlib.sha256(json.dumps(
            [evidence, report], sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        return report

    def continue_original(self, sid, task_id, fingerprint):
        actor, row = self._authorized(sid, task_id)
        # 与后台队列共用Base锁，与旧执行入口共用来源锁，核查和登记期间不并行执行。
        with self.tasks.store.review_guard():
            if not row['record_id']:
                raise Conflict('source write requires manual review')
            key = self.engine.repository.base + ':' + self.engine.repository.scan_table + ':' + row['record_id']
            with self.engine.repository.validation_guard(key) as alive:
                actor, row = self._authorized(sid, task_id)
                report = self._inspect(sid, actor, row)
                if not report['can_continue'] or not hmac.compare_digest(report['review_fingerprint'], fingerprint):
                    raise Conflict('review changed or continuation is unsafe; inspect original task again')
                alive()
                self.tasks.store.resume_review(row, actor, sid)
        self.tasks.wake.set()
        return self.tasks.summary(self.tasks.store.row(task_id, actor))
