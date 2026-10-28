"""统一处理已登记流水；用户授权、整批计划、逐步核实、逐箱事务和可恢复收尾。"""
from finding_assistant.security.native_access import verified_authorize
import time
import uuid

from finding_assistant.domain.inventory_posting import build_posting_plan, PostingStopped, BOX_TYPES, FINAL_STATUS
from finding_assistant.domain.scan_submission import normalize_record, field_text, creator_id, EVENTS
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.infrastructure.performance import timed
from finding_assistant.domain.validation_rejection import REASONS
from finding_assistant.infrastructure.validation_feedback_store import ValidationFeedbackStore
from .validation_feedback import ValidationFeedback


class InventoryExecution:
    def __init__(self, gate, access, repository, positions):
        self.gate, self.access, self.repository, self.positions = gate, access, repository, positions
        self.rejections = ValidationFeedbackStore(repository)
        self.feedback = ValidationFeedback(gate, access, self.rejections)

    def _source(self, session_id, record_id, *, query_only=False):
        self.access._id(record_id)
        identity = self.gate.authorize(session_id, 'QUERY')
        if not query_only and identity.permission not in ('full_access', 'edit'):
            raise AccessDenied('inventory operation permission required')
        source = self.access.source(identity, record_id)
        action = EVENTS.get(field_text(source['fields'].get('事件类型')))
        if not action:
            raise PostingStopped('UNSUPPORTED_SOURCE_ACTION')
        if not query_only:
            identity = self.gate.authorize(session_id, action)
        if creator_id(source['fields'].get('操作人')) != identity.open_id:
            # 后台应用身份和代他人执行的口径尚未选择，本入口只处理本人流水。
            raise AccessDenied('source creator must be the authenticated operator')
        key = self.repository.base + ':' + self.repository.scan_table + ':' + record_id
        existing = self.repository.row(key)
        status = field_text(source['fields'].get('处理状态'))
        rejection = self.rejections.get(key, identity) if not existing else None
        if status != '待处理' and not (existing and status == FINAL_STATUS[action]) and not (rejection and status == '异常'):
            raise PostingStopped('SOURCE_STATUS_REVIEW_REQUIRED')
        candidate = {**source, 'fields': {**source['fields'], '处理状态': '待处理'}}
        submission = normalize_record(self.repository.base, self.repository.scan_table, candidate)
        if not submission or submission.errors or submission.source_creator is None:
            raise PostingStopped('SOURCE_INPUT_INVALID')
        if existing and (existing['fingerprint'] != submission.fingerprint or existing['open_id'] != identity.open_id
                         or existing['tenant_key'] != identity.tenant_key or existing['action'] != submission.action):
            raise PostingStopped('SOURCE_INPUT_CHANGED')
        if rejection and rejection['fingerprint'] != submission.fingerprint:
            raise PostingStopped('SOURCE_INPUT_CHANGED')
        return identity, source, submission, existing

    def prepare(self, session_id, record_id):
        _, _, submission, _ = self._prepare_context(session_id, record_id)
        return self.repository.summary(submission.source_key)

    @timed('inventory_prepare')
    def _prepare_context(self, session_id, record_id):
        self.access._id(record_id)
        key = self.repository.base + ':' + self.repository.scan_table + ':' + record_id
        with self.repository.validation_guard(key) as guard_alive:
            return self._prepare(session_id, record_id, guard_alive)

    def _prepare(self, session_id, record_id, guard_alive):
        identity, source, submission, existing = self._source(session_id, record_id)
        if existing:
            return identity, source, submission, existing
        rejected = self.rejections.get(submission.source_key, identity)
        if rejected:
            error = PostingStopped(rejected['reason_code'], rejected['box_code'])
            error.feedback = self.feedback.apply(session_id, identity, submission, source, guard_alive)
            raise error
        self.repository.operations.tasks.enqueue(submission)
        try:
            snapshot = self.access.snapshot(identity, submission.boxes, submission.action)
            reservation, outbound_sources = self._positions(submission, snapshot)
            plan = build_posting_plan(submission, field_text(source['fields'].get('流水号')), snapshot,
                                      self.access.tables, reservation, outbound_sources, int(time.time() * 1000))
            self.access.validate_plan(identity, plan)
            guard_alive()
            prepared = self.repository.prepare(identity, submission, plan)
        except PostingStopped as error:
            self.repository.validation_rejected(identity, submission, error.code)
            if error.code in REASONS:
                try:
                    error.feedback = self.feedback.apply(session_id, identity, submission, source, guard_alive, error)
                except Exception:
                    # 无法确认授权或远端状态时保留预占；不掩盖原始业务拒绝原因。
                    error.feedback = {'state': 'UNAVAILABLE', 'inventory_posted': False, 'position_released': False}
            raise
        return identity, source, submission, prepared

    def status(self, session_id, record_id):
        identity, _, submission, existing = self._source(session_id, record_id, query_only=True)
        rejection = self.rejections.get(submission.source_key, identity) if not existing else None
        if rejection:
            return {'found': True, 'state': 'VALIDATION_REJECTED', 'inventory_posted': False,
                    'source_record_id': record_id, 'action': submission.action,
                    'feedback': self.rejections.summary(rejection)}
        return self.repository.summary(submission.source_key)

    def _positions(self, submission, snapshot):
        db_store = self.repository.operations
        with db_store.connection() as db:
            if submission.action in ('IN', 'MOVE'):
                reservations = db.execute('''SELECT * FROM finding_assistant.position_reservations
                    WHERE app_id=%s AND base_token=%s AND table_id=%s AND flow_record_id=%s''',
                    (db_store.app_id, self.repository.base, self.repository.scan_table, submission.source_record_id)).fetchall()
                if len(reservations) != 1:
                    raise PostingStopped('FLOW_RESERVATION_NOT_UNIQUE')
                return reservations[0], {}
            result = {}
            for box in snapshot['boxes']:
                fields = box['fields']
                if fields['状态'] not in ('在库', '在托'):
                    continue
                links, suffix = fields['行'], fields['位置码']
                if len(links) != 1:
                    raise PostingStopped('HISTORICAL_POSITION_NOT_TAKEN_OVER')
                if not suffix:
                    tracked = db.execute('''SELECT 1 FROM finding_assistant.position_box_claims c
                        JOIN finding_assistant.position_reservations p USING(reservation_id)
                        WHERE c.base_token=%s AND c.box_table_id=%s AND c.box_record_id=%s
                        AND p.state='OCCUPIED' LIMIT 1''',
                        (self.repository.base,self.repository.box_table,box['record_id'])).fetchone()
                    seen = db.execute('''SELECT 1 FROM finding_assistant.inventory_transactions
                        WHERE base_token=%s AND box_table_id=%s AND box_record_id=%s AND state='POSTED' LIMIT 1''',
                        (self.repository.base,self.repository.box_table,box['record_id'])).fetchone()
                    if tracked or seen:
                        raise PostingStopped('OUTBOUND_POSITION_NOT_TRACKED')
                    continue

                rows = db.execute('''SELECT reservation_id,state FROM finding_assistant.position_reservations
                    WHERE base_token=%s AND box_table_id=%s AND row_table_id=%s AND target_row_record_id=%s
                    AND position_code=%s AND state='OCCUPIED' ''',
                    (self.repository.base, self.repository.box_table, self.repository.row_table, links[0], suffix)).fetchall()
                if len(rows) != 1:
                    raise PostingStopped('OUTBOUND_POSITION_NOT_TRACKED')
                members = sorted(self.positions._members(db, rows[0]['reservation_id']))
                if box['record_id'] not in members:
                    raise PostingStopped('OUTBOUND_BATCH_MEMBER_MISMATCH')
                result[box['record_id']] = {'reservation_id': str(rows[0]['reservation_id']), 'member_ids': members,
                    'row_record_id': links[0], 'position_code': suffix}
            return None, result

    @timed('inventory_execute')
    def execute(self, session_id, record_id):
        # 同步执行与排队后执行均在开始写入前复核，任务不继承提交时的远端身份结果。
        verified_authorize(self.gate, session_id, 'QUERY')
        # 复用刚完成准备阶段的来源上下文；每次写入前的实时来源/位置复核仍保留。
        identity, _, submission, row = self._prepare_context(session_id, record_id)
        identity = self.gate.authorize(session_id, submission.action)
        plan, key = row['plan'], submission.source_key
        if row['state'] == 'SUCCEEDED':
            return self.repository.summary(key)
        self.access.validate_plan(identity, plan)
        with self.repository.lease(key) as owner:
            if owner is None:
                return self.repository.summary(key)
            try:
                self.access.verify_rows(identity, plan)
                if plan.get('version',1)>=3:
                    from .bulk_inventory import BulkInventory
                    BulkInventory(self).run(identity,plan,owner)
                else:
                    for stored in self.repository.steps(key):
                        step = stored['specification']
                        if step['kind'] == 'STATUS':
                            self._verify_all(identity, plan)
                            self._confirm_positions(identity, plan)
                            self.repository.positions_confirmed(key, owner)
                        if stored['state'] != 'CONFIRMED':
                            self._step(identity, plan, stored, owner)
                self.repository.finish(key, owner)
            except Exception as error:
                code = error.code if isinstance(error, PostingStopped) else 'EXECUTION_UNCONFIRMED'
                self.repository.stop(key, owner, code)
                raise
        return self.repository.summary(key)

    def _guard_source(self, identity, plan):
        self.access.verify_rows(identity, plan)
        source = self.access.source(identity, plan['source_record_id'])
        if field_text(source['fields'].get('处理状态')) != '待处理':
            raise PostingStopped('SOURCE_STATUS_CHANGED')
        submission = normalize_record(self.repository.base, self.repository.scan_table, source)
        if not submission or submission.fingerprint != plan['fingerprint']:
            raise PostingStopped('SOURCE_INPUT_CHANGED')

    def _step(self, identity, plan, stored, owner):
        step, key = stored['specification'], plan['source_key']
        if step['kind'] == 'LEDGER':
            records = self.access.ledger(identity, step)
            if len(records) > 1:
                raise PostingStopped('REMOTE_LEDGER_DUPLICATE')
            current = records[0] if records else None
        else:
            current = self.access.get(identity, step)
        matched = current is not None and self.access.verify(current, step['after'], step['types'])
        if matched:
            if stored['remote_record_id'] and stored['remote_record_id'] != current['record_id']:
                raise PostingStopped('REMOTE_RECORD_ID_CHANGED')
            if stored['state'] == 'PENDING' and step['kind'] != 'LEDGER':
                # 没有本地写意图时，不能把别的程序恰好写成目标值当作本任务已完成。
                if not self.access.verify(current, step['before'], step['types']):
                    raise PostingStopped('UNOWNED_REMOTE_CHANGE')
                self._guard_source(identity, plan)
            self.repository.confirm(key, owner, step['ordinal'], current['record_id'])
            return
        if stored['state'] != 'PENDING':
            raise PostingStopped('REMOTE_WRITE_RECONCILIATION_REQUIRED')
        if current is not None and (step['kind'] == 'LEDGER' or not self.access.verify(current, step['before'], step['types'])):
            raise PostingStopped('REMOTE_PRECONDITION_CHANGED')
        self._guard_source(identity, plan)
        if step['kind'] in ('LEDGER', 'DETAIL'):
            box_step = next(s for s in plan['steps'] if s['kind'] == 'BOX' and s['box_record_id'] == step['box_record_id'])
            if not self.access.verify(self.access.get(identity, box_step), box_step['after'], box_step['types']):
                raise PostingStopped('BOX_CHANGED_DURING_POSTING')
        self.repository.begin_step(key, owner, step['ordinal'])
        try:
            remote_id = self.access.write(identity, step)
            self.repository.response(key, owner, step['ordinal'], remote_id)
            observed = self.access.get(identity, step, remote_id)
            if not self.access.verify(observed, step['after'], step['types']):
                raise PostingStopped('REMOTE_POSTCONDITION_UNCONFIRMED')
            self.repository.confirm(key, owner, step['ordinal'], remote_id)
        except Exception as error:
            definitive = isinstance(error, AccessDenied) and not isinstance(error, AuthorizationUnavailable)
            self.repository.uncertain(key, owner, step['ordinal'], definitive)
            raise

    @timed('reconcile')
    def _verify_all(self, identity, plan):
        self.access.verify_rows(identity, plan)
        receipts = {s['ordinal']: s['remote_record_id'] for s in self.repository.steps(plan['source_key'])}
        # 仅合并本次最终核账阶段的独立记录读取，不跨写入步骤缓存。
        observed = {}
        for role in ('BOX', 'DETAIL'):
            ids = [s['record_id'] for s in plan['steps'] if s['kind'] == role]
            if role == 'BOX':
                ids.extend(s['record_id'] for s in plan['skipped'])
            observed[role] = self.access.get_many(identity, role, ids) if ids else {}
        ledger_rows = self.access.ledgers(identity, [s for s in plan['steps'] if s['kind'] == 'LEDGER'])
        for step in plan['steps']:
            if step['kind'] == 'STATUS':
                continue
            records = (ledger_rows[step['fields']['事务号']] if step['kind'] == 'LEDGER'
                       else [observed[step['kind']][step['record_id']]])
            if len(records) != 1 or not self.access.verify(records[0], step['after'], step['types']):
                raise PostingStopped('FINAL_POSTCONDITION_CHANGED')
            if receipts[step['ordinal']] != records[0]['record_id']:
                raise PostingStopped('REMOTE_RECORD_ID_CHANGED')
        for skipped in plan['skipped']:
            if not self.access.verify(observed['BOX'][skipped['record_id']], skipped['fields'], BOX_TYPES):
                raise PostingStopped('SKIPPED_BOX_CHANGED')

    @timed('reconcile')
    def _confirm_positions(self, identity, plan):
        evidence = 'inventory-execution:' + plan['source_key']
        if plan['position_reservation_id']:
            self.positions.confirm_posted(uuid.UUID(plan['position_reservation_id']), plan['source_record_id'],
                [t['box_record_id'] for t in plan['transactions']], evidence)
            self._confirm_departures(identity, plan.get('source_groups', []), evidence)
            return
        groups = {s['reservation_id']: s for s in plan['outbound_sources'].values()}
        if groups and all('row_record_id' in group for group in groups.values()):
            self._confirm_departures(identity, list(groups.values()), evidence)
            return
        for group in groups.values():
            members = group['member_ids']
            observed = self.access.get_many(identity, 'BOX', members)
            records = [observed[rid] for rid in members]
            all_empty = all(self.access.verify(r, {'状态': '已出库', '行': [], '位置码': ''}, BOX_TYPES) for r in records)
            if not all_empty:
                continue  # 部分出库保留原批次位置，不能按本流水完成就释放。
            with self.repository.operations.connection() as db:
                posted = {r['box_record_id'] for r in db.execute('''SELECT box_record_id
                    FROM finding_assistant.inventory_transactions WHERE source_position_id=%s AND action='OUT'
                    AND state='POSTED' ''', (uuid.UUID(group['reservation_id']),)).fetchall()}
            if set(members) <= posted:
                self.positions.confirm_empty(uuid.UUID(group['reservation_id']), members, evidence)


    def _confirm_departures(self, identity, groups, evidence):
        # 仅在全体历史成员离开来源、逐箱事务核实后冷却；部分搬动保持来源占用。
        for group in groups:
            members = group['member_ids']
            observed = self.access.get_many(identity, 'BOX', members)
            if any(self.access.verify(observed[rid], {'行': [group['row_record_id']],
                    '位置码':group['position_code']}, BOX_TYPES) for rid in members):
                continue
            with self.repository.operations.connection() as db:
                posted = {row['box_record_id'] for row in db.execute('''SELECT box_record_id
                    FROM finding_assistant.inventory_transactions WHERE source_position_id=%s AND state='POSTED' ''',
                    (uuid.UUID(group['reservation_id']),)).fetchall()}
            if set(members) <= posted:
                self.positions.confirm_empty(uuid.UUID(group['reservation_id']), members, evidence)
