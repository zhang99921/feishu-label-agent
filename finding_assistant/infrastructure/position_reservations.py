"""数据库原子分配组合位置，保存批次历史与逐箱认领；不执行飞书库存过账。"""
from collections import defaultdict
import hashlib
from types import SimpleNamespace
import uuid

from psycopg.types.json import Jsonb

from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.positions import PositionRejected, position_code, position_number
from finding_assistant.security.errors import AccessDenied


class PositionReservations:
    def __init__(self, store, base, scan_table, box_table, row_table):
        self.store, self.base, self.scan_table = store, base, scan_table
        self.box_table, self.row_table = box_table, row_table
        # 与旧整行预占器使用同一个锁域，防止新旧请求同时分配。
        self.lock_id = int.from_bytes(hashlib.sha256((base + ':' + row_table).encode()).digest()[:8],
                                      'big', signed=True)

    def _scope(self, key):
        return self.store.app_id, self.base, self.scan_table, key

    def _lock(self, db):
        db.execute("SET LOCAL lock_timeout='5s'")
        db.execute('SELECT pg_advisory_xact_lock(%s)', (self.lock_id,))

    @staticmethod
    def _check(row, identity, fingerprint):
        if row['open_id'] != identity.open_id or row['tenant_key'] != identity.tenant_key:
            raise AccessDenied('request key belongs to another identity')
        if row['input_fingerprint'] != fingerprint:
            raise Conflict('request key cannot be reused with different allocation input')
        # 完成、冷却或释放后仍可查询原流水；绝不因此重新分配新位置。
        return row

    def existing(self, identity, key, fingerprint):
        with self.store.connection() as db:
            row = db.execute('''SELECT * FROM finding_assistant.position_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone()
        return self._check(row, identity, fingerprint) if row else None

    def reserve(self, identity, key, fingerprint, fields, draft):
        with self.store.connection() as db:
            self._lock(db)
            current = db.execute('''SELECT * FROM finding_assistant.position_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone()
            if current:
                return self._check(current, identity, fingerprint)
            if db.execute('''SELECT 1 FROM finding_assistant.write_requests
                    WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone():
                raise Conflict('request key belongs to another submission')
            requested_ids = [box.record_id for box in draft.boxes]
            requested_codes = {box.box_code for box in draft.boxes}
            pending = db.execute('''SELECT 1 FROM finding_assistant.position_box_claims
                WHERE base_token=%s AND box_table_id=%s AND box_record_id=ANY(%s) AND active LIMIT 1''',
                (self.base, self.box_table, requested_ids)).fetchone()
            if pending:
                raise PositionRejected('BOX_OPERATION_PENDING', '本批有尚未确认完成的操作，请先核对原流水')
            executing = db.execute('''SELECT 1 FROM finding_assistant.inventory_transactions
                WHERE base_token=%s AND box_table_id=%s AND box_record_id=ANY(%s) AND active LIMIT 1''',
                (self.base, self.box_table, requested_ids)).fetchone()
            if executing:
                raise PositionRejected('BOX_EXECUTION_PENDING', '本批包含库存执行尚未收尾的箱子，请核对原任务')

            # 只有明确冷却且到期的组合位置可复用；UNKNOWN/RECORDED一直保留。
            db.execute('''UPDATE finding_assistant.position_reservations SET state='RELEASED',updated_at=clock_timestamp()
                WHERE base_token=%s AND row_table_id=%s AND state='COOLING' AND cooldown_until<=clock_timestamp()''',
                (self.base, self.row_table))
            occupied = db.execute('''SELECT * FROM finding_assistant.position_reservations
                WHERE base_token=%s AND row_table_id=%s AND state<>'RELEASED' ''',
                (self.base, self.row_table)).fetchall()
            legacy = db.execute('''SELECT target_row_record_id,target_location_code,payload
                FROM finding_assistant.location_reservations WHERE base_token=%s AND row_table_id=%s
                AND state<>'RELEASED' ''', (self.base, self.row_table)).fetchall()
            blocked_ids = set(draft.quarantined_rows) | {r['target_row_record_id'] for r in legacy}
            blocked_codes = {r['target_location_code'] for r in legacy}
            for old in legacy:
                claimed = {v for name, v in old['payload'].items() if name in {f'箱号{i}' for i in range(1, 37)}}
                if requested_codes & claimed:
                    raise PositionRejected('LEGACY_OPERATION_PENDING', '本批仍有旧行码预占，需先核账，不重新分配')

            batch_id, source_id = uuid.uuid4(), None
            sources = []
            member_cache = {}
            departed_cache = {}
            for original in draft.sources:
                source = dict(original)
                if not source['position_code']:
                    owned = db.execute('''SELECT 1 FROM finding_assistant.position_box_claims c
                        JOIN finding_assistant.position_reservations p USING(reservation_id)
                        WHERE c.base_token=%s AND c.box_table_id=%s AND c.box_record_id=%s
                        AND p.state='OCCUPIED' LIMIT 1''',
                        (self.base,self.box_table,source['box_record_id'])).fetchone()
                    seen = db.execute('''SELECT 1 FROM finding_assistant.inventory_transactions
                        WHERE base_token=%s AND box_table_id=%s AND box_record_id=%s AND state='POSTED' LIMIT 1''',
                        (self.base,self.box_table,source['box_record_id'])).fetchone()
                    if owned or seen:
                        raise PositionRejected('SOURCE_POSITION_CHANGED', '已有后台占用的箱子位置字段发生变化，请核账')
                    source.update(reservation_id=None, member_ids=[], legacy_row_only=True)
                else:
                    matches = [old for old in occupied if old['target_row_record_id'] == source['row_record_id']
                               and old['position_code'] == source['position_code'] and old['box_table_id'] == self.box_table]
                    if len(matches) != 1 or matches[0]['state'] != 'OCCUPIED':
                        raise PositionRejected('SOURCE_BATCH_NOT_TRACKED', '非空位置码未对应已确认占用，请核账')
                    previous = matches[0]
                    old_id = previous['reservation_id']
                    if old_id not in member_cache:
                        member_cache[old_id] = self._members(db, old_id)
                    members = member_cache[old_id]
                    if old_id not in departed_cache:
                        departed_cache[old_id] = {row['box_record_id'] for row in db.execute('''SELECT box_record_id
                            FROM finding_assistant.inventory_transactions WHERE source_position_id=%s AND state='POSTED' ''', (old_id,)).fetchall()}
                    current_members = members - departed_cache[old_id]
                    if (source['box_record_id'] not in current_members
                            or not set(source['observed_member_ids']) <= current_members):
                        raise PositionRejected('SOURCE_BATCH_MEMBERS_CHANGED', '箱表与后台位置成员不一致，请核账')
                    source.update(reservation_id=str(previous['reservation_id']), member_ids=sorted(members), legacy_row_only=False)
                sources.append(source)
            tracked = {source['reservation_id'] for source in sources}
            if sources and len(tracked) == 1 and None not in tracked:
                previous = next(old for old in occupied if str(old['reservation_id']) == sources[0]['reservation_id'])
                if set(requested_ids) == set(sources[0]['member_ids']):
                    batch_id, source_id = previous['batch_id'], previous['reservation_id']

            used = defaultdict(set)
            for row_id, number in draft.occupied:
                used[row_id].add(number)
            codes_to_ids = {row.location_code: row.record_id for row in draft.candidates}
            for old in occupied:
                used[old['target_row_record_id']].add(int(old['position_no']))
                if old['target_row_code'] in codes_to_ids:
                    used[codes_to_ids[old['target_row_code']]].add(int(old['position_no']))
            available = [row for row in draft.candidates
                         if row.record_id not in blocked_ids and row.location_code not in blocked_codes]
            if not available:
                raise PositionRejected('NO_VERIFIED_REGION', '所选仓库的区域均有未接管历史占用，暂不能安全分配')
            # 选择占用数最少的区域，再按行码排序；区域内分配最小空闲正整数。
            target = min(available, key=lambda row: (len(used[row.record_id]), row.location_code))
            number = 1
            while number in used[target.record_id]:
                number += 1
            suffix = position_code(number)
            payload = {**fields, '事件类型': '入库' if draft.action == 'IN' else '转仓', '位置码': suffix}
            if draft.action == 'IN':
                payload['行码'] = target.location_code
                if draft.sources:
                    source_codes = {source['row_code'] for source in sources}
                    if len(source_codes) == 1:
                        payload['来源区域'] = next(iter(source_codes))
            else:
                payload['目标区域'] = target.location_code
                source_codes = {source['row_code'] for source in sources}
                if len(source_codes) == 1:
                    payload['来源区域'] = next(iter(source_codes))
            reservation_id = uuid.uuid4()
            row = db.execute('''INSERT INTO finding_assistant.position_reservations
                (reservation_id,batch_id,app_id,base_token,table_id,request_key,box_table_id,row_table_id,
                 tenant_key,open_id,action,input_fingerprint,target_row_record_id,target_row_code,position_no,
                 position_code,target_warehouse,sources,payload,source_reservation_id,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'RESERVED') RETURNING *''',
                (reservation_id, batch_id, *self._scope(key), self.box_table, self.row_table,
                 identity.tenant_key, identity.open_id, draft.action, fingerprint, target.record_id, target.location_code,
                 number, suffix, draft.warehouse, Jsonb(sources), Jsonb(payload), source_id)).fetchone()
            for box in draft.boxes:
                db.execute('''INSERT INTO finding_assistant.position_box_claims
                    (reservation_id,base_token,box_table_id,box_record_id,box_code) VALUES(%s,%s,%s,%s,%s)''',
                    (reservation_id, self.base, self.box_table, box.record_id, box.box_code))
            self.store._audit(db, 'POSITION_RESERVE', 'RESERVED', identity, draft.action, key=key)
        return row

    def mark(self, identity, key, fingerprint, state, record_id=None):
        if state not in ('RECORDED', 'UNKNOWN', 'RELEASED'):
            raise ValueError('INVALID_POSITION_WRITE_STATE')
        with self.store.connection() as db:
            self._lock(db)
            row = db.execute('''SELECT * FROM finding_assistant.position_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s FOR UPDATE''', self._scope(key)).fetchone()
            if row is None:
                raise Conflict('position reservation missing')
            self._check(row, identity, fingerprint)
            if row['state'] not in ('RESERVED', 'UNKNOWN'):
                return  # 历史重放不能把已占用、已冷却或已释放记录倒退为RECORDED。
            if state == 'RECORDED' and (not isinstance(record_id, str) or not record_id):
                raise ValueError('FLOW_RECORD_REQUIRED')
            db.execute('''UPDATE finding_assistant.position_reservations SET state=%s,
                flow_record_id=COALESCE(%s,flow_record_id),updated_at=clock_timestamp() WHERE reservation_id=%s''',
                (state, record_id, row['reservation_id']))
            if state == 'RELEASED':
                db.execute('UPDATE finding_assistant.position_box_claims SET active=false WHERE reservation_id=%s',
                           (row['reservation_id'],))
            self.store._audit(db, 'POSITION_WRITE', state, identity, row['action'], key=key)

    @staticmethod
    def _members(db, reservation_id):
        return {r['box_record_id'] for r in db.execute(
            'SELECT box_record_id FROM finding_assistant.position_box_claims WHERE reservation_id=%s',
            (reservation_id,)).fetchall()}

    def _confirmation(self, db, reservation_id, box_record_ids, evidence):
        if (not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 512
                or not isinstance(box_record_ids, (list, tuple)) or not box_record_ids
                or any(not isinstance(r, str) or not r for r in box_record_ids)
                or len(box_record_ids) != len(set(box_record_ids))):
            raise ValueError('FULL_BATCH_CONFIRMATION_REQUIRED')
        self._lock(db)
        row = db.execute('''SELECT * FROM finding_assistant.position_reservations
            WHERE reservation_id=%s AND base_token=%s AND row_table_id=%s AND box_table_id=%s FOR UPDATE''',
            (reservation_id, self.base, self.row_table, self.box_table)).fetchone()
        if row is None or self._members(db, reservation_id) != set(box_record_ids):
            raise Conflict('full batch membership confirmation required')
        return row

    def confirm_posted(self, reservation_id, flow_record_id, box_record_ids, evidence):
        """仅供未来库存执行器在逐箱变更及事务核实后调用；没有对外HTTP入口。"""
        if not isinstance(flow_record_id, str) or not flow_record_id:
            raise ValueError('FLOW_RECORD_REQUIRED')
        with self.store.connection() as db:
            row = self._confirmation(db, reservation_id, box_record_ids, evidence)
            if row['flow_record_id'] != flow_record_id:
                raise Conflict('flow confirmation mismatch')
            if row['posting_evidence'] == evidence and row['state'] in ('OCCUPIED', 'COOLING', 'RELEASED'):
                return
            if row['state'] != 'RECORDED':
                raise Conflict('recorded flow must be verified before occupancy')
            if row['source_reservation_id']:
                source = db.execute('SELECT * FROM finding_assistant.position_reservations WHERE reservation_id=%s FOR UPDATE',
                                    (row['source_reservation_id'],)).fetchone()
                if source['state'] != 'OCCUPIED' or source['batch_id'] != row['batch_id']:
                    raise Conflict('source batch no longer occupied')
                self._cool(db, source['reservation_id'], evidence)
            db.execute('''UPDATE finding_assistant.position_reservations SET state='OCCUPIED',posting_evidence=%s,
                updated_at=clock_timestamp() WHERE reservation_id=%s''', (evidence, reservation_id))
            db.execute('UPDATE finding_assistant.position_box_claims SET active=false WHERE reservation_id=%s', (reservation_id,))
            self._audit_confirmation(db, row, 'OCCUPIED')

    def confirm_empty(self, reservation_id, box_record_ids, evidence):
        """整批离开且已完成外部核账后的内部回调；部分出库不能调用此方法释放。"""
        with self.store.connection() as db:
            row = self._confirmation(db, reservation_id, box_record_ids, evidence)
            if row['departure_evidence'] and row['state'] in ('COOLING', 'RELEASED'):
                return  # 并发的整批离开确认沿用第一份凭据与冷却时间，不重新起算。
            if row['state'] != 'OCCUPIED':
                raise Conflict('only confirmed occupied batch can leave')
            pending = db.execute('''SELECT 1 FROM finding_assistant.position_reservations
                WHERE (source_reservation_id=%s OR EXISTS (SELECT 1 FROM jsonb_array_elements(sources) s
                        WHERE s->>'reservation_id'=%s))
                AND state IN ('RESERVED','RECORDED','UNKNOWN') LIMIT 1''',
                (reservation_id, str(reservation_id))).fetchone()
            if pending:
                raise Conflict('source batch has a pending transfer')
            self._cool(db, reservation_id, evidence)
            self._audit_confirmation(db, row, 'COOLING')

    @staticmethod
    def _cool(db, reservation_id, evidence):
        db.execute('''UPDATE finding_assistant.position_reservations SET state='COOLING',
            cooldown_until=clock_timestamp()+interval '10 minutes',departure_evidence=%s,
            updated_at=clock_timestamp() WHERE reservation_id=%s''', (evidence, reservation_id))

    def _audit_confirmation(self, db, row, outcome):
        identity = SimpleNamespace(tenant_key=row['tenant_key'], open_id=row['open_id'])
        self.store._audit(db, 'POSITION_CONFIRM', outcome, identity, row['action'], key=str(row['request_key']))
