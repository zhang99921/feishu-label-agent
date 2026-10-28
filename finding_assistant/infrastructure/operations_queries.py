"""服务器运维的只读查询；不调用飞书，不解密令牌，不修改任务或写请求。"""
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
import uuid

from psycopg import sql

from .postgres_tasks import PostgresTasks
from .attention_cursor import scope_key, decode_cursor, encode_cursor

TASK_STATES = frozenset({'QUEUED', 'BLOCKED', 'RECONCILE'})
WRITE_STATES = frozenset({'PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'UNKNOWN'})


def json_scalar(value):
    """只转换查询结果中约定的类型，避免用任意对象的repr输出内部配置。"""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Decimal) and value.is_finite():
        # 数量保持十进制精度；JSON中输出字符串，避免浮点舍入。
        return str(value)
    raise TypeError('UNSUPPORTED_OPERATIONAL_RESULT')


def text_filter(value):
    if value is not None and (not isinstance(value, str) or not value.strip()
                              or len(value) > 512 or any(ord(c) < 32 for c in value)):
        raise ValueError('INVALID_INSPECTION_FILTER')
    return value


def request_filter(value):
    if value is None:
        return None
    try:
        parsed = uuid.UUID(value)
        if str(parsed) != value or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ValueError('UUID4_REQUEST_KEY_REQUIRED') from None
    return parsed


class OperationsQueries:
    """仅供已获服务器/数据库访问权限的维护人员使用，不是员工HTTP接口。"""

    def __init__(self, dsn):
        self.tasks = PostgresTasks(dsn)

    @contextmanager
    def connection(self):
        with self.tasks.connect() as connection:
            # 即使后续维护时写错SQL，数据库仍拒绝在本查询事务中更新数据。
            connection.execute('SET TRANSACTION READ ONLY')
            connection.execute("SET LOCAL statement_timeout = '5s'")
            connection.execute("SET LOCAL lock_timeout = '1s'")
            yield connection

    @staticmethod
    def _limit(value):
        if type(value) is not int or not 1 <= value <= 100:
            raise ValueError('INSPECTION_LIMIT_MUST_BE_1_TO_100')
        return value

    @staticmethod
    def _where(clauses):
        # 所有SQL片段由源码定义，用户筛选值只能通过参数传入。
        return sql.SQL(' WHERE ') + sql.SQL(' AND ').join(map(sql.SQL, clauses)) if clauses else sql.SQL('')

    @staticmethod
    def _page(rows, limit):
        return {'items': rows[:limit], 'has_more': len(rows) > limit, 'limit': limit,
                'read_only': True, 'inventory_posting_enabled': False}

    def rejections(self, *, app_id=None, base_token=None, record_id=None, state=None, before_id=None, limit=20):
        """查看本地回写回执及关联预占；不把本地CONFIRMED解释为当前远端仍一致。"""
        limit = self._limit(limit)
        if state is not None and state not in ('PENDING', 'RUNNING', 'UNKNOWN', 'REJECTED', 'CONFIRMED'):
            raise ValueError('INVALID_REJECTION_STATE')
        clauses, params = [], []
        for clause, value in [('r.app_id=%s', text_filter(app_id)), ('r.base_token=%s', text_filter(base_token)),
                              ('r.source_record_id=%s', text_filter(record_id)), ('r.state=%s', state),
                              ('r.rejection_id<%s', request_filter(before_id))]:
            if value is not None:
                clauses.append(clause)
                params.append(value)
        query = sql.SQL('''SELECT r.rejection_id,r.source_key,r.source_record_id,r.app_id,r.base_token,
            r.action,r.state,r.reason_code,r.box_code,r.note,r.remote_record_id,r.position_released,
            r.created_at,r.updated_at,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('reservation_id',p.reservation_id,
                'state',p.state,'row_code',p.target_row_code,'position_code',p.position_code))
                FROM finding_assistant.position_reservations p
                WHERE p.app_id=r.app_id AND p.base_token=r.base_token AND p.table_id=r.scan_table_id
                AND p.flow_record_id=r.source_record_id), '[]'::jsonb) AS reservations
            FROM finding_assistant.inventory_rejections r''') + self._where(clauses) + sql.SQL(
                ' ORDER BY r.rejection_id DESC LIMIT %s')
        with self.connection() as db:
            rows = db.execute(query, [*params, limit + 1]).fetchall()
        result = self._page(rows, limit)
        result['next_before_id'] = str(rows[limit - 1]['rejection_id']) if len(rows) > limit else None
        result['remote_state_verified'] = False
        return result

    def tasks_list(self, *, state=None, record_id=None, box_code=None, limit=20):
        limit = self._limit(limit)
        if state is not None and state not in TASK_STATES:
            raise ValueError('INVALID_TASK_STATE')
        clauses, params = [], []
        for clause, value in [('j.state = %s', state), ('j.source_record_id = %s', text_filter(record_id))]:
            if value is not None:
                clauses.append(clause)
                params.append(value)
        if text_filter(box_code) is not None:
            clauses.append('EXISTS (SELECT 1 FROM finding_assistant.scan_items i WHERE i.source_key=j.source_key AND i.box_code=%s)')
            params.append(box_code)
        query = sql.SQL('''SELECT j.source_key,j.source_record_id,j.action,j.state,j.state AS intake_state,
            e.state AS inventory_state,e.failure_code AS inventory_failure_code,
            j.payload->'errors' AS errors,j.payload->'warnings' AS warnings,j.created_at,j.updated_at,
            (SELECT count(*) FROM finding_assistant.scan_items i WHERE i.source_key=j.source_key) AS box_count
            FROM finding_assistant.scan_jobs j LEFT JOIN finding_assistant.inventory_executions e
            ON e.source_key=j.source_key''') + self._where(clauses) + sql.SQL(
                ' ORDER BY j.created_at DESC,j.source_key DESC LIMIT %s')
        with self.connection() as connection:
            rows = connection.execute(query, [*params, limit + 1]).fetchall()
        result = self._page(rows, limit)
        result['state_scope'] = 'INTAKE_REGISTRATION'
        result['inventory_state_scope'] = 'LOCAL_INVENTORY_EXECUTION'
        return result

    def task(self, source_key):
        source_key = text_filter(source_key)
        if source_key is None:
            raise ValueError('SOURCE_KEY_REQUIRED')
        with self.connection() as connection:
            # 同一事务读取任务、箱号、事件，避免核对到不同时间的快照。
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            task = connection.execute('''SELECT j.source_key,j.source_record_id,j.action,j.state,
                j.state AS intake_state,e.state AS inventory_state,e.failure_code AS inventory_failure_code,
                j.payload->'errors' AS errors,j.payload->'warnings' AS warnings,
                j.created_at,j.updated_at FROM finding_assistant.scan_jobs j
                LEFT JOIN finding_assistant.inventory_executions e ON e.source_key=j.source_key
                WHERE j.source_key=%s''',
                (source_key,)).fetchone()
            if task is None:
                return {'found': False, 'task': None, 'read_only': True, 'inventory_posting_enabled': False}
            boxes = connection.execute('''SELECT position,box_code FROM finding_assistant.scan_items
                WHERE source_key=%s ORDER BY position''', (source_key,)).fetchall()
            events = connection.execute('''SELECT id,event_code,recorded_at FROM finding_assistant.scan_job_events
                WHERE source_key=%s ORDER BY id DESC LIMIT 101''', (source_key,)).fetchall()
        return {'found': True, 'task': task, 'boxes': boxes, 'events': events[:100],
                'events_truncated': len(events) > 100, 'read_only': True, 'inventory_posting_enabled': False}

    def writes(self, *, state=None, app_id=None, request_key=None, limit=20):
        limit = self._limit(limit)
        if state is not None and state not in WRITE_STATES:
            raise ValueError('INVALID_WRITE_STATE')
        clauses, params = [], []
        for clause, value in [('state=%s', state), ('app_id=%s', text_filter(app_id)),
                              ('request_key=%s', request_filter(request_key))]:
            if value is not None:
                clauses.append(clause)
                params.append(value)
        # 不选payload/response；响应可能含业务原文，且状态排查不需要整个请求体。
        query = sql.SQL('''SELECT app_id,base_token,table_id,request_key,tenant_key,open_id,action,
            state,record_id,failure_code,created_at,updated_at FROM finding_assistant.write_requests''')
        query += self._where(clauses) + sql.SQL(''' ORDER BY updated_at DESC,app_id,base_token,
            table_id,request_key LIMIT %s''')
        with self.connection() as connection:
            rows = connection.execute(query, [*params, limit + 1]).fetchall()
        return self._page(rows, limit)

    def positions(self, *, app_id=None, request_key=None, batch_id=None, base_token=None,
                  row_code=None, position_code=None, state=None, limit=20):
        """只读追踪组合位置、原批次和流水；不提供强制释放或手动完成。"""
        limit = self._limit(limit)
        if state is not None and state not in ('RESERVED', 'RECORDED', 'UNKNOWN', 'OCCUPIED', 'COOLING', 'RELEASED'):
            raise ValueError('INVALID_POSITION_STATE')
        clauses, params = [], []
        for column, value in (
            ('p.app_id', text_filter(app_id)), ('p.request_key', request_filter(request_key)),
            ('p.batch_id', request_filter(batch_id)), ('p.base_token', text_filter(base_token)),
            ('p.target_row_code', text_filter(row_code)), ('p.position_code', text_filter(position_code)), ('p.state', state),
        ):
            if value is not None:
                clauses.append(column + '=%s')
                params.append(value)
        query = sql.SQL('''SELECT p.reservation_id,p.batch_id,p.app_id,p.base_token,p.table_id,p.request_key,
            p.action,p.target_row_code,p.position_code,p.target_warehouse,p.source_reservation_id,
            p.state,p.flow_record_id,p.cooldown_until,p.created_at,p.updated_at,
            (SELECT count(*) FROM finding_assistant.position_box_claims c
             WHERE c.reservation_id=p.reservation_id) box_count
            FROM finding_assistant.position_reservations p''')
        query += self._where(clauses) + sql.SQL(' ORDER BY p.created_at DESC,p.reservation_id LIMIT %s')
        with self.connection() as db:
            rows = db.execute(query, [*params, limit + 1]).fetchall()
        return self._page(rows, limit)

    def audit(self, *, app_id=None, request_key=None, outcome=None, before_id=None, limit=20):
        limit = self._limit(limit)
        if before_id is not None and (type(before_id) is not int or not 1 <= before_id <= 9223372036854775807):
            raise ValueError('INVALID_AUDIT_CURSOR')
        clauses, params = [], []
        for clause, value in [('app_id=%s', text_filter(app_id)), ('request_key=%s', request_filter(request_key)),
                              ('outcome=%s', text_filter(outcome)), ('id<%s', before_id)]:
            if value is not None:
                clauses.append(clause)
                params.append(value)
        query = sql.SQL('''SELECT id,app_id,tenant_key,open_id,event_type,outcome,action,
            permission,request_key,recorded_at FROM finding_assistant.audit_events''')
        query += self._where(clauses) + sql.SQL(' ORDER BY id DESC LIMIT %s')
        with self.connection() as connection:
            rows = connection.execute(query, [*params, limit + 1]).fetchall()
        page = self._page(rows, limit)
        page['next_before_id'] = page['items'][-1]['id'] if page['has_more'] else None
        return page

    def executions(self, *, app_id=None, record_id=None, state=None, box_code=None, limit=20):
        """查询实际执行进度；不返回完整计划，不提供重置/强制完成入口。"""
        limit = self._limit(limit)
        if state is not None and state not in ('PREPARED', 'RUNNING', 'RECONCILE', 'SUCCEEDED'):
            raise ValueError('INVALID_EXECUTION_STATE')
        clauses, params = [], []
        for column, value in (('e.app_id', text_filter(app_id)), ('e.source_record_id', text_filter(record_id)),
                              ('e.state', state)):
            if value is not None:
                clauses.append(column + '=%s')
                params.append(value)
        if text_filter(box_code) is not None:
            clauses.append('EXISTS (SELECT 1 FROM finding_assistant.inventory_transactions t WHERE t.source_key=e.source_key AND t.box_code=%s)')
            params.append(box_code)
        query = sql.SQL('''SELECT e.source_key,e.execution_id,e.app_id,e.base_token,e.source_record_id,e.action,e.state,
            e.failure_code,e.position_confirmed,e.created_at,e.updated_at,
            (SELECT count(*) FROM finding_assistant.inventory_transactions t WHERE t.source_key=e.source_key) box_count,
            (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key AND s.state='CONFIRMED') confirmed_steps,
            (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key) step_count
            FROM finding_assistant.inventory_executions e''')
        query += self._where(clauses) + sql.SQL(' ORDER BY e.updated_at DESC,e.source_key LIMIT %s')
        with self.connection() as db:
            rows = db.execute(query, [*params, limit + 1]).fetchall()
        return self._page(rows, limit)

    def attention(self, *, app_id, base_token=None, min_age_seconds=300, limit=20, cursor=None):
        """只读候选清单；时间阈值不是失活证据，不据此续跑或释放占用。"""
        limit = self._limit(limit)
        app_id, base_token = text_filter(app_id), text_filter(base_token)
        if app_id is None:
            raise ValueError('APP_ID_REQUIRED')
        if type(min_age_seconds) is not int or not 1 <= min_age_seconds <= 86400:
            raise ValueError('ATTENTION_AGE_MUST_BE_1_TO_86400')
        scope = scope_key(app_id,base_token,min_age_seconds)
        page = decode_cursor(cursor,scope) if cursor is not None else None
        with self.connection() as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            now = db.execute('SELECT now() as as_of').fetchone()['as_of']
            as_of = page['as_of'] if page else now
            if as_of > now:
                raise ValueError('INVALID_ATTENTION_CURSOR')
            clauses = ["e.app_id=%s", "e.state IN ('PREPARED','RUNNING','RECONCILE')",
                "e.created_at<=%s", "e.updated_at<=%s",
                "(e.state='RECONCILE' OR e.updated_at<=%s-(%s * interval '1 second'))"]
            params = [app_id,as_of,as_of,as_of,min_age_seconds]
            if base_token is not None:
                clauses.append('e.base_token=%s');params.append(base_token)
            where = self._where(clauses)
            counts = db.execute(sql.SQL('SELECT e.state,count(*) count FROM finding_assistant.inventory_executions e') +
                                where + sql.SQL(' GROUP BY e.state'), params).fetchall()
            if page:
                clauses.append("(CASE WHEN e.state='RECONCILE' THEN 0 ELSE 1 END,e.updated_at,e.source_key)>(%s,%s,%s)")
                params.extend([page['priority'],page['updated_at'],page['source_key']])
            query = sql.SQL('''SELECT e.source_key,e.execution_id,e.source_record_id,e.action,e.state,
                e.failure_code,e.position_confirmed,e.updated_at,
                GREATEST(0,extract(epoch FROM now()-e.updated_at)::bigint) age_seconds,
                (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key) step_count,
                (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key AND s.state='CONFIRMED') confirmed_steps,
                (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key AND s.state='UNKNOWN') unknown_steps,
                (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key AND s.state='RUNNING') running_steps,
                (SELECT count(*) FROM finding_assistant.inventory_steps s WHERE s.source_key=e.source_key AND s.state='REJECTED') rejected_steps
                FROM finding_assistant.inventory_executions e''') + self._where(clauses) + sql.SQL(
                " ORDER BY CASE WHEN e.state='RECONCILE' THEN 0 ELSE 1 END,e.updated_at,e.source_key LIMIT %s")
            rows = db.execute(query, [*params,limit+1]).fetchall()
        for row in rows:
            if row['unknown_steps']:
                advice = 'VERIFY_REMOTE_RESULT'
                message = '先核对远端记录及回执；不能直接重发写入或释放位置。'
            elif row['running_steps']:
                advice = 'CHECK_ACTIVE_WRITE'
                message = '步骤已有写入意图，先核实进程、锁及远端结果；不能按超时认定失败。'
            elif row['rejected_steps']:
                advice = 'REVIEW_DENIED_OPERATION'
                message = '检查权限及被拒步骤，保留已有事务和占用，由负责人确认后处理。'
            elif row['state'] == 'RECONCILE':
                advice = 'REVIEW_RECONCILIATION'
                message = '查看执行详情和故障码，确认库存、事务账与位置收尾的一致性。'
            elif row['state'] == 'RUNNING':
                advice = 'CHECK_EXECUTOR'
                message = '确认执行进程及数据库锁；运行较久不等于卡死，不自动启动另一执行者。'
            else:
                advice = 'CHECK_DISPATCH'
                message = '确认任务是否仍在队列；若进程已重启，由原操作人重新提交同一流水。'
            row['next_check'] = advice
            row['guidance'] = message
        result = self._page(rows, limit)
        result.update(counts={row['state']:row['count'] for row in counts},
                      min_age_seconds=min_age_seconds, remote_state_verified=False,
                      process_state_verified=False, automatic_recovery=False,
                      app_id_filter=app_id, base_token_filter=base_token,
                      as_of=as_of, pagination_mode='KEYSET_AS_OF', stable_snapshot=False,
                      next_cursor=encode_cursor(scope,as_of,result['items'][-1]) if result['has_more'] else None,
                      truncated=result['has_more'])
        return result

    def execution(self, source_key):
        source_key = text_filter(source_key)
        if source_key is None:
            raise ValueError('SOURCE_KEY_REQUIRED')
        with self.connection() as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            row = db.execute('''SELECT source_key,execution_id,app_id,base_token,source_record_id,action,state,
                failure_code,position_confirmed,created_at,updated_at FROM finding_assistant.inventory_executions
                WHERE source_key=%s''', (source_key,)).fetchone()
            if row is None:
                return {'found': False, 'read_only': True, 'inventory_posting_enabled': False}
            steps = db.execute('''SELECT ordinal,kind,box_record_id,state,remote_record_id,failure_code,confirmed_at
                FROM finding_assistant.inventory_steps WHERE source_key=%s ORDER BY ordinal''', (source_key,)).fetchall()
            transactions = db.execute('''SELECT transaction_id,box_record_id,box_code,action,document_reference,
                transaction_no,quantity,source_position_id,target_position_id,state,active,remote_record_id,posted_at
                FROM finding_assistant.inventory_transactions WHERE source_key=%s ORDER BY box_code''', (source_key,)).fetchall()
        return {'found': True, 'execution': row, 'steps': steps, 'transactions': transactions,
                'read_only': True, 'inventory_posting_enabled': False}
