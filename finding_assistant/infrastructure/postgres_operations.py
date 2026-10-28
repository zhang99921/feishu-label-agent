"""持久会话、一次性 OAuth 挑战、写请求与审计；连接信息和令牌不进入日志。"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid

from cryptography.fernet import Fernet, InvalidToken
import psycopg
from psycopg.types.json import Jsonb

from .postgres_tasks import PostgresTasks
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.security.login import UserSession, AuthenticationError, IdentityUnavailable, REFRESH_MARGIN_SECONDS
from finding_assistant.application.workflow import Conflict
from .performance import span


def moment(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


class PostgresOperations:
    def __init__(self, dsn, app_id, encryption_key):
        if not app_id:
            raise ValueError('APP_ID_REQUIRED')
        self.tasks, self.app_id = PostgresTasks(dsn), app_id
        try:
            self.cipher = Fernet(encryption_key)
        except (ValueError, TypeError):
            raise ValueError('VALID_TOKEN_ENCRYPTION_KEY_REQUIRED') from None

    @contextmanager
    def connection(self):
        with span('postgresql'):
            try:
                with self.tasks.connect() as c:
                    yield c
            except (psycopg.Error, InvalidToken):
                raise AuthorizationUnavailable('internal operational database unavailable') from None

    def ready(self):
        try:
            self.tasks.ready()
        except (psycopg.Error, ValueError):
            raise AuthorizationUnavailable('operational database or migration unavailable') from None

    def put_challenge(self, key, value):
        with self.connection() as c:
            c.execute('''INSERT INTO finding_assistant.oauth_challenges
                (app_id,state_hash,binding_hash,verifier_cipher,expires_at) VALUES(%s,%s,%s,%s,%s)''',
                (self.app_id,key,value['binding'],self.cipher.encrypt(value['verifier'].encode()),moment(value['expires'])))

    def consume_challenge(self, key, binding, now):
        with self.connection() as c:
            row=c.execute('''DELETE FROM finding_assistant.oauth_challenges
                WHERE app_id=%s AND state_hash=%s AND binding_hash=%s AND expires_at>%s
                RETURNING verifier_cipher''',(self.app_id,key,binding,moment(now))).fetchone()
            return {'verifier':self.cipher.decrypt(bytes(row['verifier_cipher'])).decode()} if row else None

    def put_session(self, key, session):
        with self.connection() as c:
            c.execute('''INSERT INTO finding_assistant.app_users(app_id,tenant_key,open_id) VALUES(%s,%s,%s)
                ON CONFLICT(app_id,tenant_key,open_id) DO UPDATE SET last_login_at=now()''',
                (self.app_id,session.tenant_key,session.open_id))
            c.execute('''INSERT INTO finding_assistant.user_sessions
                (app_id,session_hash,tenant_key,open_id,access_token_cipher,expires_at,access_token_expires_at,
                 refresh_token_cipher,refresh_token_expires_at,token_scopes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (self.app_id,key,session.tenant_key,session.open_id,self.cipher.encrypt(session.access_token.encode()),
                 moment(session.expires_at),moment(session.access_expires_at or session.expires_at),
                 self.cipher.encrypt(session.refresh_token.encode()) if session.refresh_token else None,
                 moment(session.refresh_expires_at) if session.refresh_expires_at is not None else None,list(session.scopes)))
            self._audit(c,'LOGIN','ALLOWED',session)

    def get_session(self, key, now):
        with self.connection() as c:
            row=c.execute('''SELECT *
                FROM finding_assistant.user_sessions WHERE app_id=%s AND session_hash=%s
                AND revoked_at IS NULL AND expires_at>%s AND refresh_state='ACTIVE' ''',(self.app_id,key,moment(now))).fetchone()
            if row:
                return self._session_value(row)

    def _session_value(self, row):
        return UserSession(row['open_id'], row['tenant_key'], row['expires_at'].timestamp(),
            self.cipher.decrypt(bytes(row['access_token_cipher'])).decode(),
            (row['access_token_expires_at'] or row['expires_at']).timestamp(),
            self.cipher.decrypt(bytes(row['refresh_token_cipher'])).decode() if row['refresh_token_cipher'] else None,
            row['refresh_token_expires_at'].timestamp() if row['refresh_token_expires_at'] else None,
            tuple(row['token_scopes']))

    def session_for_request(self, key, now, renew, clock=None):
        """先持久认领一次刷新，再调用外部接口；并发、重启和未知结果均不重复消耗旧凭据。"""
        attempt = uuid.uuid4()
        with self.connection() as c:
            c.execute("SET LOCAL lock_timeout='5s'")
            row = c.execute('''SELECT * FROM finding_assistant.user_sessions
                WHERE app_id=%s AND session_hash=%s AND revoked_at IS NULL AND expires_at>%s FOR UPDATE''',
                (self.app_id, key, moment(now))).fetchone()
            if not row:
                return None
            if row['refresh_state'] == 'UNKNOWN':
                raise AuthenticationError('refresh result unconfirmed; sign in again')
            if row['refresh_state'] == 'REFRESHING':
                # 崩溃/长时间无结果的认领同样不重放；不能猜测一次性凭据是否已经消耗。
                if row['refresh_started_at'].timestamp() + 120 <= now:
                    raise AuthenticationError('refresh interrupted; sign in again')
                raise IdentityUnavailable('session refresh already in progress')
            session = self._session_value(row)
            access_deadline = session.access_expires_at
            if not session.refresh_token:
                if access_deadline <= now:
                    raise AuthenticationError('access token expired; sign in again')
                return session
            if access_deadline > now + REFRESH_MARGIN_SECONDS:
                return session
            if not session.refresh_expires_at or session.refresh_expires_at <= now:
                raise AuthenticationError('refresh credentials expired; sign in again')
            c.execute('''UPDATE finding_assistant.user_sessions SET refresh_state='REFRESHING',
                refresh_attempt_id=%s,refresh_started_at=%s WHERE app_id=%s AND session_hash=%s''',
                (attempt, moment(now), self.app_id, key))
            self._audit(c, 'TOKEN_REFRESH', 'RUNNING', session)
        try:
            updated = renew(session, now)
        except AuthenticationError:
            self._refresh_failed(key, attempt, session, definitive=True)
            raise
        except Exception:
            self._refresh_failed(key, attempt, session, definitive=False)
            raise IdentityUnavailable('refresh result unconfirmed; sign in again') from None
        completed_at = (clock or time.time)()
        if (updated.open_id != session.open_id or updated.tenant_key != session.tenant_key or
                updated.expires_at != session.expires_at or updated.expires_at <= completed_at or
                not updated.access_expires_at or updated.access_expires_at <= completed_at or
                not updated.refresh_expires_at or updated.refresh_expires_at <= completed_at):
            self._refresh_failed(key, attempt, session, definitive=True)
            raise AuthenticationError('session expired or changed during refresh')
        with self.connection() as c:
            c.execute("SET LOCAL lock_timeout='5s'")
            # 注销后不得被正在结束的刷新复活；绝对会话到期时间保持原值。
            changed = c.execute('''UPDATE finding_assistant.user_sessions SET access_token_cipher=%s,
                access_token_expires_at=%s,refresh_token_cipher=%s,refresh_token_expires_at=%s,
                refresh_state='ACTIVE',refresh_attempt_id=NULL,refresh_started_at=NULL
                WHERE app_id=%s AND session_hash=%s AND refresh_state='REFRESHING' AND refresh_attempt_id=%s
                AND revoked_at IS NULL AND expires_at>%s RETURNING session_hash''',
                (self.cipher.encrypt(updated.access_token.encode()),moment(updated.access_expires_at),
                 self.cipher.encrypt(updated.refresh_token.encode()),moment(updated.refresh_expires_at),
                 self.app_id,key,attempt,moment(completed_at))).fetchone()
            if not changed:
                raise AuthenticationError('session revoked during refresh')
            self._audit(c, 'TOKEN_REFRESH', 'SUCCEEDED', updated)
        return updated

    def _refresh_failed(self, key, attempt, session, *, definitive):
        with self.connection() as c:
            if definitive:
                changed = c.execute('''UPDATE finding_assistant.user_sessions SET revoked_at=now(),
                    access_token_cipher=%s,refresh_token_cipher=NULL,refresh_state='UNKNOWN'
                    WHERE app_id=%s AND session_hash=%s AND refresh_attempt_id=%s AND revoked_at IS NULL''',
                    (b'', self.app_id, key, attempt)).rowcount
            else:
                changed = c.execute('''UPDATE finding_assistant.user_sessions SET refresh_state='UNKNOWN'
                    WHERE app_id=%s AND session_hash=%s AND refresh_attempt_id=%s AND revoked_at IS NULL''',
                    (self.app_id, key, attempt)).rowcount
            if changed:
                self._audit(c, 'TOKEN_REFRESH', 'REJECTED' if definitive else 'UNKNOWN', session)

    def revoke_session(self, key):
        with self.connection() as c:
            row=c.execute('''UPDATE finding_assistant.user_sessions SET revoked_at=now(),access_token_cipher=%s,
                refresh_token_cipher=NULL
                WHERE app_id=%s AND session_hash=%s AND revoked_at IS NULL RETURNING tenant_key,open_id''',
                (b'',self.app_id,key)).fetchone()
            if row:
                c.execute('''INSERT INTO finding_assistant.audit_events(app_id,tenant_key,open_id,event_type,outcome)
                    VALUES(%s,%s,%s,'LOGOUT','REVOKED')''',(self.app_id,row['tenant_key'],row['open_id']))

    def _audit(self, c, event, outcome, identity=None, action=None, permission=None, key=None):
        c.execute('''INSERT INTO finding_assistant.audit_events
            (app_id,tenant_key,open_id,event_type,outcome,action,permission,request_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',
            (self.app_id,getattr(identity,'tenant_key',None),getattr(identity,'open_id',None),event,outcome,action,permission,key))

    def audit_permission(self, identity, action, permission, outcome):
        with self.connection() as c:
            self._audit(c,'AUTHORIZE',outcome,identity,action,permission)

    def audit_http_rejection(self, request_id, code):
        """HTTP拒绝仅记录固定码和服务端关联号；未验证身份不归因给请求自报用户。"""
        if code not in ('INVALID_REQUEST', 'BUSINESS_RULE_REJECTED', 'OPERATION_CONFLICT'):
            raise ValueError('INVALID_HTTP_REJECTION_CODE')
        correlation = uuid.UUID(request_id)
        with self.connection() as c:
            c.execute("SET LOCAL statement_timeout='2s'")
            c.execute("SET LOCAL lock_timeout='2s'")
            self._audit(c, 'HTTP_REJECTED', code, key=correlation)

    def audit_sql_query(self, identity, outcome):
        if outcome not in ('ALLOWED', 'DENIED', 'UNAVAILABLE'):
            raise ValueError('INVALID_QUERY_AUDIT_OUTCOME')
        with self.connection() as c:
            self._audit(c, 'SQL_QUERY', outcome, identity, 'QUERY', identity.permission)

    def execute(self, identity, base, table, key, action, payload, send):
        digest=hashlib.sha256(json.dumps({'action':action,'fields':payload},ensure_ascii=False,sort_keys=True).encode()).hexdigest()
        target=(self.app_id,base,table,key)
        # 先提交请求身份，再进行外部写入。崩溃后 RUNNING 不会被自动重发。
        with self.connection() as c:
            c.execute('''INSERT INTO finding_assistant.write_requests
                (app_id,base_token,table_id,request_key,tenant_key,open_id,action,fingerprint,payload,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING') ON CONFLICT DO NOTHING''',
                (*target,identity.tenant_key,identity.open_id,action,digest,Jsonb(payload)))
        with self.connection() as c:
            row=c.execute('''SELECT * FROM finding_assistant.write_requests
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s FOR UPDATE''',target).fetchone()
            if row['tenant_key']!=identity.tenant_key or row['open_id']!=identity.open_id:
                raise AccessDenied('request key belongs to another identity')
            if row['fingerprint']!=digest:
                raise Conflict('request key cannot be reused with different input')
            if row['state']=='SUCCEEDED':
                self._audit(c,'WRITE_REPLAY','SUCCEEDED',identity,action,key=key)
                return row['response'] or {'record_id':row['record_id']}
            if row['state']!='PENDING':
                raise Conflict('write pending or uncertain; operator reconciliation required')
            c.execute('''UPDATE finding_assistant.write_requests SET state='RUNNING',updated_at=now()
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''',target)
            self._audit(c,'WRITE','RUNNING',identity,action,key=key)
        try:
            result=send()
            if not isinstance(result,dict) or not isinstance(result.get('record_id'),str):
                raise AuthorizationUnavailable('remote write result unconfirmed')
            with self.connection() as c:
                c.execute('''UPDATE finding_assistant.write_requests SET state='SUCCEEDED',response=%s,
                    record_id=%s,updated_at=now() WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''',
                    (Jsonb(result),result['record_id'],*target))
                self._audit(c,'WRITE','SUCCEEDED',identity,action,key=key)
            return result
        except Exception as error:
            # AuthorizationUnavailable继承AccessDenied，但不代表飞书明确拒绝写入。
            # 结果不确定时保持UNKNOWN，禁止运维将其当作确定未写入后重新建单。
            state = ('FAILED' if isinstance(error, AccessDenied)
                     and not isinstance(error, AuthorizationUnavailable) else 'UNKNOWN')
            with self.connection() as c:
                c.execute('''UPDATE finding_assistant.write_requests SET state=%s,failure_code=%s,updated_at=now()
                    WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s AND state='RUNNING' ''',
                    (state,type(error).__name__,*target))
                self._audit(c,'WRITE',state,identity,action,key=key)
            raise

    def replay(self, identity, base, table, key, action, payload):
        """兼容已停用的手动目标入口：仅查询旧成功结果，不创建请求、不调用远端。"""
        digest = hashlib.sha256(json.dumps({'action': action, 'fields': payload}, ensure_ascii=False,
                                          sort_keys=True).encode()).hexdigest()
        with self.connection() as db:
            row = db.execute('''SELECT * FROM finding_assistant.write_requests
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''',
                (self.app_id, base, table, key)).fetchone()
            if row is None:
                raise Conflict('warehouse selection and automatic position allocation required')
            if row['tenant_key'] != identity.tenant_key or row['open_id'] != identity.open_id:
                raise AccessDenied('request key belongs to another identity')
            if row['fingerprint'] != digest:
                raise Conflict('request key cannot be reused with different input')
            if row['state'] != 'SUCCEEDED':
                raise Conflict('old request result requires reconciliation')
            self._audit(db, 'WRITE_REPLAY', 'SUCCEEDED', identity, action, key=key)
            return row['response'] or {'record_id': row['record_id']}

    def maintenance(self, audit_days=None, limit=1000):
        if (audit_days is not None and (type(audit_days) is not int or not 30<=audit_days<=3650)) or type(limit) is not int or not 1<=limit<=10000:
            raise ValueError('INVALID_RETENTION')
        with self.connection() as c:
            counts={}
            counts['challenges']=c.execute('''DELETE FROM finding_assistant.oauth_challenges WHERE ctid IN
                (SELECT ctid FROM finding_assistant.oauth_challenges WHERE expires_at<now() LIMIT %s)''',(limit,)).rowcount
            counts['sessions']=c.execute('''DELETE FROM finding_assistant.user_sessions WHERE ctid IN
                (SELECT ctid FROM finding_assistant.user_sessions WHERE expires_at<now()-interval '7 days' LIMIT %s)''',(limit,)).rowcount
            counts['audit_events']=0
            if audit_days is not None:
                counts['audit_events']=c.execute('''DELETE FROM finding_assistant.audit_events WHERE ctid IN
                    (SELECT ctid FROM finding_assistant.audit_events WHERE recorded_at<now()-(%s * interval '1 day') LIMIT %s)''',(audit_days,limit)).rowcount
            self._audit(c,'MAINTENANCE','COMPLETED')
            return counts

    def status(self):
        """只返回运维计数，不输出账号、令牌、请求体或数据库连接串。"""
        with self.connection() as c:
            tables=('app_users','user_sessions','oauth_challenges','write_requests','audit_events')
            from psycopg import sql
            counts={t:c.execute(sql.SQL('SELECT count(*) n FROM finding_assistant.{}').format(sql.Identifier(t))).fetchone()['n'] for t in tables}
            counts['write_states']={r['state']:r['n'] for r in c.execute('SELECT state,count(*) n FROM finding_assistant.write_requests GROUP BY state').fetchall()}
            counts['location_reservation_states'] = {r['state']: r['n'] for r in c.execute(
                'SELECT state,count(*) n FROM finding_assistant.location_reservations GROUP BY state').fetchall()}
            counts['position_reservation_states'] = {r['state']: r['n'] for r in c.execute(
                'SELECT state,count(*) n FROM finding_assistant.position_reservations GROUP BY state').fetchall()}
            counts['inventory_execution_states'] = {r['state']: r['n'] for r in c.execute(
                'SELECT state,count(*) n FROM finding_assistant.inventory_executions GROUP BY state').fetchall()}
            counts['warehouse_task_states'] = {r['state']: r['n'] for r in c.execute(
                'SELECT state,count(*) n FROM finding_assistant.warehouse_tasks GROUP BY state').fetchall()}
            counts['unexecuted_intake_states'] = {r['state']: r['n'] for r in c.execute(
                '''SELECT j.state,count(*) n FROM finding_assistant.scan_jobs j
                WHERE NOT EXISTS(SELECT 1 FROM finding_assistant.inventory_executions e
                WHERE e.source_key=j.source_key) GROUP BY j.state''').fetchall()}
            counts['session_refresh_states'] = {r['refresh_state']: r['n'] for r in c.execute(
                'SELECT refresh_state,count(*) n FROM finding_assistant.user_sessions WHERE revoked_at IS NULL AND expires_at>now() GROUP BY refresh_state').fetchall()}
            return counts
