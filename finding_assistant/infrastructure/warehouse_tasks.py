"""持久受理、不可变输入、任务归属和单工作者锁；不向飞书发送请求。"""
from contextlib import contextmanager
import hashlib
import uuid
from psycopg.types.json import Jsonb
from finding_assistant.application.workflow import Conflict
from finding_assistant.security.errors import AccessDenied,AuthorizationUnavailable

class TaskQueueFull(AuthorizationUnavailable):
    pass


class WarehouseTaskStore:
    def __init__(self, operations, base):
        self.operations,self.base=operations,base

    def _owned(self,row,actor):
        if row is None or row['open_id']!=actor.open_id or row['tenant_key']!=actor.tenant_key:
            raise AccessDenied('task is unavailable for this account')
        return row

    def row(self,task_id,actor=None):
        with self.operations.connection() as db:
            row=db.execute('SELECT * FROM finding_assistant.warehouse_tasks WHERE task_id=%s AND app_id=%s AND base_token=%s',
                (uuid.UUID(str(task_id)),self.operations.app_id,self.base)).fetchone()
        return self._owned(row,actor) if actor is not None else row

    def enqueue(self,actor,session_id,key,action,payload,fingerprint,capacity=64):
        with self.operations.connection() as db:
            db.execute('SELECT pg_advisory_xact_lock(%s)',(self._lock('admission:'+self.operations.app_id+':'+self.base),))
            row=db.execute('SELECT * FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND request_key=%s',
                (self.operations.app_id,self.base,uuid.UUID(key))).fetchone()
            if row:
                self._owned(row,actor)
                if row['fingerprint']!=fingerprint:raise Conflict('accepted task input is immutable')
                return row
            counts=db.execute("""SELECT count(*) n,count(*) FILTER(WHERE open_id=%s AND tenant_key=%s) owned
                FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND state IN ('QUEUED','RUNNING')""",
                (actor.open_id,actor.tenant_key,self.operations.app_id,self.base)).fetchone()
            if counts['n']>=capacity or counts['owned']>=8:raise TaskQueueFull('task admission queue is full')
            row=db.execute("""INSERT INTO finding_assistant.warehouse_tasks
                (task_id,app_id,base_token,request_key,tenant_key,open_id,action,fingerprint,payload,session_cipher,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'QUEUED') RETURNING *""",
                (uuid.uuid4(),self.operations.app_id,self.base,uuid.UUID(key),actor.tenant_key,actor.open_id,action,
                 fingerprint,Jsonb(payload),self.operations.cipher.encrypt(session_id.encode()))).fetchone()
            self.operations._audit(db,'TASK_ADMISSION','QUEUED',actor,action,key=row['task_id'])
            return row

    def update(self,task_id,*,state=None,record_id=None,result=None,code=None):
        with self.operations.connection() as db:
            db.execute("""UPDATE finding_assistant.warehouse_tasks SET state=COALESCE(%s,state),
                record_id=COALESCE(%s,record_id),result=COALESCE(%s,result),failure_code=%s,
                session_cipher=CASE WHEN %s IN ('SUCCEEDED','AUTH_REQUIRED','REVIEW') THEN NULL ELSE session_cipher END,
                updated_at=clock_timestamp() WHERE task_id=%s AND app_id=%s AND base_token=%s""",
                (state,record_id,Jsonb(result) if result is not None else None,code,state,uuid.UUID(str(task_id)),self.operations.app_id,self.base))

    def resume_login(self,task_id,actor,session_id):
        with self.operations.connection() as db:
            db.execute('SELECT pg_advisory_xact_lock(%s)',(self._lock('admission:'+self.operations.app_id+':'+self.base),))
            row=db.execute('SELECT * FROM finding_assistant.warehouse_tasks WHERE task_id=%s AND app_id=%s AND base_token=%s FOR UPDATE',
                (uuid.UUID(str(task_id)),self.operations.app_id,self.base)).fetchone()
            self._owned(row,actor)
            if row['state']!='AUTH_REQUIRED':raise Conflict('task does not require renewed login')
            counts=db.execute("SELECT count(*) n,count(*) FILTER(WHERE open_id=%s AND tenant_key=%s) owned FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND state IN ('QUEUED','RUNNING')",(actor.open_id,actor.tenant_key,self.operations.app_id,self.base)).fetchone()
            if counts['n']>=64 or counts['owned']>=8:raise TaskQueueFull('task admission queue is full')
            db.execute("""UPDATE finding_assistant.warehouse_tasks SET state='QUEUED',failure_code=NULL,
                session_cipher=%s,updated_at=clock_timestamp() WHERE task_id=%s""",
                (self.operations.cipher.encrypt(session_id.encode()),row['task_id']))

    @staticmethod
    def _lock(key):return int.from_bytes(hashlib.sha256(key.encode()).digest()[:8],'big',signed=True)

    @contextmanager
    def review_guard(self):
        with self.operations.tasks.connect() as db:
            db.autocommit = True
            locked = db.execute('SELECT pg_try_advisory_lock(%s) ok',
                (self._lock('warehouse-worker:' + self.base),)).fetchone()['ok']
            if not locked:
                raise Conflict('warehouse worker is busy')
            yield

    def resume_review(self, expected, actor, session_id):
        with self.operations.connection() as db:
            db.execute('SELECT pg_advisory_xact_lock(%s)',
                (self._lock('admission:' + self.operations.app_id + ':' + self.base),))
            row = db.execute('SELECT * FROM finding_assistant.warehouse_tasks WHERE task_id=%s AND app_id=%s AND base_token=%s FOR UPDATE',
                (expected['task_id'], self.operations.app_id, self.base)).fetchone()
            self._owned(row, actor)
            if row['state'] != 'REVIEW' or row['updated_at'] != expected['updated_at']:
                raise Conflict('task changed after review')
            counts = db.execute("SELECT count(*) n,count(*) FILTER(WHERE open_id=%s AND tenant_key=%s) owned FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND state IN ('QUEUED','RUNNING')",
                (actor.open_id, actor.tenant_key, self.operations.app_id, self.base)).fetchone()
            if counts['n'] >= 64 or counts['owned'] >= 8:
                raise TaskQueueFull('task admission queue is full')
            db.execute("UPDATE finding_assistant.warehouse_tasks SET state='QUEUED',failure_code=NULL,session_cipher=%s,updated_at=clock_timestamp() WHERE task_id=%s",
                (self.operations.cipher.encrypt(session_id.encode()), row['task_id']))
            self.operations._audit(db, 'TASK_REVIEW_CONTINUE', 'QUEUED', actor, row['action'], key=row['task_id'])

    @contextmanager
    def claim(self):
        # 会话级锁一直持有到远端处理结束；死亡连接释放锁后原键才可恢复。
        with self.operations.tasks.connect() as lease:
            lease.autocommit=True
            locked=lease.execute('SELECT pg_try_advisory_lock(%s) ok',(self._lock('warehouse-worker:'+self.base),)).fetchone()['ok']
            if not locked:
                yield None,None
                return
            row=lease.execute("""SELECT * FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s
                AND state IN ('QUEUED','RUNNING') ORDER BY created_at,task_id LIMIT 1""",(self.operations.app_id,self.base)).fetchone()
            if row:self.update(row['task_id'],state='RUNNING')
            yield row,lambda:lease.execute('SELECT 1')
