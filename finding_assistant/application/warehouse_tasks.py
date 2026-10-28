"""本地快速受理，数据库队列串行执行；未知结果停留核查，绝不盲目重发。"""
import hashlib
import json
import logging
import re
import uuid
import time
from threading import Event,Thread
from finding_assistant.infrastructure.request_scope import request_scope
from finding_assistant.infrastructure.performance import request_trace
from finding_assistant.security.native_access import verified_authorize
from finding_assistant.security.login import AuthenticationError
from finding_assistant.security.errors import AccessDenied

LOG=logging.getLogger('finding_assistant.http.tasks')

class WarehouseTasks:
    def __init__(self,service,login,store,*,start=True):
        self.service,self.login,self.store=service,login,store
        self.stop,self.wake=Event(),Event()
        self.thread=Thread(target=self._loop,name='warehouse-tasks',daemon=True)
        if start:self.thread.start()

    def _actor(self,sid):
        actor=self.login.local_session(sid)
        if actor.tenant_key!=self.service.gate.tenant_key:raise AccessDenied('account belongs to another tenant')
        return actor

    @staticmethod
    def validate(key,action,warehouse,fields):
        operation=uuid.UUID(key)
        if operation.version!=4 or str(operation)!=key:raise ValueError('UUID4_REQUEST_KEY_REQUIRED')
        if action not in ('IN','OUT','MOVE') or not isinstance(fields,dict):raise ValueError('INVALID_TASK_INPUT')
        if (action in ('IN','MOVE') and warehouse not in ('优福斯仓','欣源仓')) or (action=='OUT' and warehouse is not None):
            raise ValueError('INVALID_TASK_WAREHOUSE')
        allowed={'原因','事件类型'}|{f'箱号{i}' for i in range(1,37)}
        if action in ('MOVE','OUT'):allowed.add('来源区域')
        if set(fields)-allowed:raise ValueError('SERVER_CONTROLLED_TASK_FIELDS')
        if any(not isinstance(v,str) or not v.strip() or len(v)>200 for v in fields.values()):raise ValueError('INVALID_TASK_FIELD')
        fields={k:v.strip() for k,v in fields.items()}
        if fields.get('事件类型',{'IN':'入库','OUT':'出库','MOVE':'转仓'}[action])!={'IN':'入库','OUT':'出库','MOVE':'转仓'}[action]:
            raise ValueError('EVENT_ROUTE_MISMATCH')
        codes=[v for k,v in fields.items() if re.fullmatch(r'箱号\d+',k)]
        if not codes or len(set(codes))!=len(codes) or any(re.search(r'\s',v) for v in codes):raise ValueError('UNIQUE_BOX_CODES_REQUIRED')
        payload={'action':action,'warehouse':warehouse,'fields':fields}
        digest=hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
        return payload,digest

    def _scope(self):
        execution=self.service.inventory_execution
        return {'scan_table':self.service.access.config.scan_table_id,
                'inventory_tables':execution.access.tables,'row_table':execution.repository.row_table}

    def _check_scope(self,row):
        if row['payload'].get('scope')!=self._scope():raise AccessDenied('task configuration changed; review required')

    def submit(self,sid,key,action,warehouse,fields):
        payload,fingerprint=self.validate(key,action,warehouse,fields)
        payload['scope']=self._scope()
        fingerprint=hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
        actor=self._actor(sid) # 不调用远端权限；受理不代表具有业务写入权限。
        row=self.store.enqueue(actor,sid,key,action,payload,fingerprint)
        self.wake.set()
        return self.summary(row)

    @staticmethod
    def summary(row):
        result=row.get('result') or {}
        return {'task_id':str(row['task_id']),'state':row['state'],'action':row['action'],
            'record_id':row['record_id'],'inventory_posted':row['state']=='SUCCEEDED' and result.get('inventory_posted') is True,
            'locations':result.get('locations'),'step_count':result.get('step_count',0),
            'confirmed_steps':result.get('confirmed_steps',0),'failure_code':row.get('failure_code'),
            'review_required':row['state']=='REVIEW','auth_required':row['state']=='AUTH_REQUIRED',
            'poll_after_seconds':3,'accepted':True}

    def status(self,sid,task_id):
        actor=verified_authorize(self.service.gate,sid,'QUERY')
        self.service.inventory_execution.access.reader._complete_scope(actor)
        row=self.store.row(task_id,actor)
        self._check_scope(row)
        if row['record_id'] and row['state']=='RUNNING':
            repo=self.service.inventory_execution.repository
            live=repo.summary(repo.base+':'+repo.scan_table+':'+row['record_id'])
            if live.get('found'):row={**row,'result':{**(row['result'] or {}),**live}}
        return self.summary(row)

    def resume(self,sid,task_id):
        actor=self._actor(sid)
        self._check_scope(self.store.row(task_id,actor))
        self.store.resume_login(task_id,actor,sid);self.wake.set()
        return self.summary(self.store.row(task_id,actor))

    def run_once(self):
        with self.store.claim() as (row,alive):
            if row is None:return False
            started=time.perf_counter()
            with request_scope(),request_trace() as trace:
                self._run(row,alive)
            outcome=self.store.row(row['task_id'])['state']
            LOG.info('performance=%s',json.dumps({'request_id':uuid.uuid4().hex,'task_id':str(row['task_id']),
                'route':'background:warehouse-task','status':200 if outcome=='SUCCEEDED' else 503,
                'duration_ms':round((time.perf_counter()-started)*1000,3),'stages':trace.snapshot()}))
            return True

    def _run(self,row,alive):
        task=row['task_id'];record=row['record_id']
        try:
            self._check_scope(row)
            sid=self.store.operations.cipher.decrypt(bytes(row['session_cipher'])).decode()
            identity=verified_authorize(self.service.gate,sid,row['action'])
            if identity.open_id!=row['open_id'] or identity.tenant_key!=row['tenant_key']:
                raise AccessDenied('task identity mismatch')
            alive()
            if record is None:
                p=row['payload'];key=str(row['request_key'])
                if row['action']=='IN':result=self.service.prepare_inbound(sid,key,p['warehouse'],p['fields'])
                elif row['action']=='MOVE':result=self.service.prepare_transfer(sid,key,p['warehouse'],p['fields'])
                else:result=self.service.submit(sid,key,'OUT',p['fields'])
                record=result['record']['record_id']
                alive();self.store.update(task,record_id=record,result=result)
            alive()
            result=self.service.inventory_execution.execute(sid,record)
            if result.get('state')!='SUCCEEDED' or result.get('inventory_posted') is not True:
                self.store.update(task,state='REVIEW',result=result,code='EXECUTION_NOT_CONFIRMED')
            else:self.store.update(task,state='SUCCEEDED',result=result)
        except AuthenticationError:
            self.store.update(task,state='AUTH_REQUIRED',code='LOGIN_REQUIRED')
        except Exception as error:
            # 不存异常文本，保留原流水/原键；操作员联系运维核实，不自动重试网络写入。
            code=getattr(error,'code',None)
            safe=code if isinstance(code,str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}',code) else 'TASK_REQUIRES_REVIEW'
            self.store.update(task,state='REVIEW',code=safe)
        LOG.info('warehouse_task task_id=%s processing_finished=true',task)

    def _loop(self):
        while not self.stop.is_set():
            try:
                if self.run_once():continue
            except Exception:
                LOG.warning('warehouse_task poll_unavailable=true')
            self.wake.wait(1);self.wake.clear()

    def close(self):
        self.stop.set();self.wake.set()
        if self.thread.is_alive():self.thread.join()
