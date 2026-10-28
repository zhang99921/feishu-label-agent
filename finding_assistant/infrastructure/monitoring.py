"""独立只读健康采集与本地持久告警箱；数据库故障不阻断告警状态保存。"""
from datetime import datetime,timezone
from contextlib import contextmanager
import hashlib,json,os,shutil,sqlite3,time,uuid
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from .operations_queries import OperationsQueries
from .log_exchange import atomic_json,child

@contextmanager
def state_connection(path,**options):
    db=sqlite3.connect(path,**options)
    try:
        with db:yield db
    finally:db.close()

def monitor_config(path):
    path=Path(path)
    if path.stat().st_size>32768:raise ValueError('INVALID_MONITOR_CONFIG')
    value=json.loads(path.read_text(encoding='utf-8-sig'))
    allowed={'enabled','http_base','state_dir','disk_path','interval_seconds','failure_threshold','reminder_seconds','min_free_bytes','replica_stale_seconds','task_stalled_seconds'}
    if not isinstance(value,dict) or set(value)-allowed or type(value.get('enabled')) is not bool:raise ValueError('INVALID_MONITOR_CONFIG')
    parsed=urlsplit(value.get('http_base',''))
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('INVALID_MONITOR_ENDPOINT')
    defaults={'interval_seconds':60,'failure_threshold':2,'reminder_seconds':3600,'min_free_bytes':1073741824,'replica_stale_seconds':300,'task_stalled_seconds':900}
    for key,default in defaults.items():
        item=value.setdefault(key,default)
        if type(item) is not int or item<0:raise ValueError('INVALID_MONITOR_THRESHOLD')
    if not 10<=value['interval_seconds']<=3600 or not 1<=value['failure_threshold']<=10 or value['reminder_seconds']<value['interval_seconds']:
        raise ValueError('INVALID_MONITOR_THRESHOLD')
    if value['reminder_seconds']>604800 or not 10<=value['replica_stale_seconds']<=86400 or not 60<=value['task_stalled_seconds']<=604800 or value['min_free_bytes']>2**60:
        raise ValueError('INVALID_MONITOR_THRESHOLD')
    if not value.get('state_dir') or not value.get('disk_path'):raise ValueError('INVALID_MONITOR_PATH')
    return value

def collect_health(values,config,client=None):
    checks=[]
    def check(code,ok,severity='critical',value=None):checks.append({'code':code,'ok':bool(ok),'severity':severity,'value':value})
    owned=client is None;client=client or httpx.Client(timeout=3,trust_env=False,follow_redirects=False)
    try:
        try:
            response=client.get(config['http_base'].rstrip('/')+'/health/live')
            check('HTTP_UNAVAILABLE',response.status_code==200 and response.json().get('status')=='alive')
        except Exception:check('HTTP_UNAVAILABLE',False)
        try:
            response=client.get(config['http_base'].rstrip('/')+'/health/ready')
            check('HTTP_NOT_READY',response.status_code==200 and response.json().get('database_verified') is True)
        except Exception:check('HTTP_NOT_READY',False)
    finally:
        if owned:client.close()
    try:
        free=shutil.disk_usage(config['disk_path']).free
        check('DISK_LOW',free>=config['min_free_bytes'],'critical',free)
    except OSError:check('DISK_CHECK_UNAVAILABLE',False)
    try:
        queries=OperationsQueries(values.get('FINDING_ASSISTANT_DATABASE_URL'))
        app=values.get('FEISHU_APP_ID');base=values.get('FEISHU_APP_TOKEN')
        if not app or not base:raise ValueError('MONITOR_SCOPE_REQUIRED')
        with queries.connection() as db:
            unknown=db.execute("SELECT count(*) n FROM finding_assistant.write_requests WHERE app_id=%s AND base_token=%s AND state='UNKNOWN'",(app,base)).fetchone()['n']
            review=db.execute("SELECT count(*) n FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND state='REVIEW'",(app,base)).fetchone()['n']
            stalled=db.execute("SELECT count(*) n FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND state IN ('QUEUED','RUNNING') AND updated_at<now()-(%s * interval '1 second')",(app,base,config['task_stalled_seconds'])).fetchone()['n']
            reconcile=db.execute("SELECT count(*) n FROM finding_assistant.inventory_executions WHERE app_id=%s AND base_token=%s AND state='RECONCILE'",(app,base)).fetchone()['n']
            replica=db.execute('SELECT state,failure_count,extract(epoch FROM now()-source_read_started_at) age FROM finding_assistant.business_sync_sources WHERE base_token=%s',(base,)).fetchone()
        check('DATABASE_UNAVAILABLE',True)
        check('WRITE_UNKNOWN',unknown==0,'critical',unknown);check('TASK_REVIEW',review==0,'warning',review)
        check('TASK_STALLED',stalled==0,'warning',stalled);check('INVENTORY_RECONCILE',reconcile==0,'warning',reconcile)
        age=float(replica['age']) if replica and replica['age'] is not None else None
        if replica:check('SYNC_FAILED',replica['state']!='FAILED','warning',replica['failure_count'])
        check('REPLICA_STALE',age is not None and 0<=age<=config['replica_stale_seconds'],'warning',None if age is None else int(age))
    except Exception:
        check('DATABASE_UNAVAILABLE',False)
        # 未采集到的业务项保持原告警，不把数据库故障当作“未知写入已恢复”。
    return checks

class MonitorState:
    def __init__(self,root,scope):
        self.root=Path(root).resolve();self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path=child(self.root,'monitor.sqlite3');self.scope=scope
        with state_connection(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1),scope TEXT NOT NULL,value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY,code TEXT NOT NULL,kind TEXT NOT NULL,observed_at REAL NOT NULL,payload TEXT NOT NULL)')
    def sample(self,checks,config,now=None):
        now=time.time() if now is None else now
        with state_connection(self.path,timeout=3) as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT scope,value FROM state WHERE id=1').fetchone()
            if row and row[0]!=self.scope:raise ValueError('MONITOR_STATE_SCOPE_CHANGED')
            state=json.loads(row[1]) if row else {'checks':{},'last_sample':None}
            if state['last_sample'] is not None and now<state['last_sample']:raise ValueError('MONITOR_CLOCK_REVIEW_REQUIRED')
            emitted=[]
            if state['last_sample'] is None or now-state['last_sample']>=config['interval_seconds']:
                for observation in checks:
                    code=observation['code'];entry=state['checks'].setdefault(code,{'failures':0,'active':False,'generation':0,'sequence':0,'last_event':0})
                    entry['value']=observation.get('value');entry['severity']=observation['severity'];entry['last_seen']=now
                    kind=None
                    if observation['ok']:
                        entry['failures']=0
                        if entry['active']:entry['active']=False;kind='RECOVERED'
                    else:
                        entry['failures']+=1
                        if not entry['active'] and entry['failures']>=config['failure_threshold']:
                            entry['active']=True;entry['generation']+=1;kind='OPEN'
                        elif entry['active'] and now-entry['last_event']>=config['reminder_seconds']:kind='REMINDER'
                    if kind:
                        entry['sequence']+=1;entry['last_event']=now
                        identifier=str(uuid.uuid5(uuid.NAMESPACE_URL,self.scope+':'+code+':'+str(entry['generation'])+':'+str(entry['sequence'])))
                        event={'event_id':identifier,'code':code,'kind':kind,'severity':entry['severity'],'value':entry['value'],'observed_at':datetime.fromtimestamp(now,timezone.utc).isoformat(),'delivery':'LOCAL_ONLY'}
                        db.execute('INSERT INTO events VALUES(?,?,?,?,?)',(identifier,code,kind,now,json.dumps(event)));emitted.append(event)
                state['last_sample']=now
                db.execute('INSERT INTO state VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',(self.scope,json.dumps(state)))
            total=db.execute('SELECT count(*) FROM events').fetchone()[0]
        result={'checked_at':datetime.fromtimestamp(state['last_sample'],timezone.utc).isoformat(),'active_alerts':{k:v for k,v in state['checks'].items() if v['active']},'new_events':emitted,'event_count':total,'notifications_enabled':False,'business_states_modified':False}
        atomic_json(child(self.root,'status.json'),result)
        return result

def monitor_once(values,config,client=None):
    scope=hashlib.sha256(json.dumps([values.get('FEISHU_APP_ID'),values.get('FEISHU_APP_TOKEN')]).encode()).hexdigest()
    return MonitorState(config['state_dir'],scope).sample(collect_health(values,config,client),config)
