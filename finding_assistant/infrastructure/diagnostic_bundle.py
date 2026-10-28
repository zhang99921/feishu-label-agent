"""服务器维护人员的只读诊断包：字段白名单、范围限定、脱敏、截断和校验。"""
from datetime import datetime,timedelta,timezone
from contextlib import closing
from decimal import Decimal
import gzip,hashlib,json,re,uuid,zipfile,os,sqlite3
from pathlib import Path
from .operations_queries import OperationsQueries
from .log_exchange import child,logical_name,digest

SENSITIVE=re.compile(r'access[_-]?token|refresh[_-]?token|app[_-]?secret|password|authorization|cookie|[?&](?:code|state)=',re.I)

def clean(value,secrets=()):
    if isinstance(value,dict):return {k:clean(v,secrets) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [clean(v,secrets) for v in value]
    if isinstance(value,datetime):return value.astimezone(timezone.utc).isoformat()
    if isinstance(value,(uuid.UUID,Decimal)):return str(value)
    if isinstance(value,str):
        if SENSITIVE.search(value):return '[REDACTED]'
        for secret in secrets:
            if secret and len(secret)>=8:value=value.replace(secret,'[REDACTED]')
    return value

def moment(value):
    parsed=datetime.fromisoformat(value) if isinstance(value,str) else value
    if not isinstance(parsed,datetime) or parsed.tzinfo is None:raise ValueError('UTC_WINDOW_REQUIRED')
    return parsed.astimezone(timezone.utc)

def runtime_slice(root,start,end,terms,limit,secrets):
    root=Path(root).resolve();lines=[];scanned=0;truncated=False
    if not root.is_dir():return [],{'available':False,'truncated':False}
    paths=[]
    for component in ('http','sync','intake'):
        active=child(root,component+'.log')
        if active.is_file():paths.append(active)
        archive=child(root,'archive/'+component)
        if archive.is_dir():
            for path in archive.glob('*/*.log.gz'):
                relative=path.relative_to(root).as_posix()
                if logical_name(relative):
                    try:day=datetime.strptime(path.parent.name,'%Y-%m-%d').date()
                    except ValueError:continue
                    if start.date()<=day<=end.date():paths.append(child(root,relative))
    for path in sorted(paths,key=lambda p:p.stat().st_mtime,reverse=True):
        opener=gzip.open if path.suffix=='.gz' else open
        with opener(path,'rb') as stream:
            while True:
                raw=stream.readline(32769)
                if not raw:break
                scanned+=len(raw)
                if len(raw)>32768 or scanned>16*1024*1024:truncated=True;break
                text=raw.decode('utf-8',errors='replace').rstrip('\r\n')
                try:stamp=datetime.strptime(text[:20],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                except ValueError:continue
                if not start<=stamp<=end or (terms and not any(term in text for term in terms)):continue
                lines.append({'source':path.relative_to(root).as_posix(),'line':clean(text,secrets)})
                if len(lines)>=limit:truncated=True;break
        if truncated:break
    return lines,{'available':True,'truncated':truncated,'scanned_bytes':scanned,'correlation_only':bool(terms)}

def diagnostic_bundle(dsn,app,base,scan_table,output,*,task_id=None,since=None,until=None,limit=500,log_dir=None,secrets=(),monitor_state=None):
    if not app or not base or not scan_table or type(limit) is not int or not 1<=limit<=5000:raise ValueError('INVALID_DIAGNOSTIC_SCOPE')
    end=moment(until) if until else datetime.now(timezone.utc)
    start=moment(since) if since else end-timedelta(days=1)
    if not task_id and since is None:raise ValueError('TASK_OR_TIME_WINDOW_REQUIRED')
    if start>=end or end-start>timedelta(days=7):raise ValueError('DIAGNOSTIC_WINDOW_LIMIT')
    identifier=uuid.UUID(task_id) if task_id else None
    if identifier and (identifier.version!=4 or str(identifier)!=task_id):raise ValueError('UUID4_TASK_REQUIRED')
    queries=OperationsQueries(dsn);tables={};truncated={}
    with queries.connection() as db:
        db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        def take(name,query,params):
            rows=db.execute(query+' LIMIT %s',(*params,limit+1)).fetchall()
            tables[name]=rows[:limit];truncated[name]=len(rows)>limit
            return tables[name]
        task_fields='task_id,request_key,tenant_key,open_id,action,record_id,state,failure_code,created_at,updated_at'
        if identifier:
            tasks=take('tasks','SELECT '+task_fields+' FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s AND task_id=%s',(app,base,identifier))
            if not tasks:raise ValueError('DIAGNOSTIC_TASK_NOT_FOUND')
        else:
            tasks=take('tasks','SELECT '+task_fields+''' FROM finding_assistant.warehouse_tasks WHERE app_id=%s AND base_token=%s
                AND (created_at BETWEEN %s AND %s OR updated_at BETWEEN %s AND %s) ORDER BY updated_at DESC''',(app,base,start,end,start,end))
        record=tasks[0]['record_id'] if identifier else None
        clause=' AND source_record_id=%s' if identifier else ' AND (created_at BETWEEN %s AND %s OR updated_at BETWEEN %s AND %s)'
        tail=(record,) if identifier else (start,end,start,end)
        executions=take('executions', '''SELECT source_key,execution_id,source_record_id,action,state,failure_code,position_confirmed,created_at,updated_at
            FROM finding_assistant.inventory_executions WHERE app_id=%s AND base_token=%s AND scan_table_id=%s'''+clause+' ORDER BY updated_at DESC',(app,base,scan_table,*tail))
        source_keys=[row['source_key'] for row in executions]
        # 无本应用执行记录时，不凭record_id猜测并读取其他应用的共享来源证据。
        take('steps','''SELECT source_key,ordinal,kind,box_record_id,state,remote_record_id,failure_code,confirmed_at
            FROM finding_assistant.inventory_steps WHERE source_key=ANY(%s) ORDER BY source_key,ordinal''',(source_keys,))
        take('transactions','''SELECT source_key,transaction_id,box_code,action,document_reference,transaction_no,quantity,state,active,remote_record_id,posted_at
            FROM finding_assistant.inventory_transactions WHERE source_key=ANY(%s) ORDER BY source_key,box_code''',(source_keys,))
        take('source_events','''SELECT id,source_key,event_code,recorded_at FROM finding_assistant.scan_job_events
            WHERE source_key=ANY(%s) AND recorded_at BETWEEN %s AND %s ORDER BY id''',(source_keys,start,end))
        rejections=take('rejections','''SELECT rejection_id,source_key,state,reason_code,box_code,remote_record_id,position_released,created_at,updated_at
            FROM finding_assistant.inventory_rejections WHERE app_id=%s AND base_token=%s AND source_key=ANY(%s) ORDER BY updated_at''',(app,base,source_keys))
        keys=list({row['request_key'] for row in tasks}|{row['task_id'] for row in tasks}|{row['execution_id'] for row in executions}|{row['rejection_id'] for row in rejections})
        write_clause=' AND request_key=ANY(%s)' if identifier else ' AND (created_at BETWEEN %s AND %s OR updated_at BETWEEN %s AND %s)'
        write_params=(keys,) if identifier else (start,end,start,end)
        writes=take('writes','''SELECT request_key,action,state,record_id,failure_code,created_at,updated_at FROM finding_assistant.write_requests
            WHERE app_id=%s AND base_token=%s AND table_id=%s'''+write_clause+' ORDER BY updated_at DESC',(app,base,scan_table,*write_params))
        keys=list(set(keys)|{row['request_key'] for row in writes})
        context=' OR (request_key IS NULL AND open_id=%s AND tenant_key=%s)' if identifier else ' OR request_key IS NULL'
        context_params=(tasks[0]['open_id'],tasks[0]['tenant_key']) if identifier else ()
        take('audit','''SELECT id,tenant_key,open_id,event_type,outcome,action,permission,request_key,recorded_at FROM finding_assistant.audit_events
            WHERE app_id=%s AND recorded_at BETWEEN %s AND %s AND (request_key=ANY(%s)'''+context+') ORDER BY id',(app,start,end,keys,*context_params))
    logs,log_status=runtime_slice(log_dir,start,end,[str(k) for k in keys] if identifier else [],limit,secrets) if log_dir else ([],{'available':False,'truncated':False})
    tables['runtime']=logs;truncated['runtime']=log_status['truncated']
    monitor_status={'available':False}
    tables['monitor_events']=[];truncated['monitor_events']=False
    if monitor_state:
        path=child(Path(monitor_state),'monitor.sqlite3')
        if path.is_file():
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)) as local:
                stored=local.execute('SELECT scope FROM state WHERE id=1').fetchone()
                expected=hashlib.sha256(json.dumps([app,base]).encode()).hexdigest()
                if not stored or stored[0]!=expected:raise ValueError('MONITOR_SCOPE_MISMATCH')
                events=local.execute('SELECT event_id,code,kind,observed_at,payload FROM events WHERE observed_at BETWEEN ? AND ? ORDER BY observed_at LIMIT ?',
                                     (start.timestamp(),end.timestamp(),limit+1)).fetchall()
                for event_id,code,kind,stamp,payload in events[:limit]:
                    payload=json.loads(payload)
                    tables['monitor_events'].append({'event_id':event_id,'code':code,'kind':kind,'observed_at':stamp,
                                                     **{key:payload[key] for key in ('severity','value','delivery') if key in payload}})
                truncated['monitor_events']=len(events)>limit;monitor_status={'available':True}
    files={name+'.jsonl':''.join(json.dumps(clean(row,secrets),ensure_ascii=False,sort_keys=True)+'\n' for row in rows).encode('utf-8') for name,rows in tables.items()}
    manifest={'version':1,'generated_at':datetime.now(timezone.utc).isoformat(),'task_id':task_id,'app_id':app,'base_token':base,
      'since':start.isoformat(),'until':end.isoformat(),'read_only':True,'cross_source_atomic':False,'truncated':truncated,'runtime':log_status,'monitor':monitor_status,
      'source_execution_unverified':bool(identifier and record and not executions),
      'unlinked_audit_context':'same actor/time for task mode; application/time for window mode, not proven per-task',
      'files':{name:{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'records':len(tables[name[:-6]])} for name,data in files.items()}}
    folder=Path(output).resolve();folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    name='diagnostic-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex+'.zip'
    target=child(folder,name);temporary=child(folder,name+'.tmp')
    with temporary.open('xb') as stream:
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
            for filename,data in files.items():archive.writestr(filename,data)
            archive.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,sort_keys=True))
        stream.flush();os.fsync(stream.fileno())
    temporary.replace(target)
    checksum=digest(target);child(folder,name+'.sha256').write_text(checksum+'  '+name+'\n',encoding='utf-8')
    return {'archive':str(target),'sha256':checksum,'read_only':True,'truncated':any(truncated.values()),'files':len(files)+1}
