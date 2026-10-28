"""本机长期保存的增量日志下载；SFTP只读、严格主机校验，无服务器删除命令。"""
from datetime import datetime,timezone
import json,os,re,shutil,subprocess,uuid,time
from pathlib import Path,PurePosixPath
from .log_exchange import MAX_FILE,MAX_CATALOG,atomic_json,child,digest,locked,validate_catalog

class TransferError(Exception):
    pass

def read_config(path):
    path=Path(path)
    if path.stat().st_size>32768:raise TransferError('INVALID_DOWNLOAD_CONFIG')
    value=json.loads(path.read_text(encoding='utf-8-sig'))
    allowed={'version','enabled','system_id','destination','transport','source_dir','host','port','username','identity_file','known_hosts','remote_root','daily_time','min_free_bytes'}
    if not isinstance(value,dict) or set(value)-allowed or value.get('version')!=1 or type(value.get('enabled')) is not bool:
        raise TransferError('INVALID_DOWNLOAD_CONFIG')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value.get('system_id','')) or not Path(value.get('destination','')).is_absolute():
        raise TransferError('INVALID_DOWNLOAD_CONFIG')
    minimum=value.get('min_free_bytes',1024**3)
    if type(minimum) is not int or minimum<0:raise TransferError('INVALID_DOWNLOAD_CONFIG')
    if value.get('transport') not in ('local','sftp'):raise TransferError('INVALID_DOWNLOAD_CONFIG')
    return value

class LocalSource:
    def __init__(self,root):self.root=Path(root).resolve()
    def get(self,relative,destination,resume=False,maximum=MAX_FILE):
        source=child(self.root,relative)
        if source.stat().st_size>maximum:raise TransferError('REMOTE_FILE_TOO_LARGE')
        offset=destination.stat().st_size if resume and destination.exists() else 0
        with source.open('rb') as incoming,destination.open('ab' if offset else 'wb') as outgoing:
            incoming.seek(offset)
            shutil.copyfileobj(incoming,outgoing,1024*1024);outgoing.flush();os.fsync(outgoing.fileno())

class SftpSource:
    def __init__(self,config):
        host=config.get('host','');user=config.get('username','');port=config.get('port',22)
        remote=config.get('remote_root','')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}',user) or type(port) is not int or not 1<=port<=65535:
            raise TransferError('SFTP_NOT_CONFIGURED')
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+',remote) or '..' in PurePosixPath(remote).parts:
            raise TransferError('INVALID_REMOTE_LOG_ROOT')
        key=Path(config.get('identity_file',''));known=Path(config.get('known_hosts',''))
        if not key.is_absolute() or not known.is_absolute() or not key.is_file() or not known.is_file():
            raise TransferError('SSH_FILES_NOT_CONFIGURED')
        if any(c in str(key)+str(known) for c in '\r\n"'):raise TransferError('INVALID_SSH_FILE_PATH')
        binary=shutil.which('sftp')
        if not binary:raise TransferError('OPENSSH_SFTP_REQUIRED')
        self.root=remote.rstrip('/')
        self.command=[binary,'-F','none','-b','-','-P',str(port),'-i',str(key),
          '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
          '-o','UserKnownHostsFile="'+known.as_posix()+'"','-o','GlobalKnownHostsFile=none',
          '-o','ConnectTimeout=10','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2',user+'@'+host]
    def get(self,relative,destination,resume=False,maximum=MAX_FILE):
        if relative!='catalog.json' and not re.fullmatch(r'objects/[0-9a-f]{64}\.log(?:\.gz)?',relative):
            raise TransferError('INVALID_REMOTE_OBJECT')
        local=destination.resolve().as_posix()
        if any(c in local for c in '\r\n"'):raise TransferError('INVALID_LOCAL_LOG_PATH')
        command='get '+('-a ' if resume else '')+'"'+self.root+'/'+relative+'" "'+local+'"\n'
        process=None
        try:
            process=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                     creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            process.stdin.write(command.encode('utf-8'));process.stdin.close()
            deadline=time.monotonic()+180
            while process.poll() is None:
                if destination.exists() and destination.stat().st_size>maximum:raise TransferError('REMOTE_FILE_TOO_LARGE')
                if time.monotonic()>deadline:raise TransferError('SFTP_UNAVAILABLE')
                time.sleep(0.1)
            if process.returncode!=0:raise TransferError('SFTP_UNAVAILABLE')
        except OSError:raise TransferError('SFTP_UNAVAILABLE') from None
        finally:
            if process is not None and process.poll() is None:process.kill();process.wait(timeout=10)
        if destination.stat().st_size>maximum:raise TransferError('REMOTE_FILE_TOO_LARGE')

def pull_logs(config_path):
    config=read_config(config_path)
    root=Path(config['destination']).resolve();root.mkdir(parents=True,exist_ok=True)
    workspace=child(root,config['system_id']);workspace.mkdir(exist_ok=True)
    with locked(workspace):
        status={'time':datetime.now(timezone.utc).isoformat(),'state':'RUNNING','downloaded':0,'reused':0,'server_deleted':False}
        previous=child(workspace,'status.json')
        if previous.exists():
            old=json.loads(previous.read_text(encoding='utf-8'))
            for key in ('last_success_at','last_complete_catalog'):
                if key in old:status[key]=old[key]
        try:
            if not config['enabled']:raise TransferError('DOWNLOAD_NOT_CONFIGURED')
            source=SftpSource(config) if config['transport']=='sftp' else LocalSource(config['source_dir'])
            staging=child(workspace,'.partial');staging.mkdir(exist_ok=True)
            temp=child(workspace,'.partial/catalog.json')
            if shutil.disk_usage(workspace).free<MAX_CATALOG+config.get('min_free_bytes',1024**3):raise TransferError('LOCAL_DISK_SPACE_LOW')
            source.get('catalog.json',temp,maximum=MAX_CATALOG)
            if temp.stat().st_size>MAX_CATALOG:raise TransferError('INVALID_LOG_CATALOG')
            catalog=validate_catalog(json.loads(temp.read_text(encoding='utf-8')),config['system_id'])
            objects=child(workspace,'objects');objects.mkdir(exist_ok=True)
            quarantine=child(workspace,'quarantine');quarantine.mkdir(exist_ok=True)
            for entry in catalog['files']:
                target=child(workspace,entry['object_path']);partial=child(workspace,'.partial/'+target.name+'.part')
                if target.exists():
                    if target.stat().st_size==entry['bytes'] and digest(target)==entry['sha256']:
                        status['reused']+=1;continue
                    target.replace(quarantine/(target.name+'.'+uuid.uuid4().hex))
                if partial.exists() and partial.stat().st_size>entry['bytes']:
                    partial.replace(quarantine/(partial.name+'.'+uuid.uuid4().hex))
                required=entry['bytes']-(partial.stat().st_size if partial.exists() else 0)
                if shutil.disk_usage(workspace).free<required+config.get('min_free_bytes',1024**3):raise TransferError('LOCAL_DISK_SPACE_LOW')
                source.get(entry['object_path'],partial,resume=partial.exists(),maximum=entry['bytes'])
                if partial.stat().st_size!=entry['bytes'] or digest(partial)!=entry['sha256']:
                    partial.replace(quarantine/(partial.name+'.'+uuid.uuid4().hex))
                    raise TransferError('LOG_CHECKSUM_MISMATCH')
                partial.replace(target);status['downloaded']+=1
            history=child(workspace,'manifests');history.mkdir(exist_ok=True)
            catalog_hash=digest(temp)
            history_file=child(workspace,'manifests/'+catalog_hash+'.json')
            if not history_file.exists():temp.replace(history_file)
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(catalog['generated_at'])).total_seconds()
            gap=catalog.get('skipped',0)>0
            if status.get('last_success_at'):
                gap=gap or (datetime.now(timezone.utc)-datetime.fromisoformat(status['last_success_at'])).total_seconds()>30*86400
            status.update(state='SUCCEEDED',catalog=catalog_hash,source_generated_at=catalog['generated_at'],source_skipped=catalog.get('skipped',0),source_age_seconds=max(0,int(age)),source_stale=age>36*3600)
            status.update(last_success_at=status['time'],last_complete_catalog=catalog_hash,possible_history_gap=gap,source_empty=not catalog['files'])
        except Exception as error:
            code=str(error) if isinstance(error,TransferError) else 'LOG_DOWNLOAD_UNCONFIRMED'
            if not re.fullmatch(r'[A-Z_]{1,64}',code):code='LOG_DOWNLOAD_UNCONFIRMED'
            status.update(state='FAILED',failure_code=code)
        atomic_json(child(workspace,'status.json'),status)
        with child(workspace,'download-events.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(json.dumps(status,ensure_ascii=False)+'\n')
        return status
