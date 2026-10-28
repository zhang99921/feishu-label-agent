"""日志受限导出清单：只收集组件运行日志，不读取配置、会话或数据库。"""
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
import hashlib,json,os,re,uuid
from pathlib import Path,PurePosixPath
from .local_lock import acquire,release

COMPONENTS=('http','sync','intake')
MAX_FILE=512*1024*1024
MAX_CATALOG=8*1024*1024

def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()

@contextmanager
def locked(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    lock=root/'.transfer.lock'
    if lock.is_symlink():raise ValueError('UNSAFE_LOG_PATH')
    with lock.open('a+b') as stream:
        stream.seek(0);stream.write(b'0');stream.flush();stream.seek(0)
        acquire(stream)
        try:yield
        finally:stream.seek(0);release(stream)

def child(root,relative):
    root=Path(root).resolve();parts=PurePosixPath(relative)
    if parts.is_absolute() or not parts.parts or any(p in ('..','.') or ':' in p or '\\' in p for p in parts.parts):
        raise ValueError('UNSAFE_LOG_PATH')
    path=root
    for part in parts.parts:
        path=path/part
        if path.is_symlink():raise ValueError('UNSAFE_LOG_PATH')
    if not path.resolve().is_relative_to(root):raise ValueError('UNSAFE_LOG_PATH')
    return path

def atomic_json(path,value):
    path=Path(path);temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    temporary.replace(path)

def logical_name(name):
    if name in tuple(c+'.log' for c in COMPONENTS):return True
    return bool(re.fullmatch(r'archive/(http|sync|intake)/\d{4}-\d{2}-\d{2}/\1-\d{8}T\d{12}Z-[0-9a-f]{32}\.log\.gz',name))

def validate_catalog(data,system):
    if not isinstance(data,dict) or data.get('version')!=1 or data.get('system_id')!=system:
        raise ValueError('INVALID_LOG_CATALOG')
    if not isinstance(data.get('files'),list) or len(data['files'])>20000:raise ValueError('INVALID_LOG_CATALOG')
    generated=data.get('generated_at')
    if not isinstance(generated,str) or len(generated)>64:raise ValueError('INVALID_LOG_CATALOG')
    try:
        if datetime.fromisoformat(generated).utcoffset()!=timedelta(0):raise ValueError
    except (ValueError,TypeError):raise ValueError('INVALID_LOG_CATALOG') from None
    seen=set()
    for entry in data['files']:
        if not isinstance(entry,dict) or not logical_name(entry.get('logical_path','')):raise ValueError('INVALID_LOG_CATALOG')
        sha=entry.get('sha256','');size=entry.get('bytes')
        if not re.fullmatch(r'[0-9a-f]{64}',sha) or type(size) is not int or not 0<=size<=MAX_FILE:raise ValueError('INVALID_LOG_CATALOG')
        suffix='.log.gz' if entry['logical_path'].endswith('.gz') else '.log'
        if entry.get('object_path')!='objects/'+sha+suffix or entry['logical_path'] in seen:raise ValueError('INVALID_LOG_CATALOG')
        seen.add(entry['logical_path'])
    return data

def export_logs(log_dir,output,system):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',system):raise ValueError('INVALID_LOG_SYSTEM')
    root=Path(log_dir).resolve();out=Path(output).resolve()
    if root==out or root.is_relative_to(out) or out.is_relative_to(root):raise ValueError('LOG_EXPORT_MUST_BE_SEPARATE')
    if not root.is_dir():raise ValueError('LOG_DIRECTORY_UNAVAILABLE')
    today=datetime.now(timezone.utc).date();cutoff=today-timedelta(days=29)
    with locked(out):
        objects=child(out,'objects');objects.mkdir(exist_ok=True)
        selected=[]
        for component in COMPONENTS:
            active=child(root,component+'.log')
            if active.is_file():selected.append(active)
            archive=child(root,'archive/'+component)
            if archive.is_dir():
                for path in archive.glob('*/*.log.gz'):
                    if logical_name(path.relative_to(root).as_posix()):selected.append(path)
        catalog={'version':1,'system_id':system,'generated_at':datetime.now(timezone.utc).isoformat(),'atomic_snapshot':False,'files':[],'skipped':0}
        for source in selected:
            relative=source.relative_to(root).as_posix();source=child(root,relative)
            stat=source.stat()
            day=datetime.strptime(source.parent.name,'%Y-%m-%d').date() if relative.startswith('archive/') else datetime.fromtimestamp(stat.st_mtime,timezone.utc).date()
            if day<cutoff:continue
            if stat.st_size>MAX_FILE:raise ValueError('LOG_EXPORT_FILE_TOO_LARGE')
            temp=objects/(uuid.uuid4().hex+'.tmp')
            try:
                with source.open('rb') as incoming,temp.open('xb') as outgoing:
                    remaining=stat.st_size
                    while remaining:
                        chunk=incoming.read(min(1024*1024,remaining))
                        if not chunk:raise ValueError('LOG_SOURCE_CHANGED')
                        outgoing.write(chunk);remaining-=len(chunk)
                    outgoing.flush();os.fsync(outgoing.fileno())
                if source.suffix=='.gz':
                    after=source.stat()
                    if (stat.st_ino,stat.st_size,stat.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('LOG_SOURCE_CHANGED')
                else:
                    # 活跃文件只导出已完整写出的行，不把半条UTF-8记录当作完整事件。
                    with temp.open('r+b') as stream:
                        stream.seek(max(0,stat.st_size-65536));tail=stream.read();index=tail.rfind(b'\n')
                        if index<0 and stat.st_size:raise ValueError('LOG_LINE_UNCONFIRMED')
                        stream.truncate(max(0,stat.st_size-65536)+index+1 if index>=0 else 0)
                sha=digest(temp);suffix='.log.gz' if source.suffix=='.gz' else '.log'
                target=child(out,'objects/'+sha+suffix)
                existed=target.exists()
                if existed and digest(target)!=sha:raise ValueError('LOG_EXPORT_OBJECT_CORRUPT')
                if not existed:temp.replace(target)
                stamp=datetime.combine(day,datetime.min.time(),tzinfo=timezone.utc).timestamp()
                if existed:stamp=max(target.stat().st_mtime,stamp)
                os.utime(target,(stamp,stamp))
                catalog['files'].append({'logical_path':relative,'object_path':target.relative_to(out).as_posix(),'sha256':sha,'bytes':target.stat().st_size})
            except FileNotFoundError:
                catalog['skipped']+=1
            finally:temp.unlink(missing_ok=True)
        validate_catalog(catalog,system)
        raw=json.dumps(catalog,ensure_ascii=False).encode()
        if len(raw)>MAX_CATALOG:raise ValueError('LOG_CATALOG_TOO_LARGE')
        atomic_json(child(out,'catalog.json'),catalog)
        referenced={entry['object_path'] for entry in catalog['files']}
        boundary=datetime.combine(cutoff,datetime.min.time(),tzinfo=timezone.utc).timestamp()
        for file in objects.iterdir():
            if re.fullmatch(r'[0-9a-f]{64}\.log(?:\.gz)?',file.name) and not file.is_symlink() and file.is_file() and file.stat().st_mtime<boundary and file.relative_to(out).as_posix() not in referenced:
                child(out,file.relative_to(out).as_posix()).unlink()
        return {'exported_files':len(catalog['files']),'skipped':catalog['skipped'],'business_data_exported':False}
