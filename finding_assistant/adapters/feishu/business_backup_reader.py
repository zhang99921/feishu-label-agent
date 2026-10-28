"""只读拉取表、字段定义和记录。唯一POST用于应用鉴权，不提供业务写接口。"""
import re

from .existing_forms import ExistingFormsReader, SourceUnavailable


class BusinessBackupReader:
    def __init__(self,config,session=None):
        self.source=ExistingFormsReader(config,session)

    @property
    def base_token(self):return self.source.app_token

    def _page_batches(self,path,extra_params=None):
        """记录页消费完即可释放；不在读取器中累积整张业务表。"""
        cursor=None;seen=set()
        for _ in range(10000):
            params={'page_size':100,'user_id_type':'open_id'}
            if extra_params:params.update(extra_params)
            if cursor:params['page_token']=cursor
            data=self.source._request('GET',path,params=params).get('data')
            # 飞书的空记录列表可能省略items；仅明确声明total=0且已结束时视为空表。
            if (isinstance(data,dict) and 'items' not in data and type(data.get('total')) is int
                    and data['total']==0 and data.get('has_more') is False):
                data={**data,'items':[]}
            if not isinstance(data,dict) or not isinstance(data.get('items'),list) or type(data.get('has_more')) is not bool:
                raise SourceUnavailable('BACKUP_PAGE_UNCONFIRMED')
            if len(data['items'])>100:raise SourceUnavailable('BACKUP_PAGE_SIZE_UNCONFIRMED')
            yield data['items']
            if not data['has_more']:return
            cursor=data.get('page_token')
            if not isinstance(cursor,str) or not cursor or cursor in seen:
                raise SourceUnavailable('BACKUP_CURSOR_UNCONFIRMED')
            seen.add(cursor)
        raise SourceUnavailable('BACKUP_PAGE_LIMIT')

    def _pages(self,path):
        # 表目录和字段元数据很小；手工备份的兼容入口也复用此方法。
        return [item for page in self._page_batches(path) for item in page]

    def _table_catalog(self,table_ids):
        if table_ids is not None and (not table_ids or len(set(table_ids))!=len(table_ids) or
            any(not isinstance(t,str) or not re.fullmatch(r'[A-Za-z0-9]+',t) for t in table_ids)):
            raise ValueError('INVALID_BACKUP_TABLE_IDS')
        self.source.login()
        root=f'/bitable/v1/apps/{self.base_token}/tables'
        tables=self._pages(root)
        by_id={t['table_id']:t for t in tables}
        if len(by_id)!=len(tables):raise SourceUnavailable('BACKUP_TABLES_AMBIGUOUS')
        ids=table_ids if table_ids is not None else list(by_id)
        if any(t not in by_id for t in ids):raise SourceUnavailable('BACKUP_TABLE_NOT_FOUND')
        return root,by_id,ids

    def stream_catalog(self,table_ids):
        """只读事件流。结束事件表示该表已读完且字段定义复核一致。"""
        root,by_id,ids=self._table_catalog(table_ids)
        for tid in ids:
            fields=self._pages(root+'/'+tid+'/fields')
            yield {'event':'table','table_id':tid,'table_name':by_id[tid]['name'],'fields':fields}
            for page in self._page_batches(root+'/'+tid+'/records'):
                yield {'event':'records','table_id':tid,'records':page}
            if fields!=self._pages(root+'/'+tid+'/fields'):
                raise SourceUnavailable('BACKUP_SCHEMA_CHANGED')
            yield {'event':'end_table','table_id':tid}

    def catalog(self,table_ids=None):
        root,by_id,ids=self._table_catalog(table_ids)
        result=[]
        for tid in ids:
            fields=self._pages(root+'/'+tid+'/fields')
            records=self._pages(root+'/'+tid+'/records')
            if fields!=self._pages(root+'/'+tid+'/fields'):
                raise SourceUnavailable('BACKUP_SCHEMA_CHANGED')
            result.append({'table_id':tid,'table_name':by_id[tid]['name'],'fields':fields,'records':records})
        # 记录分多次HTTP读取，不能把此副本称为飞书跨表ACID快照。
        return result

    def close(self):self.source.close()
