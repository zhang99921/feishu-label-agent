"""运维清单游标：绑定筛选范围及扫描时点，不承载身份或授权。"""
import base64
from datetime import datetime
import hashlib
import json
import re


def scope_key(app_id, base_token, age):
    return hashlib.sha256(json.dumps([app_id,base_token,age],ensure_ascii=True,
                                    separators=(',',':')).encode()).hexdigest()


def decode_cursor(value, scope):
    try:
        if not isinstance(value,str) or not 1 <= len(value) <= 4096 or not re.fullmatch(r'[A-Za-z0-9_-]+',value):
            raise ValueError
        payload=json.loads(base64.b64decode(value+'='*(-len(value)%4),altchars=b'-_',validate=True))
        if not isinstance(payload,dict) or set(payload)!={'v','scope','as_of','priority','updated_at','source_key'}:
            raise ValueError
        if type(payload['v']) is not int or payload['v']!=1 or payload['scope']!=scope:
            raise ValueError
        if type(payload['priority']) is not int or payload['priority'] not in (0,1):
            raise ValueError
        source=payload['source_key']
        if not isinstance(source,str) or not source.strip() or len(source)>512 or any(ord(c)<32 for c in source):
            raise ValueError
        for key in ('as_of','updated_at'):
            if not isinstance(payload[key],str) or len(payload[key])>64:
                raise ValueError
            value=datetime.fromisoformat(payload[key])
            if value.tzinfo is None or value.utcoffset() is None or value.year<1970:
                raise ValueError
            payload[key]=value
        if payload['updated_at']>payload['as_of']:
            raise ValueError
        return payload
    except (ValueError,TypeError,KeyError,UnicodeError,OverflowError,RecursionError):
        raise ValueError('INVALID_ATTENTION_CURSOR') from None


def encode_cursor(scope, as_of, row):
    payload={'v':1,'scope':scope,'as_of':as_of.isoformat(),
        'priority':0 if row['state']=='RECONCILE' else 1,
        'updated_at':row['updated_at'].isoformat(),'source_key':row['source_key']}
    return base64.urlsafe_b64encode(json.dumps(payload,ensure_ascii=True,separators=(',',':')).encode()).decode().rstrip('=')
