"""普通账号查询的权限/副本分页栅栏；不是授权令牌，不能代替每次权限复核。"""
import hashlib,json,hmac
from finding_assistant.application.workflow import Conflict
from .sql_visibility import VisibilityUnavailable,policy_checksum

def policy_id(policy):
    actual=policy_checksum(policy['roles'])
    if policy.get('policy_hash',actual)!=actual:raise VisibilityUnavailable('NATIVE_POLICY_CHECKSUM_UNCONFIRMED')
    return actual

def scope_token(identity,app,base,table,snapshot,policy):
    values=[identity.tenant_key,identity.open_id,app,base,table,str(snapshot),policy_id(policy),policy.get('revision')]
    return hashlib.sha256(json.dumps(values,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()

def require_scope(expected,actual,offset):
    if offset and expected is None:raise Conflict('query scope is required for the next page; restart query')
    if expected is not None and not hmac.compare_digest(expected,actual):
        raise Conflict('query permission or snapshot changed; restart query')

def verify_policy(directory,identity,policy):
    current=directory.read(identity)
    if policy_id(current)!=policy_id(policy) or current.get('revision')!=policy.get('revision'):
        raise VisibilityUnavailable('NATIVE_VISIBILITY_CHANGED_DURING_QUERY')
