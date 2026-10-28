"""查询仅访问SQL；鉴权仍按飞书当前身份执行。全量副本不能冒充普通用户的可见范围。"""
from finding_assistant.security.native_access import verified_authorize
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.infrastructure.business_sync import ReplicaUnavailable
from finding_assistant.security.query_scope import scope_token,require_scope,verify_policy
from finding_assistant.application.workflow import Conflict


class SqlInventoryQuery:
    def __init__(self, gate, replica, box_table_id, *, visibility_directory=None, row_table_id=None, app_id=None, journal=None, detail_tables=None):
        if box_table_id not in replica.config.table_ids:
            raise ValueError('SQL_BOX_TABLE_NOT_IN_SYNC_SCOPE')
        self.gate, self.replica, self.box_table_id = gate, replica, box_table_id
        self.directory, self.journal = visibility_directory, journal
        self.details_reader = None
        if detail_tables is not None:
            if set(detail_tables)-{'flows','details','ledger'}:
                raise ValueError('INVALID_DETAIL_TABLE_ROLE')
            from finding_assistant.infrastructure.inventory_details import InventoryDetails
            self.details_reader = InventoryDetails(replica, {'box':box_table_id,**detail_tables})
        self.scoped = None
        if visibility_directory is not None:
            from finding_assistant.infrastructure.scoped_inventory_queries import ScopedInventoryQueries
            self.scoped = ScopedInventoryQueries(replica, app_id, box_table_id, row_table_id)

    def authorize(self, session_id):
        identity = verified_authorize(self.gate, session_id, 'QUERY')
        if identity.permission != 'full_access' and (self.scoped is None or identity.permission not in ('edit', 'view')):
            if self.journal:
                self.journal.audit_sql_query(identity, 'DENIED')
            raise AccessDenied('SQL visibility scope has not been verified for this account')
        return identity

    def _read(self, session_id, filters, status_only=False):
        identity = self.authorize(session_id)
        try:
            if identity.permission == 'full_access':
                if filters.pop('visibility_token',None) is not None:
                    raise Conflict('query permission scope changed; restart query')
                result = self.replica.status() if status_only else self.replica.boxes(table_id=self.box_table_id, **filters)
            else:
                result = self.scoped.boxes(identity, self.directory, **filters)
                if status_only:
                    result = result['replica']
        except (AuthorizationUnavailable,ReplicaUnavailable):
            if self.journal:
                self.journal.audit_sql_query(identity, 'UNAVAILABLE')
            raise
        except AccessDenied:
            if self.journal:
                self.journal.audit_sql_query(identity, 'DENIED')
            raise
        if self.journal:
            self.journal.audit_sql_query(identity, 'ALLOWED')
        return result

    def boxes(self, session_id, **filters):
        return self._read(session_id, filters)

    def status(self, session_id):
        return self._read(session_id, {'limit': 1}, status_only=True)

    def readiness(self,session_id):
        identity=verified_authorize(self.gate,session_id,'QUERY')
        if identity.permission!='full_access' and self.scoped is None:
            return {'allowed':False,'reason':'SQL_VISIBILITY_NOT_ENABLED','read_only':True}
        try:
            self._read(session_id,{'limit':1})
        except (AuthorizationUnavailable,ReplicaUnavailable):
            return {'allowed':False,'reason':'SQL_VISIBILITY_UNCONFIRMED','read_only':True}
        except AccessDenied:
            return {'allowed':False,'reason':'SQL_ACCESS_DENIED','read_only':True}
        return {'allowed':True,'reason':'QUERY_SCOPE_VERIFIED','read_only':True}

    def details(self, session_id, record_id, **options):
        expected_scope=options.pop('visibility_token',None)
        identity=self.authorize(session_id)
        if self.details_reader is None:
            raise AuthorizationUnavailable('SQL detail query is not configured')
        try:
            policy=self.directory.read(identity) if identity.permission!='full_access' else None
            if policy is None and expected_scope is not None:raise Conflict('query permission scope changed; restart query')
            result=self.details_reader.read(record_id,policy=policy,**options)
            if policy is not None:
                token=scope_token(identity,self.scoped.app_id,self.replica.base,self.box_table_id,result['backup_id'],policy)
                require_scope(expected_scope,token,options.get('offset',0))
                verify_policy(self.directory,identity,policy)
                result['visibility_token']=token
        except (AuthorizationUnavailable,ReplicaUnavailable):
            if self.journal:self.journal.audit_sql_query(identity,'UNAVAILABLE')
            raise
        except AccessDenied:
            if self.journal:self.journal.audit_sql_query(identity,'DENIED')
            raise
        if self.journal:self.journal.audit_sql_query(identity,'ALLOWED')
        return result
