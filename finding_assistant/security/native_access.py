"""飞书四档协作权限直接映射业务角色；不维护自定义角色成员。"""
from dataclasses import dataclass, field

from .errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.infrastructure.performance import timed
from finding_assistant.infrastructure.request_scope import current_scope

PERMISSION_ROLES = {'full_access': 'admin', 'edit': 'operator', 'view': 'query', 'none': None}
ROLE_ACTIONS = {
    'admin': frozenset({'QUERY', 'IN', 'OUT', 'MOVE', 'ADMIN'}),
    'operator': frozenset({'QUERY', 'IN', 'OUT', 'MOVE'}),
    'query': frozenset({'QUERY'}),
}


@dataclass(frozen=True)
class NativeIdentity:
    open_id: str
    role: str
    permission: str
    access_token: str = field(repr=False)
    tenant_key: str = ''


class NativePermissionGate:
    """每次请求重新核实登录和权限，不接受请求体声明的身份或角色。"""
    def __init__(self, login, directory, tenant_key, audit=None):
        if not isinstance(tenant_key, str) or not tenant_key.strip():
            raise ValueError('TRUSTED_TENANT_REQUIRED')
        self.login, self.directory, self.tenant_key = login, directory, tenant_key
        self.audit = audit

    @timed('authorize')
    def authorize(self, session_id, action, *, verify_identity=False):
        scope = current_scope()
        if scope is None:
            return self._authorize(session_id, action, None, verify_identity)
        # 同请求线程间共享；不同请求、gate 和会话不会共用身份。
        with scope.lock:
            return self._authorize(session_id, action, scope, verify_identity)

    def _authorize(self, session_id, action, scope, verify_identity):
        if action not in {'QUERY', 'IN', 'OUT', 'MOVE', 'ADMIN'}:
            raise AccessDenied('unsupported operation')
        from .login import LoginService
        key = ('native_identity', self, session_id)
        cached = scope.values.get(key) if scope is not None else None
        if isinstance(self.login, LoginService):
            # 即使本次请求已有权限结果，也读取本地会话，及时发现注销/过期。
            session = self.login.local_session(session_id)
            stamp = (session.open_id, session.tenant_key, session.access_token)
            verified_key = ('native_verified_identity', self, session_id)
            verified = scope.values.get(verified_key) if scope is not None else None
            if verify_identity and verified != stamp:
                session = self.login.session(session_id)
                stamp = (session.open_id, session.tenant_key, session.access_token)
                if scope is not None: scope.values[verified_key] = stamp
            if cached is not None:
                previous, permission = cached
                if (previous.open_id, previous.tenant_key, previous.access_token) == stamp:
                    return self._decision(session, action, permission)
                scope.values.pop(key, None)
        else:
            # 兼容现有注入型登录实现；只有真实LoginService提供本地会话契约。
            if cached is not None:
                session, permission = cached
                deadline = session.access_expires_at or session.expires_at
                if self.login.clock() < session.expires_at and self.login.clock() + 60 < deadline:
                    return self._decision(session, action, permission)
                scope.values.pop(key, None)
            session = self.login.session(session_id)
        if session.tenant_key != self.tenant_key:
            if self.audit:self.audit.audit_permission(session,action,None,'DENIED_TENANT')
            raise AccessDenied('account belongs to another tenant')
        try:
            permission = self.directory.direct_permission(session.open_id)
        except (AccessDenied,AuthorizationUnavailable):
            if self.audit:self.audit.audit_permission(session,action,None,'UNAVAILABLE')
            raise
        # 未出现在直接协作者列表中也可能有群组/链接权限，不能猜测其档位。
        if permission not in PERMISSION_ROLES:
            if self.audit:self.audit.audit_permission(session,action,None,'UNRESOLVED')
            raise AuthorizationUnavailable('native permission is unresolved')
        result = self._decision(session, action, permission)
        # 只保存具有明确期限的成功身份；每个 action 仍单独检查和审计。
        from .login import UserSession
        if scope is not None and isinstance(session, UserSession):
            scope.values[key] = (session, permission)
        return result

    def _decision(self, session, action, permission):
        role = PERMISSION_ROLES[permission]
        if action not in ROLE_ACTIONS.get(role, ()):
            if self.audit:self.audit.audit_permission(session,action,permission,'DENIED')
            raise AccessDenied('native permission does not allow this operation')
        if self.audit:self.audit.audit_permission(session,action,permission,'ALLOWED')
        return NativeIdentity(session.open_id, role, permission, session.access_token, session.tenant_key)


def verified_authorize(gate, session_id, action):
    """显式敏感边界；其他授权实现沿用自身契约，不探测Mock动态属性。"""
    if isinstance(gate, NativePermissionGate):
        return gate.authorize(session_id, action, verify_identity=True)
    return gate.authorize(session_id, action)
