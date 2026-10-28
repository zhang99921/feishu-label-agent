"""指定Base的高级权限只读目录；不读取业务记录，不猜默认角色或群组成员。"""
import re

from finding_assistant.security.sql_visibility import VisibilityUnavailable, policy_checksum
from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.login import AuthenticationError


class NativeVisibilityDirectory:
    def __init__(self, access, default_role_id=''):
        if default_role_id and not re.fullmatch(r'[A-Za-z0-9]+', default_role_id):
            raise ValueError('INVALID_NATIVE_DEFAULT_ROLE')
        self.access = access
        self.base = access.config.app_token
        self.default_role_id = default_role_id

    def _request(self, *args, **kwargs):
        try:
            return self.access._request(*args, **kwargs)
        except (AccessDenied, AuthenticationError):
            # 此处使用应用身份读取权限目录；目录被拒绝不能冒充员工本人已无业务权限。
            raise VisibilityUnavailable('NATIVE_VISIBILITY_METADATA_UNAVAILABLE') from None

    def _pages(self, path, token):
        items, cursor, seen = [], None, set()
        for _ in range(1000):
            params = {'page_size': 100, 'user_id_type': 'open_id'}
            if cursor:
                params['page_token'] = cursor
            data = self._request('GET', path, token, params=params).get('data')
            if not isinstance(data, dict) or type(data.get('has_more')) is not bool or 'items' not in data:
                raise VisibilityUnavailable('NATIVE_VISIBILITY_PAGE_UNCONFIRMED')
            page = data['items']
            if page is None and type(data.get('total')) is int and data['total'] == 0 and not data['has_more']:
                page = []
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise VisibilityUnavailable('NATIVE_VISIBILITY_ITEMS_UNCONFIRMED')
            items.extend(page)
            if not data['has_more']:
                return items
            cursor = data.get('page_token')
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise VisibilityUnavailable('NATIVE_VISIBILITY_CURSOR_UNCONFIRMED')
            seen.add(cursor)
        raise VisibilityUnavailable('NATIVE_VISIBILITY_PAGE_LIMIT')

    def read(self, identity):
        auth = self._request('POST', '/auth/v3/tenant_access_token/internal', body={
            'app_id': self.access.config.app_id, 'app_secret': self.access.config.app_secret})
        token = auth.get('tenant_access_token')
        if not isinstance(token, str) or not token:
            raise VisibilityUnavailable('NATIVE_VISIBILITY_AUTH_UNCONFIRMED')
        app_path = f'/bitable/v1/apps/{self.base}'
        data = self._request('GET', app_path, token).get('data')
        app = data.get('app') if isinstance(data, dict) else None
        if (not isinstance(app, dict) or type(app.get('is_advanced')) is not bool
                or type(app.get('revision')) is not int or app['revision'] < 0):
            raise VisibilityUnavailable('NATIVE_VISIBILITY_VERSION_UNCONFIRMED')
        if app['is_advanced'] is False:
            raise VisibilityUnavailable('ADVANCED_VISIBILITY_NOT_CONFIGURED')
        if app.get('advance_version') != 'v2':
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_VISIBILITY_VERSION')
        roles = self._pages(f'/base/v2/apps/{self.base}/roles', token)
        ids = [role.get('role_id') for role in roles]
        if (any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9]+', v) for v in ids)
                or len(ids) != len(set(ids))):
            raise VisibilityUnavailable('AMBIGUOUS_NATIVE_VISIBILITY_ROLES')
        matched, indirect = [], False
        for role in roles:
            members = self._pages(f"/bitable/v1/apps/{self.base}/roles/{role['role_id']}/members", token)
            direct = False
            for member in members:
                if member.get('member_type') != 'user':
                    # 只有明确直接用户成员可证明归属，部门/群组不会转化为全量授权。
                    indirect = True
                    continue
                identifier = member.get('open_id')
                if not isinstance(identifier, str) or not identifier:
                    raise VisibilityUnavailable('NATIVE_USER_MEMBERSHIP_UNCONFIRMED')
                direct = direct or identifier == identity.open_id
            if direct and role['role_id'] != self.default_role_id:
                matched.append(role)
        if not matched:
            default = next((role for role in roles if role['role_id'] == self.default_role_id), None)
            if default is None or indirect:
                raise VisibilityUnavailable('NATIVE_DEFAULT_OR_INDIRECT_MEMBERSHIP_UNCONFIRMED')
            # 必须由运维确认并显式配置原生默认角色ID；不按名字或空成员列表推断。
            matched = [default]
        data = self._request('GET', app_path, token).get('data')
        after = data.get('app') if isinstance(data, dict) else None
        if (not isinstance(after, dict) or after.get('is_advanced') is not True
                or after.get('advance_version') != 'v2' or after.get('revision') != app.get('revision')):
            raise VisibilityUnavailable('NATIVE_VISIBILITY_CHANGED_DURING_READ')
        return {'roles': matched, 'policy_hash': policy_checksum(matched), 'revision': app.get('revision')}
