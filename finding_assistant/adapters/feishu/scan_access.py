"""指定 Base 的协作者查询和用户身份扫码读写；绝不回退到应用身份写入。"""
import re
import uuid

import httpx

from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.security.login import AuthenticationError
from finding_assistant.infrastructure.performance import timed
from finding_assistant.infrastructure.http_client import feishu_client
from finding_assistant.security.errors import UpstreamThrottled

ORIGIN = 'https://open.feishu.cn/open-apis'


class NativeScanAccess:
    def __init__(self, config, session=None):
        if not config.app_token:
            raise ValueError('RESOLVED_BASE_TOKEN_REQUIRED')
        for value in (config.app_token, config.scan_table_id):
            if not re.fullmatch(r'[A-Za-z0-9_]+', value):
                raise ValueError('INVALID_TARGET')
        self.config = config
        self.path = f'/bitable/v1/apps/{config.app_token}/tables/{config.scan_table_id}'
        self.http = session if session is not None else feishu_client()

    def close(self):
        self.http.close()

    @timed('feishu_http')
    def _request(self, method, path, token=None, body=None, params=None):
        try:
            r = self.http.request(method, ORIGIN+path, headers={'Authorization': 'Bearer '+token} if token else {},
                                  json=body, params=params, follow_redirects=False)
            if r.status_code == 429:
                raise UpstreamThrottled(r.headers.get('Retry-After'))
            data = r.json()
        except (httpx.HTTPError, ValueError):
            raise AuthorizationUnavailable('Feishu result unconfirmed; retain original request key') from None
        if not isinstance(data, dict):
            raise AuthorizationUnavailable('invalid Feishu response')
        if r.status_code == 403 or data.get('code') in (1254302, 1254304, 1254306):
            raise AccessDenied('Feishu denied this operation')
        if r.status_code == 401:
            raise AuthenticationError('Feishu user authorization expired')
        if not 200 <= r.status_code < 300 or type(data.get('code')) is not int or data['code'] != 0:
            raise AuthorizationUnavailable('Feishu result unconfirmed; retain original request key')
        return data

    @timed('native_permission')
    def direct_permission(self, open_id):
        """应用令牌仅用于查协作者；不将应用自己的权限映射给员工。"""
        auth = self._request('POST', '/auth/v3/tenant_access_token/internal', body={
            'app_id': self.config.app_id, 'app_secret': self.config.app_secret})
        token = auth.get('tenant_access_token')
        if not isinstance(token, str) or not token:
            raise AuthorizationUnavailable('permission lookup unavailable')
        data = self._request('GET', f'/drive/v1/permissions/{self.config.app_token}/members', token,
                             params={'type': 'bitable'}).get('data')
        if not isinstance(data, dict) or not isinstance(data.get('items'), list) or data.get('has_more'):
            raise AuthorizationUnavailable('collaborator response incomplete')
        matches = []
        for item in data['items']:
            if not isinstance(item, dict):
                raise AuthorizationUnavailable('invalid collaborator')
            if item.get('member_type') == 'openid' and item.get('member_id') == open_id:
                matches.append(item.get('perm'))
        if len(matches) > 1 or any(p not in ('full_access', 'edit', 'view') for p in matches):
            raise AuthorizationUnavailable('ambiguous collaborator permission')
        return matches[0] if matches else None

    def records(self, identity, page_token=None):
        # 使用用户令牌，因此高级权限的行/字段可见性仍由飞书执行。
        params = {'page_size':100, 'user_id_type':'open_id'}
        if page_token:
            params['page_token'] = page_token
        return self._request('GET', self.path+'/records', identity.access_token, params=params)['data']

    @timed('flow_write')
    def create(self, identity, request_key, fields):
        operation = uuid.UUID(request_key)
        if operation.version != 4 or operation.variant != uuid.RFC_4122 or str(operation) != request_key:
            raise ValueError('UUID4_REQUEST_KEY_REQUIRED')
        # 三种流水共用此创建入口，由服务端初始化状态；客户端仍不能指定处理结果。
        # 仅补充实际发送的字段，不改原业务输入及其幂等摘要。旧成功请求重放不会调用此处，
        # 因此不会重建旧流水，也不会将已处理或历史空状态记录重置为待处理。
        initial_fields = {**fields, '处理状态': '待处理'}
        return self._request('POST', self.path+'/records', identity.access_token, {'fields': initial_fields},
                             {'client_token': request_key, 'ignore_consistency_check': 'false',
                              'user_id_type': 'open_id'})['data']['record']
