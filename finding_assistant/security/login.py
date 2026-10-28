# 飞书 OAuth 登录：PKCE + 一次性 state + 浏览器绑定，换取用户身份后签发本地随机会话ID。
# 登录只证明“是谁”；能操作哪些批次和表仍由 PermissionGate 判定。
# 显式注入 store 时使用 PostgreSQL 持久会话；未注入时仅供本地内存测试。
"""OAuth PKCE login foundation. No tenant-token fallback, no inventory permissions.

Inject PostgreSQL storage for persistent sessions and one-time challenges; the
no-store mode remains available for isolated local tests.
"""
import base64
import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx

from .errors import AuthorizationUnavailable
from finding_assistant.infrastructure.performance import timed
from finding_assistant.infrastructure.http_client import feishu_client

AUTHORIZE = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
# Current official authorize documentation supports PKCE with this endpoint;
# the v3 pairing was actually rejected with 20049. Never drop PKCE to hide it.
TOKEN = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
USERINFO = "https://open.feishu.cn/open-apis/authen/v1/user_info"
LOGIN_SCOPE = "auth:user.id:read"
REFRESH_SCOPE = "offline_access"
DEFAULT_SESSION_SECONDS = 12 * 60 * 60
REFRESH_MARGIN_SECONDS = 60
IDENTITY_LOG = logging.getLogger('finding_assistant.identity')


def session_duration(values):
    """绝对会话期限由部署环境配置；用户请求不能改变此值。"""
    value = values.get('FINDING_ASSISTANT_SESSION_SECONDS', str(DEFAULT_SESSION_SECONDS))
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError('INVALID_SESSION_DURATION')
    seconds = int(value)
    if not 300 <= seconds <= 86400:
        raise ValueError('INVALID_SESSION_DURATION')
    return seconds


class AuthenticationError(Exception):
    pass


class IdentityUnavailable(AuthorizationUnavailable):
    """身份服务结果尚未核实，与令牌失效或用户无权限分别处理。"""
    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def validate_redirect_uri(redirect_uri):
    """只检查回调地址，不联网，不将配置值加入错误信息。"""
    try:
        url = urlsplit(redirect_uri)
        loopback = url.hostname == "127.0.0.1" and url.scheme == "http"
        valid = ((url.scheme == "https" or loopback) and url.hostname
                 and not url.username and not url.password and not url.query and not url.fragment)
        # 触发端口格式校验，防止错误端口通过配置检查。
        port = url.port
        if not valid or (port is not None and not 1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise AuthenticationError("unsafe server redirect configuration") from None
    return url


# 保存已核实的用户/租户和过期时间；用户令牌不出现在默认对象打印中。
@dataclass(frozen=True)
class UserSession:
    open_id: str
    tenant_key: str
    expires_at: float
    access_token: str = field(repr=False)
    access_expires_at: float | None = None
    refresh_token: str | None = field(default=None, repr=False)
    refresh_expires_at: float | None = None
    scopes: tuple[str, ...] = ()


class OAuthProvider:
    def __init__(self, app_id, app_secret, session=None):
        self.app_id, self._secret = app_id, app_secret
        self.http = session if session is not None else feishu_client()

    # 只允许指定身份接口，拒绝重定向；异常信息不携带授权码、令牌或密钥。
    def _request(self, method, url, **kwargs):
        if url not in (TOKEN, USERINFO):
            raise AuthenticationError("unsupported identity endpoint")
        # 只读身份接口最多两次；一次性授权码/刷新凭据绝不自动重放。
        read_identity = method == 'GET' and url == USERINFO
        max_attempts = 2 if read_identity else 1
        diagnostic_id = secrets.token_hex(8)
        for attempt in range(1, max_attempts + 1):
            try:
                return self._attempt(method, url, attempt, diagnostic_id, **kwargs)
            except IdentityUnavailable as error:
                if not (read_identity and attempt == 1 and error.retryable):
                    raise
                time.sleep(0.2)

    @timed('oauth_http')
    def _attempt(self, method, url, attempt, diagnostic_id, **kwargs):
        endpoint = 'USERINFO' if url == USERINFO else 'TOKEN'
        def record(outcome, status=0, api_code=0):
            # 不记录URL、请求/响应原文、账号、授权码或异常字符串。
            IDENTITY_LOG.info('identity_call=%s identity_endpoint=%s attempt=%s outcome=%s http_status=%s api_code=%s',
                              diagnostic_id, endpoint, attempt, outcome, status, api_code)
        try:
            response = self.http.request(method, url, follow_redirects=False, **kwargs)
            # 服务不可用与身份失效分开：暂时故障不引导用户重复登录。
            if response.status_code == 429 or response.status_code >= 500:
                record('THROTTLED' if response.status_code == 429 else 'UPSTREAM_ERROR', response.status_code)
                raise IdentityUnavailable("identity service temporarily unavailable",
                                          retryable=response.status_code in (502, 503, 504))
            if 300 <= response.status_code < 400:
                record('REDIRECT_REFUSED', response.status_code)
                raise AuthenticationError("identity redirect refused")
            result = response.json()
            if not 200 <= response.status_code < 300:
                api_code = result.get("code") if isinstance(result, dict) else None
                api_code = api_code if type(api_code) is int else "unknown"
                record('REJECTED', response.status_code, api_code)
                raise AuthenticationError(f"identity request rejected HTTP {response.status_code} API {api_code}")
            if not isinstance(result, dict) or type(result.get("code")) is not int:
                record('INVALID_RESPONSE', response.status_code)
                raise IdentityUnavailable("identity response unconfirmed")
            if result["code"] != 0:
                record('REJECTED', response.status_code, result['code'])
                raise AuthenticationError("Feishu identity response not successful")
            record('SUCCESS', response.status_code)
            return result
        except httpx.TransportError as error:
            category = ('CONNECT_TIMEOUT' if isinstance(error, httpx.ConnectTimeout) else
                        'CONNECT_ERROR' if isinstance(error, httpx.ConnectError) else
                        'READ_TIMEOUT' if isinstance(error, httpx.ReadTimeout) else 'TRANSPORT_UNAVAILABLE')
            record(category)
            # 读超时可能来自慢响应，不叠加第二次最长等待；仅连接建立失败可重试。
            raise IdentityUnavailable('identity service unavailable',
                                      retryable=isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout))) from None
        except (httpx.HTTPError, ValueError, UnicodeError):
            record('INVALID_RESPONSE')
            # Do not include response, URL parameters, token, secret or transport details.
            raise IdentityUnavailable("identity service unavailable or invalid response") from None

    def exchange(self, code, redirect_uri, verifier):
        return self._request("POST", TOKEN, data={"grant_type": "authorization_code",
            "client_id": self.app_id, "client_secret": self._secret, "code": code,
            "redirect_uri": redirect_uri, "code_verifier": verifier})

    def refresh(self, refresh_token):
        # 不传scope缩减授权；刷新后仍校验原来要求的权限集合。
        return self._request('POST', TOKEN, data={'grant_type': 'refresh_token',
            'client_id': self.app_id, 'client_secret': self._secret, 'refresh_token': refresh_token})

    # 只取服务端核实的 open_id、tenant_key，不以调用方传入的姓名或ID认定身份。
    def identity(self, access_token):
        data = self._request("GET", USERINFO, headers={"Authorization": "Bearer " + access_token}).get("data")
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k] for k in ("open_id", "tenant_key")):
            raise IdentityUnavailable("verified identity is missing")
        # Never return phone/email/name or infer identity from a caller's fields.
        return {k:data[k] for k in ("open_id", "tenant_key")}

    def close(self):
        self.http.close()


class LoginService:
    def __init__(self, provider, redirect_uri, clock=None, *, scopes=None, store=None,
                 session_seconds=DEFAULT_SESSION_SECONDS):
        validate_redirect_uri(redirect_uri)
        if type(session_seconds) is not int or not 300 <= session_seconds <= 86400:
            raise ValueError('INVALID_SESSION_DURATION')
        self.session_seconds = session_seconds
        self.store = store
        self.provider, self.redirect_uri = provider, redirect_uri
        self.clock = clock or (time.time if store is not None else time.monotonic)
        self.scopes = tuple(scopes or (LOGIN_SCOPE,))
        if LOGIN_SCOPE not in self.scopes or any(not isinstance(s, str) or not s or any(c.isspace() for c in s) for s in self.scopes):
            raise AuthenticationError("invalid login scopes")
        self._challenges, self._sessions = {}, {}
        self._refresh_unknown = set()
        self._lock = threading.RLock()
        self.last_stage = "idle"

    @staticmethod
    def _key(value):
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def _tokens(result, required_scopes):
        if not isinstance(result, dict):
            raise AuthenticationError('invalid token response')
        access, seconds = result.get('access_token'), result.get('expires_in')
        granted = result.get('scope')
        if (not isinstance(access, str) or not access or type(seconds) is not int or seconds <= 0 or
                result.get('token_type') != 'Bearer' or not isinstance(granted, str) or
                not set(required_scopes).issubset(granted.split())):
            raise AuthenticationError('token response missing required identity authorization')
        refresh, refresh_seconds = result.get('refresh_token'), result.get('refresh_token_expires_in')
        if REFRESH_SCOPE in required_scopes and (not isinstance(refresh, str) or not refresh or
                type(refresh_seconds) is not int or refresh_seconds <= 0):
            raise AuthenticationError('offline authorization and refresh credentials required')
        if REFRESH_SCOPE not in required_scopes:
            refresh, refresh_seconds = None, None
        return access, seconds, refresh, refresh_seconds

    def _renew(self, session, started_at):
        result = self.provider.refresh(session.refresh_token)
        try:
            access, seconds, refresh, refresh_seconds = self._tokens(result, session.scopes)
        except AuthenticationError:
            # 成功响应不完整时，旧刷新凭据可能已消耗，不能用旧凭据重试。
            raise IdentityUnavailable('refresh result unconfirmed; sign in again') from None
        identity = self.provider.identity(access)
        if identity != {'open_id': session.open_id, 'tenant_key': session.tenant_key}:
            raise AuthenticationError('verified identity changed during refresh')
        return UserSession(session.open_id, session.tenant_key, session.expires_at, access,
                           started_at + seconds, refresh, started_at + refresh_seconds, session.scopes)

    # 为当前浏览器创建五分钟有效的登录挑战；仅保存 state 和浏览器绑定值的摘要。
    def begin(self, browser_binding):
        if not isinstance(browser_binding, str) or len(browser_binding) < 32:
            raise AuthenticationError("browser binding required")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        value = {"binding":self._key(browser_binding),"verifier":verifier,"expires":self.clock()+300}
        if self.store is not None:
            self.store.put_challenge(self._key(state),value)
        else:
            with self._lock:
                self._challenges = {k:v for k,v in self._challenges.items() if v["expires"] > self.clock()}
                self._challenges[self._key(state)] = value
        return AUTHORIZE + "?" + urlencode({"client_id": self.provider.app_id, "response_type": "code",
            "redirect_uri": self.redirect_uri, "scope": " ".join(self.scopes), "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256"})

    # 核对浏览器绑定和 state 后先消费挑战，再换令牌；防止同一回调被重复兑换。
    def finish(self, state, browser_binding, code, error=None):
        self.last_stage = "browser_state"
        if not all(isinstance(v, str) and v for v in (state, browser_binding)):
            raise AuthenticationError("login context missing")
        if self.store is not None:
            challenge = self.store.consume_challenge(self._key(state),self._key(browser_binding),self.clock())
            if not challenge:
                raise AuthenticationError("invalid or expired login context")
        else:
            with self._lock:
                challenge = self._challenges.get(self._key(state))
                if not challenge or challenge["expires"] <= self.clock() or not secrets.compare_digest(challenge["binding"], self._key(browser_binding)):
                    raise AuthenticationError("invalid or expired login context")
                del self._challenges[self._key(state)]  # consume BEFORE external exchange
        if error or not isinstance(code, str) or not code:
            raise AuthenticationError("login denied or incomplete")
        self.last_stage = "token_exchange"
        issued_at = self.clock()
        result = self.provider.exchange(code, self.redirect_uri, challenge["verifier"])
        self.last_stage = "token_fields"
        access, seconds, refresh, refresh_seconds = self._tokens(result, self.scopes)
        self.last_stage = "user_info"
        identity = self.provider.identity(access)
        session_id = secrets.token_urlsafe(32)
        now = self.clock()
        if issued_at + seconds <= now:
            raise AuthenticationError('access token expired during login')
        deadline = now + self.session_seconds if refresh else min(now + self.session_seconds, issued_at + seconds)
        session = UserSession(identity['open_id'], identity['tenant_key'], deadline, access,
                              issued_at + seconds, refresh,
                              issued_at + refresh_seconds if refresh else None, self.scopes)
        if self.store is not None:
            self.store.put_session(self._key(session_id),session)
        else:
            with self._lock:
                self._sessions = {k:v for k,v in self._sessions.items() if v.expires_at > self.clock()}
                self._sessions[self._key(session_id)] = session
        self.last_stage = "complete"
        return session_id

    # 普通请求仅校验持久会话；必要时按原有锁机制刷新令牌。
    @timed('local_session')
    def local_session(self, session_id):
        if not isinstance(session_id, str) or not session_id:
            raise AuthenticationError("login required")
        if self.store is not None:
            session = self.store.session_for_request(self._key(session_id), self.clock(), self._renew, self.clock)
            if not session:
                raise AuthenticationError("login expired or unavailable")
        else:
            with self._lock:
                key = self._key(session_id)
                if key in self._refresh_unknown:
                    raise AuthenticationError('refresh result unconfirmed; sign in again')
                session = self._sessions.get(key)
                if not session or session.expires_at <= self.clock():
                    self._sessions.pop(key, None)
                    raise AuthenticationError("login expired or unavailable")
                access_deadline = session.access_expires_at or session.expires_at
                if session.refresh_token and access_deadline <= self.clock() + REFRESH_MARGIN_SECONDS:
                    if not session.refresh_expires_at or session.refresh_expires_at <= self.clock():
                        self._sessions.pop(key, None)
                        raise AuthenticationError('refresh credentials expired; sign in again')
                    try:
                        session = self._renew(session, self.clock())
                        if session.expires_at <= self.clock():
                            raise AuthenticationError('login expired during refresh')
                        self._sessions[key] = session
                    except AuthenticationError:
                        self._sessions.pop(key, None)
                        raise
                    except Exception:
                        self._refresh_unknown.add(key)
                        raise IdentityUnavailable('refresh result unconfirmed; sign in again') from None
        if session.expires_at <= self.clock() or (session.access_expires_at or session.expires_at) <= self.clock():
            self.logout(session_id)
            raise AuthenticationError('session or access token expired')
        return session

    @timed('login_identity')
    def session(self, session_id):
        """执行/敏感SQL读取边界显式复核远端身份，保留旧调用契约。"""
        session = self.local_session(session_id)
        try:
            identity = self.provider.identity(session.access_token)
        except AuthenticationError:
            self.logout(session_id)
            raise
        if session.expires_at <= self.clock():
            self.logout(session_id)
            raise AuthenticationError('login expired during identity verification')
        if identity != {"open_id":session.open_id, "tenant_key":session.tenant_key}:
            self.logout(session_id)
            raise AuthenticationError("verified identity changed")
        return session

    # 删除本地会话；不会修改飞书账号或文档角色配置。
    def logout(self, session_id):
        if self.store is not None:
            self.store.revoke_session(self._key(session_id))
            return
        with self._lock:
            key = self._key(session_id)
            self._sessions.pop(key, None)
            self._refresh_unknown.discard(key)
