"""OAuth PKCE login foundation. No tenant-token fallback, no inventory permissions.

Sessions/challenges are process-local for the loopback experiment. HTTP routing,
cookie settings and production session persistence are separate responsibilities.
"""
import base64
import hashlib
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx

AUTHORIZE = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
# Current official authorize documentation supports PKCE with this endpoint;
# the v3 pairing was actually rejected with 20049. Never drop PKCE to hide it.
TOKEN = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
USERINFO = "https://open.feishu.cn/open-apis/authen/v1/user_info"
LOGIN_SCOPE = "auth:user.id:read"


class AuthenticationError(Exception):
    pass


@dataclass(frozen=True)
class UserSession:
    open_id: str
    tenant_key: str
    expires_at: float
    access_token: str = field(repr=False)


class OAuthProvider:
    def __init__(self, app_id, app_secret, session=None):
        self.app_id, self._secret = app_id, app_secret
        self.http = session or httpx.Client(verify=ssl.create_default_context(), trust_env=True,
                                            follow_redirects=False, timeout=20)

    def _request(self, method, url, **kwargs):
        if url not in (TOKEN, USERINFO):
            raise AuthenticationError("unsupported identity endpoint")
        try:
            response = self.http.request(method, url, follow_redirects=False, **kwargs)
            result = response.json()
            if not 200 <= response.status_code < 300:
                api_code = result.get("code") if isinstance(result, dict) else None
                api_code = api_code if type(api_code) is int else "unknown"
                raise AuthenticationError(f"identity request rejected HTTP {response.status_code} API {api_code}")
            if not isinstance(result, dict) or type(result.get("code")) is not int or result["code"] != 0:
                raise AuthenticationError("Feishu identity response not successful")
            return result
        except (httpx.HTTPError, ValueError, UnicodeError):
            # Do not include response, URL parameters, token, secret or transport details.
            raise AuthenticationError("identity service unavailable or invalid response") from None

    def exchange(self, code, redirect_uri, verifier):
        return self._request("POST", TOKEN, data={"grant_type": "authorization_code",
            "client_id": self.app_id, "client_secret": self._secret, "code": code,
            "redirect_uri": redirect_uri, "code_verifier": verifier})

    def identity(self, access_token):
        data = self._request("GET", USERINFO, headers={"Authorization": "Bearer " + access_token}).get("data")
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k] for k in ("open_id", "tenant_key")):
            raise AuthenticationError("verified identity is missing")
        # Never return phone/email/name or infer identity from a caller's fields.
        return {k:data[k] for k in ("open_id", "tenant_key")}

    def close(self):
        self.http.close()


class LoginService:
    def __init__(self, provider, redirect_uri, clock=time.monotonic):
        url = urlsplit(redirect_uri)
        loopback = url.hostname == "127.0.0.1" and url.scheme == "http"
        if (url.scheme != "https" and not loopback) or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise AuthenticationError("unsafe server redirect configuration")
        self.provider, self.redirect_uri, self.clock = provider, redirect_uri, clock
        self._challenges, self._sessions = {}, {}
        self._lock = threading.RLock()
        self.last_stage = "idle"

    @staticmethod
    def _key(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def begin(self, browser_binding):
        if not isinstance(browser_binding, str) or len(browser_binding) < 32:
            raise AuthenticationError("browser binding required")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with self._lock:
            self._challenges = {k:v for k,v in self._challenges.items() if v["expires"] > self.clock()}
            self._challenges[self._key(state)] = {"binding": self._key(browser_binding),
                                                 "verifier": verifier, "expires": self.clock()+300}
        return AUTHORIZE + "?" + urlencode({"client_id": self.provider.app_id, "response_type": "code",
            "redirect_uri": self.redirect_uri, "scope": LOGIN_SCOPE, "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256"})

    def finish(self, state, browser_binding, code, error=None):
        self.last_stage = "browser_state"
        if not all(isinstance(v, str) and v for v in (state, browser_binding)):
            raise AuthenticationError("login context missing")
        with self._lock:
            challenge = self._challenges.get(self._key(state))
            if not challenge or challenge["expires"] <= self.clock() or not secrets.compare_digest(challenge["binding"], self._key(browser_binding)):
                raise AuthenticationError("invalid or expired login context")
            del self._challenges[self._key(state)]  # consume BEFORE external exchange
        if error or not isinstance(code, str) or not code:
            raise AuthenticationError("login denied or incomplete")
        self.last_stage = "token_exchange"
        result = self.provider.exchange(code, self.redirect_uri, challenge["verifier"])
        self.last_stage = "token_fields"
        access, seconds = result.get("access_token"), result.get("expires_in")
        if (not isinstance(access, str) or not access or type(seconds) is not int or seconds <= 0 or
                result.get("token_type") != "Bearer" or not isinstance(result.get("scope"), str) or
                LOGIN_SCOPE not in result["scope"].split()):
            raise AuthenticationError("token response missing required identity authorization")
        self.last_stage = "user_info"
        identity = self.provider.identity(access)
        session_id = secrets.token_urlsafe(32)
        session = UserSession(identity["open_id"], identity["tenant_key"], self.clock()+min(seconds, 3600), access)
        with self._lock:
            self._sessions = {k:v for k,v in self._sessions.items() if v.expires_at > self.clock()}
            self._sessions[self._key(session_id)] = session
        self.last_stage = "complete"
        return session_id

    def session(self, session_id):
        if not isinstance(session_id, str) or not session_id:
            raise AuthenticationError("login required")
        with self._lock:
            session = self._sessions.get(self._key(session_id))
            if not session or session.expires_at <= self.clock():
                self._sessions.pop(self._key(session_id), None)
                raise AuthenticationError("login expired or unavailable")
        # Detect disabled users/revoked user credentials on each authorization attempt.
        identity = self.provider.identity(session.access_token)
        if identity != {"open_id":session.open_id, "tenant_key":session.tenant_key}:
            self.logout(session_id)
            raise AuthenticationError("verified identity changed")
        return session

    def logout(self, session_id):
        with self._lock:
            self._sessions.pop(self._key(session_id), None)
