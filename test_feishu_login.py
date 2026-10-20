import json
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx

from feishu_login import AuthenticationError, LoginService, OAuthProvider, TOKEN, USERINFO


class FixtureProvider:
    app_id = "fixture-app"
    revoked = False
    seconds = 60
    scope = "auth:user.id:read"
    calls = 0
    identity_value = {"open_id": "user-one", "tenant_key": "tenant-one"}

    def exchange(self, code, redirect, verifier):
        self.calls += 1
        self.verifier = verifier
        return {"access_token": "user-token", "expires_in": self.seconds, "token_type": "Bearer", "scope": self.scope}

    def identity(self, token):
        if self.revoked:
            raise AuthenticationError("revoked")
        return dict(self.identity_value)


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.provider = FixtureProvider()
        self.now = 100
        self.service = LoginService(self.provider, "http://127.0.0.1:8765/auth/feishu/callback", lambda:self.now)
        self.binding = "browser-binding-" * 3

    def begin(self):
        return parse_qs(urlsplit(self.service.begin(self.binding)).query)

    def login(self):
        return self.service.finish(self.begin()["state"][0], self.binding, "code")

    def test_pkce_and_no_secret_in_authorization_url(self):
        query = self.begin()
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["response_type"], ["code"])
        self.assertNotIn("client_secret", query)
        self.assertNotIn("code_verifier", query)

    def test_state_is_bound_to_browser(self):
        state = self.begin()["state"][0]
        with self.assertRaises(AuthenticationError):
            self.service.finish(state, "another-browser-binding"*2, "code")
        self.assertEqual(self.provider.calls, 0)

    def test_callback_cannot_be_replayed(self):
        state = self.begin()["state"][0]
        self.service.finish(state, self.binding, "code")
        with self.assertRaises(AuthenticationError):
            self.service.finish(state, self.binding, "code")
        self.assertEqual(self.provider.calls, 1)

    def test_expired_login_context_blocks_exchange(self):
        state = self.begin()["state"][0]
        self.now += 300
        with self.assertRaises(AuthenticationError):
            self.service.finish(state, self.binding, "code")
        self.assertEqual(self.provider.calls, 0)

    def test_denial_does_not_issue_session(self):
        with self.assertRaises(AuthenticationError):
            self.service.finish(self.begin()["state"][0], self.binding, "", "access_denied")
        self.assertEqual(self.service._sessions, {})

    def test_missing_authorized_scope_fails_closed(self):
        self.provider.scope = "unrelated"
        with self.assertRaises(AuthenticationError):
            self.login()

    def test_expiry_logout_and_unknown_session(self):
        sid = self.login()
        self.assertEqual(self.service.session(sid).open_id, "user-one")
        self.now += 60
        with self.assertRaises(AuthenticationError):
            self.service.session(sid)
        sid = self.login()
        self.service.logout(sid)
        for candidate in (sid, "invented", "", None):
            with self.assertRaises(AuthenticationError):
                self.service.session(candidate)

    def test_revoked_user_is_rechecked_each_request(self):
        sid = self.login()
        self.provider.revoked = True
        with self.assertRaises(AuthenticationError):
            self.service.session(sid)

    def test_token_is_not_in_session_repr(self):
        self.assertNotIn("user-token", repr(self.service.session(self.login())))

    def test_server_redirect_rejects_unencrypted_remote_and_credentials(self):
        for url in ("http://example.com/callback", "https://a:b@example.com/cb", "https://example.com/cb#x"):
            with self.assertRaises(AuthenticationError):
                LoginService(self.provider, url)


class ProviderTests(unittest.TestCase):
    def provider(self, handler):
        session = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(session.close)
        return OAuthProvider("app", "fixture-secret", session)

    def test_supported_exchange_uses_fixed_endpoint_and_pkce(self):
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"code":0})
        self.provider(handler).exchange("code", "https://example.com/cb", "verifier")
        self.assertEqual(str(seen[0].url), TOKEN)
        form = parse_qs(seen[0].content.decode())
        self.assertEqual(form["code_verifier"], ["verifier"])

    def test_userinfo_extracts_only_verified_subject_and_tenant(self):
        def handler(request):
            self.assertEqual(str(request.url), USERINFO)
            self.assertEqual(request.headers["Authorization"], "Bearer user-token")
            return httpx.Response(200, json={"code":0,"data":{"open_id":"o","tenant_key":"t","email":"private"}})
        self.assertEqual(self.provider(handler).identity("user-token"), {"open_id":"o","tenant_key":"t"})

    def test_redirect_rate_limit_and_invalid_user_are_rejected_without_retry(self):
        for response in (httpx.Response(302, headers={"Location":"https://other.invalid"}),
                         httpx.Response(429, json={"code":1}), httpx.Response(200, json={"code":20021})):
            calls = []
            def handler(request):
                calls.append(request)
                return response
            with self.assertRaises(AuthenticationError):
                self.provider(handler).identity("token")
            self.assertEqual(len(calls), 1)

    def test_transport_details_and_secrets_are_not_reported(self):
        def handler(request):
            raise httpx.ReadTimeout("fixture-secret user-token")
        with self.assertRaises(AuthenticationError) as caught:
            self.provider(handler).identity("user-token")
        self.assertNotIn("fixture-secret", str(caught.exception))
        self.assertNotIn("user-token", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
