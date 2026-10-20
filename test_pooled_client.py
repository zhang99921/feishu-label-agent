import unittest

import httpx

from feishu_probe import DEMO, ProbeError
from pooled_client import PooledClient


class PooledClientTests(unittest.TestCase):
    def client(self, handler):
        session = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        self.addCleanup(session.close)
        client = PooledClient(dict(app_token=DEMO[0], table_id=DEMO[1], app_secret="fixture-secret"), session)
        client.token = "fixture-token"
        return client

    def test_redirect_is_refused_without_second_request(self):
        calls = []
        def response(request):
            calls.append(request)
            return httpx.Response(302, headers={"Location": "https://other.invalid/path"})
        with self.assertRaises(ProbeError):
            self.client(response).request("POST", "/test", {"data": 1})
        self.assertEqual(len(calls), 1)

    def test_uncertain_post_is_not_retried_or_leaked(self):
        calls = []
        def response(request):
            calls.append(request)
            raise httpx.ReadTimeout("fixture-secret fixture-token")
        with self.assertRaises(ProbeError) as caught:
            self.client(response).request("POST", "/test", {})
        self.assertEqual(len(calls), 1)
        self.assertNotIn("fixture-secret", str(caught.exception))
        self.assertNotIn("fixture-token", str(caught.exception))

    def test_rate_limit_is_not_retried_and_credentials_are_redacted(self):
        calls = []
        def response(request):
            calls.append(request)
            return httpx.Response(429, json={"code": 99991400, "msg": "fixture-secret fixture-token"})
        with self.assertRaises(ProbeError) as caught:
            self.client(response).request("PUT", "/test", {})
        self.assertEqual(len(calls), 1)
        self.assertIn("429", str(caught.exception))
        self.assertNotIn("fixture-token", str(caught.exception))
        self.assertNotIn("fixture-secret", str(caught.exception))

    def test_payload_headers_origin_and_query(self):
        calls = []
        def response(request):
            calls.append(request)
            return httpx.Response(200, json={"code": 0, "data": {}})
        self.client(response).request("POST", "/test", {"中文": "测试"}, {"page_size": 100})
        request = calls[0]
        self.assertEqual(request.url.host, "open.feishu.cn")
        self.assertEqual(request.url.params["page_size"], "100")
        self.assertEqual(request.headers["Authorization"], "Bearer fixture-token")
        self.assertIn("测试".encode(), request.content)

    def test_invalid_response_or_api_failure_never_confirms_success(self):
        for response in (httpx.Response(200, text="bad"), httpx.Response(200, json=[]),
                         httpx.Response(200, json={"code": False}),
                         httpx.Response(200, json={"code": 91403}), httpx.Response(204)):
            with self.subTest(status=response.status_code), self.assertRaises(ProbeError):
                self.client(lambda request: response).request("GET", "/test")

    def test_path_cannot_override_origin(self):
        calls = []
        client = self.client(lambda request: calls.append(request))
        for path in ("https://evil.invalid", "//evil.invalid", "/../evil", "/x#fragment", "/x?query", "/a\\b"):
            with self.subTest(path=path), self.assertRaises(ProbeError):
                client.request("GET", path)
        self.assertEqual(calls, [])

    def test_context_manager_closes_connection_pool(self):
        client = self.client(lambda request: httpx.Response(200, json={"code": 0}))
        with client:
            client.request("GET", "/test")
        self.assertTrue(client.session.is_closed)


if __name__ == "__main__":
    unittest.main()
