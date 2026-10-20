"""Verified-origin HTTP pooling, with TLS verification and no automatic retries."""
import json
import ssl
from urllib.parse import urlsplit

import httpx

from finding_assistant.adapters.feishu.client import Client, ORIGIN, ProbeError


class PooledClient(Client):
    supports_parallel_reads = True

    def __init__(self, config, session=None):
        super().__init__(config)
        self.transport_metrics = {"tcp_connections": 0, "tls_handshakes": 0, "requests": 0}
        # Use the system trust roots, including Windows corporate roots.
        self.session = session or httpx.Client(
            verify=ssl.create_default_context(), trust_env=True,
            follow_redirects=False, timeout=20,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2, keepalive_expiry=60))

    def _trace(self, name, info):
        if name == "connection.connect_tcp.started":
            self.transport_metrics["tcp_connections"] += 1
        elif name == "connection.start_tls.started":
            self.transport_metrics["tls_handshakes"] += 1

    def request(self, method, path, body=None, query=None):
        # Joining strings alone is insufficient: reject fragments, authorities and
        # path traversal before a credential-bearing request can leave the client.
        parsed = urlsplit(path)
        if (not path.startswith("/") or path.startswith("//") or parsed.scheme or
                parsed.netloc or parsed.query or parsed.fragment or
                any(p in (".", "..") for p in parsed.path.split("/")) or "\\" in path):
            raise ProbeError("Only an API path on the fixed origin is allowed")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        payload = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        try:
            self.transport_metrics["requests"] += 1
            response = self.session.request(method, ORIGIN + path, content=payload,
                                            params=query, headers=headers, follow_redirects=False,
                                            extensions={"trace": self._trace})
        except httpx.HTTPError:
            raise ProbeError("Transport unavailable or timed out; reuse the saved operation key") from None
        if 300 <= response.status_code < 400:
            raise ProbeError("Redirect refused: credentials stay at the configured API origin")
        try:
            result = response.json()
        except (ValueError, UnicodeError):
            raise ProbeError("Invalid API response; no success confirmed") from None
        if not isinstance(result, dict) or type(result.get("code")) is not int:
            raise ProbeError("Invalid API response shape; no success confirmed")
        if response.status_code >= 400:
            message = str(result.get("msg", ""))
            for secret in (self.config.get("app_secret"), self.token):
                if secret:
                    message = message.replace(secret, "[REDACTED]")
            raise ProbeError(f"HTTP {response.status_code}; API code={result.get('code')}; {message[:1200]}; no success confirmed")
        if not 200 <= response.status_code < 300 or result.get("code") != 0:
            raise ProbeError(f"Feishu API code={result.get('code')}; no success confirmed")
        return result

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
