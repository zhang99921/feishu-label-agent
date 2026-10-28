"""飞书适配器专用长连接客户端；不添加任何自动重试。"""
import ssl
import httpx


def feishu_client():
    return httpx.Client(verify=ssl.create_default_context(), trust_env=True,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=16, max_keepalive_connections=8, keepalive_expiry=30),
        timeout=httpx.Timeout(connect=5, read=20, write=20, pool=5))
