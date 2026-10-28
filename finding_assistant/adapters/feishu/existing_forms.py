"""读取现有扫码流水表；此适配器只读，不建表、不改字段、不执行库存过账。"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import ssl
from urllib.parse import parse_qs, urlsplit

import httpx

from finding_assistant.infrastructure.environment import env_bool, read_environment


class SourceUnavailable(Exception):
    """来源读取未完成；不要据此判定任何箱子已完成流转。"""


REQUIRED_FIELDS = {
    **{f"箱号{i}": 1 for i in range(1, 37)},
    "事件类型": 3, "行码": 1, "目标区域": 1, "来源区域": 1,
    "处理状态": 3, "处理说明": 1, "操作人": 1003,
}


def parse_base_url(value):
    """接受飞书 Base 或 Wiki 链接；Wiki 节点 token 不能直接当 Base token。"""
    if not value:
        return "", "", ""
    url = urlsplit(value)
    parts = url.path.strip("/").split("/")
    if (url.scheme != "https" or not (url.hostname or "").endswith(".feishu.cn")
            or url.username or url.password or url.port not in (None, 443)
            or len(parts) != 2 or parts[0] not in ("base", "wiki")
            or not re.fullmatch(r"[A-Za-z0-9]+", parts[1])):
        raise ValueError("INVALID_FEISHU_BASE_URL")
    tables = parse_qs(url.query).get("table", [])
    if len(tables) > 1 or (tables and not re.fullmatch(r"[A-Za-z0-9]+", tables[0])):
        raise ValueError("INVALID_FEISHU_BASE_URL")
    return (parts[1] if parts[0] == "base" else "",
            parts[1] if parts[0] == "wiki" else "", tables[0] if tables else "")


def check_schema(fields):
    names = [f.get("field_name") for f in fields if isinstance(f, dict)]
    if len(names) != len(fields) or len(names) != len(set(names)):
        raise SourceUnavailable("SOURCE_SCHEMA_AMBIGUOUS")
    if any(re.fullmatch(r"箱号\d+", name or "") and name not in REQUIRED_FIELDS for name in names):
        raise SourceUnavailable("SOURCE_SCHEMA_MISMATCH")
    by_name = {f["field_name"]: f for f in fields}
    if any(by_name.get(name, {}).get("type") != kind for name, kind in REQUIRED_FIELDS.items()):
        raise SourceUnavailable("SOURCE_SCHEMA_MISMATCH")
    if '位置码' in by_name and by_name['位置码'].get('type') != 1:
        raise SourceUnavailable('SOURCE_POSITION_SCHEMA_MISMATCH')


@dataclass(frozen=True)
class FormsConfig:
    app_id: str
    app_secret: str = field(repr=False)
    app_token: str
    scan_table_id: str
    poll_seconds: int = 30
    include_blank_status: bool = False
    base_url: str = ""

    def __post_init__(self):
        direct_token, wiki_token, _ = parse_base_url(self.base_url)
        for value in (self.app_id, self.scan_table_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_]+", value):
                raise ValueError("INVALID_FORMS_CONFIG")
        if self.app_token and not re.fullmatch(r"[A-Za-z0-9_]+", self.app_token):
            raise ValueError("INVALID_FORMS_CONFIG")
        if not self.app_token and not (direct_token or wiki_token):
            raise ValueError("BASE_TARGET_REQUIRED")
        if self.app_token and direct_token and self.app_token != direct_token:
            raise ValueError("BASE_TARGET_MISMATCH")
        if not isinstance(self.app_secret, str) or not self.app_secret.strip():
            raise ValueError("INVALID_FORMS_CONFIG")
        if type(self.poll_seconds) is not int or not 5 <= self.poll_seconds <= 3600:
            raise ValueError("INVALID_POLL_INTERVAL")
        if type(self.include_blank_status) is not bool:
            raise ValueError("INVALID_BLANK_STATUS_POLICY")

    @classmethod
    def load(cls, path):
        """兼容旧 JSON 配置；新部署使用 from_env，不再依赖此入口。"""
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        allowed = {"app_id", "app_secret", "app_token", "scan_table_id", "poll_seconds", "include_blank_status", "base_url"}
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise ValueError("INVALID_FORMS_CONFIG")
        for name in ("app_id", "app_token", "scan_table_id"):
            if not isinstance(raw.get(name), str) or not re.fullmatch(r"[A-Za-z0-9_]+", raw[name]):
                raise ValueError("INVALID_FORMS_CONFIG")
        if not isinstance(raw.get("app_secret"), str) or not raw["app_secret"].strip():
            raise ValueError("INVALID_FORMS_CONFIG")
        interval = raw.get("poll_seconds", 30)
        if type(interval) is not int or not 5 <= interval <= 3600:
            raise ValueError("INVALID_POLL_INTERVAL")
        if type(raw.get("include_blank_status", False)) is not bool:
            raise ValueError("INVALID_BLANK_STATUS_POLICY")
        return cls(**raw)

    @classmethod
    def from_env(cls, path=None):
        return cls.from_values(read_environment(path))

    @classmethod
    def from_values(cls, values):
        """使用同一份已读取的配置；供运行装配和离线自检共用。"""
        base_url = values.get("FEISHU_BASE_URL", "").strip()
        direct_token, _, table_from_url = parse_base_url(base_url)
        try:
            seconds = int(values.get("FEISHU_POLL_SECONDS", "30"))
        except ValueError:
            raise ValueError("INVALID_POLL_INTERVAL") from None
        return cls(app_id=values.get("FEISHU_APP_ID", "").strip(),
                   app_secret=values.get("FEISHU_APP_SECRET", ""),
                   app_token=values.get("FEISHU_APP_TOKEN", "").strip() or direct_token,
                   scan_table_id=values.get("FEISHU_SCAN_TABLE_ID", "").strip() or table_from_url,
                   poll_seconds=seconds,
                   include_blank_status=env_bool(values, "FEISHU_INCLUDE_BLANK_STATUS"),
                   base_url=base_url)


class ExistingFormsReader:
    def __init__(self, config, session=None):
        self.config = config
        self._token = None
        self.app_token = config.app_token or parse_base_url(config.base_url)[0]
        self.http = session or httpx.Client(verify=ssl.create_default_context(), trust_env=True,
            timeout=20, follow_redirects=False)

    def _request(self, method, path, *, body=None, params=None):
        # path 仅由下方固定接口模板构造，配置ID须先通过字母数字检查。
        headers = {"Authorization": "Bearer " + self._token} if self._token else {}
        try:
            response = self.http.request(method, "https://open.feishu.cn/open-apis" + path,
                json=body, params=params, headers=headers, follow_redirects=False)
            data = response.json()
            if not 200 <= response.status_code < 300 or not isinstance(data, dict) or type(data.get("code")) is not int or data["code"] != 0:
                raise SourceUnavailable("SOURCE_REQUEST_UNCONFIRMED")
            return data
        except (httpx.HTTPError, ValueError, UnicodeError):
            # 不将响应内容、请求参数、令牌或配置密码带入异常日志。
            raise SourceUnavailable("SOURCE_REQUEST_UNCONFIRMED") from None

    def login(self):
        data = self._request("POST", "/auth/v3/tenant_access_token/internal", body={
            "app_id": self.config.app_id, "app_secret": self.config.app_secret})
        token = data.get("tenant_access_token")
        if not isinstance(token, str) or not token:
            raise SourceUnavailable("APPLICATION_AUTHENTICATION_UNCONFIRMED")
        self._token = token
        if not self.config.app_token:
            _, node, _ = parse_base_url(self.config.base_url)
            if node:
                result = self._request("GET", "/wiki/v2/spaces/get_node", params={"token": node}).get("data")
                resolved = result.get("node") if isinstance(result, dict) else None
                if not isinstance(resolved, dict):
                    raise SourceUnavailable("WIKI_BASE_TARGET_UNCONFIRMED")
                target = resolved.get("obj_token")
                if resolved.get("obj_type") != "bitable" or not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9]+", target):
                    raise SourceUnavailable("WIKI_BASE_TARGET_UNCONFIRMED")
                if self.app_token and self.app_token != target:
                    raise SourceUnavailable("WIKI_BASE_TARGET_CHANGED")
                self.app_token = target

    def _pages(self, suffix):
        if not self.app_token:
            raise SourceUnavailable("BASE_TARGET_REQUIRED")
        path = f"/bitable/v1/apps/{self.app_token}/tables/{self.config.scan_table_id}/{suffix}"
        token, seen = None, set()
        for _ in range(1000):
            query = {"page_size": 100}
            if token:
                query["page_token"] = token
            data = self._request("GET", path, params=query).get("data")
            if not isinstance(data, dict) or not isinstance(data.get("items"), list) or type(data.get("has_more")) is not bool:
                raise SourceUnavailable("INCOMPLETE_SOURCE_PAGE")
            yield from data["items"]
            if not data["has_more"]:
                return
            token = data.get("page_token")
            if not isinstance(token, str) or not token or token in seen:
                raise SourceUnavailable("INVALID_SOURCE_PAGINATION")
            seen.add(token)
        raise SourceUnavailable("SOURCE_PAGE_LIMIT_REACHED")

    def records(self):
        # 每轮换取应用令牌并核对表结构；先核对再读数据，不迁就字段漂移自动改表。
        self.login()
        check_schema(list(self._pages("fields")))
        yield from self._pages("records")

    def close(self):
        self.http.close()
