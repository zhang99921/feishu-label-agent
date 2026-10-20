"""Real HTTP feasibility probe, restricted to the user-authorized Demo table.

No deletes, no schema changes, no inventory workflow claims. Local state retains
the exact create payload and UUID before sending, for explicit same-key retries.
Run without --write to inspect metadata only. Credentials never enter reports.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler

from finding_assistant.infrastructure.paths import STATE_DIR

DEMO = ("R4XEbXH12agWO6scaO7ciAC8nUc", "tblrAufM4mVvQB8x")
ORIGIN = "https://open.feishu.cn/open-apis"


class ProbeError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProbeError("Redirect refused: credentials stay at the configured API origin")


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class Client:
    def __init__(self, config):
        if (config.get("app_token"), config.get("table_id")) != DEMO:
            raise ProbeError("Only the authorized Demo table is allowed")
        self.config = config
        self.token = None
        self.opener = build_opener(NoRedirect())

    def request(self, method, path, body=None, query=None):
        url = ORIGIN + path
        if query:
            url += "?" + urlencode(query)
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        payload = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                result = json.load(response)
        except HTTPError as error:
            # Retain only API error code/message; never log full error bodies or credentials.
            try:
                details = json.load(error)
                message = str(details.get("msg", ""))
                for secret in (self.config.get("app_secret"), self.token):
                    if secret:
                        message = message.replace(secret, "[REDACTED]")
                detail = f"; API code={details.get('code')}; {message[:1200]}"
            except (ValueError, TypeError):
                detail = ""
            raise ProbeError(f"HTTP {error.code}{detail}; no success confirmed") from None
        except (URLError, TimeoutError, OSError):
            raise ProbeError("Transport unavailable or timed out; reuse the saved operation key") from None
        except (ValueError, UnicodeError):
            raise ProbeError("Invalid API response; no success confirmed") from None
        if not isinstance(result, dict):
            raise ProbeError("Invalid API response shape; no success confirmed")
        if result.get("code") != 0:
            raise ProbeError(f"Feishu API code={result.get('code')}; no success confirmed")
        return result

    def login(self):
        if not self.config.get("app_id") or not self.config.get("app_secret"):
            raise ProbeError("Fill the ignored config.local.json before HTTP tests")
        response = self.request("POST", "/auth/v3/tenant_access_token/internal", {
            "app_id": self.config["app_id"], "app_secret": self.config["app_secret"]})
        self.token = response["tenant_access_token"]

    @property
    def table_path(self):
        return f"/bitable/v1/apps/{DEMO[0]}/tables/{DEMO[1]}"

    def fields(self):
        items, page_token = [], None
        while True:
            query = {"page_size": 100}
            if page_token:
                query["page_token"] = page_token
            data = self.request("GET", self.table_path + "/fields", query=query)["data"]
            items.extend(data.get("items", []))
            if not data.get("has_more"):
                return items
            next_token = data.get("page_token")
            if not next_token or next_token == page_token:
                raise ProbeError("Invalid pagination response")
            page_token = next_token

    def create(self, key, fields):
        return self.request("POST", self.table_path + "/records", {"fields": fields},
                            {"client_token": key, "ignore_consistency_check": "false"})["data"]["record"]

    def get(self, record_id):
        return self.request("GET", self.table_path + "/records/" + record_id)["data"]["record"]

    def update(self, record_id, fields):
        return self.request("PUT", self.table_path + "/records/" + record_id,
                            {"fields": fields})["data"]["record"]


def text(value):
    if isinstance(value, list):
        return "".join(item.get("text", "") for item in value if isinstance(item, dict))
    return str(value)


def make_fields(schema, key):
    expected = {"FNSKU": "X0HTTPTEST1", "商品名称": "CODEX_HTTP_TEST_" + key,
                "商品信息": "仅用于Demo接口验证；非真实库存", "箱规数量": 50,
                "国家站点": "美国", "商品标签": "常规"}
    by_name = {item["field_name"]: item for item in schema}
    for name in expected:
        if name not in by_name:
            raise ProbeError(f"Missing expected Demo field: {name}")
        field = by_name[name]
        if field["type"] not in (1, 2, 3):
            raise ProbeError(f"Unsupported field type for {name}: {field['type']}")
        if name == "箱规数量" and field["type"] == 1:
            expected[name] = "50"
        if field["type"] == 3:
            options = [option["name"] for option in field.get("property", {}).get("options", [])]
            if expected[name] not in options:
                raise ProbeError(f"Selection option not present in {name}")
    return expected


def run(client, root, write):
    report = {"mode": "REAL_FEISHU_HTTP", "authentication": "PENDING", "tests": {},
              "inventory_workflow_verified": False, "records_deleted": 0}
    report_path = root / "http_results.local.json"
    try:
        client.login()
        report["authentication"] = "PASS"
        schema = client.fields()
        report["fields"] = [{k: field.get(k) for k in ("field_id", "field_name", "type", "ui_type")}
                            for field in schema]
        report["tests"]["read_schema"] = "PASS"
        if not write:
            report["status"] = "COMPLETED_SCHEMA_READ"
            return report
        state_path = root / "probe_state.local.json"
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("target") != list(DEMO):
                raise ProbeError("Saved operation target does not match Demo")
        else:
            key = str(uuid.uuid4())
            state = {"target": list(DEMO), "client_token": key, "fields": make_fields(schema, key)}
            save(state_path, state)  # Durable before any request that could create a row.
        record = client.create(state["client_token"], state["fields"])
        record_id = record["record_id"]
        if state.get("record_id") and state["record_id"] != record_id:
            raise ProbeError("Same saved key returned a different record; reconciliation required")
        state["record_id"] = record_id
        save(state_path, state)
        report["test_record_id"] = record_id
        report["tests"]["create"] = "PASS"
        replay = client.create(state["client_token"], state["fields"])
        if replay["record_id"] != record_id:
            report["extra_record_id"] = replay["record_id"]
            raise ProbeError("Same-key duplicate created a second record")
        report["tests"]["same_key_replay_same_record"] = "PASS"
        current = client.get(record_id)["fields"]
        if text(current.get("商品名称")) != state["fields"]["商品名称"]:
            raise ProbeError("Read-back does not match the created test row")
        report["tests"]["read_after_create"] = "PASS"
        update = {"商品信息": "仅用于Demo接口验证；非真实库存；HTTP修改已验证"}
        client.update(record_id, update)
        current = client.get(record_id)["fields"]
        if text(current.get("商品信息")) != update["商品信息"]:
            raise ProbeError("Updated value is not visible; no update success confirmed")
        report["tests"]["update_and_read_back"] = "PASS"
        report["status"] = "COMPLETED_LIMITED_HTTP_PROBE"
        return report
    except ProbeError as error:
        report["status"] = "BLOCKED_OR_RECONCILIATION_REQUIRED"
        report["error"] = str(error)
        return report
    finally:
        save(report_path, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=STATE_DIR / "config.local.json")
    parser.add_argument("--write", action="store_true", help="Create/replay and update only our marked Demo test record")
    args = parser.parse_args()
    if not args.config.exists():
        parser.exit(2, "Missing local app configuration; copy config.example.json to config.local.json\n")
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    report = run(Client(config), STATE_DIR, args.write)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
