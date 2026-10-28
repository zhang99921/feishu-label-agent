"""在没有线上授权时，从飞书 .base 导出文件只读预览扫码任务。"""
import base64
import gzip
import io
import json
from pathlib import Path

from .existing_forms import check_schema


def read_scan_export(path):
    path = Path(path)
    if path.stat().st_size > 50_000_000:
        raise ValueError("EXPORT_FILE_TOO_LARGE")
    outer = json.loads(path.read_text(encoding="utf-8-sig"))
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(outer["gzipSnapshot"], validate=True))) as stream:
        raw = stream.read(250_000_001)
    if len(raw) > 250_000_000:
        raise ValueError("EXPORT_SNAPSHOT_TOO_LARGE")
    chunks = json.loads(raw)
    found = None
    for chunk in chunks:
        schema = chunk["schema"]
        data = schema["data"]
        table = data["table"]
        tid = table["meta"]["id"]
        if schema["tableMap"][tid]["name"] != "扫码流水表":
            continue
        if found is not None:
            if found[2] != data:
                raise ValueError("AMBIGUOUS_SCAN_EXPORT")
            continue
        found = (schema["base"]["token"], tid, data)
    if found is None:
        raise ValueError("SCAN_TABLE_NOT_FOUND")
    base_token, tid, data = found
    field_map = data["table"]["fieldMap"]
    check_schema([{"field_name": f["name"], "type": f["type"]} for f in field_map.values()])
    records = []
    for rid, cells in data["recordMap"].items():
        fields = {}
        for fid, definition in field_map.items():
            cell = cells.get(fid)
            value = cell.get("value") if isinstance(cell, dict) else None
            if definition["type"] == 3:
                options = {o["id"]: o["name"] for o in definition.get("property", {}).get("options", [])}
                value = options.get(value, value)
            fields[definition["name"]] = value
        records.append({"record_id": rid, "fields": fields})
    return base_token, tid, records
