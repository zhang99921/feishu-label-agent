# 仅打印未来工具分组：python -m finding_assistant.servers --catalog；不会启动 MCP 传输。
"""Inspect server boundaries without starting a transport or reading credentials."""
import argparse
import json

from . import admin, operations, query


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog",action="store_true",help="List server/tool boundaries; does not start an MCP service")
    args = parser.parse_args()
    if args.catalog:
        print(json.dumps({"transport_started":False,"servers":{
            module.NAME:list(module.TOOL_NAMES) for module in (query,operations,admin)}},ensure_ascii=False,indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
