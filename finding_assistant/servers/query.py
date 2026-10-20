"""Query MCP server: no inventory mutations are registered."""
from typing import Callable

from .contracts import ServerRuntime, ToolRegistry

NAME = "finding-query"
TOOL_NAMES = ("query_inventory",)


def create_server(runtime: ServerRuntime, *, server_factory: Callable[[str],ToolRegistry]):
    server = server_factory(NAME)

    @server.tool(name="query_inventory",description="查询指定批次内托盘的库存状态与库位码，服务端校验当前用户权限。")
    def query_inventory(unit: str, batch: str) -> dict:
        return runtime.query(unit,batch)

    return server
