"""Pallet movement MCP server: fixed actions, shared authorization/idempotency."""
from typing import Callable

from .contracts import MutationTool, ServerRuntime, ToolRegistry, register_mutations

NAME = "finding-operations"
TOOLS = (
    MutationTool("receive_pallet","IN","托盘入库；沿用幂等键及预期版本，服务端校验身份与批次。"),
    MutationTool("release_pallet","OUT","整托出库；托盘码按现有规则释放并冷却。"),
    MutationTool("transfer_pallet","MOVE","托盘转仓；服务端校验目标仓、当前状态和预期版本。"),
    MutationTool("partial_release_pallet","PARTIAL_OUT","按整箱部分出库；托盘仍有货时保留原码。"),
    MutationTool("reenter_pallet","REENTER","显式重新入库；须确认箱数，不能用重复请求替代。"),
)
TOOL_NAMES = tuple(tool.name for tool in TOOLS)


def create_server(runtime: ServerRuntime, *, server_factory: Callable[[str],ToolRegistry]):
    return register_mutations(server_factory(NAME),runtime,TOOLS)
