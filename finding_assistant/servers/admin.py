"""Administration MCP server: explicit server-side admin authorization required."""
from typing import Callable

from .contracts import MutationTool, ServerRuntime, ToolRegistry, register_mutations

NAME = "finding-admin"
TOOLS = (
    MutationTool("correct_quantity","CORRECT","管理员数量纠错；须关联原操作、填写原因并确认，追加补偿记录。"),
    MutationTool("undo_operation","UNDO","管理员撤销；须关联原操作、填写原因并确认，沿用状态与版本校验。"),
)
TOOL_NAMES = tuple(tool.name for tool in TOOLS)


def create_server(runtime: ServerRuntime, *, server_factory: Callable[[str],ToolRegistry]):
    return register_mutations(server_factory(NAME),runtime,TOOLS)
