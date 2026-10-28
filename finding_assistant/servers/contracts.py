# 未来 MCP 适配契约：这里只注册工具，不启动传输、不读取密钥，也不引入 MCP SDK。
# 适配器通过 ServiceRuntime 复用后端权限、幂等和业务流程。
"""Optional MCP registration contract; core application has no MCP dependency."""
from dataclasses import dataclass
from typing import Callable, Protocol

from finding_assistant.application.service import GuardedWorkflow, RequestIdentity
from finding_assistant.application.service import ServiceRuntime as ServerRuntime


class ToolRegistry(Protocol):
    def tool(self, *, name: str, description: str) -> Callable: ...


@dataclass(frozen=True)
class MutationTool:
    name: str
    action: str
    description: str


# 每个工具通过独立闭包固定动作，避免循环闭包使所有工具执行最后一个动作。
def register_mutations(server: ToolRegistry, runtime: ServerRuntime, tools: tuple[MutationTool,...]):
    def register(spec):
        # A separate closure per tool keeps its fixed action; callers cannot switch it.
        def invoke(request_key: str, request: dict) -> dict:
            return runtime.submit(spec.action,request_key,request)
        server.tool(name=spec.name,description=spec.description)(invoke)
    for spec in tools:
        register(spec)
    return server
