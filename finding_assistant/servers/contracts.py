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


def register_mutations(server: ToolRegistry, runtime: ServerRuntime, tools: tuple[MutationTool,...]):
    def register(spec):
        # A separate closure per tool keeps its fixed action; callers cannot switch it.
        def invoke(request_key: str, request: dict) -> dict:
            return runtime.submit(spec.action,request_key,request)
        server.tool(name=spec.name,description=spec.description)(invoke)
    for spec in tools:
        register(spec)
    return server
