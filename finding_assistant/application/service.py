# 共享应用入口：HTTP 与未来 MCP 都应使用经过鉴权的业务接口，复用同一业务规则。
"""Shared application boundary for HTTP and optional future MCP adapters."""
from dataclasses import dataclass, field
from typing import Callable, Protocol

from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.login import AuthenticationError


# 传输层依赖的接口约定；实际应装配 AuthenticatedWorkflow，而非直接暴露测试身份。
class GuardedWorkflow(Protocol):
    def query(self, session_id: str, unit: str, batch: str) -> dict: ...
    def submit(self, session_id: str, key: str, payload: dict) -> dict: ...


# 由可信传输适配器解析的本地会话凭据；repr 隐藏凭据，避免日志意外打印。
@dataclass(frozen=True)
class RequestIdentity:
    """Created by a trusted transport resolver, never by the model's arguments."""
    session_id: str = field(repr=False)


# 供适配器使用的运行上下文；每次调用重新解析当前请求身份。
@dataclass(frozen=True)
class ServiceRuntime:
    workflow: GuardedWorkflow = field(repr=False)
    resolve_identity: Callable[[], RequestIdentity] = field(repr=False)

    # 拒绝缺失或格式错误的可信身份，不从工具参数猜测用户。
    def session(self) -> str:
        identity = self.resolve_identity()
        if not isinstance(identity, RequestIdentity) or not isinstance(identity.session_id, str) or not identity.session_id:
            raise AuthenticationError("authenticated request identity required")
        return identity.session_id

    def query(self, unit: str, batch: str) -> dict:
        return self.workflow.query(self.session(),unit,batch)

    # 动作由注册入口固定，参数不得覆盖身份/角色；调用者需保留稳定幂等键用于重试。
    def submit(self, action: str, request_key: str, request: dict) -> dict:
        if not isinstance(request, dict) or any(k in request for k in
                ("action","role","actor","open_id","tenant_key","session_id")):
            raise AccessDenied("tool arguments cannot override action or identity")
        if not isinstance(request_key,str) or not request_key or len(request_key) > 100:
            raise ValueError("stable idempotency key required")
        return self.workflow.submit(self.session(),request_key,{**request,"action":action})
