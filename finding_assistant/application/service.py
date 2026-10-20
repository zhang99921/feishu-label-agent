"""Shared application boundary for HTTP and optional future MCP adapters."""
from dataclasses import dataclass, field
from typing import Callable, Protocol

from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.login import AuthenticationError


class GuardedWorkflow(Protocol):
    def query(self, session_id: str, unit: str, batch: str) -> dict: ...
    def submit(self, session_id: str, key: str, payload: dict) -> dict: ...


@dataclass(frozen=True)
class RequestIdentity:
    """Created by a trusted transport resolver, never by the model's arguments."""
    session_id: str = field(repr=False)


@dataclass(frozen=True)
class ServiceRuntime:
    workflow: GuardedWorkflow = field(repr=False)
    resolve_identity: Callable[[], RequestIdentity] = field(repr=False)

    def session(self) -> str:
        identity = self.resolve_identity()
        if not isinstance(identity, RequestIdentity) or not isinstance(identity.session_id, str) or not identity.session_id:
            raise AuthenticationError("authenticated request identity required")
        return identity.session_id

    def query(self, unit: str, batch: str) -> dict:
        return self.workflow.query(self.session(),unit,batch)

    def submit(self, action: str, request_key: str, request: dict) -> dict:
        if not isinstance(request, dict) or any(k in request for k in
                ("action","role","actor","open_id","tenant_key","session_id")):
            raise AccessDenied("tool arguments cannot override action or identity")
        if not isinstance(request_key,str) or not request_key or len(request_key) > 100:
            raise ValueError("stable idempotency key required")
        return self.workflow.submit(self.session(),request_key,{**request,"action":action})
