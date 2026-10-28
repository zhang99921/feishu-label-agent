# 权限链：飞书用户会话 → 租户核实 → 当前原生角色 → 业务角色/批次映射 → 所需表及字段权限。
# 无法解释的原生权限配置不会自动放行；当前只识别直接用户成员，未实现部门/群组继承。
"""Conservative native-role gate; unsupported restrictions never become grants.

Only direct user membership is supported in this experiment. Group/department
membership and record-rule evaluation remain pending, so they do not grant access.
"""
from dataclasses import dataclass

from finding_assistant.adapters.feishu.client import DEMO, ProbeError
from finding_assistant.application.workflow import TestPrincipal, writer_gate


from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.adapters.feishu.roles import RoleDirectory


# 服务端配置：将一个飞书 role_id 映射到业务角色及允许访问的批次集合。
@dataclass(frozen=True)
class Binding:
    role_id: str
    business_role: str
    batches: frozenset[str]


# 某个动作必须满足的表、字段及读写要求；不是客户端传入的权限声明。
@dataclass(frozen=True)
class TableRequirement:
    table_id: str
    fields: frozenset[str]
    edit: bool = False


# 业务角色动作白名单，与飞书“可管理/可编辑/可阅读”表权限分别检查。
ROLE_ACTIONS = {
    "query": frozenset({"QUERY"}),
    "operator": frozenset({"QUERY", "IN", "OUT", "MOVE", "REENTER", "PARTIAL_OUT"}),
    "admin": frozenset({"QUERY", "IN", "OUT", "MOVE", "REENTER", "PARTIAL_OUT", "CORRECT", "UNDO"}),
}


# 可审查的权限判定结果；reason 保留具体拒绝原因，便于受控诊断。
@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str
    table_id: str | None = None


# 逐表逐字段检查实际权限；缺失字段权限、未解释的记录/视图规则均拒绝。
# 这里检查原生权限，ROLE_ACTIONS 另行限制业务动作，两者必须同时通过。
def assess_requirements(role, requirements):
    """Explain denials without converting unresolved native defaults into grants."""
    tables = role.get("table_roles")
    if not isinstance(tables, list):
        return PermissionDecision(False,"invalid_tables")
    if any(not isinstance(t, dict) or not isinstance(t.get("table_id"), str) for t in tables):
        return PermissionDecision(False,"invalid_tables")
    by_id = {t["table_id"]:t for t in tables}
    if len(by_id) != len(tables):
        return PermissionDecision(False,"ambiguous_tables")
    for requirement in requirements:
        native = by_id.get(requirement.table_id)
        if not native or type(native.get("table_perm")) is not int:
            return PermissionDecision(False,"missing_or_invalid_table",requirement.table_id)
        # 此接口表权限枚举：1 读、2 编辑、4 管理；其他值不授予访问。
        permission = native["table_perm"]
        if permission not in (1, 2, 4) or (requirement.edit and permission not in (2, 4)):
            return PermissionDecision(False,"table_permission_denied",requirement.table_id)
        # These restrictions need explicit interpreters before they can grant access.
        if any(native.get(k) for k in ("rec_rule", "other_rec_rule", "view_rules")):
            return PermissionDecision(False,"record_or_view_rules_unresolved",requirement.table_id)
        if permission != 4:
            # 字段权限采用另一套枚举：1 读、2 新增、3 编辑；不能与表权限混用。
            fields = native.get("field_perm")
            if not isinstance(fields, dict):
                return PermissionDecision(False,"field_permissions_unresolved",requirement.table_id)
            # Advanced permissions v2: 1 read, 2 add, 3 edit. Do not confuse v1's 2=edit.
            for name in requirement.fields:
                value = fields.get(name)
                if type(value) is not int or value not in ((3,) if requirement.edit else (1, 3)):
                    return PermissionDecision(False,"field_permission_denied",requirement.table_id)
    return PermissionDecision(True,"allowed")


def meets_requirements(role, requirements):
    return assess_requirements(role,requirements).allowed


class PermissionGate:
    def __init__(self, login, directory, tenant_key, bindings, requirements):
        self.login, self.directory, self.tenant_key = login, directory, tenant_key
        self.bindings, self.requirements = tuple(bindings), requirements

    # 每次操作重新核实会话和原生角色，权限撤销后不能靠旧会话或旧幂等结果继续操作。
    def authorize(self, session_id, action, batch):
        if not self.tenant_key or not isinstance(batch, str) or not batch:
            raise AccessDenied("trusted tenant and batch configuration required")
        if not isinstance(action, str) or action not in self.requirements or not self.requirements[action]:
            raise AccessDenied("operation permission definition missing")
        session = self.login.session(session_id)
        if session.tenant_key != self.tenant_key:
            raise AccessDenied("account belongs to another tenant")
        roles = self.directory.direct_roles(session.open_id)  # fresh on EVERY operation
        for binding in self.bindings:
            if batch not in binding.batches or action not in ROLE_ACTIONS.get(binding.business_role, ()):
                continue
            for native in roles:
                if native.get("role_id") == binding.role_id and meets_requirements(native, self.requirements[action]):
                    return TestPrincipal("feishu:"+session.open_id, binding.business_role, batch)
        raise AccessDenied("native role does not authorize this operation and batch")


# 对外业务鉴权边界：先取得可信身份，再调用底层库存流程。
class AuthenticatedWorkflow:
    """Guarded integration boundary; the HTTP app must expose this, not fixture APIs."""
    def __init__(self, workflow, gate):
        self.workflow, self.gate = workflow, gate

    # 即使是重复请求，也先重新授权；客户端不能指定操作人、角色或租户。
    def submit(self, session_id, key, payload):
        if not isinstance(payload, dict) or any(k in payload for k in ("role", "actor", "open_id", "tenant_key")):
            raise AccessDenied("caller identity and role fields are not accepted")
        with writer_gate():
            principal = self.gate.authorize(session_id, payload.get("action"), payload.get("batch"))
            return self.workflow.submit(key, payload, principal)

    def query(self, session_id, unit, batch):
        with writer_gate():
            principal = self.gate.authorize(session_id, "QUERY", batch)
            return self.workflow.query(unit, principal)
