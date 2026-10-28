"""将已核实的飞书高级权限转换为参数化SQL；未知规则不产生授权。"""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json

from .errors import AuthorizationUnavailable


class VisibilityUnavailable(AuthorizationUnavailable):
    pass


@dataclass(frozen=True)
class Clause:
    sql: str
    params: tuple = ()


TRUE, FALSE = Clause('TRUE'), Clause('FALSE')


def combine(operator, clauses):
    clauses = tuple(clauses)
    if operator not in ('AND', 'OR'):
        raise ValueError('INVALID_SQL_COMBINATION')
    if not clauses:
        return TRUE if operator == 'AND' else FALSE
    return Clause('(' + (' ' + operator + ' ').join(c.sql for c in clauses) + ')',
                  tuple(p for c in clauses for p in c.params))


@dataclass(frozen=True)
class Condition:
    field_name: str
    field_type: int
    operator: str
    value: object

    def clause(self, alias):
        if alias not in ('box_data', 'row_data'):
            raise ValueError('INVALID_SQL_ALIAS')
        function = 'query_scalar_number' if self.field_type == 2 else 'query_scalar_text'
        # 字段名也作为值参数传递，不将飞书配置拼进SQL列名或运算符。
        return Clause(f'COALESCE(finding_assistant.{function}({alias}.fields -> %s) = %s,FALSE)',
                      (self.field_name, self.value))


@dataclass(frozen=True)
class Predicate:
    conjunction: str
    conditions: tuple[Condition, ...]

    def clause(self, alias):
        return combine(self.conjunction, (c.clause(alias) for c in self.conditions))


@dataclass(frozen=True)
class Grant:
    fields: frozenset[str]
    primary: Predicate | None = None
    other: Predicate | None = None
    other_all: bool = False

    def rows(self, alias):
        if self.other_all or self.primary is None:
            return TRUE
        # 主规则已经授予阅读；“主规则或其余可读记录”可直接做并集，不用在SQL猜否定语义。
        return combine('OR', (self.primary.clause(alias),
                              self.other.clause(alias) if self.other is not None else FALSE))


@dataclass(frozen=True)
class TableVisibility:
    grants: tuple[Grant, ...]

    def rows(self, alias):
        return combine('OR', (g.rows(alias) for g in self.grants))

    def field(self, name, alias):
        # 每个字段沿用授予它的角色自己的行范围；不能先合并行再合并字段。
        return combine('OR', (g.rows(alias) for g in self.grants if name in g.fields))


def schema_fields(schema):
    if not isinstance(schema, list):
        raise VisibilityUnavailable('INVALID_VISIBILITY_SCHEMA')
    result = {}
    for field in schema:
        if (not isinstance(field, dict) or not isinstance(field.get('field_name'), str)
                or type(field.get('type')) is not int or field['field_name'] in result):
            raise VisibilityUnavailable('AMBIGUOUS_VISIBILITY_SCHEMA')
        result[field['field_name']] = field
    return result


def predicate(rule, fields):
    if (not isinstance(rule, dict) or rule.get('condition_groups')
            or rule.get('display_rec_rule_version') is not None
            or set(rule) - {'conditions', 'conjunction', 'perm', 'other_perm', 'condition_groups', 'display_rec_rule_version'}):
        raise VisibilityUnavailable('UNSUPPORTED_NATIVE_RECORD_RULE')
    conditions = rule.get('conditions')
    if (rule.get('conjunction') not in ('and', 'or') or not isinstance(conditions, list)
            or not conditions or len(conditions) > 100):
        raise VisibilityUnavailable('UNCONFIRMED_NATIVE_RECORD_RULE')
    parsed = []
    for condition in conditions:
        if not isinstance(condition, dict) or set(condition) - {'field_name', 'field_type', 'operator', 'value'}:
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_CONDITION')
        name, operator, values = condition.get('field_name'), condition.get('operator'), condition.get('value')
        if (not isinstance(name, str) or name not in fields or operator != 'is'
                or not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str)
                or not values[0] or len(values[0]) > 200):
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_CONDITION')
        field = fields[name]
        kind, value = field['type'], values[0]
        if condition.get('field_type') is not None and (type(condition['field_type']) is not int or condition['field_type'] != kind):
            raise VisibilityUnavailable('NATIVE_CONDITION_FIELD_CHANGED')
        if kind == 2:
            try:
                value = Decimal(value)
                if not value.is_finite() or abs(value.adjusted()) > 999:
                    raise ValueError
            except (InvalidOperation, ValueError):
                raise VisibilityUnavailable('INVALID_NATIVE_NUMERIC_CONDITION') from None
        elif kind == 3:
            properties = field.get('property')
            if not isinstance(properties, dict):
                raise VisibilityUnavailable('UNCONFIRMED_NATIVE_OPTIONS')
            options = properties.get('options')
            if (not isinstance(options, list) or any(not isinstance(o, dict) or not isinstance(o.get('id'), str)
                    or not isinstance(o.get('name'), str) for o in options)
                    or len({o['id'] for o in options}) != len(options)):
                raise VisibilityUnavailable('UNCONFIRMED_NATIVE_OPTIONS')
            matches = {o['name'] for o in options if value in (o['id'], o['name'])}
            if len(matches) != 1:
                raise VisibilityUnavailable('NATIVE_OPTION_SOURCE_CHANGED')
            value = matches.pop()
        elif kind != 1:
            # 人员/当前用户、日期、公式、关联以及复杂条件组须另行实现其精确语义。
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_FIELD_TYPE')
        parsed.append(Condition(name, kind, operator, value))
    return Predicate(rule['conjunction'].upper(), tuple(parsed))


def table_visibility(roles, table_id, schema):
    fields = schema_fields(schema)
    grants = []
    for role in roles:
        tables = role.get('table_roles') if isinstance(role, dict) else None
        if not isinstance(tables, list) or any(not isinstance(t, dict) or not isinstance(t.get('table_id'), str) for t in tables):
            raise VisibilityUnavailable('UNCONFIRMED_NATIVE_TABLES')
        if len({t['table_id'] for t in tables}) != len(tables):
            raise VisibilityUnavailable('AMBIGUOUS_NATIVE_TABLES')
        table = next((t for t in tables if t['table_id'] == table_id), None)
        if table is None:
            continue
        allowed_keys = {'table_id', 'table_name', 'table_perm', 'rec_rule', 'other_rec_rule', 'field_perm',
                        'allow_add_record', 'allow_delete_record', 'view_perm', 'view_rules', 'field_action_rules'}
        perm = table.get('table_perm')
        if type(perm) is not int or perm not in (0, 1, 2, 4) or set(table) - allowed_keys:
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_TABLE_PERMISSION')
        if perm == 0:
            continue
        if perm == 4:
            # 表级可管理没有可配置的记录/字段限制；仍拒绝矛盾配置。
            if table.get('rec_rule') or table.get('other_rec_rule') or table.get('view_rules'):
                raise VisibilityUnavailable('CONTRADICTORY_NATIVE_MANAGEMENT_RULE')
            grants.append(Grant(frozenset(fields)))
            continue
        if table.get('view_rules') or (table.get('view_perm') is not None
                and (type(table['view_perm']) is not int or table['view_perm'] != 1)):
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_VIEW_SCOPE')
        actions = table.get('field_action_rules')
        if actions is not None and (not isinstance(actions, dict) or set(actions) - {'select_option_edit', 'attachment_export'}):
            raise VisibilityUnavailable('UNSUPPORTED_NATIVE_FIELD_ACTION')
        # 飞书 v2 的“全部字段可阅读”省略 field_perm；Demo 网页设置与
        # 实际角色接口已逐项核对。显式 null/畸形映射仍不能视作全字段授权。
        if 'field_perm' not in table:
            permissions = {name: 1 for name in fields}
        else:
            permissions = table['field_perm']
        if (not isinstance(permissions, dict) or any(type(v) is not int or v not in (0, 1, 2, 3) for v in permissions.values())
                or any(name not in fields for name in permissions)):
            raise VisibilityUnavailable('UNCONFIRMED_NATIVE_FIELD_SCOPE')
        readable = frozenset(name for name, value in permissions.items() if value in (1, 3))
        rule, other_rule = table.get('rec_rule'), table.get('other_rec_rule')
        if rule is None:
            if other_rule is not None:
                raise VisibilityUnavailable('NATIVE_OTHER_RULE_WITHOUT_PRIMARY')
            grants.append(Grant(readable))
            continue
        primary = predicate(rule, fields)
        primary_perm = rule.get('perm', perm)
        if type(primary_perm) is not int or primary_perm not in (1, 2):
            raise VisibilityUnavailable('UNCONFIRMED_NATIVE_RECORD_PERMISSION')
        other_all = False
        other = None
        if perm == 2:
            other_perm = rule.get('other_perm')
            if type(other_perm) is not int or other_perm not in (0, 1):
                raise VisibilityUnavailable('UNCONFIRMED_NATIVE_OTHER_PERMISSION')
            other_all = other_perm == 1
            if other_rule is not None and not other_all:
                if not isinstance(other_rule, dict) or other_rule.get('perm') != 1 or type(other_rule.get('perm')) is not int:
                    raise VisibilityUnavailable('UNCONFIRMED_NATIVE_OTHER_RULE')
                other = predicate(other_rule, fields)
        elif other_rule is not None:
            raise VisibilityUnavailable('UNSUPPORTED_READ_ONLY_OTHER_RULE')
        grants.append(Grant(readable, primary, other, other_all))
    return TableVisibility(tuple(grants))


def policy_checksum(roles):
    return hashlib.sha256(json.dumps(roles, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
