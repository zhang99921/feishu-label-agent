# 文档协作者权限诊断：view=可阅读、edit=可编辑、full_access=可管理。
# 这些文档权限不等同于业务角色，也不会自动映射成管理员/操作员/查询员。
"""Read direct document collaborator privileges; never infer a default role.

Indirect group/link access and owner resolution are not implemented here. A
missing direct entry means unresolved, not that the account has no document access.
"""
from .client import DEMO, ProbeError
from finding_assistant.security.errors import AuthorizationUnavailable


class DocumentAccessDirectory:
    def __init__(self,client):
        self.client = client

    # 只识别明确的 openid 协作者项；返回 None 表示未查到直接授权，不等于无任何访问权限。
    def direct_permission(self,open_id):
        if not isinstance(open_id,str) or not open_id:
            raise AuthorizationUnavailable("verified user identity required")
        try:
            data = self.client.request("GET","/drive/v1/permissions/"+DEMO[0]+"/members",
                query={"type":"bitable"}).get("data")
            if not isinstance(data,dict) or not isinstance(data.get("items"),list):
                raise AuthorizationUnavailable("document collaborator response incomplete")
            matches = []
            for item in data["items"]:
                if not isinstance(item,dict):
                    raise AuthorizationUnavailable("document collaborator response invalid")
                # appid, groups and other ID namespaces cannot prove user membership.
                if item.get("member_type") == "openid" and item.get("member_id") == open_id:
                    matches.append(item.get("perm"))
            if len(matches) > 1 or any(p not in ("view","edit","full_access") for p in matches):
                raise AuthorizationUnavailable("document privilege is ambiguous")
            return matches[0] if matches else None
        except ProbeError:
            raise AuthorizationUnavailable("document privileges cannot be verified") from None
