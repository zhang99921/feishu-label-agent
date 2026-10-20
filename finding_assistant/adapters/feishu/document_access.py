"""Read direct document collaborator privileges; never infer a default role.

Indirect group/link access and owner resolution are not implemented here. A
missing direct entry means unresolved, not that the account has no document access.
"""
from .client import DEMO, ProbeError
from finding_assistant.security.errors import AuthorizationUnavailable


class DocumentAccessDirectory:
    def __init__(self,client):
        self.client = client

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
