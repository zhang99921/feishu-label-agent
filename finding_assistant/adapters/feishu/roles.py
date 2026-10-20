"""Read-only native Feishu role directory adapter."""
from finding_assistant.adapters.feishu.client import DEMO, ProbeError
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable


class RoleDirectory:
    def __init__(self, client):
        self.client = client

    def _pages(self, path):
        items, cursor, seen = [], None, set()
        while True:
            query = {"page_size":30}
            if cursor:
                query["page_token"] = cursor
            data = self.client.request("GET", path, query=query).get("data")
            if not isinstance(data, dict) or type(data.get("has_more")) is not bool:
                raise AuthorizationUnavailable("incomplete native role response")
            page = data.get("items")
            # The live member endpoint returns items:null, total:0 for an empty role.
            # Accept only that explicit empty case; missing/malformed pages still fail.
            if "items" in data and page is None and type(data.get("total")) is int and data["total"] == 0 and data["has_more"] is False:
                page = []
            if not isinstance(page, list):
                raise AuthorizationUnavailable("incomplete native role response")
            items.extend(page)
            if not data["has_more"]:
                return items
            cursor = data.get("page_token")
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise AuthorizationUnavailable("invalid native role pagination")
            seen.add(cursor)

    def direct_roles(self, open_id):
        try:
            app = self.client.request("GET", "/bitable/v1/apps/"+DEMO[0])["data"]["app"]
            if app.get("is_advanced") is not True:
                raise AuthorizationUnavailable("Demo advanced permissions are not enabled")
            roles = self._pages("/base/v2/apps/"+DEMO[0]+"/roles")
            identifiers = [r.get("role_id") for r in roles if isinstance(r, dict)]
            if len(identifiers) != len(roles) or any(not isinstance(v, str) or not v for v in identifiers) or len(set(identifiers)) != len(identifiers):
                raise AuthorizationUnavailable("ambiguous native roles")
            matched = []
            for role in roles:
                role_id = role["role_id"]
                if not role_id.isalnum():
                    raise AuthorizationUnavailable("invalid native role identifier")
                members = self._pages("/bitable/v1/apps/"+DEMO[0]+"/roles/"+role_id+"/members")
                if any(m.get("member_type") == "user" and m.get("open_id") == open_id for m in members):
                    matched.append(role)
            return matched
        except (ProbeError, KeyError, TypeError, AttributeError):
            raise AuthorizationUnavailable("native roles cannot be verified") from None
