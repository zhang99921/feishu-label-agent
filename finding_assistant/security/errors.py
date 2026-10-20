"""Shared authorization failures; no remote API dependencies."""
class AccessDenied(Exception):
    pass


class AuthorizationUnavailable(AccessDenied):
    pass
