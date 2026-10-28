"""Shared authorization failures; no remote API dependencies."""
class AccessDenied(Exception):
    pass


class AuthorizationUnavailable(AccessDenied):
    pass


class UpstreamThrottled(AuthorizationUnavailable):
    def __init__(self, retry_after=None):
        # 只接受短整数，不将上游响应内容传入错误或HTTP头。
        self.retry_after = (min(60, max(1, int(retry_after)))
            if isinstance(retry_after, str) and retry_after.isascii() and
            retry_after.isdecimal() and len(retry_after) <= 3 else 5)
        super().__init__('upstream temporarily throttled; verify write result before retry')
