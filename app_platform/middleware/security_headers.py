"""Security response headers middleware."""

from __future__ import annotations

from starlette.datastructures import MutableHeaders

DEFAULT_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://accounts.google.com "
    "https://cdn.plaid.com https://*.plaid.com https://app.snaptrade.com "
    "https://*.snaptrade.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
    "https://accounts.google.com; "
    "img-src 'self' data: blob: https:; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "connect-src 'self' https://accounts.google.com https://*.google.com "
    "https://*.googleapis.com https://cdn.plaid.com https://*.plaid.com "
    "https://app.snaptrade.com https://*.snaptrade.com wss://*.snaptrade.com; "
    "frame-src 'self' https://accounts.google.com https://*.google.com "
    "https://cdn.plaid.com https://*.plaid.com https://app.snaptrade.com "
    "https://*.snaptrade.com; "
    "worker-src 'self' blob:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

BASE_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}
SOURCE_HTML_PATH_PREFIX = "/api/research/content/documents/source-html"
SOURCE_HTML_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'none'; "
    "object-src 'none'; "
    "connect-src 'none'; "
    "frame-src 'none'; "
    "style-src 'unsafe-inline'; "
    "img-src 'self' data: https://www.sec.gov; "
    "font-src 'self' data:; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'self'"
)
SOURCE_HTML_SECURITY_HEADERS = {
    **BASE_SECURITY_HEADERS,
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
}


class SecurityHeadersMiddleware:
    """Add browser security headers to HTTP responses."""

    def __init__(
        self,
        app,
        *,
        is_production: bool = False,
        content_security_policy: str = DEFAULT_CONTENT_SECURITY_POLICY,
    ) -> None:
        self.app = app
        self.headers = dict(BASE_SECURITY_HEADERS)
        if is_production:
            self.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
            if content_security_policy:
                self.headers["Content-Security-Policy"] = content_security_policy

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                response_headers = self._headers_for_path(scope.get("path", ""))
                for name, value in response_headers.items():
                    headers[name] = value
                if scope.get("path", "").startswith(SOURCE_HTML_PATH_PREFIX):
                    headers["Content-Security-Policy"] = SOURCE_HTML_CONTENT_SECURITY_POLICY
            await send(message)

        await self.app(scope, receive, send_with_security_headers)

    def _headers_for_path(self, path: str) -> dict[str, str]:
        if path.startswith(SOURCE_HTML_PATH_PREFIX):
            headers = dict(SOURCE_HTML_SECURITY_HEADERS)
            if "Strict-Transport-Security" in self.headers:
                headers["Strict-Transport-Security"] = self.headers["Strict-Transport-Security"]
            return headers
        return self.headers


__all__ = [
    "BASE_SECURITY_HEADERS",
    "DEFAULT_CONTENT_SECURITY_POLICY",
    "SecurityHeadersMiddleware",
    "SOURCE_HTML_CONTENT_SECURITY_POLICY",
    "SOURCE_HTML_PATH_PREFIX",
    "SOURCE_HTML_SECURITY_HEADERS",
]
