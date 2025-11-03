import asyncio
import contextvars
import logging
import uuid
from ipaddress import ip_address
from typing import Any, Dict, Optional

# Context variable used to propagate request scoped logging metadata safely in
# both synchronous and asynchronous views.
_request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "request_context", default={}
)


def _validate_ip(candidate: Optional[str]) -> Optional[str]:
    if not candidate:
        return None

    candidate = candidate.strip()
    if not candidate or candidate.lower() == "unknown":
        return None

    try:
        # This will raise a ValueError for malformed addresses.
        ip_address(candidate)
    except ValueError:
        return None
    return candidate


def get_client_ip(request):
    """Return the best-effort client IP, taking proxy headers into account."""

    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        for part in forwarded_for.split(","):
            validated = _validate_ip(part)
            if validated:
                return validated

    real_ip = _validate_ip(request.META.get("HTTP_X_REAL_IP"))
    if real_ip:
        return real_ip

    client_ip = _validate_ip(request.META.get("HTTP_CLIENT_IP"))
    if client_ip:
        return client_ip

    forwarded = _validate_ip(request.META.get("HTTP_X_FORWARDED"))
    if forwarded:
        return forwarded

    remote_addr = _validate_ip(request.META.get("REMOTE_ADDR"))
    if remote_addr:
        return remote_addr

    return "unknown"


def get_request_context() -> Dict[str, Any]:
    """Expose the current request logging context (mainly for tests)."""

    return _request_context.get({}) or {}


class RequestContextFilter(logging.Filter):
    """Attach request specific metadata (user id, IP, request id, …) to logs."""

    def filter(self, record):
        context = get_request_context()
        record.user_id = context.get("user_id", "anonymous")
        record.ip = context.get("ip", "unknown")
        record.request_id = context.get("request_id", "unknown")
        record.http_method = context.get("method", "UNKNOWN")
        record.path = context.get("path", "")
        record.user_agent = context.get("user_agent", "")
        record.referer = context.get("referer", "")
        record.host = context.get("host", "")
        return True


def _build_request_context(request) -> Dict[str, Any]:
    user_id = "anonymous"
    if getattr(request, "user", None) is not None and getattr(request.user, "is_authenticated", False):
        user_id = str(request.user.id)

    request_id = request.headers.get("X-Request-ID") if hasattr(request, "headers") else None
    if not request_id:
        request_id = str(uuid.uuid4())

    return {
        "user_id": user_id,
        "ip": get_client_ip(request),
        "method": getattr(request, "method", "UNKNOWN"),
        "path": getattr(request, "path", ""),
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "referer": request.META.get("HTTP_REFERER", ""),
        "host": request.get_host() if hasattr(request, "get_host") else request.META.get("HTTP_HOST", ""),
        "request_id": request_id,
    }


class LoggingMiddleware:
    """Populate the request context used by logging filters."""

    def __init__(self, get_response):
        self.get_response = get_response
        self._is_async = asyncio.iscoroutinefunction(get_response)

    def __call__(self, request):
        if self._is_async:
            return self._async_call(request)
        return self._sync_call(request)

    def _set_context(self, request):
        context = _build_request_context(request)
        token = _request_context.set(context)
        setattr(request, "request_id", context["request_id"])
        return context, token

    def _finalize_response(self, response, context):
        if response is None or isinstance(response, (dict, list)):
            return response
        if hasattr(response, "__setitem__"):
            response["X-Request-ID"] = context["request_id"]
        return response

    def _reset_context(self, token):
        _request_context.reset(token)

    def _sync_call(self, request):
        context, token = self._set_context(request)
        try:
            response = self.get_response(request)
        finally:
            self._reset_context(token)
        return self._finalize_response(response, context)

    async def _async_call(self, request):
        context, token = self._set_context(request)
        try:
            response = await self.get_response(request)
        finally:
            self._reset_context(token)
        return self._finalize_response(response, context)