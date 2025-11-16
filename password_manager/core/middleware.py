import logging
import threading
from ipaddress import ip_address, ip_network

from django.conf import settings
from django.http import HttpResponse

from core.logging_utils import get_security_logger
from core.rate_limit import (
    RateLimitScenario,
    increment_rate_limit,
    is_rate_limited,
)

# Thread-local storage for request data
_request_data = threading.local()


def _normalize_ip(candidate: str):
    """Return a cleaned IP address string or ``None`` if invalid."""
    if not candidate:
        return None

    value = candidate.strip().strip('"')

    # Handle Forwarded header values e.g. for="[2001:db8::1]:1234"
    if value.startswith('for='):
        value = value[4:]

    if value.startswith('[') and ']' in value:
        value = value[value.index('[') + 1:value.index(']')]

    if value.startswith('::ffff:'):
        value = value.split('::ffff:')[-1]

    # Remove port suffix for IPv4 values encoded as host:port
    if value.count(':') == 1 and value.replace(':', '').replace('.', '').isdigit() and '.' in value:
        host, _, _ = value.partition(':')
        value = host

    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _remote_addr_is_trusted(meta):
    remote_addr = (meta or {}).get('REMOTE_ADDR')
    if not remote_addr:
        return False
    try:
        candidate = ip_address(remote_addr)
    except ValueError:
        return False
    for network in getattr(settings, 'TRUSTED_PROXY_IPS', ()):  # type: ignore[attr-defined]
        try:
            network_obj = network if not isinstance(network, str) else ip_network(network, strict=False)
        except ValueError:
            continue
        if candidate in network_obj:
            return True
    return False


def _candidate_ips_from_request(request):
    """Yield potential client IP addresses from request headers."""
    meta = getattr(request, 'META', {}) or {}
    trust_proxy_headers = _remote_addr_is_trusted(meta)

    if trust_proxy_headers:
        forwarded_for = meta.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            for part in forwarded_for.split(','):
                cleaned = _normalize_ip(part)
                if cleaned:
                    yield cleaned

        forwarded_header = meta.get('HTTP_FORWARDED')
        if forwarded_header:
            for segment in forwarded_header.split(';'):
                cleaned = _normalize_ip(segment)
                if cleaned:
                    yield cleaned

        for header in ('HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP'):
            cleaned = _normalize_ip(meta.get(header))
            if cleaned:
                yield cleaned

    cleaned_remote = _normalize_ip(meta.get('REMOTE_ADDR'))
    if cleaned_remote:
        yield cleaned_remote


def get_client_ip(request):
    """Return the most appropriate client IP address for the request."""
    public_candidate = None
    fallback_candidate = None

    for candidate in _candidate_ips_from_request(request):
        ip_obj = ip_address(candidate)
        if getattr(ip_obj, 'is_global', False):
            return candidate
        if fallback_candidate is None:
            fallback_candidate = candidate
        if not ip_obj.is_private and public_candidate is None:
            public_candidate = candidate

    return public_candidate or fallback_candidate or 'unknown'


class UserIdFilter(logging.Filter):
    """
    Custom logging filter to add user information and IP address to log records.
    """

    def filter(self, record):
        user_id = getattr(_request_data, 'user_id', None)
        user_email = getattr(_request_data, 'user_email', None)
        ip_value = getattr(_request_data, 'ip_address', None)
        path = getattr(_request_data, 'path', None)
        method = getattr(_request_data, 'method', None)

        request = getattr(record, 'request', None)
        if request is not None:
            if user_id is None and getattr(request, 'user', None) is not None:
                user = request.user
                if getattr(user, 'is_authenticated', False):
                    user_id = str(getattr(user, 'id', getattr(user, 'pk', 'anonymous')))
                    user_email = getattr(user, 'email', user_email)
            if ip_value in (None, 'unknown'):
                resolved_ip = get_client_ip(request)
                if resolved_ip:
                    ip_value = resolved_ip
            path = path or getattr(request, 'get_full_path', lambda: getattr(request, 'path', None))()
            method = method or getattr(request, 'method', None)

        record.user_id = user_id or 'anonymous'
        record.user_email = user_email or 'anonymous'
        record.ip = ip_value or 'unknown'
        if path:
            record.path = path
        if method:
            record.http_method = method
        return True


class LoggingMiddleware:
    """Middleware to capture user information and IP address for logging."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Populate thread-local context for downstream log records
        user = getattr(request, 'user', None)
        if getattr(user, 'is_authenticated', False):
            _request_data.user_id = str(getattr(user, 'id', getattr(user, 'pk', 'anonymous')))
            _request_data.user_email = getattr(user, 'email', None)
        else:
            _request_data.user_id = 'anonymous'
            _request_data.user_email = None

        _request_data.ip_address = get_client_ip(request)
        _request_data.path = getattr(request, 'get_full_path', lambda: getattr(request, 'path', None))()
        _request_data.method = getattr(request, 'method', None)

        try:
            response = self.get_response(request)
        finally:
            # Clean up thread-local data to avoid leaking between requests
            for attribute in ('user_id', 'user_email', 'ip_address', 'path', 'method'):
                if hasattr(_request_data, attribute):
                    delattr(_request_data, attribute)

        return response


class RateLimitMiddleware:
    """Middleware that throttles sensitive and malicious requests."""

    LOGIN_PATH_PREFIX = "/accounts/login"
    PASSWORD_RESET_PATH_PREFIX = "/accounts/password/reset"
    MALICIOUS_PATTERNS = (
        ".env",
        "wp-admin",
        "wp-login.php",
        "phpmyadmin",
        "\.git",
        "etc/passwd",
        "adminer.php",
    )

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = get_security_logger()

    def __call__(self, request):
        client_ip = get_client_ip(request)

        # Always block if the IP is already rate limited for login failures.
        if self._should_block_login_attempt(request, client_ip):
            return self._too_many_requests(
                "Too many failed login attempts. Please try again later.",
                client_ip,
            )

        # Block suspicious traffic probing well-known sensitive paths.
        if self._is_malicious_request(request):
            result = increment_rate_limit(
                RateLimitScenario.MALICIOUS_TRAFFIC_IP,
                client_ip,
                limit=3,
                window=900,
                block=86400,
            )
            if not result.allowed:
                self.logger.security_event(
                    "Blocked malicious probing after repeated suspicious requests",
                    extra_data={"ip": client_ip, "retry_after": result.retry_after},
                )
                return self._too_many_requests(
                    "Suspicious activity detected from your IP.",
                    client_ip,
                    retry_after=result.retry_after,
                )

        if request.method == "POST" and request.path.startswith(self.PASSWORD_RESET_PATH_PREFIX):
            response = self._apply_password_reset_limits(request, client_ip)
            if response:
                return response

        return self.get_response(request)

    def _apply_password_reset_limits(self, request, client_ip):
        result_ip = increment_rate_limit(
            RateLimitScenario.PASSWORD_RESET_IP,
            client_ip,
            limit=3,
            window=3600,
            block=14400,
        )
        if not result_ip.allowed:
            self.logger.security_event(
                "Password reset attempt rate limited by IP",
                extra_data={"ip": client_ip, "retry_after": result_ip.retry_after},
            )
            return self._too_many_requests(
                "Too many password reset requests. Please try again later.",
                client_ip,
                retry_after=result_ip.retry_after,
            )

        email = (request.POST.get("email") or request.POST.get("login") or "").strip()
        if email:
            result_email = increment_rate_limit(
                RateLimitScenario.PASSWORD_RESET_EMAIL,
                email,
                limit=2,
                window=3600,
                block=14400,
            )
            if not result_email.allowed:
                self.logger.security_event(
                    "Password reset attempt rate limited by email",
                    extra_data={"email": email, "ip": client_ip, "retry_after": result_email.retry_after},
                )
                return self._too_many_requests(
                    "Too many password reset requests for this account.",
                    email,
                    retry_after=result_email.retry_after,
                )
        return None

    def _should_block_login_attempt(self, request, client_ip):
        if request.method != "POST":
            return False
        if not request.path.startswith(self.LOGIN_PATH_PREFIX):
            return False

        result_ip = is_rate_limited(RateLimitScenario.LOGIN_IP, client_ip)
        if not result_ip.allowed:
            self.logger.security_event(
                "Login blocked due to IP rate limit",
                extra_data={"ip": client_ip, "retry_after": result_ip.retry_after},
            )
            return True

        identifier = self._extract_login_identifier(request)
        if identifier:
            result_email = is_rate_limited(RateLimitScenario.LOGIN_EMAIL, identifier)
            if not result_email.allowed:
                self.logger.security_event(
                    "Login blocked due to account rate limit",
                    extra_data={
                        "email": identifier,
                        "ip": client_ip,
                        "retry_after": result_email.retry_after,
                    },
                )
                return True
        return False

    def _is_malicious_request(self, request):
        path = (getattr(request, "path", "") or "").lower()
        if not path:
            return False
        return any(pattern in path for pattern in self.MALICIOUS_PATTERNS)

    def _extract_login_identifier(self, request):
        possible_keys = ("login", "email", "username")
        for key in possible_keys:
            value = request.POST.get(key)
            if value:
                return value.strip().lower()
        return None

    def _too_many_requests(self, message, identifier, retry_after=None):
        retry_value = retry_after if retry_after is not None else 0
        response = HttpResponse(message, status=429)
        if retry_value:
            response["Retry-After"] = str(retry_value)
        return response
