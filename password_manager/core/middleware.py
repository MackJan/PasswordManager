import logging
import threading
from ipaddress import ip_address

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


def _candidate_ips_from_request(request):
    """Yield potential client IP addresses from request headers."""
    meta = getattr(request, 'META', {}) or {}

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

    for header in ('HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR'):
        cleaned = _normalize_ip(meta.get(header))
        if cleaned:
            yield cleaned


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
