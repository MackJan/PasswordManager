import logging
import threading

# Thread-local storage for request data
_request_data = threading.local()

def get_client_ip(request):
    """
    Get the client's IP address from the request, considering proxies
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class UserIdFilter(logging.Filter):
    """
    Custom logging filter to add user ID and IP address to log records
    """
    def filter(self, record):
        user_id = getattr(_request_data, 'user_id', 'anonymous')
        ip_address = getattr(_request_data, 'ip_address', 'unknown')
        record.user_id = user_id
        record.ip = ip_address
        return True

class LoggingMiddleware:
    """
    Middleware to capture user information and IP address for logging
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Store user ID and IP address in thread-local storage
        if hasattr(request, 'user') and request.user.is_authenticated:
            _request_data.user_id = str(request.user.id)
        else:
            _request_data.user_id = 'anonymous'
        
        # Store IP address
        _request_data.ip_address = get_client_ip(request)

        response = self.get_response(request)
        
        # Clean up thread-local data
        if hasattr(_request_data, 'user_id'):
            delattr(_request_data, 'user_id')
        if hasattr(_request_data, 'ip_address'):
            delattr(_request_data, 'ip_address')

        return response