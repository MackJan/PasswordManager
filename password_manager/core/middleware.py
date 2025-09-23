import logging
import threading

# Thread-local storage for request data
_request_data = threading.local()

class UserIdFilter(logging.Filter):
    """
    Custom logging filter to add user ID to log records
    """
    def filter(self, record):
        user_id = getattr(_request_data, 'user_id', 'anonymous')
        record.user_id = user_id
        return True

class LoggingMiddleware:
    """
    Middleware to capture user information for logging
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Store user ID in thread-local storage
        if hasattr(request, 'user') and request.user.is_authenticated:
            _request_data.user_id = str(request.user.id)
        else:
            _request_data.user_id = 'anonymous'
        
        response = self.get_response(request)
        
        # Clean up thread-local data
        if hasattr(_request_data, 'user_id'):
            delattr(_request_data, 'user_id')
        
        return response