"""
Centralized logging utilities for the password manager application.
Provides consistent logging patterns and helper functions.
"""

import logging
from typing import Optional, Dict, Any
from django.contrib.auth import get_user_model

User = get_user_model()


class AppLogger:
    """Centralized logger utility for consistent logging across the application."""

    def __init__(self, logger_name: str):
        """
        Initialize the app logger.

        Args:
            logger_name: Name of the logger (e.g., 'accounts', 'vault', 'core')
        """
        self.logger = logging.getLogger(logger_name)
        self.security_logger = logging.getLogger('django.security')
        self.alerts_logger = logging.getLogger('alerts')

    def info(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log an info message."""
        self._log('info', message, user, extra_data)

    def warning(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a warning message."""
        self._log('warning', message, user, extra_data)

    def error(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log an error message."""
        self._log('error', message, user, extra_data)

    def critical(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a critical message and also send to alerts."""
        self._log('critical', message, user, extra_data)
        # Also log to alerts for critical issues
        self.alerts_logger.error(f"CRITICAL: {message}")

    def security_event(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a security-related event directly to security log."""
        security_message = f"SECURITY EVENT: {message}"
        self._log_to_security(security_message, user, extra_data)

    def user_activity(self, action: str, user: User, details: Optional[str] = None):
        """Log user activity with consistent format."""
        message = f"User {getattr(user, 'email', 'unknown')} performed action: {action}"
        if details:
            message += f" - {details}"
        self.info(message, user)

    def encryption_event(self, event: str, user: Optional[User] = None, success: bool = True):
        """Log encryption-related events."""
        status = "SUCCESS" if success else "FAILURE"
        message = f"ENCRYPTION {status}: {event}"
        if success:
            self.info(message, user)
        else:
            self.error(message, user)

    def _log(self, level: str, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Internal method to handle actual logging."""
        formatted_message = self._format_message(message, user, extra_data)
        log_method = getattr(self.logger, level)
        log_method(formatted_message)

    def _log_to_security(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log directly to security logger."""
        formatted_message = self._format_message(message, user, extra_data)
        self.security_logger.warning(formatted_message)

    def _format_message(self, message: str, user: Optional[User] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Format message with user info and extra data."""
        # Format message with user info if available
        if user:
            user_email = getattr(user, 'email', 'unknown')
            formatted_message = f"[User: {user_email}] {message}"
        else:
            formatted_message = message

        # Add extra data if provided
        if extra_data:
            extra_info = ", ".join([f"{k}: {v}" for k, v in extra_data.items()])
            formatted_message += f" | Extra: {extra_info}"

        return formatted_message


# Convenience functions for getting loggers
def get_accounts_logger():
    """Get the accounts logger."""
    return AppLogger('accounts')

def get_vault_logger():
    """Get the vault logger."""
    return AppLogger('vault')

def get_core_logger():
    """Get the core logger."""
    return AppLogger('core')

def get_security_logger():
    """Get a logger specifically for security events."""
    return AppLogger('django.security')
