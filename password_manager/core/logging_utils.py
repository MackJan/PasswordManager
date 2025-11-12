"""
Centralized logging utilities for the password manager application.
Provides consistent logging patterns and helper functions.
"""

import logging
from typing import Optional, Dict, Any


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

    def info(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log an info message."""
        self._log('info', message, user, extra_data)

    def warning(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a warning message."""
        self._log('warning', message, user, extra_data)

    def error(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log an error message."""
        self._log('error', message, user, extra_data)

    def critical(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a critical message and also send to alerts."""
        formatted_message, context = self._prepare_message(message, user, extra_data)
        if context:
            self.logger.critical(formatted_message, extra=context)
        else:
            self.logger.critical(formatted_message)
        if context:
            self.alerts_logger.error(f"CRITICAL: {message}", extra=context)
        else:
            self.alerts_logger.error(f"CRITICAL: {message}")

    def security_event(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Log a security-related event directly to security log."""
        formatted_message, context = self._prepare_message(f"SECURITY EVENT: {message}", user, extra_data)
        if context:
            self.security_logger.warning(formatted_message, extra=context)
        else:
            self.security_logger.warning(formatted_message)

    def user_activity(self, action: str, user: Any, details: Optional[str] = None):
        """Log user activity with consistent format."""
        message = f"User {getattr(user, 'email', 'unknown')} performed action: {action}"
        if details:
            message += f" - {details}"
        self.info(message, user)

    def encryption_event(self, event: str, user: Optional[Any] = None, success: bool = True):
        """Log encryption-related events."""
        status = "SUCCESS" if success else "FAILURE"
        message = f"ENCRYPTION {status}: {event}"
        if success:
            self.info(message, user)
        else:
            self.error(message, user)

    def _log(self, level: str, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Internal method to handle actual logging."""
        formatted_message, context = self._prepare_message(message, user, extra_data)
        log_method = getattr(self.logger, level)
        if context:
            log_method(formatted_message, extra=context)
        else:
            log_method(formatted_message)

    def _prepare_message(self, message: str, user: Optional[Any], extra_data: Optional[Dict[str, Any]]):
        """Return the formatted message and logging context."""
        formatted_message = self._format_message(message, user, extra_data)
        context = self._build_context(user, extra_data)
        if context:
            return formatted_message, {'context': context}
        return formatted_message, None

    def _build_context(self, user: Optional[Any], extra_data: Optional[Dict[str, Any]]):
        context: Dict[str, Any] = {}
        if user is not None:
            context.setdefault('user_email', getattr(user, 'email', None))
            user_identifier = getattr(user, 'id', getattr(user, 'pk', None))
            if user_identifier is not None:
                context.setdefault('user_pk', user_identifier)
        if extra_data:
            context.update(extra_data)
        return context

    def _format_message(self, message: str, user: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Format message with user info and extra data."""
        if user:
            user_email = getattr(user, 'email', 'unknown')
            formatted_message = f"[User: {user_email}] {message}"
        else:
            formatted_message = message

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
