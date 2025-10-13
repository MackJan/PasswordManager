"""
Signal handlers for django-allauth events to provide comprehensive logging
"""

from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from allauth.account.signals import (
    user_signed_up, password_reset, password_changed, password_set,
    email_confirmed, email_confirmation_sent
)
from allauth.mfa.signals import authenticator_added, authenticator_removed
from core.logging_utils import get_accounts_logger

logger = get_accounts_logger()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log when a user successfully logs in"""
    ip = _get_client_ip(request)
    logger.user_activity("user_logged_in_signal", user, f"User login signal received from IP: {ip}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log when a user logs out"""
    if user:
        logger.user_activity("user_logged_out_signal", user, "User logout signal received")
    else:
        ip = _get_client_ip(request)
        logger.info("Anonymous user logout signal received", extra_data={"ip": ip})


@receiver(user_login_failed)
def log_login_failure(sender, credentials, request, **kwargs):
    """Log failed login attempts"""
    email = credentials.get('username') or credentials.get('email', 'unknown')
    ip = _get_client_ip(request)
    logger.security_event("Login failed - Django signal", extra_data={
        "email": email,
        "ip": ip,
        "credentials_keys": list(credentials.keys())
    })


@receiver(user_signed_up)
def log_user_signup(sender, request, user, **kwargs):
    """Log when a new user signs up"""
    ip = _get_client_ip(request)
    logger.user_activity("user_signed_up", user, f"User registration signal received from IP: {ip}")


@receiver(password_reset)
def log_password_reset(sender, request, user, **kwargs):
    """Log password reset events"""
    ip = _get_client_ip(request)
    logger.security_event("Password reset initiated", user, extra_data={"ip": ip})


@receiver(password_changed)
def log_password_changed(sender, request, user, **kwargs):
    """Log password change events"""
    ip = _get_client_ip(request)
    logger.security_event("Password changed", user, extra_data={"ip": ip})


@receiver(password_set)
def log_password_set(sender, request, user, **kwargs):
    """Log when a password is set (usually for new users)"""
    ip = _get_client_ip(request)
    logger.user_activity("password_set", user, f"Password set for user from IP: {ip}")


@receiver(email_confirmed)
def log_email_confirmed(sender, request, email_address, **kwargs):
    """Log email confirmation events"""
    user = email_address.user
    ip = _get_client_ip(request) if request else "unknown"
    logger.user_activity("email_confirmed_signal", user,
                       f"Email confirmed: {email_address.email} from IP: {ip}")


@receiver(email_confirmation_sent)
def log_email_confirmation_sent(sender, request, confirmation, signup, **kwargs):
    """Log when email confirmations are sent"""
    user = confirmation.email_address.user
    ip = _get_client_ip(request) if request else "unknown"
    logger.user_activity("email_confirmation_sent_signal", user,
                       f"Email confirmation sent to: {confirmation.email_address.email} from IP: {ip}")


@receiver(authenticator_added)
def log_mfa_authenticator_added(sender, request, authenticator, **kwargs):
    """Log when MFA authenticators are added"""
    user = authenticator.user
    ip = _get_client_ip(request) if request else "unknown"
    logger.user_activity("mfa_authenticator_added", user,
                       f"MFA authenticator added: {authenticator.type} from IP: {ip}")
    logger.security_event("MFA authenticator enabled", user, extra_data={
        "authenticator_type": authenticator.type,
        "ip": ip
    })


@receiver(authenticator_removed)
def log_mfa_authenticator_removed(sender, request, authenticator, **kwargs):
    """Log when MFA authenticators are removed"""
    user = authenticator.user
    ip = _get_client_ip(request) if request else "unknown"
    logger.user_activity("mfa_authenticator_removed", user,
                       f"MFA authenticator removed: {authenticator.type} from IP: {ip}")
    logger.security_event("MFA authenticator disabled", user, extra_data={
        "authenticator_type": authenticator.type,
        "ip": ip
    })


def _get_client_ip(request):
    """
    Get the client's IP address from the request, considering proxies
    """
    if not request:
        return "unknown"

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
