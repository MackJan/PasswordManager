from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.utils import user_pk_to_url_str
from django.db import transaction
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from vault.encryption_service import EncryptionService
from vault.crypto_utils import CryptoError
from core.logging_utils import get_accounts_logger
from typing import Optional

User = get_user_model()

# Get centralized logger
logger = get_accounts_logger()

class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter to integrate encryption service with allauth user registration
    and provide comprehensive logging for all authentication events
    """

    def save_user(self, request, user, form, commit=True):
        """
        Override to set up encryption when saving a new user
        """
        if commit:
            try:
                with transaction.atomic():
                    # Save the user first
                    user = super().save_user(request, user, form, commit=True)

                    # Set up encryption for the new user
                    EncryptionService.setup_user_encryption(user)

                    logger.user_activity("registration_completed", user, "User registered with encryption setup")
                    return user

            except CryptoError as e:
                logger.error("Encryption setup failed during registration", user, extra_data={"error": str(e)})
                logger.critical("Critical error during user registration - encryption setup failed", user)
                # Re-raise to prevent user creation if encryption setup fails
                raise
        else:
            return super().save_user(request, user, form, commit=False)

    def pre_authenticate(self, request, **credentials):
        """
        Log authentication attempts before they happen
        """
        email = credentials.get('email') or credentials.get('username')
        logger.info("Authentication attempt initiated", extra_data={
            "email": email,
            "ip": self._get_client_ip(request)
        })
        return super().pre_authenticate(request, **credentials)

    def authenticate(self, request, **credentials):
        """
        Override to log authentication results
        """
        email = credentials.get('email') or credentials.get('username')
        user = super().authenticate(request, **credentials)

        if user:
            logger.user_activity("successful_login", user, "User authenticated successfully")
        else:
            logger.security_event("Login failed - Invalid credentials", extra_data={
                "email": email,
                "ip": self._get_client_ip(request)
            })

        return user

    def login(self, request, user):
        """
        Override to log successful login events
        """
        logger.user_activity("login_completed", user, f"User logged in from IP: {self._get_client_ip(request)}")
        return super().login(request, user)

    def logout(self, request):
        """
        Override to log logout events
        """
        if request.user.is_authenticated:
            logger.user_activity("logout", request.user, "User logged out")
        else:
            logger.info("Anonymous logout attempt", extra_data={"ip": self._get_client_ip(request)})
        return super().logout(request)

    def add_message(self, request, level, message_template, message_context=None, extra_tags=""):
        """
        Override to log important messages (like failed login attempts)
        """
        if message_context is None:
            message_context = {}

        # Log security-relevant messages
        if "invalid" in message_template.lower() or "incorrect" in message_template.lower():
            logger.security_event("Authentication failure message displayed", extra_data={
                "message": message_template,
                "ip": self._get_client_ip(request)
            })
        elif "email" in message_template.lower() and "confirm" in message_template.lower():
            logger.info("Email confirmation message sent", extra_data={
                "message": message_template,
                "ip": self._get_client_ip(request)
            })

        return super().add_message(request, level, message_template, message_context, extra_tags)

    def send_confirmation_mail(self, request, emailconfirmation, signup):
        """
        Override to log email confirmation events
        """
        user = emailconfirmation.email_address.user
        logger.user_activity("email_confirmation_sent", user,
                           f"Email confirmation sent to {emailconfirmation.email_address.email}")
        return super().send_confirmation_mail(request, emailconfirmation, signup)

    def confirm_email(self, request, email_address):
        """
        Override to log email confirmation events
        """
        user = email_address.user
        logger.user_activity("email_confirmed", user,
                           f"Email address confirmed: {email_address.email}")
        return super().confirm_email(request, email_address)

    def is_open_for_signup(self, request):
        """
        Override to log signup attempts when registration is closed
        """
        is_open = super().is_open_for_signup(request)
        if not is_open:
            logger.security_event("Registration attempt when signup is closed", extra_data={
                "ip": self._get_client_ip(request)
            })
        return is_open

    def get_login_redirect_url(self, request):
        """
        Override to log login redirects
        """
        url = super().get_login_redirect_url(request)
        if request.user.is_authenticated:
            logger.user_activity("login_redirect", request.user, f"Redirected to: {url}")
        return url

    def get_logout_redirect_url(self, request):
        """
        Override to log logout redirects
        """
        url = super().get_logout_redirect_url(request)
        logger.info("Logout redirect", extra_data={
            "redirect_url": url,
            "ip": self._get_client_ip(request)
        })
        return url

    def _get_client_ip(self, request):
        """
        Get the client's IP address from the request, considering proxies
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
