from allauth.mfa.adapter import DefaultMFAAdapter
from core.logging_utils import get_accounts_logger

# Get centralized logger
logger = get_accounts_logger()

class CustomMFAAdapter(DefaultMFAAdapter):
    """
    Custom MFA adapter to log all multi-factor authentication events
    """

    def authenticate_via_totp(self, user, code):
        """
        Override to log TOTP authentication attempts
        """
        result = super().authenticate_via_totp(user, code)

        if result:
            logger.user_activity("2fa_totp_success", user, "TOTP authentication successful")
        else:
            logger.security_event("2FA TOTP authentication failed", user, extra_data={
                "method": "totp"
            })

        return result

    def authenticate_via_recovery_codes(self, user, code):
        """
        Override to log recovery code authentication attempts
        """
        result = super().authenticate_via_recovery_codes(user, code)

        if result:
            logger.user_activity("2fa_recovery_success", user, "Recovery code authentication successful")
            logger.security_event("Recovery code used for authentication", user, extra_data={
                "method": "recovery_code"
            })
        else:
            logger.security_event("2FA recovery code authentication failed", user, extra_data={
                "method": "recovery_code"
            })

        return result

    def generate_totp_secret(self, user):
        """
        Override to log TOTP secret generation
        """
        secret = super().generate_totp_secret(user)
        logger.user_activity("2fa_totp_secret_generated", user, "TOTP secret generated for user")
        return secret

    def get_totp_key(self, user):
        """
        Override to log TOTP key access
        """
        key = super().get_totp_key(user)
        if key:
            logger.info("2FA TOTP key accessed", user)
        return key

    def activate_totp(self, request, authenticator):
        """
        Override to log TOTP activation
        """
        result = super().activate_totp(request, authenticator)
        user = authenticator.user
        logger.user_activity("2fa_totp_activated", user, "TOTP authenticator activated")
        logger.security_event("2FA TOTP enabled for user", user)
        return result

    def deactivate_totp(self, request, authenticator):
        """
        Override to log TOTP deactivation
        """
        result = super().deactivate_totp(request, authenticator)
        user = authenticator.user
        logger.user_activity("2fa_totp_deactivated", user, "TOTP authenticator deactivated")
        logger.security_event("2FA TOTP disabled for user", user)
        return result

    def generate_recovery_codes(self, user):
        """
        Override to log recovery code generation
        """
        codes = super().generate_recovery_codes(user)
        logger.user_activity("2fa_recovery_codes_generated", user, f"Generated {len(codes)} recovery codes")
        logger.security_event("2FA recovery codes generated", user, extra_data={
            "code_count": len(codes)
        })
        return codes
