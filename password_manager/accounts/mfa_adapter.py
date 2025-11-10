from allauth.mfa.adapter import DefaultMFAAdapter
from allauth.mfa.models import Authenticator
from core.logging_utils import get_accounts_logger
import secrets
import hashlib

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
        Override to generate recovery codes with proper allauth format
        """
        # Generate a seed for the recovery codes
        seed = secrets.token_bytes(32)

        # Generate recovery codes using the seed
        codes = []
        for i in range(10):  # Generate 10 recovery codes
            code_input = seed + i.to_bytes(4, 'big')
            code_hash = hashlib.sha256(code_input).hexdigest()[:8]
            codes.append(code_hash)

        logger.user_activity("2fa_recovery_codes_generated", user, f"Generated {len(codes)} recovery codes")
        logger.security_event("2FA recovery codes generated", user, extra_data={
            "code_count": len(codes)
        })

        return codes

    def get_recovery_codes_data(self, codes):
        """
        Generate the data structure that allauth expects for recovery codes
        """
        # Generate a seed for the recovery codes
        seed = secrets.token_bytes(32)

        return {
            'seed': seed.hex(),  # This is what allauth expects
            'unused_codes': codes,  # Keep this for compatibility with existing views
            'used_mask': 0  # Bitfield to track which codes have been used (0 = all unused)
        }
