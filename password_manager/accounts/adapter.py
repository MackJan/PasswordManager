from allauth.account.adapter import DefaultAccountAdapter
from django.db import transaction
from vault.encryption_service import EncryptionService
from vault.crypto_utils import CryptoError
import logging

logger = logging.getLogger('accounts')

class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter to integrate encryption service with allauth user registration
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

                    logger.info(f"Successfully registered user: {user.email} with encryption setup")
                    return user

            except CryptoError as e:
                logger.error(f"Encryption setup failed for user {user.email}: {str(e)}")
                # Re-raise to prevent user creation if encryption setup fails
                raise
        else:
            return super().save_user(request, user, form, commit=False)
