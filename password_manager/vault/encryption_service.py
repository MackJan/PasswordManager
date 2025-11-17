"""
Encryption service layer for password manager.
Handles registration, login, and vault encryption workflows.
"""

import base64
from typing import Dict
from django.contrib.auth import get_user_model
from django.db import transaction
from accounts.models import UserKeystore
from vault.models import VaultItem
from vault.crypto_utils import (
    generate_key, generate_salt, wrap_umk, unwrap_umk, wrap_dek, unwrap_dek,
    encrypt_item_data, decrypt_item_data, secure_zero, CryptoError
)
from core.logging_utils import get_vault_logger

User = get_user_model()

logger = get_vault_logger()

class EncryptionService:
    """Service for handling encryption workflows"""
    
    @staticmethod
    def setup_user_encryption(user: User) -> None:
        """
        Set up encryption for a newly registered user.
        Creates UMK and wraps it with AMK.
        
        Args:
            user: The user instance
        """
        try:
            # Check if keystore already exists
            if hasattr(user, 'keystore') and user.keystore.wrapped_umk_b64:
                logger.info("Encryption already set up for user", user)
                return  # Already set up

            # Generate User Master Key
            umk = generate_key()
            
            # Wrap UMK with AMK
            wrapped_umk_b64, nonce_b64, amk_version = wrap_umk(umk, user.id)
            
            # Create or update keystore entry
            keystore, created = UserKeystore.objects.get_or_create(
                user=user,
                defaults={
                    'amk_key_version': amk_version,
                    'wrapped_umk_b64': wrapped_umk_b64,
                    'umk_nonce_b64': nonce_b64,
                    'algo_version': 1
                }
            )

            if not created:
                # Update existing keystore
                keystore.amk_key_version = amk_version
                keystore.wrapped_umk_b64 = wrapped_umk_b64
                keystore.umk_nonce_b64 = nonce_b64
                keystore.algo_version = 1
                keystore.save()

            logger.encryption_event("user encryption setup completed", user, success=True)

        except Exception as e:
            logger.encryption_event(f"user encryption setup failed: {str(e)}", user, success=False)
            raise CryptoError(f"Failed to set up user encryption: {str(e)}")
        finally:
            # Secure cleanup
            if 'umk' in locals():
                secure_zero(umk)

    @staticmethod
    def _get_user_master_key(user: User) -> bytes:
        """
        Retrieve and unwrap the User Master Key for a user.

        Args:
            user: The user instance
            
        Returns:
            32-byte User Master Key
            
        Raises:
            CryptoError: If keystore not found or decryption fails
        """

        try:
            keystore = user.keystore
            if not keystore.wrapped_umk_b64:
                raise CryptoError("User encryption not set up")

            logger.encryption_event(f"keystore found - AMK version: {keystore.amk_key_version}, algo_version: {keystore.algo_version}", user)

        except UserKeystore.DoesNotExist:
            logger.error("User keystore not found", user)
            raise CryptoError("User keystore not found")
        
        try:
            logger.encryption_event("attempting to unwrap UMK", user)
            umk = unwrap_umk(
                keystore.wrapped_umk_b64,
                keystore.umk_nonce_b64,
                user.id,
                keystore.amk_key_version,
                keystore.algo_version
            )
            logger.encryption_event("successfully unwrapped UMK", user)
            return umk

        except CryptoError as e:
            logger.error(f"Failed to unwrap UMK: {str(e)}", user)
            logger.error(f"Keystore details - wrapped_umk_b64 length: {len(keystore.wrapped_umk_b64) if keystore.wrapped_umk_b64 else 0}, "
                        f"umk_nonce_b64 length: {len(keystore.umk_nonce_b64) if keystore.umk_nonce_b64 else 0}, "
                        f"amk_version: {keystore.amk_key_version}, algo_version: {keystore.algo_version}", user)
            raise

    @staticmethod
    def is_item_encrypted_with_new_system(vault_item: VaultItem) -> bool:
        """Check if a vault item uses the new encryption system"""
        return bool(vault_item.wrapped_dek_b64 and vault_item.ciphertext_b64)

    @staticmethod
    @transaction.atomic
    def create_vault_item(user: User, item_data: Dict[str, str]) -> VaultItem:
        """
        Create a new encrypted vault item.
        
        Args:
            user: The user instance
            item_data: Dictionary with 'name', 'username', 'password', etc.
            
        Returns:
            The created VaultItem instance
        """
        umk = None
        dek = None
        
        try:
            # Ensure user has encryption set up
            EncryptionService.setup_user_encryption(user)

            # Get User Master Key - this is where the error likely occurs
            logger.info(f"Attempting to get UMK for user {user.id} during vault item creation", user)

            umk = EncryptionService._get_user_master_key(user)
            logger.info(f"Successfully retrieved UMK for user {user.id}", user)

            # Generate Data Encryption Key
            dek = generate_key()
            logger.info(f"Generated DEK for user {user.id}", user)

            # Create vault item to get ID
            item_salt = generate_salt()
            item_salt_b64 = base64.b64encode(item_salt).decode('ascii')

            vault_item = VaultItem.objects.create(
                user=user,
                wrapped_dek_b64='',  # Will be set below
                dek_wrap_nonce_b64='',
                ciphertext_b64='',
                item_nonce_b64='',
                item_salt_b64=item_salt_b64,
                display_name='',
            )
            logger.info(f"Created vault item {vault_item.id} for user {user.id}", user)

            # Wrap DEK with UMK
            logger.info(f"Attempting to wrap DEK for vault item {vault_item.id}", user)
            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))
            logger.info(f"Successfully wrapped DEK for vault item {vault_item.id}", user)

            # Encrypt item data with DEK
            logger.info(f"Attempting to encrypt item data for vault item {vault_item.id}", user)
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(
                item_data, dek, user.id, str(vault_item.id), item_salt=item_salt
            )
            logger.info(f"Successfully encrypted item data for vault item {vault_item.id}", user)

            # Update vault item with encrypted data
            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.item_salt_b64 = item_salt_b64
            vault_item.save(update_fields=[
                'wrapped_dek_b64', 'dek_wrap_nonce_b64',
                'ciphertext_b64', 'item_nonce_b64', 'item_salt_b64'
            ])
            
            logger.info(f"Successfully created and saved encrypted vault item {vault_item.id} for user {user.id}", user)
            return vault_item
            
        except CryptoError as e:
            logger.error(f"CryptoError during vault item creation for user {user.id}: {str(e)}", user)
            raise
        except Exception as e:
            logger.error(f"Unexpected error during vault item creation for user {user.id}: {type(e).__name__}: {str(e)}", user)
            raise
        finally:
            # Secure zero sensitive keys
            if umk:
                secure_zero(umk)
            if dek:
                secure_zero(dek)
    
    @staticmethod
    def decrypt_vault_item(user: User, vault_item: VaultItem) -> Dict[str, str]:
        """
        Decrypt a vault item and return its data.
        Handles both old and new encryption systems during migration.

        Args:
            user: The user instance
            vault_item: The VaultItem to decrypt
            
        Returns:
            Dictionary containing decrypted item data
        """
        # Check if this item uses the new encryption system
        if not EncryptionService.is_item_encrypted_with_new_system(vault_item):
            # Handle old encryption system or unencrypted items
            # For now, return empty data or migrate the item
            return {
                'name': getattr(vault_item, 'name', vault_item.display_name or 'Legacy Item'),
                'username': getattr(vault_item, 'username', ''),
                'password': getattr(vault_item, 'password', ''),
                'url': '',
                'notes': 'This item needs to be migrated to the new encryption system'
            }

        umk = None
        dek = None
        
        try:
            # Get User Master Key
            umk = EncryptionService._get_user_master_key(user)
            
            # Get the algorithm version, defaulting to 1 if not set
            algo_version = getattr(vault_item, 'algo_version', 1)

            # Prepare optional item salt
            item_salt = None
            if getattr(vault_item, 'item_salt_b64', ''):
                try:
                    item_salt = base64.b64decode(vault_item.item_salt_b64)
                except (ValueError, TypeError) as exc:
                    raise CryptoError(f"Invalid item salt for vault item {vault_item.id}: {exc}")

            # Unwrap DEK
            dek = unwrap_dek(
                vault_item.wrapped_dek_b64,
                vault_item.dek_wrap_nonce_b64,
                umk,
                str(vault_item.id),
                algo_version
            )

            # Decrypt item data
            item_data = decrypt_item_data(
                vault_item.ciphertext_b64,
                vault_item.item_nonce_b64,
                dek,
                user.id,
                str(vault_item.id),
                algo_version,
                item_salt=item_salt
            )
            
            return item_data
            
        except CryptoError as e:
            # If decryption fails, it might be due to the old AAD inconsistency
            # Try to recover by attempting decryption with different AAD patterns
            if umk is not None:
                try:
                    # Try with the old inconsistent pattern (for recovery)
                    return EncryptionService._attempt_legacy_decryption(user, vault_item, umk)
                except CryptoError:
                    pass

            # If all recovery attempts fail, re-raise the original error
            raise e

        finally:
            # Secure zero sensitive keys
            if umk:
                secure_zero(umk)
            if dek:
                secure_zero(dek)

    @staticmethod
    def _attempt_legacy_decryption(user: User, vault_item: VaultItem, umk: bytes) -> Dict[str, str]:
        """
        Attempt to decrypt vault items that were encrypted with the old inconsistent AAD.
        This is for recovery purposes only.

        Args:
            user: The user instance
            vault_item: The VaultItem to decrypt
            umk: The User Master Key

        Returns:
            Dictionary containing decrypted item data

        Raises:
            CryptoError: If decryption fails
        """
        dek = None
        try:
            # The old system might have used different AAD patterns
            # Try the most likely legacy pattern first
            algo_version = getattr(vault_item, 'algo_version', 1)

            dek = unwrap_dek(
                vault_item.wrapped_dek_b64,
                vault_item.dek_wrap_nonce_b64,
                umk,
                str(vault_item.id),
                algo_version
            )

            # Try decrypting with the standard pattern
            item_salt = None
            if getattr(vault_item, 'item_salt_b64', ''):
                try:
                    item_salt = base64.b64decode(vault_item.item_salt_b64)
                except (ValueError, TypeError):
                    item_salt = None

            item_data = decrypt_item_data(
                vault_item.ciphertext_b64,
                vault_item.item_nonce_b64,
                dek,
                user.id,
                str(vault_item.id),
                algo_version,
                item_salt=item_salt
            )

            return item_data

        finally:
            if dek:
                secure_zero(dek)

    @staticmethod
    @transaction.atomic
    def update_vault_item(user: User, vault_item: VaultItem, item_data: Dict[str, str]) -> VaultItem:
        """
        Update an existing vault item with new encrypted data.
        Generates a new DEK for security.
        
        Args:
            user: The user instance
            vault_item: The VaultItem to update
            item_data: Dictionary with updated item data
            
        Returns:
            The updated VaultItem instance
        """
        umk = None
        dek = None
        
        try:
            # Ensure user has encryption set up
            EncryptionService.setup_user_encryption(user)

            # Get User Master Key
            umk = EncryptionService._get_user_master_key(user)
            
            # Generate new Data Encryption Key for security
            dek = generate_key()

            # Wrap new DEK with UMK
            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))

            # Refresh item salt to harden ciphertext uniqueness
            item_salt = generate_salt()
            item_salt_b64 = base64.b64encode(item_salt).decode('ascii')

            # Encrypt new item data with new DEK
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(
                item_data, dek, user.id, str(vault_item.id), item_salt=item_salt
            )
            
            # Update vault item
            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.item_salt_b64 = item_salt_b64
            vault_item.display_name = ''
            vault_item.save()
            
            return vault_item
            
        finally:
            # Secure zero sensitive keys
            if umk:
                secure_zero(umk)
            if dek:
                secure_zero(dek)
    
    @staticmethod
    def get_vault_items_metadata(user: User) -> list:
        """
        Get vault items with minimal metadata for listing.
        Does not decrypt sensitive data.
        
        Args:
            user: The user instance
            
        Returns:
            List of dictionaries with item metadata
        """
        items = VaultItem.objects.filter(user=user).values(
            'id', 'display_name', 'created_at', 'updated_at'
        )
        
        return [
            {
                'id': str(item['id']),
                'display_name': item['display_name'] or f"Item {str(item['id'])[:8]}",
                'created_at': item['created_at'],
                'updated_at': item['updated_at']
            }
            for item in items
        ]


class VaultItemProxy:
    """
    Proxy class to provide easy access to decrypted vault item data.
    Decrypts data on-demand and caches it for the request lifecycle.
    """
    
    def __init__(self, user: User, vault_item: VaultItem):
        self.user = user
        self.vault_item = vault_item
        self._decrypted_data = None
    
    @property
    def id(self):
        return self.vault_item.id
    
    @property
    def created_at(self):
        return self.vault_item.created_at
    
    @property
    def updated_at(self):
        return self.vault_item.updated_at
    
    def _get_decrypted_data(self) -> Dict[str, str]:
        """Decrypt and cache item data"""
        if self._decrypted_data is None:
            self._decrypted_data = EncryptionService.decrypt_vault_item(
                self.user, self.vault_item
            )
        return self._decrypted_data
    
    @property
    def name(self) -> str:
        return self._get_decrypted_data().get('name', '')
    
    @property
    def username(self) -> str:
        return self._get_decrypted_data().get('username', '')
    
    @property
    def password(self) -> str:
        return self._get_decrypted_data().get('password', '')
    
    @property
    def url(self) -> str:
        return self._get_decrypted_data().get('url', '')
    
    @property
    def notes(self) -> str:
        return self._get_decrypted_data().get('notes', '')
    
    def get_all_data(self) -> Dict[str, str]:
        """Get all decrypted item data"""
        return self._get_decrypted_data().copy()
