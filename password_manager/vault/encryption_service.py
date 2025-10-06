"""
Encryption service layer for password manager.
Handles registration, login, and vault encryption workflows.
"""

from typing import Dict, Any, Optional, Tuple
from django.contrib.auth import get_user_model
from django.db import transaction
from accounts.models import UserKeystore
from .models import VaultItem
from .crypto_utils import (
    generate_key, wrap_umk, unwrap_umk, wrap_dek, unwrap_dek,
    encrypt_item_data, decrypt_item_data, secure_zero, CryptoError
)

User = get_user_model()


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

            if not created and not keystore.wrapped_umk_b64:
                # Update existing empty keystore
                keystore.amk_key_version = amk_version
                keystore.wrapped_umk_b64 = wrapped_umk_b64
                keystore.umk_nonce_b64 = nonce_b64
                keystore.save()

        finally:
            # Secure zero the UMK
            if 'umk' in locals():
                secure_zero(umk)
    
    @staticmethod
    def get_user_master_key(user: User) -> bytes:
        """
        Retrieve and decrypt the User Master Key for a user.
        
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
        except UserKeystore.DoesNotExist:
            raise CryptoError("User keystore not found")
        
        umk = unwrap_umk(
            keystore.wrapped_umk_b64,
            keystore.umk_nonce_b64,
            user.id,
            keystore.amk_key_version,
            keystore.algo_version
        )
        
        return umk
    
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

            # Get User Master Key
            umk = EncryptionService.get_user_master_key(user)
            
            # Generate Data Encryption Key
            dek = generate_key()
            
            # Create vault item to get ID
            vault_item = VaultItem.objects.create(
                user=user,
                wrapped_dek_b64='',  # Will be set below
                dek_wrap_nonce_b64='',
                ciphertext_b64='',
                item_nonce_b64='',
                display_name=item_data.get('name', '')[:50] if item_data.get('name') else ''
            )
            
            # Wrap DEK with UMK
            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))
            
            # Encrypt item data with DEK
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(
                item_data, dek, user.id, str(vault_item.id)
            )
            
            # Update vault item with encrypted data
            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.save(update_fields=[
                'wrapped_dek_b64', 'dek_wrap_nonce_b64', 
                'ciphertext_b64', 'item_nonce_b64'
            ])
            
            return vault_item
            
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
            umk = EncryptionService.get_user_master_key(user)
            
            # Unwrap DEK
            dek = unwrap_dek(
                vault_item.wrapped_dek_b64,
                vault_item.dek_wrap_nonce_b64,
                umk,
                str(vault_item.id),
                vault_item.algo_version
            )
            
            # Decrypt item data
            item_data = decrypt_item_data(
                vault_item.ciphertext_b64,
                vault_item.item_nonce_b64,
                dek,
                user.id,
                str(vault_item.id),
                vault_item.algo_version
            )
            
            return item_data
            
        finally:
            # Secure zero sensitive keys
            if umk:
                secure_zero(umk)
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
            umk = EncryptionService.get_user_master_key(user)
            
            # Generate new Data Encryption Key for security
            dek = generate_key()
            
            # Wrap new DEK with UMK
            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))
            
            # Encrypt new item data with new DEK
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(
                item_data, dek, user.id, str(vault_item.id)
            )
            
            # Update vault item
            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.display_name = item_data.get('name', '')[:50] if item_data.get('name') else ''
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
