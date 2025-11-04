"""Encryption service layer for password manager."""

from __future__ import annotations

from typing import Dict, Optional

from django.contrib.auth import get_user_model
from django.db import transaction

from accounts.models import UserKeystore
from core.audit import get_audit_logger
from core.logging_utils import get_vault_logger
from core.security_controls import get_decrypt_rate_monitor
from vault.crypto_utils import (
    UMKWrapResult,
    decrypt_item_data,
    encrypt_item_data,
    generate_key,
    secure_zero,
    unwrap_dek,
    unwrap_umk,
    wrap_dek,
    wrap_umk,
)
from vault.exceptions import CryptoError
from vault.models import VaultItem

User = get_user_model()

logger = get_vault_logger()
audit_logger = get_audit_logger()
decrypt_monitor = get_decrypt_rate_monitor()


class EncryptionService:
    """Service for handling encryption workflows."""

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _persist_umk_result(
        keystore: UserKeystore,
        wrap_result: UMKWrapResult,
        *,
        reset_previous: bool = False,
    ) -> None:
        """Persist wrapped UMK metadata to the keystore."""

        keystore.amk_key_version = wrap_result.amk_version
        keystore.wrapped_umk_b64 = wrap_result.wrapped_umk_b64
        keystore.umk_nonce_b64 = ''
        keystore.kms_key_id = wrap_result.kms_key_id
        keystore.kms_encryption_algorithm = wrap_result.kms_encryption_algorithm
        keystore.umk_encryption_context = wrap_result.encryption_context
        keystore.algo_version = 1

        if reset_previous:
            keystore.previous_wrapped_umk_b64 = ''
            keystore.previous_kms_key_id = ''
            keystore.previous_kms_encryption_algorithm = ''
            keystore.previous_umk_encryption_context = {}

        keystore.save()

    @staticmethod
    def _archive_current_umk(keystore: UserKeystore) -> None:
        """Move current UMK metadata into the previous slots."""

        keystore.previous_wrapped_umk_b64 = keystore.wrapped_umk_b64
        keystore.previous_kms_key_id = keystore.kms_key_id
        keystore.previous_kms_encryption_algorithm = keystore.kms_encryption_algorithm
        keystore.previous_umk_encryption_context = keystore.umk_encryption_context or {}
        keystore.save()

    @staticmethod
    def _clear_previous_umk_if_unused(user: User) -> None:
        """Clear previous UMK metadata when no items require it."""

        try:
            keystore = user.keystore
        except UserKeystore.DoesNotExist:
            return

        if not keystore.previous_wrapped_umk_b64:
            return

        if VaultItem.objects.filter(user=user, dek_rotation_required=True).exists():
            return

        keystore.previous_wrapped_umk_b64 = ''
        keystore.previous_kms_key_id = ''
        keystore.previous_kms_encryption_algorithm = ''
        keystore.previous_umk_encryption_context = {}
        keystore.save(update_fields=[
            'previous_wrapped_umk_b64',
            'previous_kms_key_id',
            'previous_kms_encryption_algorithm',
            'previous_umk_encryption_context',
        ])

    # ------------------------------------------------------------------
    # Key management operations
    # ------------------------------------------------------------------
    @staticmethod
    @transaction.atomic
    def setup_user_encryption(user: User) -> None:
        """Ensure a user has a UMK and corresponding KMS metadata."""

        try:
            if hasattr(user, 'keystore') and user.keystore.wrapped_umk_b64:
                logger.info("Encryption already configured", user)
                return

            umk = generate_key()
            wrap_result = wrap_umk(umk, user.id)

            keystore, created = UserKeystore.objects.get_or_create(
                user=user,
                defaults={
                    'amk_key_version': wrap_result.amk_version,
                    'wrapped_umk_b64': wrap_result.wrapped_umk_b64,
                    'umk_nonce_b64': '',
                    'kms_key_id': wrap_result.kms_key_id,
                    'kms_encryption_algorithm': wrap_result.kms_encryption_algorithm,
                    'umk_encryption_context': wrap_result.encryption_context,
                    'algo_version': 1,
                },
            )

            if not created:
                EncryptionService._persist_umk_result(keystore, wrap_result)

            audit_logger.log_event(
                'user_encryption_setup',
                user_id=user.id,
                metadata={'kms_key_id': wrap_result.kms_key_id, 'amk_version': wrap_result.amk_version},
            )
            logger.encryption_event("user encryption setup completed", user, success=True)

        except Exception as exc:
            logger.encryption_event(f"user encryption setup failed: {exc}", user, success=False)
            raise CryptoError(f"Failed to set up user encryption: {exc}") from exc
        finally:
            if 'umk' in locals():
                secure_zero(umk)

    @staticmethod
    def _get_user_master_key(user: User, *, use_previous: bool = False) -> bytes:
        """Retrieve and unwrap the user's master key via KMS."""

        try:
            keystore = user.keystore
        except UserKeystore.DoesNotExist as exc:
            logger.error("User keystore not found", user)
            raise CryptoError("User keystore not found") from exc

        if use_previous:
            wrapped = keystore.previous_wrapped_umk_b64
            context = keystore.previous_umk_encryption_context or {}
            kms_key_id = keystore.previous_kms_key_id or keystore.kms_key_id
            algorithm = keystore.previous_kms_encryption_algorithm or keystore.kms_encryption_algorithm or 'SYMMETRIC_DEFAULT'
        else:
            wrapped = keystore.wrapped_umk_b64
            context = keystore.umk_encryption_context or {}
            kms_key_id = keystore.kms_key_id
            algorithm = keystore.kms_encryption_algorithm or 'SYMMETRIC_DEFAULT'

        if not wrapped or not kms_key_id:
            raise CryptoError("User encryption not set up")

        context_strings = {str(k): str(v) for k, v in context.items()}
        umk = unwrap_umk(
            wrapped,
            encryption_context=context_strings,
            kms_key_id=kms_key_id,
            kms_encryption_algorithm=algorithm,
        )

        audit_logger.log_event(
            'umk_unwrapped',
            user_id=user.id,
            metadata={'kms_key_id': kms_key_id, 'previous': use_previous},
        )
        return umk

    @staticmethod
    @transaction.atomic
    def rotate_user_master_key(user: User) -> None:
        """Rotate a user's UMK and mark DEKs for lazy re-wrap."""

        EncryptionService.setup_user_encryption(user)
        keystore = user.keystore
        new_umk = generate_key()
        try:
            wrap_result = wrap_umk(new_umk, user.id)
        finally:
            secure_zero(new_umk)

        EncryptionService._archive_current_umk(keystore)
        EncryptionService._persist_umk_result(keystore, wrap_result)

        VaultItem.objects.filter(user=user).update(dek_rotation_required=True)
        audit_logger.log_event(
            'user_umk_rotated',
            user_id=user.id,
            metadata={'kms_key_id': wrap_result.kms_key_id, 'amk_version': wrap_result.amk_version},
        )

    @staticmethod
    @transaction.atomic
    def rewrap_all_user_master_keys() -> int:
        """Rewrap every stored UMK under the current KMS key."""

        count = 0
        for keystore in UserKeystore.objects.select_related('user'):
            user = keystore.user
            umk = EncryptionService._get_user_master_key(user)
            try:
                wrap_result = wrap_umk(umk, user.id)
                EncryptionService._persist_umk_result(keystore, wrap_result, reset_previous=True)
                audit_logger.log_event(
                    'user_umk_rewrapped',
                    user_id=user.id,
                    metadata={'kms_key_id': wrap_result.kms_key_id, 'amk_version': wrap_result.amk_version},
                )
                count += 1
            finally:
                secure_zero(umk)
        return count

    # ------------------------------------------------------------------
    # Vault operations
    # ------------------------------------------------------------------
    @staticmethod
    def is_item_encrypted_with_new_system(vault_item: VaultItem) -> bool:
        """Return True if the vault item contains modern encrypted payloads."""

        return bool(vault_item.wrapped_dek_b64 and vault_item.ciphertext_b64)

    @staticmethod
    @transaction.atomic
    def create_vault_item(user: User, item_data: Dict[str, str]) -> VaultItem:
        """Create a new encrypted vault item."""

        umk = None
        dek = None

        try:
            EncryptionService.setup_user_encryption(user)
            umk = EncryptionService._get_user_master_key(user)
            dek = generate_key()

            vault_item = VaultItem.objects.create(
                user=user,
                wrapped_dek_b64='',
                dek_wrap_nonce_b64='',
                ciphertext_b64='',
                item_nonce_b64='',
                display_name=item_data.get('name', '')[:50] if item_data.get('name') else '',
                dek_rotation_required=False,
            )

            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(item_data, dek, user.id, str(vault_item.id))

            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.dek_rotation_required = False
            vault_item.save(update_fields=[
                'wrapped_dek_b64',
                'dek_wrap_nonce_b64',
                'ciphertext_b64',
                'item_nonce_b64',
                'dek_rotation_required',
            ])

            audit_logger.log_event(
                'vault_item_created',
                user_id=user.id,
                metadata={'item_id': str(vault_item.id)},
            )
            logger.info(f"Successfully created vault item {vault_item.id}", user)
            return vault_item

        except CryptoError:
            logger.error(f"CryptoError during vault item creation for user {user.id}", user)
            raise
        except Exception as exc:
            logger.error(f"Unexpected error during vault item creation: {exc}", user)
            raise
        finally:
            if umk:
                secure_zero(umk)
            if dek:
                secure_zero(dek)

    @staticmethod
    def decrypt_vault_item(user: User, vault_item: VaultItem) -> Dict[str, str]:
        """Decrypt a vault item and return its contents."""

        if not EncryptionService.is_item_encrypted_with_new_system(vault_item):
            return {
                'name': getattr(vault_item, 'name', vault_item.display_name or 'Legacy Item'),
                'username': getattr(vault_item, 'username', ''),
                'password': getattr(vault_item, 'password', ''),
                'url': '',
                'notes': 'This item needs to be migrated to the new encryption system',
            }

        umk_in_use = None
        dek = None
        rotation_required = getattr(vault_item, 'dek_rotation_required', False)

        try:
            umk_in_use = EncryptionService._get_user_master_key(user, use_previous=rotation_required)
            algo_version = getattr(vault_item, 'algo_version', 1)

            dek = unwrap_dek(
                vault_item.wrapped_dek_b64,
                vault_item.dek_wrap_nonce_b64,
                umk_in_use,
                str(vault_item.id),
                algo_version=algo_version,
            )

            item_data = decrypt_item_data(
                vault_item.ciphertext_b64,
                vault_item.item_nonce_b64,
                dek,
                user.id,
                str(vault_item.id),
                algo_version=algo_version,
            )

            audit_logger.log_event(
                'vault_item_decrypted',
                user_id=user.id,
                metadata={'item_id': str(vault_item.id)},
            )

            if decrypt_monitor.record(user.id):
                audit_logger.log_security_alert(
                    'vault_item_decrypt_rate_anomaly',
                    user_id=user.id,
                    metadata={'item_id': str(vault_item.id)},
                )

            if rotation_required:
                new_umk = EncryptionService._get_user_master_key(user)
                try:
                    wrapped_dek_b64, dek_nonce_b64 = wrap_dek(
                        dek,
                        new_umk,
                        str(vault_item.id),
                        algo_version=algo_version,
                    )
                    vault_item.wrapped_dek_b64 = wrapped_dek_b64
                    vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
                    vault_item.dek_rotation_required = False
                    vault_item.save(update_fields=[
                        'wrapped_dek_b64',
                        'dek_wrap_nonce_b64',
                        'dek_rotation_required',
                    ])
                    audit_logger.log_event(
                        'vault_item_rewrapped',
                        user_id=user.id,
                        metadata={'item_id': str(vault_item.id)},
                    )
                finally:
                    secure_zero(new_umk)
                    EncryptionService._clear_previous_umk_if_unused(user)

            return item_data

        except CryptoError as exc:
            if umk_in_use is not None:
                try:
                    return EncryptionService._attempt_legacy_decryption(user, vault_item, umk_in_use)
                except CryptoError:
                    pass
            raise exc

        finally:
            if umk_in_use:
                secure_zero(umk_in_use)
            if dek:
                secure_zero(dek)

    @staticmethod
    def _attempt_legacy_decryption(user: User, vault_item: VaultItem, umk: bytes) -> Dict[str, str]:
        """Attempt decryption using legacy parameters for recovery."""

        dek = None
        try:
            algo_version = getattr(vault_item, 'algo_version', 1)
            dek = unwrap_dek(
                vault_item.wrapped_dek_b64,
                vault_item.dek_wrap_nonce_b64,
                umk,
                str(vault_item.id),
                algo_version=algo_version,
            )
            return decrypt_item_data(
                vault_item.ciphertext_b64,
                vault_item.item_nonce_b64,
                dek,
                user.id,
                str(vault_item.id),
                algo_version=algo_version,
            )
        finally:
            if dek:
                secure_zero(dek)

    @staticmethod
    @transaction.atomic
    def update_vault_item(user: User, vault_item: VaultItem, item_data: Dict[str, str]) -> VaultItem:
        """Update an existing vault item with fresh encrypted data."""

        umk = None
        dek = None

        try:
            EncryptionService.setup_user_encryption(user)
            umk = EncryptionService._get_user_master_key(user)
            dek = generate_key()

            wrapped_dek_b64, dek_nonce_b64 = wrap_dek(dek, umk, str(vault_item.id))
            ciphertext_b64, item_nonce_b64 = encrypt_item_data(item_data, dek, user.id, str(vault_item.id))

            vault_item.wrapped_dek_b64 = wrapped_dek_b64
            vault_item.dek_wrap_nonce_b64 = dek_nonce_b64
            vault_item.ciphertext_b64 = ciphertext_b64
            vault_item.item_nonce_b64 = item_nonce_b64
            vault_item.display_name = item_data.get('name', '')[:50] if item_data.get('name') else ''
            vault_item.dek_rotation_required = False
            vault_item.save()

            audit_logger.log_event(
                'vault_item_updated',
                user_id=user.id,
                metadata={'item_id': str(vault_item.id)},
            )
            return vault_item

        finally:
            if umk:
                secure_zero(umk)
            if dek:
                secure_zero(dek)

    @staticmethod
    def get_vault_items_metadata(user: User) -> list:
        """Return lightweight metadata for all vault items."""

        items = VaultItem.objects.filter(user=user).values(
            'id', 'display_name', 'created_at', 'updated_at'
        )

        return [
            {
                'id': str(item['id']),
                'display_name': item['display_name'] or f"Item {str(item['id'])[:8]}",
                'created_at': item['created_at'],
                'updated_at': item['updated_at'],
            }
            for item in items
        ]


class VaultItemProxy:
    """Proxy class providing decrypted accessors for a VaultItem."""

    def __init__(self, user: User, vault_item: VaultItem):
        self.user = user
        self.vault_item = vault_item
        self._decrypted_data: Optional[Dict[str, str]] = None

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
        if self._decrypted_data is None:
            self._decrypted_data = EncryptionService.decrypt_vault_item(self.user, self.vault_item)
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
        return self._get_decrypted_data().copy()
