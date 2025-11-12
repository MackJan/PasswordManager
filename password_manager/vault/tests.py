import base64
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase

from vault import crypto_utils
from vault.crypto_utils import (
    CryptoError,
    create_aad,
    decrypt_item_data,
    derive_item_key,
    encrypt_item_data,
    generate_salt,
    unwrap_dek,
    unwrap_umk,
    wrap_dek,
    wrap_umk,
)
from vault.encryption_service import EncryptionService, VaultItemProxy
from vault import views as vault_views
from vault.fields import EncryptedField, EncryptedKeyField, SECRET_KEY
from vault.models import VaultItem
from vault.utils import decrypt_data, encrypt_data


try:
    secret_key = settings.SECRET_KEY
except ImproperlyConfigured:
    settings.SECRET_KEY = 'test-secret'
else:
    if not secret_key:
        settings.SECRET_KEY = 'test-secret'


class VaultUtilsTests(SimpleTestCase):
    def setUp(self):
        self.secret_key = os.urandom(32)

    def test_encrypt_and_decrypt_round_trip(self):
        plaintext = 'sensitive-value'
        encrypted = encrypt_data(plaintext, self.secret_key)
        self.assertIsInstance(encrypted, str)
        decrypted = decrypt_data(encrypted, self.secret_key)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_returns_none_when_plaintext_missing(self):
        self.assertIsNone(encrypt_data('', self.secret_key))

    def test_decrypt_returns_none_when_cipher_missing(self):
        self.assertIsNone(decrypt_data('', self.secret_key))


class DummyAMKManager:
    def __init__(self, key):
        self._key = key

    def get_latest_version(self):
        return 1

    def get_amk(self, version):
        if version != 1:
            raise CryptoError('AMK version not found')
        return self._key


class CryptoUtilsTests(SimpleTestCase):
    def setUp(self):
        self.original_manager = crypto_utils.amk_manager
        self.test_key = bytes(range(32))
        crypto_utils.amk_manager = DummyAMKManager(self.test_key)

    def tearDown(self):
        crypto_utils.amk_manager = self.original_manager

    def test_create_aad_contains_sorted_fields(self):
        aad_bytes = create_aad(user_id=5, item_id='abc', algo_version=2, amk_version=7)
        aad_dict = json.loads(aad_bytes.decode('utf-8'))
        self.assertEqual(aad_dict, {'algo_version': 2, 'amk_version': 7, 'item_id': 'abc', 'user_id': 5})

    def test_wrap_and_unwrap_umk_round_trip(self):
        umk = b'\x01' * 32
        wrapped, nonce, version = wrap_umk(umk, user_id=9)
        self.assertEqual(version, 1)
        unwrapped = unwrap_umk(wrapped, nonce, user_id=9, amk_version=version)
        self.assertEqual(unwrapped, umk)

    def test_wrap_and_unwrap_dek_round_trip(self):
        dek = b'\x02' * 32
        umk = b'\x03' * 32
        wrapped, nonce = wrap_dek(dek, umk, item_id='item-123')
        unwrapped = unwrap_dek(wrapped, nonce, umk, item_id='item-123')
        self.assertEqual(unwrapped, dek)

    def test_generate_salt_returns_expected_length(self):
        salt = generate_salt(24)
        self.assertEqual(len(salt), 24)

    def test_derive_item_key_requires_salt(self):
        dek = b'\x04' * 32
        with self.assertRaises(CryptoError):
            derive_item_key(dek, b'')

    def test_encrypt_and_decrypt_item_data_round_trip(self):
        dek = b'\x04' * 32
        item_data = {'name': 'Example', 'username': 'alice', 'password': 'secret'}
        salt = b's' * 16
        ciphertext, nonce = encrypt_item_data(
            item_data, dek, user_id=11, item_id='item-456', item_salt=salt
        )
        decrypted = decrypt_item_data(
            ciphertext, nonce, dek, user_id=11, item_id='item-456', item_salt=salt
        )
        self.assertEqual(decrypted, item_data)

    def test_encrypt_and_decrypt_item_data_without_salt_for_legacy_support(self):
        dek = b'\x04' * 32
        item_data = {'name': 'Example'}
        ciphertext, nonce = encrypt_item_data(item_data, dek, user_id=99, item_id='item-legacy')
        decrypted = decrypt_item_data(ciphertext, nonce, dek, user_id=99, item_id='item-legacy')
        self.assertEqual(decrypted, item_data)

    def test_aead_encrypt_requires_expected_key_length(self):
        with self.assertRaises(CryptoError):
            crypto_utils.aead_encrypt(b'short', b'data')

    def test_aead_decrypt_requires_expected_key_length(self):
        key = b'\x05' * 32
        nonce, ciphertext = crypto_utils.aead_encrypt(key, b'data')
        with self.assertRaises(CryptoError):
            crypto_utils.aead_decrypt(b'short', nonce, ciphertext)

    def test_aead_decrypt_raises_on_tampered_ciphertext(self):
        key = b'\x06' * 32
        nonce, ciphertext = crypto_utils.aead_encrypt(key, b'data')
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with self.assertRaises(CryptoError):
            crypto_utils.aead_decrypt(key, nonce, tampered)


User = get_user_model()


class EncryptionServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', password='password123')

    def test_is_item_encrypted_with_new_system(self):
        item = VaultItem.objects.create(
            user=self.user,
            wrapped_dek_b64='wrapped',
            dek_wrap_nonce_b64='nonce',
            ciphertext_b64='ciphertext',
            item_nonce_b64='itemnonce',
        )
        legacy_item = VaultItem.objects.create(user=self.user)

        self.assertTrue(EncryptionService.is_item_encrypted_with_new_system(item))
        self.assertFalse(EncryptionService.is_item_encrypted_with_new_system(legacy_item))

    @patch('vault.encryption_service.secure_zero')
    @patch('vault.encryption_service.encrypt_item_data', return_value=('ciphertext', 'itemnonce'))
    @patch('vault.encryption_service.wrap_dek', return_value=('wrapped', 'deknonce'))
    @patch('vault.encryption_service.generate_salt', return_value=b's' * 16)
    @patch('vault.encryption_service.generate_key', return_value=b'd' * 32)
    @patch.object(EncryptionService, '_get_user_master_key', return_value=b'u' * 32)
    @patch.object(EncryptionService, 'setup_user_encryption')
    def test_create_vault_item_persists_encrypted_fields(
        self,
        mock_setup_encryption,
        mock_get_umk,
        mock_generate_key,
        mock_generate_salt,
        mock_wrap_dek,
        mock_encrypt_item_data,
        mock_secure_zero,
    ):
        item_data = {
            'name': 'Example Vault Item',
            'username': 'alice',
            'password': 'super-secret',
            'notes': 'note',
            'url': 'https://example.com',
        }

        vault_item = EncryptionService.create_vault_item(self.user, item_data)

        self.assertEqual(VaultItem.objects.count(), 1)
        self.assertEqual(vault_item.wrapped_dek_b64, 'wrapped')
        self.assertEqual(vault_item.dek_wrap_nonce_b64, 'deknonce')
        self.assertEqual(vault_item.ciphertext_b64, 'ciphertext')
        self.assertEqual(vault_item.item_nonce_b64, 'itemnonce')
        self.assertEqual(vault_item.display_name, 'Example Vault Item')

        mock_generate_salt.assert_called_once()
        mock_wrap_dek.assert_called_once_with(b'd' * 32, b'u' * 32, str(vault_item.id))
        mock_encrypt_item_data.assert_called_once_with(
            item_data, b'd' * 32, self.user.id, str(vault_item.id), item_salt=b's' * 16
        )
        mock_secure_zero.assert_has_calls([call(b'u' * 32), call(b'd' * 32)])
        expected_salt_b64 = base64.b64encode(b's' * 16).decode('ascii')
        self.assertEqual(vault_item.item_salt_b64, expected_salt_b64)

    def test_decrypt_vault_item_returns_placeholder_for_legacy_items(self):
        legacy_item = VaultItem.objects.create(user=self.user, display_name='Old item')

        decrypted = EncryptionService.decrypt_vault_item(self.user, legacy_item)

        self.assertEqual(decrypted['name'], 'Old item')
        self.assertEqual(decrypted['username'], '')
        self.assertEqual(decrypted['password'], '')
        self.assertIn('needs to be migrated', decrypted['notes'])

    @patch('vault.encryption_service.secure_zero')
    @patch.object(EncryptionService, '_attempt_legacy_decryption', return_value={'name': 'Recovered'})
    @patch('vault.encryption_service.unwrap_dek', side_effect=CryptoError('failure'))
    @patch.object(EncryptionService, '_get_user_master_key', return_value=b'u' * 32)
    def test_decrypt_vault_item_falls_back_to_legacy_strategy(
        self,
        mock_get_umk,
        mock_unwrap_dek,
        mock_attempt_legacy,
        mock_secure_zero,
    ):
        encrypted_item = VaultItem.objects.create(
            user=self.user,
            wrapped_dek_b64='wrapped',
            dek_wrap_nonce_b64='nonce',
            ciphertext_b64='cipher',
            item_nonce_b64='itemnonce',
        )

        data = EncryptionService.decrypt_vault_item(self.user, encrypted_item)

        self.assertEqual(data, {'name': 'Recovered'})
        mock_attempt_legacy.assert_called_once_with(self.user, encrypted_item, b'u' * 32)
        mock_secure_zero.assert_called_once_with(b'u' * 32)

    @patch('vault.encryption_service.secure_zero')
    @patch('vault.encryption_service.decrypt_item_data', return_value={'name': 'Decrypted'})
    @patch('vault.encryption_service.unwrap_dek', return_value=b'd' * 32)
    def test_attempt_legacy_decryption_uses_standard_flow(
        self,
        mock_unwrap_dek,
        mock_decrypt_item_data,
        mock_secure_zero,
    ):
        item = VaultItem.objects.create(
            user=self.user,
            wrapped_dek_b64='wrapped',
            dek_wrap_nonce_b64='nonce',
            ciphertext_b64='cipher',
            item_nonce_b64='itemnonce',
        )

        result = EncryptionService._attempt_legacy_decryption(self.user, item, b'u' * 32)

        self.assertEqual(result, {'name': 'Decrypted'})
        mock_unwrap_dek.assert_called_once_with('wrapped', 'nonce', b'u' * 32, str(item.id), item.algo_version)
        mock_decrypt_item_data.assert_called_once_with(
            'cipher', 'itemnonce', b'd' * 32, self.user.id, str(item.id), item.algo_version, item_salt=None
        )
        mock_secure_zero.assert_called_once_with(b'd' * 32)

    def test_get_vault_items_metadata_includes_fallback_name(self):
        item_with_name = VaultItem.objects.create(
            user=self.user,
            display_name='Stored Item',
            wrapped_dek_b64='wrapped',
            dek_wrap_nonce_b64='nonce',
            ciphertext_b64='cipher',
            item_nonce_b64='itemnonce',
        )
        item_without_name = VaultItem.objects.create(user=self.user)

        metadata = EncryptionService.get_vault_items_metadata(self.user)
        ids = {entry['id'] for entry in metadata}
        self.assertIn(str(item_with_name.id), ids)
        self.assertIn(str(item_without_name.id), ids)

        fallback_entry = next(entry for entry in metadata if entry['id'] == str(item_without_name.id))
        self.assertTrue(fallback_entry['display_name'].startswith('Item '))

    def test_vault_item_proxy_caches_decrypted_data(self):
        item = VaultItem.objects.create(
            user=self.user,
            wrapped_dek_b64='wrapped',
            dek_wrap_nonce_b64='nonce',
            ciphertext_b64='cipher',
            item_nonce_b64='itemnonce',
        )
        decrypted = {
            'name': 'Example',
            'username': 'alice',
            'password': 'secret',
            'url': 'https://example.com',
            'notes': 'note',
        }

        with patch.object(EncryptionService, 'decrypt_vault_item', return_value=decrypted) as mock_decrypt:
            proxy = VaultItemProxy(self.user, item)
            self.assertEqual(proxy.name, 'Example')
            self.assertEqual(proxy.username, 'alice')
            self.assertEqual(proxy.password, 'secret')
            self.assertEqual(proxy.url, 'https://example.com')
            self.assertEqual(proxy.notes, 'note')
            self.assertEqual(proxy.get_all_data(), decrypted)
            mock_decrypt.assert_called_once_with(self.user, item)


class VaultFieldTests(SimpleTestCase):
    def test_encrypted_field_encrypts_on_prep(self):
        field = EncryptedField()
        with patch('vault.fields.encrypt_data', return_value='ciphertext') as mock_encrypt:
            result = field.get_prep_value('secret')

        self.assertEqual(result, 'ciphertext')
        mock_encrypt.assert_called_once_with('secret', secret_key=SECRET_KEY)

    def test_encrypted_field_returns_none_for_null(self):
        field = EncryptedField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertIsNone(field.from_db_value(None, None, None))

    def test_encrypted_key_field_decrypts_from_db(self):
        field = EncryptedKeyField()
        with patch('vault.fields.decrypt_data', return_value='plaintext') as mock_decrypt:
            result = field.from_db_value('cipher', None, None)

        self.assertEqual(result, 'plaintext')
        mock_decrypt.assert_called_once_with('cipher', secret_key=SECRET_KEY)


class VaultViewsTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(email='vault@example.com', password='password123')

    def _prepare_request(self, method='get', path='/vault/', data=None, user=None):
        method = method.lower()
        if method == 'post':
            request = self.factory.post(path, data or {})
        else:
            request = self.factory.get(path, data or {})

        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        request.user = user or self.user
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        return request

    def test_handle_create_item_validates_required_fields(self):
        request = self._prepare_request(method='post', data={'name': '', 'username': '', 'password': ''})

        with patch('vault.views.logger') as mock_logger, patch('vault.views.messages.error') as mock_error:
            vault_views._handle_create_item(request)

        mock_logger.user_activity.assert_called_once()
        mock_error.assert_called_once()

    def test_handle_create_item_success_calls_service(self):
        request = self._prepare_request(method='post', data={
            'name': 'Item',
            'username': 'alice',
            'password': 'secret',
            'url': 'https://example.com',
            'notes': 'note',
        })

        with patch('vault.views.logger'), patch(
            'vault.views.EncryptionService.create_vault_item',
            return_value=SimpleNamespace(id='item-id')
        ) as mock_create, patch('vault.views.messages.success') as mock_success:
            vault_views._handle_create_item(request)

        mock_create.assert_called_once()
        mock_success.assert_called_once()

    def test_handle_create_item_crypto_error_adds_message(self):
        request = self._prepare_request(method='post', data={
            'name': 'Item',
            'username': 'alice',
            'password': 'secret',
        })

        with patch('vault.views.logger'), patch(
            'vault.views.EncryptionService.create_vault_item', side_effect=CryptoError('boom')
        ), patch('vault.views.messages.error') as mock_error:
            vault_views._handle_create_item(request)

        mock_error.assert_called_once()

    def test_handle_edit_item_updates_existing_item(self):
        item = VaultItem.objects.create(user=self.user)
        request = self._prepare_request(method='post', data={
            'id': str(item.id),
            'name': 'Updated',
            'username': 'alice',
            'password': 'new-secret',
            'notes': 'note',
        })

        with patch('vault.views.logger'), patch('vault.views.EncryptionService.update_vault_item') as mock_update, patch(
            'vault.views.messages.success'
        ) as mock_success:
            vault_views._handle_edit_item(request)

        mock_update.assert_called_once()
        mock_success.assert_called_once()

    def test_handle_edit_item_requires_required_fields(self):
        item = VaultItem.objects.create(user=self.user)
        request = self._prepare_request(method='post', data={
            'id': str(item.id),
            'name': '',
            'username': '',
            'password': '',
        })

        with patch('vault.views.logger'), patch('vault.views.messages.error') as mock_error:
            vault_views._handle_edit_item(request)

        mock_error.assert_called_once()

    def test_handle_edit_item_missing_object_logs_security_event(self):
        request = self._prepare_request(method='post', data={
            'id': 'missing',
            'name': 'Updated',
            'username': 'alice',
            'password': 'new-secret',
        })

        with patch('vault.views.get_object_or_404', side_effect=VaultItem.DoesNotExist), patch(
            'vault.views.logger'
        ) as mock_logger, patch('vault.views.messages.error') as mock_error:
            vault_views._handle_edit_item(request)

        mock_logger.security_event.assert_called_once()
        mock_error.assert_called_once()

    def test_handle_delete_item_removes_object(self):
        item = VaultItem.objects.create(user=self.user, display_name='Stored')
        request = self._prepare_request(method='post', data={'id': str(item.id)})

        with patch('vault.views.logger'), patch('vault.views.messages.success') as mock_success:
            vault_views._handle_delete_item(request)

        mock_success.assert_called_once()
        self.assertFalse(VaultItem.objects.filter(id=item.id).exists())

    def test_handle_delete_item_missing_object_logs_security_event(self):
        request = self._prepare_request(method='post', data={'id': 'missing'})

        with patch('vault.views.get_object_or_404', side_effect=VaultItem.DoesNotExist), patch(
            'vault.views.logger'
        ) as mock_logger, patch('vault.views.messages.error') as mock_error:
            vault_views._handle_delete_item(request)

        mock_logger.security_event.assert_called_once()
        mock_error.assert_called_once()

    def test_vault_dashboard_redirects_anonymous_users(self):
        request = self._prepare_request(user=AnonymousUser())

        with patch('vault.views.logger') as mock_logger:
            response = vault_views.vault_dashboard(request)

        mock_logger.warning.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/login')

    def test_vault_dashboard_post_dispatches_action(self):
        request = self._prepare_request(method='post', data={'action': 'delete', 'id': '123'})

        with patch('vault.views.logger'), patch('vault.views._handle_delete_item') as mock_delete:
            response = vault_views.vault_dashboard(request)

        mock_delete.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/vault/')

    def test_vault_dashboard_get_success_sets_secure_headers(self):
        item = VaultItem.objects.create(user=self.user)
        request = self._prepare_request()

        with patch('vault.views.logger'), patch('vault.views.VaultItemProxy', side_effect=lambda user, itm: SimpleNamespace(id=itm.id)), patch(
            'vault.views.render', return_value=HttpResponse('ok')
        ) as mock_render:
            response = vault_views.vault_dashboard(request)

        mock_render.assert_called_once()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Cache-Control'], 'no-store, private')
        self.assertEqual(response['Pragma'], 'no-cache')

    def test_vault_dashboard_handles_crypto_errors(self):
        VaultItem.objects.create(user=self.user)
        request = self._prepare_request()

        with patch('vault.views.logger'), patch('vault.views.VaultItemProxy', side_effect=CryptoError('boom')), patch(
            'vault.views.messages.error'
        ) as mock_error, patch('vault.views.render', return_value=HttpResponse('ok')):
            response = vault_views.vault_dashboard(request)

        mock_error.assert_called_once()
        self.assertEqual(response.status_code, 200)
