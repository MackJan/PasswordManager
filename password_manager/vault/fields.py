from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models

from .utils import decrypt_data, encrypt_data


def _get_legacy_field_key():
    key = getattr(settings, 'LEGACY_FIELD_KEY', None)
    if key is None:
        raise ImproperlyConfigured('LEGACY_FIELD_KEY is not configured')
    return key


def _get_fallback_key():
    return getattr(settings, 'LEGACY_FIELD_FALLBACK_KEY', None)


class EncryptedField(models.TextField):
    """
    A custom Django model field for encrypting and decrypting data using AES.
    """

    def from_db_value(self, value, expression, connection):
        """
        Decrypt the value when reading from the database.
        """
        if value is None:
            return value
        return decrypt_data(
            value,
            secret_key=_get_legacy_field_key(),
            fallback_key=_get_fallback_key(),
        )

    def get_prep_value(self, value):
        """
        Encrypt the value before saving it to the database.
        """
        if value is None:
            return value
        return encrypt_data(value, secret_key=_get_legacy_field_key())


class EncryptedKeyField(models.TextField):
    """
    A custom Django model field for an AES encryption key
    """

    def from_db_value(self, value, expression, connection):
        """
        Decrypt the value when reading from the database.
        """
        if value is None:
            return value
        return decrypt_data(
            value,
            secret_key=_get_legacy_field_key(),
            fallback_key=_get_fallback_key(),
        )

    def get_prep_value(self, value):
        """
        Encrypt the value before saving it to the database.
        """
        if value is None:
            return value
        return encrypt_data(value, secret_key=_get_legacy_field_key())
