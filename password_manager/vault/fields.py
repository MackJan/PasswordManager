from django.db import models
from .utils import encrypt_data, decrypt_data

SECRET_KEY = b'0MoRi0Kgs7iLDut2bSrTghGHL1pDoQyn'  # AES-256 requires a 32-byte key


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
        return decrypt_data(value, secret_key=SECRET_KEY)

    def get_prep_value(self, value):
        """
        Encrypt the value before saving it to the database.
        """
        if value is None:
            return value
        return encrypt_data(value, secret_key=SECRET_KEY)


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
        return decrypt_data(value, secret_key=SECRET_KEY)

    def get_prep_value(self, value):
        """
        Encrypt the value before saving it to the database.
        """
        if value is None:
            return value
        return encrypt_data(value, secret_key=SECRET_KEY)
