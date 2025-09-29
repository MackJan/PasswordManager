import uuid
from django.db import models
from django.conf import settings
from .fields import EncryptedField

# Create your models here.
class VaultItem(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,related_name='vault_items')

    name = EncryptedField(max_length=200)
    username = EncryptedField(max_length=200)
    password = EncryptedField(max_length=200)

    class Meta:
        ordering = ['name']

    def __str__(self): return self.name

