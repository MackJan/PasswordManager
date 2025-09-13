import uuid
from django.contrib.auth.models import User
from django.db import models
from django.conf import settings

# Create your models here.
class VaultItem(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,related_name='vault_items')

    name = models.CharField(max_length=200)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)

    class Meta:
        ordering = ['name']

    def __str__(self): return self.name