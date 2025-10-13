import uuid
from django.db import models
from django.conf import settings

# Create your models here.
class VaultItem(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vault_items')

    # Encrypted DEK and item data (nullable for migration compatibility)
    wrapped_dek_b64 = models.TextField(blank=True,default='')  # AEAD(UMK, DEK, aad={item_id, ver})
    dek_wrap_nonce_b64 = models.CharField(max_length=64, blank=True,default='')
    ciphertext_b64 = models.TextField(blank=True,default='')  # AEAD(DEK, item_json, aad={user_id,item_id,ver})
    item_nonce_b64 = models.CharField(max_length=64, blank=True,default='')
    algo_version = models.SmallIntegerField(default=1)

    # Optional display name (keep minimal/empty for full encryption)
    display_name = models.CharField(max_length=200, blank=True)

    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)

    class Meta:
        ordering = ['-created_at']
        db_table = 'vault_vaultitem'

    def __str__(self):
        return f"VaultItem {self.id} for {self.user.email}"
