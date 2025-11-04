"""
Management command to migrate existing vault items to the new encryption system.
Run this after applying the database migrations.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from vault.models import VaultItem
from vault.encryption_service import EncryptionService
from vault.exceptions import CryptoError
from accounts.models import UserKeystore

User = get_user_model()

class Command(BaseCommand):
    help = 'Migrate existing vault items to new encryption system'

    def handle(self, *args, **options):
        self.stdout.write('Starting migration to new encryption system...')

        # Setup encryption for users who don't have keystores yet
        users_without_keystore = User.objects.filter(keystore__isnull=True)
        for user in users_without_keystore:
            try:
                EncryptionService.setup_user_encryption(user)
                self.stdout.write(f'✓ Setup encryption for user: {user.email}')
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to setup encryption for user {user.email}: {str(e)}')
                )

        self.stdout.write(f'Migration completed. {users_without_keystore.count()} users processed.')
