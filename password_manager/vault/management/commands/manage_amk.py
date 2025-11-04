"""Management command for interacting with vault key material."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from vault.encryption_service import EncryptionService
from vault.exceptions import CryptoError
from vault.kms_service import SoftwareKMSService, get_kms_service

User = get_user_model()


class Command(BaseCommand):
    help = 'Inspect and rotate vault encryption keys backed by KMS.'

    def add_arguments(self, parser):  # pragma: no cover - exercised via CLI
        parser.add_argument('--status', action='store_true', help='Display current KMS status and configuration')
        parser.add_argument('--rewrap-umks', action='store_true', help='Rewrap all user master keys with the active KMS key')
        parser.add_argument('--rotate-user', type=str, help='Rotate UMK for the specified user email')

    def handle(self, *args, **options):  # pragma: no cover - exercised via CLI
        try:
            if options['status']:
                self.show_status()
            elif options['rewrap_umks']:
                self.rewrap_all_umks()
            elif options['rotate_user']:
                self.rotate_user_umk(options['rotate_user'])
            else:
                self.stdout.write(self.style.WARNING('No action specified. Use --help to see available options.'))
        except Exception as exc:
            raise CommandError(f'Key management operation failed: {exc}') from exc

    def show_status(self):
        service = get_kms_service()
        backend = 'software' if isinstance(service, SoftwareKMSService) else 'aws-kms'
        self.stdout.write(self.style.SUCCESS('=== Vault KMS Status ==='))
        self.stdout.write(f'Mode: {backend}')
        if backend == 'software':
            self.stdout.write('WARNING: Running in software fallback mode. Do not use in production.')

        if hasattr(service, 'alias'):
            self.stdout.write(f'Key alias/id: {service.alias}')

        # Attempt a health check by performing a round trip encrypt/decrypt
        plaintext = b'health-check'
        wrap = service.encrypt(plaintext=plaintext, encryption_context={'purpose': 'health-check'})
        recovered = service.decrypt(
            ciphertext_blob=wrap.ciphertext_blob,
            encryption_context={'purpose': 'health-check'},
            kms_key_id=wrap.key_id,
            encryption_algorithm=wrap.encryption_algorithm,
        )
        if recovered == plaintext:
            self.stdout.write(self.style.SUCCESS('KMS health check succeeded'))
        else:
            self.stdout.write(self.style.ERROR('KMS health check failed - ciphertext mismatch'))

    def rewrap_all_umks(self):
        count = EncryptionService.rewrap_all_user_master_keys()
        self.stdout.write(self.style.SUCCESS(f'Rewrapped {count} user master keys'))

    def rotate_user_umk(self, email: str):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist as exc:
            raise CommandError(f'User with email {email} not found') from exc

        try:
            EncryptionService.rotate_user_master_key(user)
        except CryptoError as exc:
            raise CommandError(f'Failed to rotate UMK for {email}: {exc}') from exc

        self.stdout.write(self.style.SUCCESS(f'UMK rotation scheduled for {email}'))
