"""
Django management command to manage Application Master Key (AMK) operations.
This command helps with AMK backup, restore, and troubleshooting.
"""

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from pathlib import Path
import json
import base64
import os
from vault.crypto_utils import amk_manager, CryptoError


class Command(BaseCommand):
    help = 'Manage Application Master Key (AMK) operations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--backup',
            action='store_true',
            help='Create a backup of the current AMK'
        )
        parser.add_argument(
            '--restore',
            type=str,
            help='Restore AMK from backup file path'
        )
        parser.add_argument(
            '--status',
            action='store_true',
            help='Show AMK status and location'
        )
        parser.add_argument(
            '--generate',
            action='store_true',
            help='Generate a new AMK (WARNING: This will make existing data unreadable!)'
        )
        parser.add_argument(
            '--export-env',
            action='store_true',
            help='Export current AMK as environment variable format'
        )

    def handle(self, *args, **options):
        try:
            if options['status']:
                self.show_status()
            elif options['backup']:
                self.backup_amk()
            elif options['restore']:
                self.restore_amk(options['restore'])
            elif options['generate']:
                self.generate_new_amk()
            elif options['export_env']:
                self.export_env()
            else:
                self.stdout.write(
                    self.style.WARNING('No action specified. Use --help to see available options.')
                )
        except Exception as e:
            raise CommandError(f'AMK operation failed: {e}')

    def show_status(self):
        """Show current AMK status"""
        self.stdout.write(self.style.SUCCESS('=== AMK Status ==='))

        # Check if AMK is loaded from environment
        env_amk = os.environ.get('AMK_V1')
        if env_amk:
            self.stdout.write(self.style.SUCCESS('✓ AMK loaded from environment variable AMK_V1'))
        else:
            self.stdout.write('✗ No AMK found in environment variable AMK_V1')

        # Check file location
        amk_file_path = amk_manager._amk_file_path
        self.stdout.write(f'AMK file location: {amk_file_path}')

        if amk_file_path.exists():
            self.stdout.write(self.style.SUCCESS('✓ AMK file exists'))
            try:
                with open(amk_file_path, 'r') as f:
                    amk_data = json.load(f)
                    versions = list(amk_data.keys())
                    self.stdout.write(f'Available AMK versions: {versions}')
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ AMK file corrupted: {e}'))
        else:
            self.stdout.write(self.style.WARNING('✗ AMK file does not exist'))

        # Check loaded versions
        try:
            latest_version = amk_manager.get_latest_version()
            self.stdout.write(f'Loaded AMK version: {latest_version}')
            self.stdout.write(self.style.SUCCESS('✓ AMK successfully loaded'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ AMK not properly loaded: {e}'))

    def backup_amk(self):
        """Create a backup of the current AMK"""
        amk_file_path = amk_manager._amk_file_path

        if not amk_file_path.exists():
            raise CommandError('No AMK file found to backup')

        # Create backup with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = amk_file_path.parent / f'amk_backup_{timestamp}.key'

        try:
            import shutil
            shutil.copy2(amk_file_path, backup_path)
            backup_path.chmod(0o600)

            self.stdout.write(
                self.style.SUCCESS(f'✓ AMK backed up to: {backup_path}')
            )
            self.stdout.write(
                self.style.WARNING('IMPORTANT: Store this backup file securely!')
            )
        except Exception as e:
            raise CommandError(f'Backup failed: {e}')

    def restore_amk(self, backup_file_path):
        """Restore AMK from backup file"""
        backup_path = Path(backup_file_path)

        if not backup_path.exists():
            raise CommandError(f'Backup file not found: {backup_path}')

        # Validate backup file
        try:
            with open(backup_path, 'r') as f:
                amk_data = json.load(f)
                for version_str, key_b64 in amk_data.items():
                    int(version_str)  # Validate version is integer
                    base64.b64decode(key_b64)  # Validate base64
        except Exception as e:
            raise CommandError(f'Invalid backup file format: {e}')

        # Create backup of current file if it exists
        amk_file_path = amk_manager._amk_file_path
        if amk_file_path.exists():
            backup_current_path = amk_file_path.with_suffix('.backup_before_restore')
            try:
                import shutil
                shutil.copy2(amk_file_path, backup_current_path)
                self.stdout.write(f'Current AMK backed up to: {backup_current_path}')
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Could not backup current AMK: {e}'))

        # Restore from backup
        try:
            import shutil
            shutil.copy2(backup_path, amk_file_path)
            amk_file_path.chmod(0o600)

            self.stdout.write(
                self.style.SUCCESS(f'✓ AMK restored from: {backup_path}')
            )
            self.stdout.write(
                self.style.WARNING('Please restart the application to load the restored AMK')
            )
        except Exception as e:
            raise CommandError(f'Restore failed: {e}')

    def generate_new_amk(self):
        """Generate a new AMK (WARNING: destructive operation)"""
        self.stdout.write(
            self.style.ERROR('WARNING: Generating a new AMK will make ALL existing encrypted data unreadable!')
        )
        self.stdout.write(
            self.style.ERROR('This includes all user vault items and keystore data.')
        )

        confirm = input('Type "CONFIRM" to proceed with generating a new AMK: ')
        if confirm != 'CONFIRM':
            self.stdout.write('Operation cancelled.')
            return

        # Backup existing AMK if it exists
        amk_file_path = amk_manager._amk_file_path
        if amk_file_path.exists():
            backup_path = amk_file_path.with_suffix('.backup_before_new')
            try:
                import shutil
                shutil.copy2(amk_file_path, backup_path)
                self.stdout.write(f'Old AMK backed up to: {backup_path}')
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Could not backup old AMK: {e}'))

        # Generate new AMK
        try:
            # Remove existing file
            if amk_file_path.exists():
                amk_file_path.unlink()

            # Force regeneration by reinitializing
            amk_manager._amk_cache.clear()
            amk_manager._generate_and_save_amk()

            self.stdout.write(
                self.style.SUCCESS('✓ New AMK generated and saved')
            )
            self.stdout.write(
                self.style.WARNING('All existing encrypted data is now unreadable!')
            )
            self.stdout.write(
                self.style.WARNING('Users will need to be recreated or migrated.')
            )
        except Exception as e:
            raise CommandError(f'Failed to generate new AMK: {e}')

    def export_env(self):
        """Export current AMK for environment variable usage"""
        try:
            amk = amk_manager.get_amk(1)
            amk_b64 = base64.b64encode(amk).decode('ascii')

            self.stdout.write('=== Environment Variable Export ===')
            self.stdout.write(f'AMK_V1={amk_b64}')
            self.stdout.write('')
            self.stdout.write('You can set this in your environment or docker-compose file:')
            self.stdout.write('export AMK_V1=' + amk_b64)
            self.stdout.write('or in docker-compose.yml:')
            self.stdout.write('environment:')
            self.stdout.write(f'  - AMK_V1={amk_b64}')

        except Exception as e:
            raise CommandError(f'Failed to export AMK: {e}')
