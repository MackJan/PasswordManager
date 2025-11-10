import secrets
from django.core.management.base import BaseCommand
from allauth.mfa.models import Authenticator


class Command(BaseCommand):
    help = 'Fix recovery codes authenticators that are missing the seed key'

    def handle(self, *args, **options):
        # Find all recovery codes authenticators that don't have a 'seed' key or 'used_mask' key
        recovery_auths = Authenticator.objects.filter(
            type=Authenticator.Type.RECOVERY_CODES
        )

        fixed_count = 0

        for auth in recovery_auths:
            needs_fix = False

            # Add seed if missing
            if 'seed' not in auth.data:
                seed = secrets.token_bytes(32)
                auth.data['seed'] = seed.hex()
                needs_fix = True

            # Add or fix used_mask if missing or wrong type
            if 'used_mask' not in auth.data or not isinstance(auth.data.get('used_mask'), int):
                # Initialize as 0 (bitfield where all codes are unused)
                auth.data['used_mask'] = 0
                needs_fix = True

            if needs_fix:
                auth.save()
                fixed_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Fixed recovery codes for user: {auth.user.email}')
                )

        if fixed_count == 0:
            self.stdout.write(
                self.style.SUCCESS('No recovery codes authenticators needed fixing.')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Fixed {fixed_count} recovery codes authenticators.')
            )
