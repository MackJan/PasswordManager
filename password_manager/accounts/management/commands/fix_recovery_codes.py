import secrets
from django.core.management.base import BaseCommand
from allauth.mfa.models import Authenticator


class Command(BaseCommand):
    help = 'Fix recovery codes authenticators that are missing the seed key'

    def handle(self, *args, **options):
        # Find all recovery codes authenticators that don't have a 'seed' key
        recovery_auths = Authenticator.objects.filter(
            type=Authenticator.Type.RECOVERY_CODES
        )

        fixed_count = 0

        for auth in recovery_auths:
            if 'seed' not in auth.data:
                # Generate a seed for this authenticator
                seed = secrets.token_bytes(32)
                auth.data['seed'] = seed.hex()
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
