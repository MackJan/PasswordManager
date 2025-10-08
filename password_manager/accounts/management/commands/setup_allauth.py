from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from accounts.models import CustomUser
from allauth.account.models import EmailAddress


class Command(BaseCommand):
    help = 'Setup allauth for existing users and create default site'

    def handle(self, *args, **options):
        # Create or update the default site
        site, created = Site.objects.get_or_create(
            pk=1,
            defaults={
                'domain': 'localhost:8000',
                'name': 'Password Manager'
            }
        )
        if created:
            self.stdout.write(
                self.style.SUCCESS('Created default site')
            )
        else:
            site.domain = 'localhost:8000'
            site.name = 'Password Manager'
            site.save()
            self.stdout.write(
                self.style.SUCCESS('Updated default site')
            )

        # For existing users, create EmailAddress entries
        users_updated = 0
        for user in CustomUser.objects.all():
            _, created = EmailAddress.objects.get_or_create(
                user=user,
                email=user.email,
                defaults={
                    'verified': True,  # Assume existing users have verified emails
                    'primary': True,
                }
            )
            if created:
                users_updated += 1

        if users_updated > 0:
            self.stdout.write(
                self.style.SUCCESS(f'Updated {users_updated} existing users for allauth')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('No existing users needed updates')
            )
