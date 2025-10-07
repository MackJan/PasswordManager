# accounts/management/commands/test_email.py
from django.core.management.base import BaseCommand
from django.core.mail import send_mail

class Command(BaseCommand):
    def handle(self, *args, **options):
        try:
            send_mail(
                'Test Email',
                'This is a test email from your password manager.',
                'noreply@janmack.de',
                ['mack-jan@web.de'],
                fail_silently=False,
            )
            self.stdout.write('Email sent successfully!')
        except Exception as e:
            self.stdout.write(f'Email failed: {e}')
