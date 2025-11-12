"""Management command to send a test email."""

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Send a test email to verify email backend configuration.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--to',
            dest='email',
            help='Email address to deliver the test message to. Defaults to DEFAULT_FROM_EMAIL.',
        )

    def handle(self, *args, **options):
        recipient = options.get('email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)
        if not recipient:
            raise CommandError('Provide an email with --to or configure DEFAULT_FROM_EMAIL.')

        sent = send_mail(
            subject='Password Manager test email',
            message='This is a test email from the Password Manager application.',
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None) or recipient,
            recipient_list=[recipient],
            fail_silently=False,
        )

        if sent:
            self.stdout.write(self.style.SUCCESS('Email sent successfully'))
        else:
            raise CommandError('Failed to send test email')
