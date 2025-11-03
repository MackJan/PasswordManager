from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.core import management
from django.test import RequestFactory, TestCase
from django.urls import reverse

from accounts import views


try:
    secret_key = settings.SECRET_KEY
except ImproperlyConfigured:
    settings.SECRET_KEY = 'test-secret'
else:
    if not secret_key:
        settings.SECRET_KEY = 'test-secret'


class AccountsViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(
            email='user@example.com',
            password='password123',
        )

    def _prepare_request(self, request, *, user=None):
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        request.user = user or self.user
        return request

    def test_generate_recovery_codes_creates_formatted_codes(self):
        codes = views.generate_recovery_codes(count=3)
        self.assertEqual(len(codes), 3)
        for code in codes:
            self.assertEqual(len(code), 9)
            self.assertEqual(code[4], '-')

    def test_get_recovery_codes_data_provides_seed_and_codes(self):
        with patch('accounts.views.secrets.token_bytes', return_value=b'\x01' * 32):
            codes = ['ABCD-EFGH']
            data = views.get_recovery_codes_data(codes)

        self.assertEqual(data['seed'], '01' * 32)
        self.assertEqual(data['unused_codes'], codes)

    @patch('accounts.views.logout')
    def test_logout_page_logs_and_redirects(self, mock_logout):
        request = self._prepare_request(self.factory.get('/logout/'))

        with patch.object(views, 'logger') as mock_logger:
            response = views.logout_page(request)

        mock_logger.info.assert_called_once_with('User logged out', user=request.user)
        mock_logout.assert_called_once_with(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/login/')

    def test_profile_view_renders_context_with_authenticators(self):
        request = self._prepare_request(self.factory.get('/profile/'))

        fake_authenticator = MagicMock()
        with patch('accounts.views.is_mfa_enabled', return_value=True), patch(
            'accounts.views.Authenticator.objects.filter', return_value=[fake_authenticator]
        ), patch('accounts.views.render') as mock_render:
            mock_render.return_value = MagicMock()
            views.profile_view(request)

        (_, __, context), _ = mock_render.call_args
        self.assertTrue(context['mfa_enabled'])
        self.assertEqual(context['authenticators'], [fake_authenticator])

    def test_security_settings_includes_recovery_code_flag(self):
        request = self._prepare_request(self.factory.get('/profile/security/'))
        totp_qs = MagicMock()
        recovery_qs = MagicMock()
        recovery_qs.exists.return_value = True

        def filter_side_effect(*args, **kwargs):
            if kwargs.get('type') == views.Authenticator.Type.TOTP:
                return totp_qs
            return recovery_qs

        with patch('accounts.views.Authenticator.objects.filter', side_effect=filter_side_effect), patch(
            'accounts.views.render'
        ) as mock_render:
            mock_render.return_value = MagicMock()
            views.security_settings(request)

        (_, __, context), _ = mock_render.call_args
        self.assertTrue(context['has_recovery_codes'])

    def test_enable_2fa_short_circuits_when_totp_exists(self):
        request = self._prepare_request(self.factory.get('/profile/enable-2fa/'))
        request.session['totp_secret'] = 'SECRET'

        qs = MagicMock()
        qs.exists.return_value = True

        with patch('accounts.views.Authenticator.objects.filter', return_value=qs), patch(
            'accounts.views.messages.warning'
        ) as mock_warning:
            response = views.enable_2fa(request)

        mock_warning.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('security_settings'))

    def test_disable_2fa_logs_when_authenticators_removed(self):
        request = self._prepare_request(self.factory.post('/profile/disable-2fa/'))
        qs = MagicMock()
        qs.delete.return_value = (2, {})

        with patch('accounts.views.Authenticator.objects.filter', return_value=qs), patch(
            'accounts.views.messages.success'
        ) as mock_success:
            response = views.disable_2fa(request)

        mock_success.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('security_settings'))

    def test_regenerate_recovery_codes_updates_existing_authenticator(self):
        request = self._prepare_request(self.factory.post('/profile/regenerate-recovery-codes/'))

        existing_authenticator = MagicMock()
        with patch('accounts.views.generate_recovery_codes', return_value=['NEW-CODE']), patch(
            'accounts.views.get_recovery_codes_data', return_value={'seed': 'abc', 'unused_codes': ['NEW-CODE']}
        ), patch(
            'accounts.views.Authenticator.objects.get_or_create', return_value=(existing_authenticator, False)
        ), patch('accounts.views.messages.success') as mock_success:
            response = views.regenerate_recovery_codes(request)

        self.assertEqual(request.session['new_recovery_codes'], ['NEW-CODE'])
        existing_authenticator.save.assert_called_once()
        mock_success.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('show_recovery_codes'))

    def test_show_recovery_codes_without_session_redirects(self):
        request = self._prepare_request(self.factory.get('/profile/show-recovery-codes/'))

        with patch('accounts.views.messages.error') as mock_error:
            response = views.show_recovery_codes(request)

        mock_error.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('security_settings'))

    def test_recovery_code_login_successfully_consumes_code(self):
        anonymous = AnonymousUser()
        request = self._prepare_request(self.factory.post('/profile/recovery-login/', {
            'email': 'user@example.com',
            'recovery_code': 'CODE-ONE',
        }), user=anonymous)

        recovery_auth = MagicMock()
        recovery_auth.data = {'unused_codes': ['CODE-ONE']}

        with patch('accounts.views.CustomUser.objects.get', return_value=self.user), patch(
            'accounts.views.Authenticator.objects.filter'
        ) as mock_filter, patch('accounts.views.messages.success') as mock_success, patch(
            'accounts.views.messages.warning'
        ) as mock_warning, patch('accounts.views.messages.error') as mock_error, patch(
            'django.contrib.auth.login'
        ) as mock_login:
            mock_filter.return_value.first.return_value = recovery_auth
            response = views.recovery_code_login(request)

        mock_login.assert_called_once()
        mock_success.assert_called_once()
        mock_error.assert_not_called()
        mock_warning.assert_called()
        self.assertEqual(response.status_code, 302)

    def test_recovery_code_login_missing_data(self):
        anonymous = AnonymousUser()
        request = self._prepare_request(self.factory.post('/profile/recovery-login/', {
            'email': '',
            'recovery_code': '',
        }), user=anonymous)

        with patch('accounts.views.messages.error') as mock_error:
            response = views.recovery_code_login(request)

        mock_error.assert_called_once()
        self.assertEqual(response.status_code, 200)


class HardenedPasswordResetViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _prepare_request(self):
        request = self.factory.get('/accounts/reset/')
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        return request

    def test_invalid_token_redirects_with_message(self):
        request = self._prepare_request()
        view = views.HardenedPasswordResetFromKeyView()
        view.setup(request)

        with patch('accounts.views.messages.error') as mock_error:
            response = view.render_to_response({'token_fail': True})

        mock_error.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('account_reset_password'))


class AccountsSignalTests(TestCase):
    def test_log_user_login_uses_client_ip(self):
        request = SimpleNamespace(META={'REMOTE_ADDR': '127.0.0.1'})
        user = SimpleNamespace(email='user@example.com')

        with patch('accounts.signals.logger') as mock_logger:
            from accounts import signals

            signals.log_user_login(sender=None, request=request, user=user)

        mock_logger.user_activity.assert_called_once()

    def test_log_login_failure_records_credentials(self):
        request = SimpleNamespace(META={'HTTP_X_FORWARDED_FOR': '1.2.3.4'})
        with patch('accounts.signals.logger') as mock_logger:
            from accounts import signals

            signals.log_login_failure(
                sender=None,
                credentials={'username': 'user@example.com', 'extra': 'value'},
                request=request,
            )

        mock_logger.security_event.assert_called_once()


class AccountManagementCommandTests(TestCase):
    @patch('accounts.management.commands.fix_recovery_codes.Authenticator')
    @patch('accounts.management.commands.fix_recovery_codes.secrets.token_bytes', return_value=b'\x02' * 32)
    def test_fix_recovery_codes_generates_missing_seed(self, _mock_token_bytes, mock_authenticator):
        auth_without_seed = MagicMock()
        auth_without_seed.data = {}
        auth_without_seed.user.email = 'user@example.com'
        auth_with_seed = MagicMock()
        auth_with_seed.data = {'seed': 'existing'}
        mock_authenticator.objects.filter.return_value = [auth_without_seed, auth_with_seed]

        out = StringIO()
        management.call_command('fix_recovery_codes', stdout=out)

        self.assertIn('Fixed recovery codes for user', out.getvalue())
        self.assertIn('Fixed 1 recovery codes authenticators.', out.getvalue())
        auth_without_seed.save.assert_called_once()

    @patch('accounts.management.commands.test_email.send_mail', return_value=1)
    def test_test_email_command_reports_success(self, mock_send_mail):
        out = StringIO()
        management.call_command('test_email', stdout=out)

        mock_send_mail.assert_called_once()
        self.assertIn('Email sent successfully', out.getvalue())


class VaultManagementCommandTests(TestCase):
    @patch('vault.management.commands.migrate_encryption.EncryptionService.setup_user_encryption')
    @patch('vault.management.commands.migrate_encryption.User.objects.filter')
    def test_migrate_encryption_sets_up_missing_keystores(self, mock_filter, mock_setup):
        user = SimpleNamespace(email='user@example.com')
        users_qs = MagicMock()
        users_qs.__iter__.return_value = [user]
        users_qs.count.return_value = 1
        mock_filter.return_value = users_qs

        out = StringIO()
        management.call_command('migrate_encryption', stdout=out)

        mock_setup.assert_called_once_with(user)
        self.assertIn('1 users processed', out.getvalue())
