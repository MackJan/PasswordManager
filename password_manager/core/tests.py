from types import SimpleNamespace
import logging
from unittest.mock import MagicMock, patch

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase

from core.logging_utils import AppLogger
from core.middleware import (
    LoggingMiddleware,
    RequestContextFilter,
    _request_context,
    get_client_ip,
    get_request_context,
)
from core import views as core_views


class AppLoggerTests(SimpleTestCase):
    def setUp(self):
        self.logger = AppLogger('core.tests')
        self.user = SimpleNamespace(email='user@example.com')

    def test_info_logs_formatted_message_with_user_and_extra(self):
        extra = {'ip': '127.0.0.1', 'action': 'view'}
        with self.assertLogs('core.tests', level='INFO') as captured:
            self.logger.info('Test message', user=self.user, extra_data=extra)
        self.assertEqual(len(captured.output), 1)
        logged_message = captured.output[0]
        self.assertIn('[User: user@example.com] Test message', logged_message)
        self.assertIn('ip: 127.0.0.1', logged_message)
        self.assertIn('action: view', logged_message)

    def test_security_event_uses_security_logger(self):
        with self.assertLogs('django.security', level='WARNING') as captured:
            self.logger.security_event('Suspicious activity', user=self.user)
        self.assertEqual(len(captured.output), 1)
        self.assertIn('SECURITY EVENT: Suspicious activity', captured.output[0])

    def test_critical_logs_to_alerts_logger(self):
        with self.assertLogs('alerts', level='ERROR') as alerts_log, self.assertLogs(
            'core.tests', level='CRITICAL'
        ) as core_log:
            self.logger.critical('Critical failure detected')
        self.assertTrue(any('CRITICAL: Critical failure detected' in entry for entry in alerts_log.output))
        self.assertTrue(any('Critical failure detected' in entry for entry in core_log.output))

    def test_encryption_event_logs_success_and_failure(self):
        with self.assertLogs('core.tests', level='INFO') as success_log:
            self.logger.encryption_event('Key rotation complete', user=self.user, success=True)
        self.assertTrue(any('ENCRYPTION SUCCESS: Key rotation complete' in entry for entry in success_log.output))

        with self.assertLogs('core.tests', level='ERROR') as failure_log:
            self.logger.encryption_event('Key rotation failed', user=self.user, success=False)
        self.assertTrue(any('ENCRYPTION FAILURE: Key rotation failed' in entry for entry in failure_log.output))

    def test_user_activity_includes_email_and_action(self):
        with self.assertLogs('core.tests', level='INFO') as captured:
            self.logger.user_activity('login', self.user, details='via MFA')
        entry = captured.output[0]
        self.assertIn('User user@example.com performed action: login - via MFA', entry)


class MiddlewareTests(SimpleTestCase):
    def test_get_client_ip_prefers_forwarded_header(self):
        request = SimpleNamespace(META={'HTTP_X_FORWARDED_FOR': '203.0.113.10, 10.0.0.1'})
        self.assertEqual(get_client_ip(request), '203.0.113.10')

    def test_get_client_ip_falls_back_to_remote_addr(self):
        request = SimpleNamespace(META={'REMOTE_ADDR': '198.51.100.5'})
        self.assertEqual(get_client_ip(request), '198.51.100.5')

    def test_get_client_ip_skips_unknown_entries(self):
        request = SimpleNamespace(
            META={'HTTP_X_FORWARDED_FOR': 'unknown, 203.0.113.1', 'REMOTE_ADDR': '198.51.100.5'}
        )
        self.assertEqual(get_client_ip(request), '203.0.113.1')

    def test_request_context_filter_adds_context_information(self):
        token = _request_context.set(
            {
                'user_id': '42',
                'ip': '192.0.2.55',
                'request_id': 'req-1',
                'method': 'GET',
                'path': '/test/',
            }
        )
        try:
            record = logging.LogRecord('test', logging.INFO, __file__, 10, 'msg', (), None)
            RequestContextFilter().filter(record)
            self.assertEqual(record.user_id, '42')
            self.assertEqual(record.ip, '192.0.2.55')
            self.assertEqual(record.request_id, 'req-1')
            self.assertEqual(record.http_method, 'GET')
            self.assertEqual(record.path, '/test/')
        finally:
            _request_context.reset(token)

    def test_logging_middleware_populates_and_cleans_context(self):
        class AuthenticatedUser:
            is_authenticated = True
            id = 7

        factory = RequestFactory()
        request = factory.get('/vault/', HTTP_X_FORWARDED_FOR='198.51.100.7')
        request.user = AuthenticatedUser()

        captured_state = {}

        def get_response(request):
            captured_state['context'] = get_request_context().copy()
            return HttpResponse('ok')

        middleware = LoggingMiddleware(get_response)
        response = middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn('X-Request-ID', response.headers)
        self.assertTrue(hasattr(request, 'request_id'))
        self.assertEqual(request.request_id, response.headers['X-Request-ID'])
        self.assertTrue(captured_state['context'])
        self.assertEqual(captured_state['context']['request_id'], response.headers['X-Request-ID'])
        self.assertEqual(captured_state['context']['user_id'], '7')
        self.assertEqual(captured_state['context']['ip'], '198.51.100.7')
        self.assertEqual(captured_state['context']['method'], 'GET')
        self.assertEqual(captured_state['context']['path'], '/vault/')
        self.assertEqual(get_request_context(), {})


class CoreViewTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_home_logs_access_and_renders_context(self):
        request = self.factory.get('/home/')
        request.user = SimpleNamespace(is_authenticated=True, email='user@example.com')
        request.META['REMOTE_ADDR'] = '127.0.0.1'

        with patch.object(core_views, 'logger') as mock_logger, patch(
            'core.views.loader.get_template'
        ) as mock_loader:
            template = MagicMock()
            template.render.return_value = 'rendered'
            mock_loader.return_value = template

            response = core_views.home(request)

        mock_logger.info.assert_called_once()
        mock_logger.user_activity.assert_called_once()
        self.assertEqual(response.content.decode('utf-8'), 'rendered')

    def test_root_redirects_to_home(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'

        with patch.object(core_views, 'logger') as mock_logger:
            response = core_views.root(request)

        mock_logger.info.assert_called_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/home/')
