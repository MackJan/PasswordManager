from types import SimpleNamespace
import logging

from django.test import SimpleTestCase

from core.logging_utils import AppLogger
from core.middleware import (
    LoggingMiddleware,
    UserIdFilter,
    _request_data,
    get_client_ip,
)


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

    def test_user_id_filter_adds_thread_local_information(self):
        _request_data.user_id = '42'
        _request_data.ip_address = '192.0.2.55'
        try:
            record = logging.LogRecord('test', logging.INFO, __file__, 10, 'msg', (), None)
            UserIdFilter().filter(record)
            self.assertEqual(record.user_id, '42')
            self.assertEqual(record.ip, '192.0.2.55')
        finally:
            if hasattr(_request_data, 'user_id'):
                delattr(_request_data, 'user_id')
            if hasattr(_request_data, 'ip_address'):
                delattr(_request_data, 'ip_address')

    def test_logging_middleware_populates_and_cleans_thread_local(self):
        class AuthenticatedUser:
            is_authenticated = True
            id = 7

        class DummyRequest:
            META = {'REMOTE_ADDR': '198.51.100.7'}
            user = AuthenticatedUser()

        captured_state = {}

        def get_response(request):
            captured_state['user_id'] = getattr(_request_data, 'user_id', None)
            captured_state['ip'] = getattr(_request_data, 'ip_address', None)
            return 'response'

        middleware = LoggingMiddleware(get_response)
        response = middleware(DummyRequest())

        self.assertEqual(response, 'response')
        self.assertEqual(captured_state['user_id'], '7')
        self.assertEqual(captured_state['ip'], '198.51.100.7')
        self.assertFalse(hasattr(_request_data, 'user_id'))
        self.assertFalse(hasattr(_request_data, 'ip_address'))
