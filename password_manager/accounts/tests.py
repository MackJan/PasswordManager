from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils.http import int_to_base36


class PasswordResetSecurityTests(TestCase):
    def setUp(self):
        self.password = "OriginalPass123!"
        self.user = get_user_model().objects.create_user(
            email="user@example.com", password=self.password
        )
        self.reset_url = reverse(
            "account_reset_password_from_key",
            kwargs={
                "uidb36": int_to_base36(self.user.pk),
                "key": "set-password",
            },
        )

    def test_invalid_reset_link_shows_error(self):
        response = self.client.get(self.reset_url)
        self.assertContains(response, "password reset link is invalid or has expired", status_code=200)
        self.assertNotContains(response, "name=\"password1\"")

    def test_invalid_reset_link_does_not_change_password(self):
        response = self.client.post(
            self.reset_url,
            {
                "password1": "NewSecurePass456!",
                "password2": "NewSecurePass456!",
            },
        )
        self.assertContains(response, "password reset link is invalid or has expired", status_code=200)
        user = get_user_model().objects.get(pk=self.user.pk)
        self.assertTrue(user.check_password(self.password))
