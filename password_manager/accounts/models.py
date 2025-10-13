from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **kwargs):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, **kwargs)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **kwargs):
        kwargs.setdefault('is_staff', True)
        kwargs.setdefault('is_superuser', True)

        if not kwargs.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not kwargs.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **kwargs)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class UserKeystore(models.Model):
    """Store encrypted User Master Key (UMK) and related metadata."""

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='keystore',
    )
    amk_key_version = models.SmallIntegerField(default=1)
    wrapped_umk_b64 = models.TextField(null=True, blank=True)
    umk_nonce_b64 = models.CharField(max_length=64, null=True, blank=True)
    algo_version = models.SmallIntegerField(default=1)
    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)

    class Meta:
        db_table = 'accounts_userkeystore'

    def __str__(self):
        return f"Keystore for {self.user.email}"
