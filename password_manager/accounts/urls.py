from django.urls import path
from . import views

urlpatterns = [
    # Account profile and 2FA management
    path('', views.profile_view, name='profile'),
    path('security/', views.security_settings, name='security_settings'),
    path('enable-2fa/', views.enable_2fa, name='enable_2fa'),
    path('disable-2fa/', views.disable_2fa, name='disable_2fa'),
    path('regenerate-recovery-codes/', views.regenerate_recovery_codes, name='regenerate_recovery_codes'),
    path('show-recovery-codes/', views.show_recovery_codes, name='show_recovery_codes'),
    path('recovery-login/', views.recovery_code_login, name='recovery_code_login'),
]