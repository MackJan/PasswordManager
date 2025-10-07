from django.urls import path
from . import views

urlpatterns = [
    path('', views.vault_dashboard, name='vault_dashboard'),
]