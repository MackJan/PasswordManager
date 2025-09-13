from django.urls import path
from . import views

urlpatterns = [
    path('vault/', views.vault_dashboard,name='vault_dashboard'),
]