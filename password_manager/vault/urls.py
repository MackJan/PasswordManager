from django.urls import path
from . import views

urlpatterns = [
    path('vault/', views.vault_dashboard,name='vault_dashboard'),
    path('vault/edit/', views.edit_dashboard,name='edit_dashboard'),
]