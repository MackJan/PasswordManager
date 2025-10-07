"""
URL configuration for password_manager project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    path('vault/', include('vault.urls')),
    path('', include('django_prometheus.urls')),  # /metrics endpoint
    path('accounts/', include('allauth.urls')),  # allauth authentication URLs
    path('profile/', include('accounts.urls')),  # Custom account management views

    # Legacy redirects for old authentication URLs
    path('login/', RedirectView.as_view(url='/accounts/login/', permanent=True)),
    path('register/', RedirectView.as_view(url='/accounts/signup/', permanent=True)),
    path('logout/', RedirectView.as_view(url='/accounts/logout/', permanent=True)),
]
