from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='main'),
    path('login/', views.login_page, name='login'),
    path('register/',views.register_page,name='register'),
]