from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='main'),
    path('',views.root,name='root'),
]