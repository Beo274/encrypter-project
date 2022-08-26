from django.urls import path
from . import views

app_name = 'decipher'

urlpatterns = [
    path('', views.decryption, name = 'decryption'),
]