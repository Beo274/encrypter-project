from django import forms
from django.forms import ModelForm
from .models import Text

class TextEncryptionForm(forms.Form):
    text = forms.CharField()
    password = forms.CharField(max_length = 100)
