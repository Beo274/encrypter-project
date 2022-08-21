from django import forms

class TextEncryptionForm(forms.Form):
    text = forms.CharField(max_length = '1000')
    password = forms.CharField(max_length = 100)



