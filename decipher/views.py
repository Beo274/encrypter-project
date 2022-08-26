from django.shortcuts import render

# Create your views here.

def decryption(request):
    return render(request, 'decipher/decryption.html')