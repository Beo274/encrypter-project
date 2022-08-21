import hashlib
from django.shortcuts import render, get_object_or_404
from django.template import RequestContext
from .forms import TextEncryptionForm
from .models import Text
from django.http import HttpResponse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def home(request):
    return render(request, 'encrypt/home.html')

# def encryption(request, *args, **kwargs):
#     pk = kwargs.get('pk')
#     # if request.method == 'GET':
#     #     return render(request, 'encrypt/encryption.html', {'form':TextEncryptionForm()})
#     # else:
#     #     submitbutton= request.POST.get("submit")
#     #
#     #     text = ''
#     #     password = ''
#     #
#     #     form = TextEncryptionForm(request.POST or None)
#     #     if form.is_valid:
#     #         text = form.cleaned_data("text")
#     #         password = form.cleaned_data("password")
#     #     context= {'form': form, 'text': text,
#     #           'password':password, 'submitbutton': submitbutton}
#     #     return render(request, 'encrypt/encryption.html', context)
#     # form = TextEncryptionForm(request.POST or None)
#     # if request.method == "POST" and form.is_valid():
#     #     text = form.cleaned_data['text']
#     #     password = form.cleaned_data['password']
#     # return render(request, "encrypt/encryption.html", {"form":TextEncryptionForm()})
#     if request.method == 'GET':
#         return render(request, 'encrypt/encryption.html')
#     else:
#         aesbutton= request.POST.get("AESButton")
#         form = get_object_or_404(Text, pk = pk)
#         text = request.POST.get('text')
#         password = request.POST.get('password')
#         context = {'text':text, 'password':password}
#         # return HttpResponse([aesbutton, ' ', password, ' ', text])
#         return render(request, 'encrypt/encryption.html', {'form':form})

def encryption(request):
    text = ''
    password = ''
    ciphertext = ''
    deciphertext = ''

    form = TextEncryptionForm(request.POST or None)
    if form.is_valid() and request.method == 'POST':
        text = form.cleaned_data.get('text')
        text = text.encode('utf-8')

        password = form.cleaned_data.get('password')
        # password = password.encode('utf-8')
        key = hashlib.sha256(password.encode()).digest()

        # Шифрование
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext = cipher.encrypt_and_digest(text)
        nonce = cipher.nonce

        # Дешифровка
        #cipher = AES.new(password, AES.MODE_EAX, nonce)
        #deciphertext = cipher.decrypt_and_verify(ciphertext, tag)

    return render(request, 'encrypt/encryption.html', {'form':form, 'ciphertext':ciphertext, 'text':text, 'deciphertext':deciphertext, 'password':password})


