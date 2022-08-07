from django.shortcuts import render, get_object_or_404
from django.template import RequestContext
from .forms import TextEncryptionForm
from .models import Text
from django.http import HttpResponse

# Create your views here.

def home(request):
    return render(request, 'encrypt/home.html')

def encryption(request):
    # if request.method == 'GET':
    #     return render(request, 'encrypt/encryption.html', {'form':TextEncryptionForm()})
    # else:
    #     submitbutton= request.POST.get("submit")
    #
    #     text = ''
    #     password = ''
    #
    #     form = TextEncryptionForm(request.POST or None)
    #     if form.is_valid:
    #         text = form.cleaned_data("text")
    #         password = form.cleaned_data("password")
    #     context= {'form': form, 'text': text,
    #           'password':password, 'submitbutton': submitbutton}
    #     return render(request, 'encrypt/encryption.html', context)
    # form = TextEncryptionForm(request.POST or None)
    # if request.method == "POST" and form.is_valid():
    #     text = form.cleaned_data['text']
    #     password = form.cleaned_data['password']
    # return render(request, "encrypt/encryption.html", {"form":TextEncryptionForm()})
    if request.method == 'GET':
        return render(request, 'encrypt/encryption.html')
    else:
        # submitbutton= request.POST.get("submit")
        form = get_object_or_404(Text, pk = 1)
        form.save
        text = request.POST.get('text')
        password = request.POST.get('password')
        context = {'form':form, 'text':text, 'password':password}
        return render(request,context)
