import hashlib
from os.path import isfile, join

from django.shortcuts import render
from Crypto.Cipher import AES
from django.core.files.storage import FileSystemStorage
from os import listdir
from .forms import FileForm
from .models import File

def home(request):
    return render(request, 'encrypt/home.html')

def fileSave(cipherdata,file_url):
    with open(file_url + '_encrypted.bin', 'w+', encoding="utf-8") as newFile:
        newFile.write(cipherdata)
    return newFile


def aesFileEncryption(data,password,file_url):
    key = hashlib.sha256(password.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    cipherdata, tag = cipher.encrypt_and_digest(data)

    nonce = cipher.nonce
    #print('nonce =', nonce, 'tag = ', tag, 'key = ', key)
    cipherdata = nonce.decode('utf-8', errors='ignore') + 'Н' + '\n' + tag.decode('utf-8', errors='ignore') + 'Т' + '\n' + cipherdata.decode('utf-8', errors='ignore')
    print(cipherdata)
    newFile = fileSave(cipherdata,file_url)

    return newFile

def xorFileEncryption(data,password,file_url):
    encrypted_data = []
    cipherdata = ''
    nonce = ''
    tag = ''

    key = bytes(password, encoding='utf-8')
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
        cipherdata += chr(encrypted_data[i])

    newFile = fileSave(cipherdata, file_url)

    return newFile

def fileProcessing(request, buttonValue):
    upload = request.FILES.get('upload', False)

    fss = FileSystemStorage()
    file = fss.save(upload.name, upload)
    file_url = fss.url(file)[1:]

    with open(file_url,'rb') as file:
        data = file.read()

    password = request.POST.get('filePassword')

    if buttonValue == 'AESpressedFile':
        newFile = aesFileEncryption(data,password,file_url)
        return newFile, password

    elif buttonValue == 'XORpressedFile':
        newFile = xorFileEncryption(data,password,file_url)
        return newFile, password

def aesTextEncryption(text,password):
    data = text.encode('utf-8')

    key = hashlib.sha256(password.encode('utf-8')).digest()

    cipher = AES.new(key, AES.MODE_EAX)
    cipherdata, tag = cipher.encrypt_and_digest(data)

    nonce = cipher.nonce
    # print('nonce =', nonce, 'tag = ', tag, 'key = ', key)
    cipherdata = nonce.decode('utf-8', errors='ignore') + 'Н' + '\n' + tag.decode('utf-8', errors='ignore') + 'Т' + '\n' + cipherdata.decode('utf-8', errors='ignore')
    #print('\nnonce = ' + nonce.decode('utf-8', errors='ignore') + '\ntag = ' + tag.decode('utf-8', errors='ignore'))
    return data.decode('utf-8', errors='ignore'), cipherdata

def xorTextEncryption(text,password):
    encrypted_data = []
    cipherdata = ''
    data = bytes(text, encoding='utf-8')
    key = bytes(password, encoding='utf-8')
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
        cipherdata += chr(encrypted_data[i])
    # print('key =', key)
    return cipherdata

def textProcessing(buttonValue,text,password):
        if buttonValue == 'AESpressedText':
            data,cipherdata = aesTextEncryption(text,password)
            return cipherdata
        elif buttonValue == 'XORpressedText':
            cipherdata = xorTextEncryption(text,password)
            return cipherdata

def encryption(request):
    filePassword = ''
    cipherdata = ''
    newFile = ''
    if request.method == 'POST':
        buttonValue = request.POST.get('button')
        text = request.POST.get('text')
        password = request.POST.get('textPassword')
        if text == None and password == None:
            text = ''
            password = ''
        if request.FILES.get('upload', False):
            newFile,filePassword = fileProcessing(request, buttonValue)
        else:
            cipherdata = textProcessing(buttonValue,text,password)
        return render(request, 'encrypt/encryption.html', {'text':text, 'textPassword':password, 'cipherdata': cipherdata, 'newFile':newFile,'filePassword':filePassword})
    else:
        return render(request, 'encrypt/encryption.html')

