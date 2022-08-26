def fileProcessing(file_url):
    with open(file_url,'rb') as file:
        data = file.read()
        return data

def encryption(request):
    cipherdata = ''
    data = ''
    if request.method == 'POST':
        buttonValue = request.POST.get('button')
        text = request.POST.get('text')
        if request.FILES.get('upload', False):
            upload = request.FILES.get('upload', False)
            fss = FileSystemStorage()
            file = fss.save(upload.name, upload)
            file_url = fss.url(file)[1:]
            # print(file_url)
            # onlyfiles = [f for f in listdir('media') if isfile(join('media', f))]
            # print(onlyfiles)
            data = fileProcessing(file_url)
            password = request.POST.get('filePassword')
        else:
            password = request.POST.get('textPassword')
        if buttonValue == 'AESpressed':
            key = hashlib.sha256(password.encode('utf-8')).digest()
            cipher = AES.new(key, AES.MODE_EAX)
            if not request.FILES.get('upload', False):
                data = text.encode('utf-8')
            cipherdata, tag = cipher.encrypt_and_digest(data)
            nonce = cipher.nonce
            print(nonce, tag, key)
            print({'text': data.decode('utf-8', errors='ignore'),'cipherdata': cipherdata.decode('utf-8',errors='ignore'),'textPassword': password})
        elif buttonValue == 'XORpressed':
            encrypted_data = []
            data = bytes(text, encoding='utf-8')
            key = bytes(password, encoding='utf-8')
            for i in range(len(data)):
                encrypted_data.append(data[i] ^ key[i % len(key)])
                cipherdata += chr(encrypted_data[i])
            return render(request, 'encrypt/encryption.html', {'text': text, 'textPassword': password, 'cipherdata': cipherdata})
    else:
        return render('just result')