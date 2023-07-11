import hashlib
import mimetypes
import os, shutil
from base64 import b64encode,b64decode
from wsgiref.util import FileWrapper
from django.http import StreamingHttpResponse
from django.shortcuts import render
from Crypto.Cipher import AES
from django.core.files.storage import FileSystemStorage
from pathlib import Path
from Crypto.Util.Padding import pad


def home(request):
    """
    Осуществляет загрузку домашней страницы
    @param request: запрос
    @return: запрос, html-страницу
    """
    return render(request, 'encrypt/home.html')


def error_processing(text: str, password: str, placeholder_text: str, cipher_text: str, placeholder_password: str):
    """
    Осуществляет обработку ошибок ввода данных пользователем
    @param text: Текст, вводимый пользователем
    @param password: Пароль, вводимый пользователем
    @param placeholder_text: Текст в строке ввода текста
    @param cipher_text: Зашифрованный текст
    @param placeholder_password: Текст в строке ввода пароля
    @return: Ошибка в строке зашифрованного текста, ошибка в строке текста, ошибка в строке пароля, ошибка в строке текста, ошибка в строке пароля
    """
    if text == '' and password == '':
        cipher_text = 'Nothing to encrypt :( \nPlease enter text to encrypt and password'
        text = ''
        password = ''
    if text == '' and password != '':
        placeholder_text = 'Please enter some text'
        text = ''
        cipher_text = 'Nothing to encrypt :( \nEnter text to encrypt'
    elif text != '' and password == '':
        placeholder_password = 'Please enter some password'
        password = ''
        cipher_text = 'Not enough data to encrypt your text :(\nEnter some password'
    return cipher_text, text, password, placeholder_text, placeholder_password


def download_file(file_url: str):
    """
    Осуществялет скачивание файла с сервера на устройство пользователя
    @param file_url: Путь к файлу на сервере
    @return: Данные, необходимые для скачивания файла
    """
    file = file_url
    file_name = os.path.basename(file)
    chunk_size = 8192
    response = StreamingHttpResponse(FileWrapper(open(file, 'rb'), chunk_size),
                                     content_type=mimetypes.guess_type(file)[0])
    response['Content-Length'] = os.path.getsize(file)
    response['Content-Disposition'] = "attachment; filename=%s" % file_name
    return response


def file_save(cipher_data: bytes, file_url: str):
    """
    Осуществялет сохранение файла на сервер
    @param cipher_data: Зашифрованные данные
    @param file_url: Путь к файлу на сервере
    @return: Данные, необходимые для скачивания файла
    """
    file_url = file_url + '.encrypted'
    with open(file_url, 'wb') as new_file:
        new_file.write(cipher_data)
    return download_file(file_url)


def file_processing(request, button_value: str):
    """
    Осуществляет получение данных из файла
    @param request: Запрос
    @param button_value: Значение нажатой кнопки
    @return: Данные, необходимые для скачивания файла
    """
    upload = request.FILES.get('upload', False)
    fss = FileSystemStorage()
    file = fss.save(upload.name, upload)
    file_url = fss.url(file)[1:]

    with open(file_url, 'rb') as file:
        data = file.read()
    password = request.POST.get('filePassword')
    if button_value == 'AESpressedFile':
        return aes_encryption(data, password, button_value, file_url)

    elif button_value == 'XORpressedFile':
        return xor_encryption(data, password, button_value, file_url)


def aes_encryption(binary_data: bytes, password: str, button_value:str, file_url:str):

    key = hashlib.sha256(password.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_data = cipher.encrypt(pad(binary_data, AES.block_size))

    if 'Text' in button_value:
        return cipher.iv + cipher_data
    if 'File' in button_value:
        return file_save(cipher.iv + cipher_data, file_url)


def xor_encryption(data: bytes, password: str, button_value: str, file_url: str):
    try:
        encrypted_data = []

        for i in range(len(data)):
            encrypted_data.append(data[i] ^ ord(password[i % len(password)]))
        cipher_data = bytes(encrypted_data)
        print('cipher data = ',cipher_data)
        if 'Text' in button_value:
            return b64encode(cipher_data)
        elif 'File' in button_value:
            return file_save(cipher_data, file_url)

    except ZeroDivisionError:
        return 'Not enough data to encrypt your text :(\nEnter some password'


def text_processing(button_value, text, password):
    """
    Осуществляет получение данных из формы на сервере
    @param button_value: Значение нажатой пользователем кнопки
    @param text: Текст, введеный пользователем
    @param password: Пароль введеный пользователем
    @return: Зашифрованный текст
    """
    cipher_text = ''
    file_url = ''
    if 'AES' in button_value:
        cipher_text = aes_encryption(text.encode('utf-8'), password, button_value, file_url)
        cipher_text = b64encode(cipher_text).decode('utf-8')
    elif 'XOR' in button_value:
        cipher_text = xor_encryption(text.encode(), password, button_value, file_url)
        print('text:', cipher_text)
        # cipher_text - это просто строка
        cipher_text = cipher_text.decode('utf-8')
        print('b64:', cipher_text)
    return cipher_text


def encryption(request):
    """
    Осуществляет получение данных из форм на сервере, определяет вводимые данные, удаляет файлы с сервера
    @param request: Запрос с сервера
    @return: Запрос, html-страница, словарь с выходными данными
    """
    placeholder_text = "Enter your text"
    placeholder_password = 'Enter your password'
    file_password_placeholder = "Enter your password"

    media_path = Path(__file__).resolve().parent.parent / 'media'
    for files in os.listdir(media_path):
        path = os.path.join(media_path, files)
        try:
            shutil.rmtree(path)
        except OSError:
            os.remove(path)

    if request.method == 'POST':
        button_value = request.POST.get('button')
        text = request.POST.get('text')
        password = request.POST.get('textPassword')
        if request.FILES.get('upload', False):
            return file_processing(request, button_value)
        else:
            cipher_text = text_processing(button_value, text, password)

        cipher_text, text, password, placeholder_text, placeholder_password = error_processing(text, password,
                                                                                               placeholder_text,
                                                                                               cipher_text,
                                                                                               placeholder_password)

        return render(request, 'encrypt/encryption.html',
                      {'text': text,
                       'textPassword': password,
                       'ciphertext': cipher_text,
                       'placeholder_text': placeholder_text,
                       'placeholder_password': placeholder_password})
    else:
        return render(request, 'encrypt/encryption.html',
                      {'placeholder_text': placeholder_text,
                       'placeholder_password': placeholder_password,
                       'file_password_placeholder': file_password_placeholder})
