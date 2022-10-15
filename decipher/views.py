import hashlib
import mimetypes
import os, shutil, sys
from wsgiref.util import FileWrapper
from django.http import StreamingHttpResponse
from django.shortcuts import render
from Crypto.Cipher import AES
from django.core.files.storage import FileSystemStorage
from pathlib import Path
from Crypto.Util.Padding import unpad
from base64 import b64decode


def download_file(file_url):
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


def file_save(decipher_data: bytes, file_url):
    """
    Осуществляет скачивание файла на сервер
    @param decipher_data: Расшифрованные данные
    @param file_url: Путь к файлу на сервере
    @return: Данные, необходимые для скачивания файла
    """
    file_url = file_url[0:-10]
    with open(file_url, 'wb') as newFile:
        newFile.write(decipher_data)
    return download_file(file_url)


def xor_file_decryption(cipher_data: bytes, password, file_url):
    """
    Осуществляет расшифровку файла с помощью алгоритма XOR
    @param cipher_data: Зашифрованные данные
    @param password: Пароль, вводимый пользователем
    @param file_url: Путь к файлу на сервере
    @return: Данные, необходимые для скачивания файла
    """
    decrypted_data = []
    for i in range(len(cipher_data)):
        decrypted_data.append(cipher_data[i] ^ ord(password[i % len(password)]))
    decipher_data = bytes(decrypted_data)
    return file_save(decipher_data, file_url)


def aes_file_decryption(cipher_data: bytes, password: str, file_url: str):
    """
    Осущетсвляет шифрование файла с помощью алгоритма AES
    @param cipher_data: Зашифрованные данные
    @param password: Пароль, вводимый пользователем
    @param file_url: Путь к файлу на сервере
    @return: Данные, необходимые для скачивания файла
    """
    try:
        key = hashlib.sha256(password.encode('utf-8')).digest()
        iv = cipher_data[:16]
        encrypted_data = cipher_data[16:]
        decipher = AES.new(key, AES.MODE_CBC, iv)
        decipher_data = unpad(decipher.decrypt(encrypted_data), AES.block_size)
        return file_save(decipher_data, file_url)
    except (ValueError, KeyError) as e:
        print(f"Incorrect decryption. Error: {e}")


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
    if button_value == 'AESdcrptFile':
        return aes_file_decryption(data, password, file_url)
    elif button_value == 'XORdcrptFile':
        return xor_file_decryption(data, password, file_url)


def xor_text_decryption(encrypted_text: str, password: str):
    """
    Осуществляет рассшифровку текстовых данных с помощью алгоритма XOR
    :param encrypted_text: зашифрованный текст
    :param password: пароль для рассшифровки
    :return: расшифрованный текст
    """
    try:
        decrypted_data = []
        for i in range(len(encrypted_text)):
            decrypted_data.append(ord(encrypted_text[i]) ^ ord(password[i % len(password)]))
        decrypted_text = ''
        for i in range(len(decrypted_data)):
            decrypted_text = decrypted_text + chr(decrypted_data[i])
        return decrypted_text
    except ZeroDivisionError:
        return 'Not enough data to encrypt your text :(\nEnter some password'


def aes_text_decryption(cipher_text: bytes, password: str):
    """
    Осуществляет расшифровку текста с помощью алгоритма AES
    @param cipher_text: Зашифрованные текст
    @param password: Пароль, вводимый пользователем
    @return: Расшифрованный текст
    """
    try:
        key = hashlib.sha256(password.encode('utf-8')).digest()
        iv = cipher_text[:16]
        encrypted_data = cipher_text[16:]
        decipher = AES.new(key, AES.MODE_CBC, iv)
        decipher_text = unpad(decipher.decrypt(encrypted_data), AES.block_size)
        return decipher_text
    except (ValueError, KeyError) as e:
        print(f"Incorrect decryption. Error: {e}")


def encrypted_text_processing(button_value: str, cipher_text: str, password):
    """
    Осуществляет получение данных из формы на сервере
    @param button_value: Значение нажатой пользователем кнопки
    @param cipher_text: Зашифрованный текст
    @param password: Пароль, введеный пользователем
    @return: Расшифрованный текст
    """
    if button_value == 'AESdcrptText':
        decipher_text = aes_text_decryption(b64decode(cipher_text), password)
        decipher_text = decipher_text.decode("utf-8")
        return decipher_text
    elif button_value == 'XORdcrptText':
        cipher_text_b64 = b64decode(cipher_text)
        decipher_text = xor_text_decryption(cipher_text_b64.decode("utf-8"), password)
        return decipher_text


def decryption(request):
    """
    Осуществляет получение расшифрованных данных из форм на сервере, определяет вводимые данные, удаляет файлы с сервера
    @param request: Запрос
    @return: Запрос, html-страница, словарь с выходными данными
    """
    media_path = Path(__file__).resolve().parent.parent / 'media'
    for files in os.listdir(media_path):
        path = os.path.join(media_path, files)
        try:
            shutil.rmtree(path)
        except OSError:
            os.remove(path)
    if request.method == 'POST':
        button_value = request.POST.get('button', False)
        cipher_text = request.POST.get('encryptedText', False)
        password = request.POST.get('textPassword', False)
        if request.FILES.get('upload', False):
            return file_processing(request, button_value)
        else:
            decipher_text = encrypted_text_processing(button_value, cipher_text, password)
        return render(request, 'decipher/decryption.html',
                      {'ciphertext': cipher_text,
                       'textPassword': password,
                       'deciphertext': decipher_text})
    else:
        return render(request, 'decipher/decryption.html')
