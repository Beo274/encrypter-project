import hashlib

from Crypto.Cipher import AES

text = "some text"
text = text.encode('utf-8')

password = "some password"
key = hashlib.sha256(password.encode()).digest()
print(key)

# Шифрование
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(text)
nonce = cipher.nonce
print(ciphertext)

# Дешифровка
cipher = AES.new(key, AES.MODE_EAX, nonce)
deciphertext = cipher.decrypt_and_verify(ciphertext, tag)
print(deciphertext)
