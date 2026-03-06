import base64
from Crypto.Cipher import AES

key = b"YELLOW SUBMARINE"
cipher = b""
with open("7.txt", "r") as file:
    data = base64.b64decode(file.read())

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(data)

print(plaintext.decode())
