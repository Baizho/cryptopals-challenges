from Crypto.Cipher import AES
import base64

def aes_ecb_decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

key = b"YELLOW SUBMARINE"
iv = b"\x00" * 16

plaintext = b""
prev = iv

data = b""
with open("10.txt", "r") as file:
    data = base64.b64decode(file.read())

for i in range(0, len(data), 16):
    block = data[i:i+16]

    decrypted = aes_ecb_decrypt(block, key)

    xored = bytes(a ^ b for a, b in zip(prev, decrypted))

    plaintext += xored
    prev = block

print(plaintext.decode())
