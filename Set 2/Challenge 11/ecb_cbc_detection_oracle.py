import secrets
from Crypto.Cipher import AES
import base64

def pkcs7_pad(data: bytes, blocksize: int):
    pad = blocksize - (len(data) % blocksize)
    return data + bytes([pad]) * pad

def aes_ecb_encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def cbc_encrypt(data: bytes, key: bytes, iv: bytes):
    ciphertext = b""
    prev = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        xored = bytes(a ^ b for a, b in zip(prev, block))

        encrypted = aes_ecb_encrypt(xored, key)

        ciphertext += encrypted
        prev = encrypted

    return ciphertext

def get_aes_key():
    return secrets.token_bytes(16)

def encrypt_random(data: bytes):
    prefix = secrets.randbelow(6) + 5
    suffix = secrets.randbelow(6) + 5
    data = secrets.token_bytes(prefix) + data + secrets.token_bytes(suffix)
    data = pkcs7_pad(data, 16)

    if secrets.randbelow(2) == 0:
        print ("ECB")
        return aes_ecb_encrypt(data, get_aes_key())
    else:
        print ("CBC")
        return cbc_encrypt(data, get_aes_key(), secrets.token_bytes(16))

def detect_ecb(data: bytes) -> bool:
    seen = set()

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        if block in seen:
            return True
        seen.add(block)

    return False

for _ in range(20):
    ciphertext = encrypt_random(b"A" * 64)

    if detect_ecb(ciphertext):
        print("Detected ECB")
    else:
        print("Detected CBC")

