import secrets
from Crypto.Cipher import AES
import base64

KEY = secrets.token_bytes(16)

def pkcs7_pad(data: bytes, blocksize: int):
    pad = blocksize - (len(data) % blocksize)
    return data + bytes([pad]) * pad

def aes_ecb_encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

with open("SECRET_STRING.txt", "r") as file:
    SECRET_STRING = base64.b64decode(file.read())

def oracle(data: bytes):
    plaintext = data + SECRET_STRING
    plaintext = pkcs7_pad(plaintext, 16)
    return aes_ecb_encrypt(plaintext, KEY)

def get_blocksize() -> int:
    prev = len(oracle(b""))

    for i in range(1, 100):
        data = b"A" * i
        new = len(oracle(data))
        print(i, new)

        if new > prev:
            return new - prev

def check_ECB() -> bool:
    cipher = oracle(b"A" * 64)
    seen = set()

    for i in range(0, len(cipher), 16):
        block = cipher[i:i+16]
        if block in seen:
            return True
        seen.add(block)
    return False


def decrypt_secret():
    blocksize = get_blocksize()
    known = b""

    total_len = len(oracle(b""))

    for i in range(total_len):

        prefix_len = blocksize - 1 - (len(known) % blocksize)
        prefix = b"A" * prefix_len

        block_index = len(known) // blocksize

        target = oracle(prefix)[block_index*blocksize:(block_index+1)*blocksize]

        dictionary = {}

        for b in range(256):
            guess = prefix + known + bytes([b])
            out = oracle(guess)

            block = out[block_index*blocksize:(block_index+1)*blocksize]

            dictionary[block] = b

        if target in dictionary:
            known += bytes([dictionary[target]])
        else:
            break

    return known

if check_ECB():
    print ("It's using ECB")
else:
    print ("Idk what it's using")
print(decrypt_secret())
