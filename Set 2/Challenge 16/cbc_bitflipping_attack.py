import secrets
from Crypto.Cipher import AES

KEY = secrets.token_bytes(16)
IV = secrets.token_bytes(16)

def pkcs7_pad(data: bytes, blocksize: int):
    pad = blocksize - (len(data) % blocksize)
    return data + bytes([pad]) * pad

def aes_ecb_encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_ecb_decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def cbc_encrypt(data: bytes, key: bytes, iv: bytes = secrets.token_bytes(16)):
    data = pkcs7_pad(data, 16)
    ciphertext = b""
    prev = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        xored = bytes(a ^ b for a, b in zip(prev, block))

        encrypted = aes_ecb_encrypt(xored, key)

        ciphertext += encrypted
        prev = encrypted

    return ciphertext

def cbc_decrypt(cipher: bytes, key: bytes, iv: bytes):
    plaintext = b""
    prev = iv

    for i in range(0, len(cipher), 16):
        block = cipher[i:i+16]

        decrypted = aes_ecb_decrypt(block, key)

        xored = bytes(a ^ b for a, b in zip(prev, decrypted))

        plaintext += xored
        prev = block

    return plaintext

def func1(user_input: str):
    sanitized_input = user_input.replace(';', '%3B').replace('=', '%3D')
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    combine = prefix + sanitized_input + suffix

    print(combine)

    cipher = cbc_encrypt(combine.encode(), KEY, IV)

    return cipher

def func2(cipher: bytes):
    plaintext = cbc_decrypt(cipher, KEY, IV)

    items = plaintext.split(b";")
    for item in items:
        if b'=' in item:
            k, v = item.split(b"=", 1)
            if k == b"admin" and v == b"true":
                print("ADMIN PERMISSIONS GIVEN")
                return True

    print("USER PERMISSIONS GIVEN")
    return False

inject = b";admin=true;" #  12 bytes
cipher = func1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

block1 = bytearray(cipher[16:32])
for i in range(len(inject)):
    block1[i] ^= (ord('A') ^ inject[i])

cipher = cipher[:16] + block1 + cipher[32:]

func2(cipher)

