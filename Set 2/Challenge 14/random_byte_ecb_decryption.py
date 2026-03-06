import json
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

RANDOM_PREFIX = secrets.token_bytes(secrets.randbelow(100))

print("Length of random prefix: ", len(RANDOM_PREFIX))

def oracle(data: bytes):
    plaintext = RANDOM_PREFIX + data + SECRET_STRING
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

def decrypt_secret(blocksize: int):
    known = b""
    random_prefix_pad = 0
    random_prefix_len = 0

    for pad in range(0, 16):
        # random + pad + 32A
        prefix = b"A" * pad + b"A" * 32
        cipher = oracle(prefix)
        found = False
        for i in range(32, len(cipher), 16):
            # print(i, cipher[i-32:i-16])
            if cipher[i-32:i-16] == cipher[i-16:i]:
                random_prefix_pad = pad
                random_prefix_len = i - 32 - pad
                found = True
                break
        if found:
            break
    print("Decrypted random prefix length: ", random_prefix_len, random_prefix_pad)

    total_len = len(oracle(b""))
    for i in range(total_len):
        prefix_len = random_prefix_len + random_prefix_pad + blocksize - 1 - (len(known) % blocksize)
        prefix = b"A" * (prefix_len - random_prefix_len)

        block_index = (random_prefix_len + random_prefix_pad) // blocksize + len(known) // blocksize

        target = oracle(prefix)[block_index * blocksize : (block_index + 1) * blocksize]

        dict = {}

        for b in range(256):
            guess = prefix + known + bytes([b])
            block = oracle(guess)[block_index * blocksize : (block_index + 1) * blocksize]

            dict[block] = b

        if target in dict:
            known += bytes([dict[target]])
        else:
            break
    return known

blocksize = get_blocksize()
print("BlockSize: ", blocksize)
if check_ECB():
    print ("It's using ECB")
else:
    print ("Idk what it's using")

print(decrypt_secret(blocksize))
