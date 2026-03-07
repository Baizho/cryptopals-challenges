import secrets
from Crypto.Cipher import AES
import base64

KEY = b"YELLOW SUBMARINE"

def aes_ctr(data: bytes, key: bytes, nonce: int):
    cipher = AES.new(key, AES.MODE_ECB)

    result = b""
    counter = 0

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        counter_block = nonce.to_bytes(8, 'little') + counter.to_bytes(8, 'little')

        keystream = cipher.encrypt(counter_block)

        result += bytes(a ^ b for a, b in zip(block, keystream))

        counter += 1

    return result

input_string = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
ciphertext = base64.b64decode(input_string)

print(aes_ctr(ciphertext, KEY, 0))
