import secrets
from Crypto.Cipher import AES
import base64

KEY = secrets.token_bytes(16)

def aes_ctr(data: bytes, key: bytes, nonce: int = 0):
    cipher = AES.new(key, AES.MODE_ECB)

    result = b""
    counter = 0

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        counter_block = nonce.to_bytes(8, "little") + counter.to_bytes(8, "little")

        keystream = cipher.encrypt(counter_block)

        result += bytes(a ^ b for a, b in zip(block, keystream))
        counter += 1

    return result

ciphers = []
with open("20.txt", "r") as file:
    for line in file:
        plaintext = base64.b64decode(line.strip())
        ciphertext = aes_ctr(plaintext, KEY)
        ciphers.append(ciphertext)
        print(ciphertext)
        # since nonce wasn't randomized, same characters have same encryptions since their keystream is same for that byte

def score(text: bytes):
    score = 0
    for c in text:
        if 65 <= c <= 90 or 97 <= c <= 122:   # letters
            score += 2
        elif c == 32:                         # space
            score += 3
        elif 32 <= c <= 126:                  # printable
            score += 1
        else:                                 # garbage
            score -= 5
    return score

# we can breakthis
max_len = max(len(c) for c in ciphers)
columns = []

for i in range(max_len):
    column = []
    for c in ciphers:
        if i < len(c):
            column.append(c[i])
    columns.append(column)

keystream = []

for column in columns:

    best_score = 0
    best_key = 0

    for k in range(256):
        decrypted = bytes(c ^ k for c in column)
        s = score(decrypted)

        if s > best_score:
            best_score = s
            best_key = k

    keystream.append(best_key)

for c in ciphers:
    plaintext = bytes(c[i] ^ keystream[i] for i in range(len(c)))
    print(plaintext)
