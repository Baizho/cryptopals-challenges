from Crypto.Cipher import AES
import secrets
import base64

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

def cbc_decrypt(data: bytes, key: bytes, iv: bytes):
    plaintext = b""
    prev = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        decrypted = aes_ecb_decrypt(block, key)

        xored = bytes(a ^ b for a, b in zip(prev, decrypted))

        plaintext += xored
        prev = block

    return plaintext


random_strings = []
with open("RANDOM_STRINGS.txt", "r") as file:
    for line in file:
        random_strings.append(line.strip())

def func1():
    random_string = random_strings[secrets.randbelow(10)].encode()

    padded = pkcs7_pad(random_string, 16)
    cipher = cbc_encrypt(padded, KEY, IV)

    return cipher

def valid_pkcs7(data: bytes, blocksize: int = 16):
    pad = data[-1]
    if pad == 0 or pad > blocksize:
        return False
    if data[-pad:] != bytes([pad]) * pad:
        return False
    return True

def func2(cipher: bytes):
    plaintext = cbc_decrypt(cipher, KEY, IV)
    return valid_pkcs7(plaintext)

cipher = IV + func1()
blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]

print(len(blocks))
print(blocks[-2])
print(blocks[-1])

# C1 = bytearray(blocks[-2])
# C2 = blocks[-1]
#
# guessed = b""
# for guess in range(0, 256):
#     modified = C1.copy()
#     test_cipher = bytes(modified) + C2
#     modified[15] ^= guess
#
#
#     if func2(test_cipher):
#         guessed = guess
#         print("valid padding guess:", guess)
# now we know guessed ^ C1_lastbit ^ C2_lastbit = 0x01, so C2_lastbit = 0x01 ^ guessed ^ C1_lastbit lol
# since we know C2_lastbit, C2_lastbit = P2_lastbit ^ C1_lastbit, P2_lastbit = C1_lastbit ^ C2_lastbit, P2_lastbit = C1_lastbit ^ 0x01 ^ guessed ^ C1_lastbit -> = 0x01 ^ guessed
# using that, we write the algorithm

plaintext = []
for i in range(1, len(blocks)):
    cur_block = blocks[-i]
    prev_block = bytearray(blocks[-i - 1])

    for pad in range(1, 17):
        for j in range(1, pad):
            prev_block[16 - j] ^= pad
        for guess in range(256):
            modified = prev_block.copy()

            modified[16 - pad] ^= guess

            test_cipher = bytes(modified) + cur_block
            if func2(test_cipher):
                if pad == 1:
                    verify = bytearray(modified)
                    verify[14] ^= 1
                    if not func2(bytes(verify) + cur_block):
                        continue
                prev_block[16 - pad] ^= guess ^ pad # make it 0-bit always
                plaintext_byte = guess ^ pad
                plaintext.append(plaintext_byte)
                break

        for j in range(1, pad):
            prev_block[16 - j] ^= pad

plaintext.reverse()
output = bytes(plaintext).decode()
plain = base64.b64decode(output)
print(plain)

