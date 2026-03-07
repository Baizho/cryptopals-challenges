plaintext = input()

def pkcs7_unpad(data: bytes, blocksize: int = 16):
    pad = data[-1]

    if pad == 0 or pad > blocksize:
        raise ValueError("Invalid padding")

    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")

    return data[:-pad]

print(pkcs7_unpad(plaintext))
