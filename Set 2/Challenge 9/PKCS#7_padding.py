def pkcs7_pad(data: bytes, block_size: int):
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad

print(pkcs7_pad(b"YELLOW SUBMARINE", 20))
