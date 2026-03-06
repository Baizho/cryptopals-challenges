def encrypt(data: bytes, key: bytes):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

repeatingkey = b"ICE"

lines = []
while True:
    line = input()
    if not line:
        break
    lines.append(line)

full_text = '\n'.join(lines)

encrypted = encrypt(full_text.encode(), repeatingkey)
print(encrypted.hex())
