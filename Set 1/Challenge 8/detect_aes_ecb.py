# from Crypto.Cipher import AES
#
# def aes_ecb_decrypt(data: bytes, key):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.decrypt(data)

with open("8.txt", "r") as file:
    for line in file:
        data = bytes.fromhex(line.strip())

        seen = set()
        found = False

        for i in range(0, len(data), 16):
            block = data[i:i+16]

            if block in seen:
                found = True
                break

            seen.add(block)

        if found:
            print(line.strip())
            break
