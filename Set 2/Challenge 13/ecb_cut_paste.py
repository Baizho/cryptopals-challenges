import json
import secrets
from Crypto.Cipher import AES

KEY = secrets.token_bytes(16)

def parse(link: str):
    dict = {}
    for info in link.split("&"):
        name, data = info.split("=")
        dict[name] = data;

        if name == "role":
            if data == "admin":
                print("ADMIN PERMISSIONS GIVEN")
            else:
                print("USER PERMISSIONS GIVEN")
    return json.dumps(dict, indent=4)

def profile_for(email: str):
    if "&" in email or "=" in email:
        return ValueError("email mustn't have encoding metacharacters such as & and =")
    dict = {
        "email": email,
        "uid": 1232,
        "role": 'user'
    }
    link = ""
    for key, value in dict.items():
        if link:
            link += "&"
        link += str(key) + "=" + str(value)
    return link.encode()

def pkcs7_pad(data: bytes, blocksize: int):
    pad = blocksize - (len(data) % blocksize)
    return data + bytes([pad]) * pad

def encrypt(data: bytes):
    data = pkcs7_pad(data, 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(data)

def pkcs7_unpad(data: bytes):
    pad = data[-1]
    return data[:-pad]

def decrypt(data: bytes):
    cipher = AES.new(KEY, AES.MODE_ECB)
    plaintext = cipher.decrypt(data)
    return pkcs7_unpad(plaintext)

cipher1 = encrypt(profile_for("AAAAAAAAAA" + "admin" + "\x0b"*11))
cipher2 = encrypt(profile_for("f@gmail.com"))
admin_block = cipher1[16:32]
cipher2 = cipher2[:32] + admin_block

link = decrypt(cipher2).decode()
print(link)
print(parse(link))

