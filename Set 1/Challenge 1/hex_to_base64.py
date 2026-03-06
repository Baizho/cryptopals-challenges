import base64

hex_string = input()
raw_bytes = bytes.fromhex(hex_string)
base64_string = base64.b64encode(raw_bytes)

print(base64_string)
