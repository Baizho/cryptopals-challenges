import itertools

def xor_bytes (data: bytes, key: bytes):
	return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

def score (text: bytes):
	common = b"ETAOIN SHRDLUetaoinshrdlu"
	return sum(c in common for c in text)

def find_encryption (data: bytes):
    best_score = 0
    best_key = "None"
    best_plaintext = b""

    for key in range(0, 256):
        decrypted = xor_bytes(data, bytes([key]))
        s = score(decrypted)

        if s > best_score:
            best_score = s
            best_key = key
            best_plaintext = decrypted

    return best_score, best_key, best_plaintext;

best_score = 0
best_key = "None"
best_plaintext = b""

with open("4.txt", "r") as file:
    for line in file:
        cipher = line.strip()
        raw_bytes_cipher= bytes.fromhex(cipher)

        s, key, plaintext = find_encryption(raw_bytes_cipher)

        if s > best_score:
            best_score = s
            best_key = key
            best_plaintext = plaintext

print(best_key, best_plaintext)


