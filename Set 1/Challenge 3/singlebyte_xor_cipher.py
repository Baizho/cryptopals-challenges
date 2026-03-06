import itertools

def xor_bytes (data: bytes, key: bytes):
	return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

def score(text: bytes):
	common = b"ETAOIN SHRDLUetaoinshrdlu"
	return sum(c in common for c in text)

cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
raw_bytes_cipher= bytes.fromhex(cipher)

best_score = 0
best_key = "None"
best_plaintext = b""

for key in range(0, 256):
	decrypted = xor_bytes(raw_bytes_cipher, bytes([key]))
	s = score(decrypted)

	if s > best_score:
		best_score = s
		best_key = key
		best_plaintext = decrypted

print(best_key, best_plaintext)
