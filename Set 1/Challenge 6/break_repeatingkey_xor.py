import base64
import heapq
import itertools

def xor_bytes (data: bytes, key: bytes):
	return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

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

def find_encryption (data: bytes):
    best_score = 0
    best_key = 0
    best_plaintext = b""

    for key in range(0, 256):
        decrypted = xor_bytes(data, bytes([key]))
        s = score(decrypted)

        if s > best_score:
            best_score = s
            best_key = key
            best_plaintext = decrypted

    return best_score, best_key, best_plaintext;

def hamming_distance(A: bytes, B: bytes) -> int:
    return sum((byteA ^ byteB).bit_count() for byteA, byteB in zip(A, B))

cipher = ""
with open("6.txt", "r") as file:
    cipher = base64.b64decode(file.read())

#print(hamming_distance(b"this is a test", b"wokka wokka!!!")) // 37 should be output

keysize_variants = []

for KEYSIZE in range(2, 41):
    block1 = cipher[0:KEYSIZE]
    block2 = cipher[KEYSIZE:2*KEYSIZE]
    block3 = cipher[2*KEYSIZE:3*KEYSIZE]
    block4 = cipher[3*KEYSIZE:4*KEYSIZE]

    dist = (
        hamming_distance(block1, block2) +
        hamming_distance(block2, block3) +
        hamming_distance(block3, block4)
    ) / 3

    normalized_distance = dist / KEYSIZE

    heapq.heappush(keysize_variants, (normalized_distance, KEYSIZE))

print(heapq.nsmallest(3, keysize_variants))

for _, KEYSIZE in heapq.nsmallest(3, keysize_variants):
    blocks = [bytearray() for _ in range(KEYSIZE)]

    for idx, byte in enumerate(cipher):
        blocks[idx % KEYSIZE].append(byte)

    key_bytes = bytearray()
    for block in blocks:
        s, key, plaintext = find_encryption(bytes(block))
        key_bytes.append(key)

    key = bytes(key_bytes)
    plaintext = xor_bytes(cipher, key)
    print("KEY:", key)
    print(plaintext.decode(errors="ignore"))
