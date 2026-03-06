

def xor_bytes (a: bytes, b: bytes):
	if len(a) != len(b):
		return ValueError("bytes objects must be of same length")
	return bytes(byte_a ^ byte_b for byte_a, byte_b in zip(a, b))
s1 = input()
s2 = input()

fixed_xor = xor_bytes(bytes.fromhex(s1), bytes.fromhex(s2))
print(fixed_xor.hex())
