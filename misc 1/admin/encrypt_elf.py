#!/usr/bin/env python3
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

aes_key = sha256(str(Gx).encode()).digest()
print(f"AES key : {aes_key.hex()}")

with open('professor.elf', 'rb') as f:
    plaintext = f.read()
print(f"ELF size: {len(plaintext)} bytes")

pad_len = 16 - (len(plaintext) % 16)
plaintext_padded = plaintext + bytes([pad_len] * pad_len)

iv = os.urandom(16)

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                backend=default_backend())
enc = cipher.encryptor()
ciphertext = enc.update(plaintext_padded) + enc.finalize()

output = iv + ciphertext
with open('professor.elf.enc', 'wb') as f:
    f.write(output)

print(f"IV      : {iv.hex()}")
print(f"Written : professor.elf.enc ({len(output)} bytes)")

cipher2 = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
dec = cipher2.decryptor()
recovered_padded = dec.update(ciphertext) + dec.finalize()
pad = recovered_padded[-1]
recovered = recovered_padded[:-pad]
assert recovered == plaintext, "Decryption mismatch!"
print("Round-trip verified successfully")