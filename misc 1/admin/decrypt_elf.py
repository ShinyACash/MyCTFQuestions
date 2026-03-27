from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Step 1 — derive the key (they figured this out from reading keygen.py)
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
aes_key = sha256(str(Gx).encode()).digest()

with open('professor.elf.enc', 'rb') as f:
    data = f.read()

iv         = data[:16]
ciphertext = data[16:]

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                backend=default_backend())
dec = cipher.decryptor()
padded = dec.update(ciphertext) + dec.finalize()

pad = padded[-1]
elf = padded[:-pad]

with open('professor.elf', 'wb') as f:
    f.write(elf)

print(f"Decrypted: {len(elf)} bytes")