#!/usr/bin/env python3
import sys, os
def xor_decrypt(data: bytes, key: str) -> bytes:
    kb = key.encode()
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ kb[i % len(kb)])
    return bytes(out)

enc_path = os.path.join(os.path.dirname(__file__), "secret_flag.enc")
if not os.path.exists(enc_path):
    print("secret_flag.enc not found. Are you in the right folder?")
    sys.exit(1)

pwd = input("Enter password to unlock: ").strip()
with open(enc_path,"rb") as f:
    enc = f.read()
try:
    dec = xor_decrypt(enc, pwd)
    text = dec.decode("utf-8")
except:
    print("Wrong password or file corrupted.")
    sys.exit(1)

print("--- Decrypted file content ---")
for ch in text:
    if ord(ch) == 0x200b:
        print("[ZWSP]", end="")
    elif ord(ch) == 0x200c:
        print("[ZWNJ]", end="")
    else:
        print(ch, end="")
print("\n--- end ---")
print("Hint: Decode zero-width characters to reveal the flag.")
