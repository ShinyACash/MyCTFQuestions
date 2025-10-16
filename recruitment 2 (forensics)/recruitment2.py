import os
import base64
import piexif
from PIL import Image, PngImagePlugin
import textwrap

# ==============================
# CONFIG
# ==============================
OUTPUT_DIR = "challenge_output"  
PASSWORD = "cats_ar3_cut3"           
FLAG = "HTB{d4ng_br0_r3aLLy_f0unD_mY_fL4g}"  
AUTHOR_NAME = "Garfield"          
RED_HERRING = "Ym9vaG9vIHRoaXMgYWludCB0aGUgcGFzc3dvcmQgeW91IGFyZSBsb29raW5nIGZvcg=="
HINT = "Breadcrumbs are tasty too, just like the metadata of these files"

# ==============================
# HELPER FUNCTIONS
# ==============================
def zw_encode(s: str) -> str:
    """Encode string into zero-width characters."""
    bits = "".join(f"{ord(c):08b}" for c in s)
    mapping = {"1": "\u200b", "0": "\u200c"}
    return "".join(mapping[b] for b in bits)

def xor_encrypt(data: bytes, key: str) -> bytes:
    """Very simple XOR encryption (easy diff)."""
    kb = key.encode()
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ kb[i % len(kb)])
    return bytes(out)

# ==============================
# 1) FOLDER STRUCTURE
# ==============================
folders = [
    "home/garfield",
    "home/garfield/images",
    "home/garfield/projects/crypto_tool",
    "home/garfield/projects/unfinished_story",
    "home/garfield/random"
]

# Remove old folder if exists
if os.path.exists(OUTPUT_DIR):
    import shutil
    shutil.rmtree(OUTPUT_DIR)

# Make folders
for folder in folders:
    os.makedirs(os.path.join(OUTPUT_DIR, folder), exist_ok=True)

# ==============================
# 2) STORY FILES
# ==============================
notes = f"""
Log entry - 2024-11-02
The research is almost done. I'm paranoid about leaving leftovers.
If anyone ever gets my disk, they'll need to follow the breadcrumbs.
-- {AUTHOR_NAME}
""".strip()

todo = """
- finish chapter 2 of the story
- clean up temp keys
- hide the final note where only those who read through will find it
""".strip()

chapter1 = f"""
Chapter 1: The city lights were weak, and {AUTHOR_NAME} kept whispering to the screen.
He scribbled something that looked like nonsense: '{RED_HERRING}' but with weird spacing.
""".strip()

chapter2 = f"""
Chapter 2: The wizard cat left a clue in an old poster. Look deeper - not every picture is just a picture.
Remember: {HINT}
""".strip()

with open(f"{OUTPUT_DIR}/home/garfield/notes.txt", "w") as f:
    f.write(notes)

with open(f"{OUTPUT_DIR}/home/garfield/todo.txt", "w") as f:
    f.write(todo)

with open(f"{OUTPUT_DIR}/home/garfield/projects/unfinished_story/chapter1.txt", "w") as f:
    f.write(chapter1)

with open(f"{OUTPUT_DIR}/home/garfield/projects/unfinished_story/chapter2.txt", "w") as f:
    f.write(chapter2)

# ==============================
# 3) RED HERRING PASSWORD FILE
# ==============================
encoded_hint = "ZG8geW91IHdhbm5hIGJlIHRoZSBuZXcgcmVjcnVpdD8="
with open(f"{OUTPUT_DIR}/home/garfield/projects/crypto_tool/passwords.txt", "w") as f:
    f.write(f"old_passwords:\n- ilovecats\n- cAr_g0_bRRRR\n- i5th1Swh4ty0uar3l00k1ngf0r\n\nhalf-remembered: {encoded_hint}\n")

# ==============================
# 4) IMAGE WITH PASSWORD IN METADATA
# ==============================

CUSTOM_IMAGE_PATH = "profile.jpg"
DEST_IMAGE_PATH = f"{OUTPUT_DIR}/home/garfield/images/profile.jpg"

shutil.copy(CUSTOM_IMAGE_PATH, DEST_IMAGE_PATH)
img = Image.open(DEST_IMAGE_PATH)

exif_dict = {"0th": {piexif.ImageIFD.ImageDescription: PASSWORD.encode("utf-8")}}
exif_bytes = piexif.dump(exif_dict)

img.save(DEST_IMAGE_PATH, exif=exif_bytes)

# ==============================
# 5) RANDOM FILES
# ==============================
with open(f"{OUTPUT_DIR}/home/garfield/random/joke.txt", "w") as f:
    f.write("this file has a password hidden ;)")

# ==============================
# 6) FLAG ENCRYPTION
# ==============================
embedded_text = "Thanks for finding my note. You must be curious.\n\n- " + AUTHOR_NAME + "\n"
embedded_text += zw_encode(FLAG) 

encrypted_flag = xor_encrypt(embedded_text.encode(), PASSWORD)

with open(f"{OUTPUT_DIR}/home/garfield/secret_flag.enc", "wb") as f:
    f.write(encrypted_flag)

# ==============================
# 7) UNLOCK SCRIPT
# ==============================
unlock_script = r'''#!/usr/bin/env python3
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
'''

with open(f"{OUTPUT_DIR}/home/garfield/unlock.py", "w") as f:
    f.write(unlock_script)

os.chmod(f"{OUTPUT_DIR}/home/garfield/unlock.py", 0o755)

print(f"Challenge folder created in: {OUTPUT_DIR}")
