# Solution

Player is provided with `try_me.png` and `professor.elf.enc`.
NOTE: This challenge is a mix of multiple domains with multiple layers and is made as a joke (idea credit to vitthal bhaiya lmso).

## OSINT

`try_me.png` is a very small snap of the youtube channel "rio_cooked" (which also has been mentioned in one of the cryptography challenges.)
This part of the challenge will be harder for the players that weren't rickrolled by the challenge `The Brainrot Heist`.
<br />
The channel description contains a drive link that points towards an image named `bobby.png`.
Link: `https://drive.google.com/file/d/1GqbI1-WHuvkp6l9aBvDLvAHsYo4LOX9s/view?usp=sharing`

## Steganography/Forensics

Using any steganography tool the player needs to access the blue channels to reveal a QR code hidden in the image that points towards a github repository @`https://github.com/d3adpr0fes0r/bank-heist-top-secret`
This repository contains the following useful files: -
- `keygen.py`
- `decrypt.py`

## Cryptography

`keygen.py` contains the logic that generates an AES key from an ECC public key to generate a key that can decrypt the `professor.elf.enc` file.

### What you have at this point
 
The player has collected three files:
 
- `keygen.py` -  El Profesor's key generation script
- `decrypt.py` - an incomplete decryption script (needed later)
- `professor.elf.enc` - an encrypted binary
 
The goal of this layer is to recover `professor.elf` from `professor.elf.enc`.
 
---
 
#### Step 1 - Understand the encrypted file
 
Start by examining `professor.elf.enc`:
 
```bash
file professor.elf.enc
# professor.elf.enc: data
 
wc -c professor.elf.enc
# 710704
 
python3 -c "print(710704 % 16)"
# 0
```
 
The file is pure binary with no recognizable signature, and its size is an exact multiple
of 16. This immediately tells you it's a block cipher, almost certainly AES (pretty evident from `keygen.py` now). The fact that the size is a multiple of 16 confirms the data
has been padded to the block boundary.
 
---
 
#### Step 2 - Read keygen.py carefully
 
Open `keygen.py`. It generates an AES key using elliptic curve cryptography on secp256k1:
 
```python
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
 
def point_add(P1, P2):
    ...
    if x1 == x2:
        return None      # <-- look at ts
    ...
 
def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)   # <-- and ts
        k >>= 1
    return result
 
private_key = int.from_bytes(os.urandom(32), 'big')
G = (Gx, Gy)
public_key = scalar_mult(private_key, G)
 
aes_key = sha256(str(public_key[0]).encode()).digest()
```
 
At first glance this looks like a standard ECC key derivation. But read `point_add()` again.
 
---
 
#### Step 3 - Spot the bug
 
In a correct ECC implementation, when `x1 == x2` there are two cases:
 
| Condition | Meaning | Correct action |
|---|---|---|
| `x1 == x2` and `y1 == y2` | Same point (P == Q) | Point doubling formula |
| `x1 == x2` and `y1 != y2` | Additive inverse (P == -Q) | Return point at infinity |
 
This implementation returns `None` (point at infinity) for **both** cases, it never
does point doubling at all.
 
Now trace what this does to `scalar_mult`:
 
```
k = private_key  (some random 256-bit number)
addend = G       (the generator point)
 
Iteration 1:
  if k & 1:  result = point_add(None, G) = G   (if LSB is 1)
  addend = point_add(G, G)                      = None  (BUG: G+G hits x1==x2)
  k >>= 1
 
Iteration 2:
  if k & 1:  result = point_add(result, None) = result  (None is neutral)
  addend = point_add(None, None)               = None
  k >>= 1
 
All subsequent iterations: addend stays None, contributes nothing.
```
 
The conclusion: **only the LSB of the private key matters**. Since `private_key` is a
random 256-bit number, its LSB is 1 roughly half the time and 0 the other half.
 
In practice El Profesor's private key has LSB = 1 (you can verify by running `keygen.py`
and observing the public key equals `Gx`), so:
 
```
public_key = G   always
public_key[0] = Gx   always
```
 
This means the AES key is **constant** regardless of the random private key:
 
```python
aes_key = sha256(str(Gx).encode()).digest()
# = 1c5f65ce01e30de4314899e861bdafef288d8346b540236601a4e45a49738b79
```
 
Run `keygen.py` ten time, you'll get the same AES key every time.
 
---
 
#### Step 4 - Identify the file format
 
Now you have the key. But how is the file encrypted?
 
AES requires an IV (initialization vector) for CBC mode, a random 16-byte value that
ensures identical plaintexts encrypt to different ciphertexts. The universal convention
for AES-CBC encrypted files is:
 
```
[ IV (16 bytes) ][ ciphertext (remainder) ]
```
 
This is how OpenSSL, Python's cryptography library, and virtually every CTF tool formats
AES-CBC output. Verify the math:
 
```
Total file size : 710704 bytes
IV              :     16 bytes
Ciphertext      : 710688 bytes  (710704 - 16)
710688 % 16     :      0        valid ciphertext length
```
 
So the first 16 bytes are the IV, everything after is the ciphertext.
 
---
 
#### Step 5 - Decrypt
 
Write the decryption script:
 
```python
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
 
# Step 1: derive the constant AES key
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
aes_key = sha256(str(Gx).encode()).digest()
print(f"AES key: {aes_key.hex()}")
 
# Step 2: read the encrypted file
with open('professor.elf.enc', 'rb') as f:
    data = f.read()
 
# Step 3: split IV and ciphertext
iv         = data[:16]
ciphertext = data[16:]
print(f"IV: {iv.hex()}")
 
# Step 4: decrypt
cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CBC(iv),
    backend=default_backend()
)
dec = cipher.decryptor()
padded = dec.update(ciphertext) + dec.finalize()
 
# Step 5: strip PKCS7 padding
# the last byte tells you how many padding bytes were added
pad_len = padded[-1]
elf = padded[:-pad_len]
 
# Step 6: verify it's a real ELF
print(f"Magic bytes: {elf[:4].hex()}")  # should be 7f454c46 = \x7fELF
print(f"ELF size: {len(elf)} bytes")
 
# Step 7: write it out
with open('professor.elf', 'wb') as f:
    f.write(elf)
 
print("Saved: professor.elf")
```
 
Run it:
 
```bash
python3 decrypt_elf.py
# AES key: 1c5f65ce01e30de4314899e861bdafef288d8346b540236601a4e45a49738b79
# IV: 8c03b882a15f8d33754378f61520d974
# Magic bytes: 7f454c46
# ELF size: 710672 bytes
# Saved: professor.elf
```
 
The magic bytes `7f454c46` confirm you have a valid ELF binary.
 
---
 
#### Step 6 - Make it executable and run it
 
```bash
chmod +x professor.elf
./professor.elf
# Enter passphrase: test
# Output: 3f9a1c...
```
 
You now have the binary. Move on to the Rev layer — load it into Ghidra and start
reversing the 3-stage bit transformation.
 
---

## Reverse Engineering

The goal is to reverse the binary, understand the transformation it applies to input,
and use that knowledge to implement the missing function in `decrypt.py`.
 
---
 #### step 1 - run it first before doing anything else
 
seriously, always run the binary before touching ghidra. you learn more in 10 seconds than 10 minutes of staring at decompiled code.
 
```bash
chmod +x professor.elf
./professor.elf
Enter passphrase: hello
Output: 9866cc...
```
 
things to notice:
 
- output length matches input length. 5 chars in, 5 bytes out. this is NOT a hash, its a transformation
- now try this:
 
```bash
./professor.elf
Enter passphrase: aaaa
Output: 98989896
 
./professor.elf
Enter passphrase: aaaaaa
Output: 989898989868
```
 
the first three bytes of `aaaa` and `aaaaaa` are identical (`989898`) but byte 4 onwards differs. same character, different position, different output. the transform is position-dependent. keep that in mind.
 
---
 
#### step 2 - load into ghidra
 
open ghidra, new project, import `professor.elf`, accept all defaults, click yes to analyze.
 
everything will be named `FUN_xxxxxxxx` because the binary is stripped. that is completely normal, do not panic.
 
---
 
#### step 3 - find main()
 
open the `entry` function. it looks like this:
 
```c
void processEntry entry(undefined8 param_1, undefined8 param_2) {
    FUN_00404640(FUN_00401ccb, param_2, ...);
    do { } while(true);
}
```
 
`entry` is `_start`. it calls `__libc_start_main` (the big function) and passes `main` as the first argument. so `FUN_00401ccb` is main. double click it.
 
the infinite loop is just ghidra misreading the `hlt` instruction. ignore it.
 
---
 
#### step 4 - read main() and find what matters
 
main is long and ugly but you only need three things out of it.
 
**the transform call:**
 
somewhere in the middle you will see a function called with three arguments that look like input buffer, length, output buffer:
 
```c
FUN_00401a3e(&local_438, lVar5, local_338);
```
 
that is `transform(input, len, output)`. navigate there next.
 
**the hardcoded blob:**
 
near the bottom you will see a strcmp against a long hex string:
 
```c
thunk_FUN_00413120(local_238,
    "a824ed1218c832195fe9da9d23649d9935eb5fcac84de0d718c9669981ecfa9c");
```
 
that blob is the flag run through the transform. this is what you will feed into decrypt.py once you have implemented all three undo functions. write it down.
 
---
 
#### step 5 - navigate to the transform
 
press `G` in ghidra and type `00401a3e` to jump there. this is where the actual challenge is.
 
the function will look messy. there is intentional junk code in there to slow you down. here is how to spot it and skip it.
 
**junk branches look like this:**
 
```c
if (FUN_00401b20(buf) == 0xDEAD) {
    for (i = 0; i < len; i++) tmp[i] ^= 0xFF;
}
```
 
the condition `== 0xDEAD` can never be true. the function before it always returns something else. any code inside a block like this is dead, skip it completely. if you include this in your reimplementation your output will be wrong.
 
**the real logic is three loops.** ignore everything else and look for loops that operate on a temporary buffer sequentially.
 
---
 
#### step 6 - reverse engineer the three stages
 
here is what the three loops actually do. figure them out yourself from the ghidra output, but use this to verify your findings.
 
**stage 1 - bit reversal**
 
every byte has its 8 bits flipped in order. first bit becomes last, last becomes first.
 
```
0b10110010  becomes  0b01001101
```
 
in ghidra this looks like a loop running 8 times, shifting bits right and building a new byte from LSB to MSB.
 
**stage 2 - rotation**
 
every byte is rotated LEFT by `(index % 5) + 1` positions. the rotation amount changes depending on where the byte is in the input. this is why position 0,1,2,3,4 give different outputs even for the same input byte.
 
rotation amounts by position:
```
index 0  ->  rotate left 1
index 1  ->  rotate left 2
index 2  ->  rotate left 3
index 3  ->  rotate left 4
index 4  ->  rotate left 5
index 5  ->  rotate left 1  (wraps back)
index 6  ->  rotate left 2
...
```
 
**stage 3 - adjacent byte swap**
 
pairs of bytes are swapped. first two bytes swap, next two swap, and so on.
 
```
[b0, b1, b2, b3, b4, b5]  becomes  [b1, b0, b3, b2, b5, b4]
```
 
if the input has an odd length, the last byte is left alone.
 
---
 
#### step 7 - verify before writing decrypt.py
 
before touching decrypt.py, verify you understood the transform correctly. reimplement it in python and check that it matches the binary output.
 
```python
def reverse_bits(b):
    r = 0
    for _ in range(8):
        r = (r << 1) | (b & 1)
        b >>= 1
    return r & 0xFF
 
def rotate_left(b, n):
    n = n % 8
    return ((b << n) | (b >> (8 - n))) & 0xFF
 
def transform(data):
    tmp = bytearray()
    for byte in data:
        tmp.append(reverse_bits(byte))
    for i in range(len(tmp)):
        r = (i % 5) + 1
        tmp[i] = rotate_left(tmp[i], r)
    for i in range(0, len(tmp) - 1, 2):
        tmp[i], tmp[i+1] = tmp[i+1], tmp[i]
    return tmp.hex()
 
# test it
print(transform(b"hello"))
```
 
run the binary with `hello` and compare. if they match, you are good to go. if they dont, go back to ghidra and figure out what you got wrong.
 
---
 
#### step 8 - implement all three undo functions in decrypt.py
 
open `decrypt.py`. all three undo functions are stubbed out with `pass`. your job is to implement each one.
 
the key thing to understand is that you apply the undos in **reverse order**. the transform applied stage 1 then 2 then 3, so to undo it you go stage 3 then 2 then 1.
 
 
figure out the inverse of each stage:
 
- `undo_stage1` - hint: reversing bits is its own inverse. applying it twice gets you back to the original.
- `undo_stage2` - hint: the binary rotated LEFT, so you need to rotate RIGHT by the same amount. right rotation formula: `((b >> r) | (b << (8 - r))) & 0xFF`
- `undo_stage3` - hint: swapping pairs is its own inverse. swap again and you are back.
 
implement all three, then run:
 
```bash
python3 decrypt.py
Enter hex blob: a824ed1218c832195fe9da9d23649d9935eb5fcac84de0d718c9669981ecfa9c
```
 
if you implemented everything correctly you get the flag:
```
Decrypted: HTB{b0bby_sm1L3s_e5_eL_pr0f3s0r}
```

im sure no one's gonna solve ts but this is built for the love of the game.