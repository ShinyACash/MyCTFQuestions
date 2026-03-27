import base64

def obscure_flag(plaintext, shift=13, xor_key=0x69):
    rotated = ""
    for char in plaintext:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            rotated += chr((ord(char) - start + shift) % 26 + start)
        elif char.isdigit():
            rotated += chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
        else:
            rotated += char
    xored_bytes = bytes([ord(c) ^ xor_key for c in rotated])
    obscured = base64.b64encode(xored_bytes).decode('utf-8')
    
    return obscured


plaintext_flag = "HTB{c4r5_c4n_c0d3_t00_dc1aff2bf63f0a9fe7144d8ad5639ecd}" 
ciphertext = obscure_flag(plaintext_flag)

print(f"{plaintext_flag}")
print(f"{ciphertext}")
