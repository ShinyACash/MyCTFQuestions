#!/usr/bin/env python3

def reverse_bits(b):
    return int(f'{b:08b}'[::-1], 2)

def undo_stage1(data):
    return bytes([reverse_bits(b) for b in data])

def undo_stage2(data):
    result = []
    for i, b in enumerate(data):
        r = (i % 5) + 1
        result.append(((b >> r) | (b << (8 - r))) & 0xFF)
    return bytes(result)

def undo_stage3(data):
    result = bytearray(data)
    for i in range(0, len(result) - 1, 2):
        result[i], result[i + 1] = result[i + 1], result[i]
    return bytes(result)

def decrypt(blob: str) -> str:
    data = bytes.fromhex(blob)
    data = undo_stage3(data)
    data = undo_stage2(data)  
    data = undo_stage1(data)
    return data.decode()

if __name__ == "__main__":
    blob = input("Enter hex blob: ").strip()
    try:
        result = decrypt(blob)
        print(f"Decrypted: {result}")
    except Exception as e:
        print(f"Error: {e} — make sure undo_stage2() is implemented correctly.")
