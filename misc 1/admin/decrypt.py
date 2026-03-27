#!/usr/bin/env python3
"""
El Profesor's decryption script.

Usage: python3 decrypt.py

NOTE: undo_stages are incomplete — you need to implement them.

"""

def reverse_bits(b):
    """Reverse all 8 bits of a byte."""
    return int(f'{b:08b}'[::-1], 2)

def undo_stage1(data):
    """
    TODO: implement this function.
    """
    pass  # your implementation here

def undo_stage2(data):
    """
    TODO: implement this function.
    """
    pass  # your implementation here

def undo_stage3(data):
    """
    TODO: implement this function.
    """
    pass  # your implementation here

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
        print(f"Error: {e} — make sure all undo_stages are implemented correctly.")
