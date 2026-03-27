#!/usr/bin/env python3
"""
El Profesor's key derivation script.
Generates an AES key from an ECC public key for encrypting sensitive data.
"""
from hashlib import sha256
import os

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def modinv(a, m):
    return pow(a, -1, m)

def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2:
        # this is an intentional bug here, the players will solve ts. the if statement should be y1 == y2
        return None

    lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3  = (lam * lam - x1 - x2) % P
    y3  = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)  
        k >>= 1
    return result

private_key = int.from_bytes(os.urandom(32), 'big')

G = (Gx, Gy)
public_key = scalar_mult(private_key, G)

aes_key = sha256(str(public_key[0]).encode()).digest()

print(f"[keygen] Public key x: {public_key[0]}")
print(f"[keygen] AES key (hex): {aes_key.hex()}")
