import base64

def dec(c): return "".join([chr((((b^0x69)-97-13)%26)+97) if 97<=b^0x69<=122 else chr((((b^0x69)-65-13)%26)+65) if 65<=b^0x69<=90 else chr((((b^0x69)-48-13)%10)+48) if 48<=b^0x69<=57 else chr(b^0x69) for b in base64.b64decode(c)])
ciphertext = "PC4mEhleDFE2GV4INhlaGF82DlpaNhgZXQcaGlwGGlBfGloHWxobWV1eXhhYBxhRUF9bGxkYFA=="
print(dec(ciphertext))