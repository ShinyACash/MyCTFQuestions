# Solution

1. Initial Analysis
Opening the PCAP in Wireshark, we see two distinct types of traffic:

TCP Traffic (Port 8080): A single packet containing a Base64 string:
- `flag={PC4mEhleDFE2GV4INhlaGF82DlpaNhgZXQcaGlwGGlBfGloHWxobWV1eXhhYBxhRUF9bGxkYFA==}`. Decoding this directly results in gibberish, suggesting a second layer of encryption.

ICMP Traffic: Thousands of Echo Requests. Many have random IDs (0xDEAD, 0xBEEF), but one stream uses ID 0x1337.

2. Decoding the ICMP Tunnel
The ICMP payloads for ID 0x1337 are consistently 8 bytes long. This is a classic signature of USB HID (Human Interface Device) Reports.

The Challenges:
- The Shuffle: The packets are out of order. We must sort them by the ICMP Sequence Number.

- The State: The attacker made typos. We see HID code 0x2a (Backspace) frequently. We need a LIFO stack to reconstruct the final text.

- The Modifiers: Symbols like (, %, and <= are sent using the Shift Modifier (the first byte of the HID report).

3. Reconstruction Script
Using Python and scapy, we filter for 0x1337, sort by seq, and map the HID codes to characters.
(see solve.py for a sample solve script)
The reconstructed script reveals a Python one-liner that performs a ROT13 shift followed by an XOR with 0x69 towards the end of the other random functions.

The Logic:
`def _0xb0(c): return "".join([chr((((b^0x69)-97-13)%26)+97) if 97<=b^0x69<=122 else ... for b in base64.b64decode(c)])`
Running the Base64 string from the flag packet through this function:
- XOR: Each byte is XORed with 0x69.
- ROT13: The letters are shifted back by 13.

Result: HTB{c4r5_c4n_c0d3_t00_dc1aff2bf63f0a9fe7144d8ad5639ecd}