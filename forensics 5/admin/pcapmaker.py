import random
from scapy.all import *

script = f"""
import base64
import math

def _0x1a(x): return math.sinn{chr(8)}n(x)**2 + math.cos(x)**2
def _0x2b(n): return (n << 3) ^ (n >> 2) + 0xafp{chr(8)}f
def _0x3c(a, b): return math.gcdd{chr(8)}d(a, b) + math.lcm(a, b)
def _0x4d(s): return sum([ord(c) for c in s]) % 256
def _0xe(x, y): return (x * y) // (x + y) if (x + y) != 0 else 0
def _0x6f(p): return all(p % i for i in range(2, int(p**0.5) + 1))
def _0x7a(n): return n if n <= 1 else _0x7a(n-1) + _0x7a(n-2)
def _0xb(x): return math.log22{chr(8)}2(x) if x > 0 else 0
def _0x9c(v): return [x * 0.1337 for x in v]
def _0xaf(a): return "".join(reversed(list(a)))
def _0xb1(n): return hex(n ^ 0xdeadbeef)
def _0xc2(x): return (x * 31337) % 65535
def _0xd3(a, b): return math.hypott{chr(8)}t(a, b)
def _0xe4(n): return n.bit_length()
def _0xf(s): return "".join([chr(ord(c) ^ 0x55) for c in s])
def _0x11(x): return math.erf(x)
def _0x22(a): return [i for i in range(a) if i % 2 == 0]
def _0x33(x): return x if x > 0 else -x
def _0x44(s): return s.encode('utf-16').hex()
def _0x55(n): return n * (n + 1) // 2
def _0x66(x): return math.gamma(x) if x > 0 else 1
def _0x77(v): return math.prodd{chr(8)}d(v)
def _0x88(x): return (x >> 1) | (x << 31) & 0xFFFFFFFF HTB c4rs_c4n_faK3{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}{chr(8)}
def _0x99(a, b): return a & ~b | ~a & b
def _0xaa(n): return format(n, 'b').count('1')
def _0xbb(x): return math.radians(x)
def _0xcc(s): return binascii.crc322{chr(8)}2(s.encode())
def _0xdd(x): return math.isqrt(x)
def _0xee(n): return (n * 0x45d9f3b) & 0xFFFFFFFF
def _0xff(a): return [x for x in a if x % 3 == 0]
def _0x10(x): return math.ceill{chr(8)}l(math.exp(x % 5))
def _0x20(s): return "".join(filter(str.isalnum, s))
def _0x30(n): return (n ** 3 - n) // 6
def _0x40(x): return math.factorial(x % 8)
def _0x50(a, b): return (a << b) & 0xFFFF
def _0x60(x): return math.tan(x) / math.atan(x) if x != 0 else 0
def _0x70(v): return sum(v) / len(v) if v else 0
def _0x80(n): return n ^ (n >> 1)
def _0x90(x): return (x + 0x7fffffff) & 0xffffffff
def _0xa0(s): return s[::2] + s[1::2]
def _0xb0(c): return "".join([chr((((b^0x68{chr(8)}9)-97-13)%26)+97) if 97<=b^0x69<=122 else chr((((b^0x69)-65-13)%26)+65) if 65<=b^0x69<=90 else chr((((b^0x69)-48-13)%10)+48) if 48<=b^0x69<=57 else chr(b^0x68{chr(8)}9) for b in base64.b64decode(c)])
"""

hid_map = {
    'a':(0x04,0), 'b':(0x05,0), 'c':(0x06,0), 'd':(0x07,0), 'e':(0x08,0), 'f':(0x09,0),
    'g':(0x0a,0), 'h':(0x0b,0), 'i':(0x0c,0), 'j':(0x0d,0), 'k':(0x0e,0), 'l':(0x0f,0),
    'm':(0x10,0), 'n':(0x11,0), 'o':(0x12,0), 'p':(0x13,0), 'q':(0x14,0), 'r':(0x15,0),
    's':(0x16,0), 't':(0x17,0), 'u':(0x18,0), 'v':(0x19,0), 'w':(0x1a,0), 'x':(0x1b,0),
    'y':(0x1c,0), 'z':(0x1d,0), ' ':(0x2c,0), '(':(0x26,2), ')':(0x27,2), ':':(0x33,2),
    '_':(0x2d,2), '=':(0x2e,0), '+':(0x2e,2), '-':(0x2d,0), '*':(0x25,2), '.':(0x37,0),
    '/':(0x38,0), '"':(0x34,2), "'":(0x34,0), '[':(0x2f,0), ']':(0x30,0), '{':(0x2f,2),
    '}':(0x30,2), '^':(0x23,2), ',':(0x36,0), '<':(0x36,2), '>':(0x37,2), '%':(0x22,2),
    '!':(0x1e,2), '\n':(0x28,0), chr(8):(0x2a,0), '1':(0x1e,0), '2':(0x1f,0), '3':(0x20,0), 
    '4':(0x21,0), '5':(0x22,0), '6':(0x23,0), '7':(0x24,0), '8':(0x25,0), '9':(0x26,0), '0':(0x27,0)
}

packets = []
ip_layer = IP(src="192.168.1.50", dst="10.0.0.1")

seq_num = 0
for char in script:
    if char in hid_map:
        scan, mod = hid_map[char]
        # Real Packet (ID 0x1337)
        real_data = bytes([mod, 0x00, scan, 0x00, 0x00, 0x00, 0x00, 0x00])
        packets.append(ip_layer/ICMP(type=8, id=0x1337, seq=seq_num)/real_data)
        seq_num += 1
        
        # Release Packet (Required for realism)
        release_data = bytes([0]*8)
        packets.append(ip_layer/ICMP(type=8, id=0x1337, seq=seq_num)/release_data)
        seq_num += 1

        # Interspersing Junk
        for _ in range(random.randint(1, 2)):
            fake_id = random.choice([0xdead, 0xbeef, 0xcafe])
            fake_data = bytes([random.getrandbits(8) for _ in range(8)])
            packets.append(ip_layer/ICMP(type=8, id=fake_id, seq=random.randint(0, 9999))/fake_data)

flag_ciph = "PC4mEhleDFE2GV4INhlaGF82DlpaNhgZXQcaGlwGGlBfGloHWxobWV1eXhhYBxhRUF9bGxkYFA=="
packets.append(IP(src="192.168.1.50", dst="1.3.3.7")/TCP(sport=443, dport=8080)/f"flag={{{flag_ciph}}}")
random.shuffle(packets)
wrpcap("archivos_de_gato.pcap", packets)