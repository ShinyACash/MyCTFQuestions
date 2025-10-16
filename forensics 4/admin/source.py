from scapy.all import *
import random

# The final, correct command the player needs to reconstruct.
# This one uses rot13 and base64 to hide the flag.
FINAL_COMMAND = "echo 'ZmxhZ3tlWGVjVVQxbmdfY21kNV8wbjNfazNZX2FUX2FfVDFtM180ZjQxMjQzODQ3ZGE2OTNhNGYzNTZjMDQ4NjExNGJjNn0=' | base64 -d"

# The actual sequence of characters typed by the "attacker", including typos
# and backspaces (\b). This is what gets converted into scan codes.
TYPED_STRING = "echo 'ZmxhZ3tlWGVjVVQxbmdfY21kNV8wbjNfazNZX2FUX2FfVDFtM180ZjQxMjQzODQ3ZGE2OTNhNGYzNTZjMDQ4NjExNGJjNn0=' | bsae\b\b\b\base64 -d\n"

PCAP_FILENAME = "typingcats.pcapng"

SCAN_CODES = {
    'a': (0x04, False), 'b': (0x05, False), 'c': (0x06, False), 'd': (0x07, False),
    'e': (0x08, False), 'f': (0x09, False), 'g': (0x0a, False), 'h': (0x0b, False),
    'i': (0x0c, False), 'j': (0x0d, False), 'k': (0x0e, False), 'l': (0x0f, False),
    'm': (0x10, False), 'n': (0x11, False), 'o': (0x12, False), 'p': (0x13, False),
    'q': (0x14, False), 'r': (0x15, False), 's': (0x16, False), 't': (0x17, False),
    'u': (0x18, False), 'v': (0x19, False), 'w': (0x1a, False), 'x': (0x1b, False),
    'y': (0x1c, False), 'z': (0x1d, False),
    '1': (0x1e, False), '2': (0x1f, False), '3': (0x20, False), '4': (0x21, False),
    '5': (0x22, False), '6': (0x23, False), '7': (0x24, False), '8': (0x25, False),
    '9': (0x26, False), '0': (0x27, False),
    'A': (0x04, True), 'B': (0x05, True), 'C': (0x06, True), 'D': (0x07, True),
    'E': (0x08, True), 'F': (0x09, True), 'G': (0x0a, True), 'H': (0x0b, True),
    'I': (0x0c, True), 'J': (0x0d, True), 'K': (0x0e, True), 'L': (0x0f, True),
    'M': (0x10, True), 'N': (0x11, True), 'O': (0x12, True), 'P': (0x13, True),
    'Q': (0x14, True), 'R': (0x15, True), 'S': (0x16, True), 'T': (0x17, True),
    'U': (0x18, True), 'V': (0x19, True), 'W': (0x1a, True), 'X': (0x1b, True),
    'Y': (0x1c, True), 'Z': (0x1d, True),
    ' ': (0x2c, False), '-': (0x2d, False), '=': (0x2e, False),
    '[': (0x2f, False), ']': (0x30, False), '\\': (0x31, False), ';': (0x33, False),
    '\'': (0x34, False), '{': (0x2f, True), '}': (0x30, True), '|': (0x31, True),
    ':': (0x33, True), '"': (0x34, True), '_': (0x2d, True), '+': (0x2e, True),
    '\n': (0x28, False), # Enter
    '\b': (0x2a, False), # Backspace
}

def create_usb_hid_report(modifier=0, keycode=0):
    return bytes([modifier, 0, keycode, 0, 0, 0, 0, 0])

def create_usb_hid_mouse_report():
    x_mov = random.randint(-5, 5) & 0xff 
    y_mov = random.randint(-5, 5) & 0xff
    return bytes([0, x_mov, y_mov, 0, 0, 0, 0, 0])

def create_packets_for_char(char):
    packets = []

    def make_pkt(report):
        return IP(src="1.3.3.7", dst="1.0.0.1")/UDP(sport=1337, dport=1337)/Raw(load=report)

    scan_code, needs_shift = SCAN_CODES.get(char, (0, False))

    if needs_shift:
        packets.append(make_pkt(create_usb_hid_report(modifier=0x02)))

    packets.append(make_pkt(create_usb_hid_report(modifier=0x02 if needs_shift else 0, keycode=scan_code)))

    packets.append(make_pkt(create_usb_hid_report(modifier=0x02 if needs_shift else 0)))

    if needs_shift:
        packets.append(make_pkt(create_usb_hid_report()))
        
    return packets

if __name__ == "__main__":
    print(f"[*] Final command to be reconstructed: {FINAL_COMMAND}")
    all_packets = []
    print(f"[*] Generating packets for the typed string...")

    def make_pkt(report):
        return IP(src="1.3.3.7", dst="1.0.0.1")/UDP(sport=1337, dport=1337)/Raw(load=report)

    all_packets = []
    print(f"[*] Generating packets for the typed string and adding dummy mouse traffic...")

    for char in TYPED_STRING:
        # Main packets
        all_packets.extend(create_packets_for_char(char, make_pkt))
        
        # Hiding shit with mouse inputs
        for _ in range(random.randint(1, 10)):
            all_packets.append(make_pkt(create_usb_hid_mouse_report()))

    print(f"[*] Generated a total of {len(all_packets)} packets (including dummy traffic).")
    print("[*] Shuffling packets to obscure the order...")
    random.shuffle(all_packets)
    
    print(f"[*] Writing packets to '{PCAP_FILENAME}'...")
    wrpcapng(PCAP_FILENAME, all_packets)

    print("[+] Done! PCAP file created successfully.")
    print("\nTo verify the flag, run this in a Linux terminal:")
    print(f"    {FINAL_COMMAND}")
    flag_output = os.popen(FINAL_COMMAND).read().strip()
    print(f"    Expected Flag: {flag_output}")
