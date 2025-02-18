from scapy.all import *
from PIL import Image
import io
import base64
import random
from cryptography.fernet import Fernet

def split_image(image_path, num_parts):
    with Image.open(image_path) as img:
        width, height = img.size
        part_width = width // num_parts
        parts = []
        for i in range(num_parts):
            left = i * part_width
            right = (i + 1) * part_width
            part = img.crop((left, 0, right, height))
            parts.append(part)
    return parts

def image_to_bytes(image):
    img_bytes = io.BytesIO()
    image.save(img_bytes, format="PNG") 
    return img_bytes.getvalue()

def bytes_to_base64(data):
    return base64.b64encode(data).decode('ascii')

def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data.decode('utf-8')


random_strings = [
    "Nothing to see here",
    "amazing",
    "There are parts to this, be careful",
    "I hope you don't let our little secret out",
    "https://www.srmist.edu.in/",
    "The egyptians believed that the most significant thing one could do was die",
    "Look for requests if you're stuck.",
    "Hey there, you must be really smart",
    "Hey there (with rizz)",
    "Ever heard of amaro?",
    "I like kirby",
    "POYO!",
    "This is a random string.",
    "Another random string.",
    "Yet another random string."
]


key = Fernet.generate_key()
image_path = "flag.png" 
num_parts = 10

src_ip = "192.168.0.65"
dst_ip = "192.168.5.36"


packets = []

image_parts = split_image(image_path, num_parts)

key_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=21)/key.decode() 
packets.append(key_packet) 

initial_packets = [] #initial traffic
for _ in range(400):
    if random.choice([True, False]):
        src_ip = random.choice(["192.168.5.10", "192.168.5.20", "192.168.5.15", "192.168.5.25"])
        dst_port = random.randint(1024, 65535)
        initial_packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=dst_port))
    else:
        src_ip = random.choice(["192.168.5.10", "192.168.5.20", "192.168.5.15", "192.168.5.25"])
        dst_port = random.randint(1024, 65535)
        initial_packets.append(IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65535), dport=dst_port))


for i, part in enumerate(image_parts):
    part_bytes = image_to_bytes(part)
    base64_part = bytes_to_base64(part_bytes)
    encrypted_part = encrypt_data(base64_part, key)
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=21)/encrypted_part.encode()) 


def generate_random_traffic(num_packets):
    traffic = []
    for _ in range(num_packets):
        if random.random() < 0.5: 
            http_src_ip = random.choice(["192.168.5.10", "192.168.5.20", "192.168.5.15", "192.168.5.25"])
            traffic.append(IP(src=http_src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80)/"GET /index.html HTTP/1.1\r\n\r\n")
        else:
            tcp_src_ip = random.choice(["192.168.5.10", "192.168.5.20", "192.168.5.15", "192.168.5.25"])
            tcp_dst_port = random.randint(1024, 65535)
            random_string = random.choice(random_strings)
            base64_string = bytes_to_base64(random_string.encode()) 
            traffic.append(IP(src=tcp_src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=tcp_dst_port)/base64_string.encode())
    return traffic


random_packets = generate_random_traffic(1000)
all_packets = initial_packets + packets + random_packets
all_packets[len(initial_packets):] = random.sample(all_packets[len(initial_packets):], len(all_packets[len(initial_packets):])) 




wrpcap("secret.pcap", all_packets) 
print(f"Encryption Key: {key.decode()}")