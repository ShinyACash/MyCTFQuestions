from scapy.all import *
import random

def create_ctf_pcap(flag, hidden_strings):
    num_packets = 1000 
    packets = []
    src_ip = "192.168.0.65"
    dst_ip = "192.168.5.36"

    flag_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))/Raw(load=flag)

    for string in hidden_strings:
        string_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))/Raw(load=string)
        packets.append(string_packet)

    for _ in range(num_packets):
        if random.choice([True, False]): 
            packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))/Raw(load=RandString(size=random.randint(400, 500)))
        else:
            packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))/Raw(load=RandString(size=random.randint(400, 500)))
        packets.append(packet)
    packets.insert(random.randint(0, num_packets), flag_packet)

    random.shuffle(packets)
    wrpcap("secret2.pcap", packets)


flag = "flag: {(]$3q!6|0xb?(xq|8@k`<o_"
hidden_strings = ["part1 aHR0cHM6L", "part2 y93d3cueW9", "part3 1ubiZS5jb20", "part4 v/d2F0Y2g/dj", "part5 =aSGd5UUdv", "part6 ZWFCMCBmaXJ", "part7 zdCA4IGxld", "part8 HRlcnM="] 
create_ctf_pcap(flag, hidden_strings)