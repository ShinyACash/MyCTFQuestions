from scapy.all import *
import base64, random, string

username = "newRecruitHTB"
password = "HTB{d0_Y0u_kn0W_dA_wAy}"  # FLAG

rot13 = lambda s: s.translate(str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
))
encoded_creds = f"{rot13(username)}:{rot13(password)}" 

def random_rot13(length=8):
    return rot13(''.join(random.choice(string.ascii_lowercase) for _ in range(length)))

src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
dport = 80

packets = []

def make_http_stream(sport, user, pwd, is_flag=False):
    seq_client = random.randint(1000, 50000)
    seq_server = random.randint(1000, 50000)
    

    syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=seq_client)
    synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_server, ack=seq_client+1)
    ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=seq_client+1, ack=seq_server+1)
    
    # HTTP POST
    post_body = f"user={user}&pass={pwd}\r\n"
    http_payload = (
        "POST /login HTTP/1.1\r\n"
        "Host: htbchennai\r\n"
        "User-Agent: WannaGetIn?\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)*2+11}\r\n"
        "\r\n"
        f"user={post_body}&pass={post_body}\r\n"
    )
    
    http_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_client+1, ack=seq_server+1)/Raw(load=http_payload)

    resp_payload = (
        "HTTP/1.1 200 OK\r\n"
        "Server: iloveCats\r\n"
        "Content-Length: 19\r\n"
        "\r\n"
        "Login Successful!\n"
        if is_flag else
        "HTTP/1.1 200 OK\r\n"
        "Server: iloveCats\r\n"
        "Content-Length: 22\r\n"
        "\r\n"
        "Invalid Credentials!\n"
    )
    resp_pkt = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="PA", seq=seq_server+1, ack=seq_client+1+len(http_payload))/Raw(load=resp_payload)

    fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=seq_client+1+len(http_payload), ack=seq_server+1+len(resp_payload))
    finack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="FA", seq=seq_server+1+len(resp_payload), ack=seq_client+2+len(http_payload))
    last_ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=seq_client+2+len(http_payload), ack=seq_server+2+len(resp_payload))

    return [syn, synack, ack, http_pkt, resp_pkt, fin, finack, last_ack]


for sport in [12345, 12346, 12347, 12348]:
    if sport == 12347:
        packets += make_http_stream(
        sport=12347,
        user=rot13(username),
        pwd=rot13(password),
        is_flag=True
    )
    packets += make_http_stream(sport, random_rot13(), random_rot13(), False)

wrpcap("ilovecats.pcap", packets)
print("PCAP file generated: ilovecats.pcap")
