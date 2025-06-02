from scapy.all import sniff, ARP, IP, Ether
seen_hosts = set()

def packet_handler(pkt):
    mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
    
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        if ip != '0.0.0.0' and (ip, mac) not in seen_hosts:
            seen_hosts.add((ip, mac))
            print(f"[ARP] Host discovered: {ip} | MAC: {mac}")

    elif pkt.haslayer(IP):
        src_ip = pkt[IP].src
        if (src_ip, mac) not in seen_hosts:
            seen_hosts.add((src_ip, mac))
            print(f"[IP ] Host discovered: {src_ip} | MAC: {mac}")

print("sniffing...")
sniff(filter="broadcast or multicast", prn=packet_handler, store=False)