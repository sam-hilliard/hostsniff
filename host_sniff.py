from scapy.all import sniff, ARP, IP, Ether

seen_hosts = set()

def packet_handler(pkt):
    mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"

    if pkt.haslayer(ARP) or pkt.haslayer(IP):
        ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src
        if ip != '0.0.0.0' and (ip, mac) not in seen_hosts:
            seen_hosts.add((ip, mac))
            print(f"{ip}: {mac}")

sniff(filter="broadcast or multicast", prn=packet_handler, store=False)