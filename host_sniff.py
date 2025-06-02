from scapy.all import sniff, ARP, IP, Ether
from rich.live import Live
from rich.table import Table
from rich import box

seen_hosts = {}

def build_table():
    table =  Table(box=box.SIMPLE)
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="magenta")
    for ip, mac in seen_hosts.items():
        table.add_row(ip, mac)
    return table

def packet_handler(pkt):
    mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
    if pkt.haslayer(ARP) or pkt.haslayer(IP):
        ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src
        if ip != '0.0.0.0' and ip not in seen_hosts:
            seen_hosts[ip] = mac

def handle(pkt):
    packet_handler(pkt)
    live.update(build_table())

with Live(build_table(), refresh_per_second=2) as live:
    sniff(filter="broadcast or multicast", prn=handle, store=False)