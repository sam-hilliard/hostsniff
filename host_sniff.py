from scapy.all import sniff, ARP, IP, Ether
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from time import time
from rich import box

seen_hosts = {}
start_time = time()
packet_count = 0

def build_header():
    elapsed = int(time() - start_time)
    minutes, seconds = divmod(elapsed, 60)

    return Text(
        f"Sniffing for hosts...   "
        f"Time: {minutes:02}:{seconds:02}   "
        f"Packets: {packet_count}   "
        f"Hosts: {len(seen_hosts)}",
        style="bold"
    )

def build_table():
    table = Table(box=box.SIMPLE)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    for ip, mac in seen_hosts.items():
        table.add_row(ip, mac)
    return table

def build_view():
    return Group(
        build_header(),
        build_table()
    )

def packet_handler(pkt):
    global packet_count
    mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
    if pkt.haslayer(ARP) or pkt.haslayer(IP):
        ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src
        if ip != '0.0.0.0' and ip not in seen_hosts:
            seen_hosts[ip] = mac
    packet_count += 1

def handle(pkt):
    packet_handler(pkt)
    live.update(build_view())

with Live(build_view(), refresh_per_second=1, screen=True) as live:
    sniff(filter="broadcast or multicast", prn=handle, store=False)