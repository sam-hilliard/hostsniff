from scapy.all import sniff, ARP, IP, Ether
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from rich import box
from time import time
from mac_vendor_lookup import MacLookup
import signal
import sys

seen_hosts = {}
start_time = time()
packet_count = 0
running = True
mac_lookup = MacLookup()

def signal_handler(sig, frame):
    global running
    running = False

def format_time(secs):
    mins, secs = divmod(int(secs), 60)
    return f"{mins:02}:{secs:02}"

def build_header():
    elapsed = format_time(time() - start_time)
    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right")
    grid.add_column(justify="right")
    grid.add_column(justify="right")
    grid.add_row(
        f"Time: {elapsed}",
        f"Packets: {packet_count}",
        f"Hosts: {len(seen_hosts)}"
    )
    return grid

def build_table():
    table = Table(box=box.SIMPLE)
    table.add_column("IP Address", no_wrap=True)
    table.add_column("MAC Address")
    table.add_column("Vendor")
    
    for ip, mac in seen_hosts.items():
        try:
            vendor = mac_lookup.lookup(str(mac))
        except (KeyError, Exception):
            vendor = "Unknown"
        table.add_row(ip, mac, vendor)
    return table

def build_view():
    return Group(
        Text("[+] Passively detecting hosts... (Press Ctrl+C to stop)\n"),
        build_header(),
        build_table()
    )

def handle_packet(pkt):
    global packet_count
    ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src if pkt.haslayer(IP) else None
    mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    if ip and ip != '0.0.0.0' and ip not in seen_hosts and mac:
        seen_hosts[ip] = mac
    packet_count += 1

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    print("[+] Updating MAC vendor lookup database...")
    try:
        mac_lookup.update_vendors()
        print("[+] Database up to date.")
    except Exception as e:
        print(f"[-] Warning: Could not update vendor database: {e}")
    
    with Live(build_view(), refresh_per_second=2) as live:
        while running:
            sniff(
                filter="broadcast or multicast",
                prn=handle_packet,
                store=False,
                timeout=1,
            )
            if running:  
                live.update(build_view())