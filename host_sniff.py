from scapy.all import sniff, ARP, IP, Ether
from rich.live import Live
from rich.table import Table
from rich.console import Group 
from rich.console import Console
from rich.text import Text
from rich import box
from time import time, sleep
from threading import Thread

seen_hosts = {}
start_time = time()
packet_count = 0
running = True

def format_time(secs):
    return f"{int(secs // 60):02}:{int(secs % 60):02}"

# Header display above table output
# metrics including: elapsed time, number packets captured, and number of hosts discovered 
def build_header():
    elapsed = format_time(time() - start_time)
    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right")
    grid.add_column(justify="right")
    grid.add_column(justify="right")
    grid.add_row(
        f"[bold yellow]Time:[/] {elapsed}",
        f"[bold cyan]Packets:[/] {packet_count}",
        f"[bold magenta]Hosts:[/] {len(seen_hosts)}"
    )
    return grid

# Displays discovered hosts + mac
def build_table():
    table = Table(box=box.SIMPLE)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    for ip, mac in seen_hosts.items():
        table.add_row(ip, mac)
    return table

# Header + table view grouped
def build_view():
    return Group(
        Text("Passively detecting hosts...\n", style="bold green"),
        build_header(),
        build_table()
    )

# IP and MAC gathered from captured packets
def handle_packet(pkt):
    global packet_count
    if pkt.haslayer(ARP) or pkt.haslayer(IP):
        ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src
        mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
        if ip != '0.0.0.0' and ip not in seen_hosts:
            seen_hosts[ip] = mac
    packet_count += 1

# Refreshes display
def update_view(live):
    Console().clear()
    while running:
        live.update(build_view())
        sleep(0.25)

with Live(build_view(), refresh_per_second=10) as live:
    Thread(target=update_view, args=(live,), daemon=True).start()
    sniff(filter="broadcast or multicast", prn=handle_packet, store=False)