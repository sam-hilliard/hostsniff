from scapy.all import sniff, ARP, IP, Ether, conf, get_if_list
import argparse
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from rich import box
from time import time
from mac_vendor_lookup import MacLookup
import signal

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
    """formats UI header with statistics"""

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
    """Outputs sniffed IPs, MACs, and Vendors into a table"""

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
    """Groups header and table"""

    return Group(
        Text("[+] Passively detecting hosts... (Press Ctrl+C to stop)\n"),
        build_header(),
        build_table()
    )

def handle_packet(pkt):
    """ Parses IP/MAC from packets gathered by scapy """

    global packet_count
    ip = pkt[ARP].psrc if pkt.haslayer(ARP) else pkt[IP].src if pkt.haslayer(IP) else None
    mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    if ip and ip != '0.0.0.0' and ip not in seen_hosts and mac:
        seen_hosts[ip] = mac
    packet_count += 1

def init_arg_parse():

    """ Configures arguments and help menu with arg parse """

    parser = argparse.ArgumentParser(
        description="Passive network host discovery tool."
    )
    parser.add_argument(
        "-i", "--interface",
        metavar="<interface",
        help="Network interface to listen on (default: Auto-detected active interface)",
        default=conf.iface
    )
    args = parser.parse_args()

    # Validating interface
    available_ifaces = get_if_list()
    if args.interface not in available_ifaces:
        parser.error(f"Invalid interface: '{args.interface}'. Available: {', '.join(available_ifaces)}")

    return args

if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    args = init_arg_parse()

    print(f"[+] Using interface: {args.interface}")
    print("[+] Updating MAC vendor lookup database...")
    try:
        mac_lookup.update_vendors()
        print("[+] Database up to date.")
    except Exception as e:
        print(f"[-] Warning: Could not update vendor database: {e}")
    
    with Live(build_view(), refresh_per_second=2) as live:
        while running:
            sniff(
                iface=args.interface,
                filter="broadcast or multicast",
                prn=handle_packet,
                store=False,
                timeout=1,
            )
            if running:
                live.update(build_view())