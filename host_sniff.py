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
    
    for ip, data in seen_hosts.items():
        table.add_row(ip, data["mac"], data["vendor"])
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
        try:
            vendor = mac_lookup.lookup(str(mac))
        except Exception:
            vendor = "Unknown"
        seen_hosts[ip] = {"mac": mac, "vendor": vendor}

    packet_count += 1

def export_results(filename):
    with open(filename, "w") as f:
        f.write("{:<20}\t{:<20}\t{:<20}\n".format("IP Address", "MAC Address", "Vendor"))
        for ip, data in seen_hosts.items():
            f.write("{:<20}\t{:<20}\t{}\n".format(ip, data['mac'], data['vendor']))
    print(f"[+] Results written to {filename}")

def init_arg_parse():
    parser = argparse.ArgumentParser(description="Passive network host discovery tool.")
    parser.add_argument("-i", "--interface", metavar="<interface>", help="Network interface to listen on (default: Auto-detected active interface)", default=conf.iface)
    parser.add_argument("-c", "--count", metavar="packet limit", type=int, help="Stop capture after certain number of packets")
    parser.add_argument("-t", "--time", metavar="time limit (minutes)", type=int, help="Stop capture after certain number of minutes")
    parser.add_argument("-o", "--output", metavar="<filename>", help="Output results to a text file", type=str)
    args = parser.parse_args()

    available_ifaces = get_if_list()
    if args.interface not in available_ifaces:
        parser.error(f"Invalid interface: '{args.interface}'. Available: {', '.join(available_ifaces)}")

    return args

def should_continue(live, args):
    return running and (args.time is None or (time() - start_time) / 60 < args.time) and (args.count is None or packet_count < args.count)

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

    start_time = time()
    with Live(build_view(), refresh_per_second=3) as live:
        while should_continue(live, args):
            sniff(iface=args.interface, filter="broadcast or multicast", prn=handle_packet, store=False, timeout=1)
            live.update(build_view())

    if args.output:
        export_results(args.output)