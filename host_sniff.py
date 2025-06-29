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
import xml.etree.ElementTree as ET
import os

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

def export_nmap_xml(filename, hosts):
    nmaprun = ET.Element("nmaprun")

    for ip, data in hosts.items():
        host = ET.SubElement(nmaprun, "host")
        ET.SubElement(host, "status", state="up")
        ET.SubElement(host, "address", addr=ip, addrtype="ipv4")
        ET.SubElement(host, "address", addr=data["mac"], addrtype="mac", vendor=data["vendor"])

    tree = ET.ElementTree(nmaprun)
    tree.write(filename, encoding="unicode", xml_declaration=True)
    print(f"[+] Nmap-style XML written to {filename}")

def export_results(filename, filetype):
    if filetype == "N":
        with open(filename, "w") as f:
            f.write("{:<20}\t{:<20}\t{:<20}\n".format("IP Address", "MAC Address", "Vendor"))
            for ip, data in seen_hosts.items():
                f.write("{:<20}\t{:<20}\t{}\n".format(ip, data['mac'], data['vendor']))
    elif filetype == "J":
        import json
        with open(filename, "w") as f:
            json.dump(seen_hosts, f, indent=4)
    elif filetype == "X":
        export_nmap_xml(filename, seen_hosts)
    elif filetype == "A":
        export_results(filename + ".txt", "N")
        export_nmap_xml(filename + ".xml", seen_hosts)
        export_results(filename + ".json", "J")
    else:
        raise ValueError("Invalid filetype")
    if filetype != "A":
        print(f"[+] Results written to {filename}")

def init_arg_parse():
    parser = argparse.ArgumentParser(description="Passive network host discovery tool.")
    parser.add_argument("-i", "--interface", metavar="<interface>", help="Network interface to listen on (default: Auto-detected active interface)", default=conf.iface)
    parser.add_argument("-c", "--count", metavar="packet limit", type=int, help="Stop capture after certain number of packets")
    parser.add_argument("-t", "--time", metavar="time limit (minutes)", type=int, help="Stop capture after certain number of minutes")
    parser.add_argument("-o", "--output", metavar="<filename>", help="Output results to a text file", type=str)
    parser.add_argument("-oJ", "--output-json", metavar="<filename>", help="Output results to a JSON file", type=str)
    parser.add_argument("-oX", "--output-xml", metavar="<filename>", help="Output results to an XML file", type=str)
    parser.add_argument("-oA", "--output-all", metavar="<filename>", help="Output results to a text, JSON, and XML file", type=str)
    
    args = parser.parse_args()

    available_ifaces = get_if_list()
    if args.interface not in available_ifaces:
        parser.error(f"Invalid interface: '{args.interface}'. Available: {', '.join(available_ifaces)}")

    return args

def should_continue(live, args):
    return running and (args.time is None or (time() - start_time) / 60 < args.time) and (args.count is None or packet_count < args.count)

if __name__ == "__main__":
    
    if os.getuid() != 0:
        print("[-] You don't have sufficient privileges to run this script, try running with sudo.")
        exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    args = init_arg_parse()

    print(f"[+] Using interface: {args.interface}")

    start_time = time()
    with Live(build_view(), refresh_per_second=3) as live:
        while should_continue(live, args):
            sniff(iface=args.interface, filter="broadcast or multicast", prn=handle_packet, store=False, timeout=1)
            live.update(build_view())

    # export results to a file
    if args.output:
        export_results(args.output, "N")
    elif args.output_json:
        export_results(args.output_json, "J")
    elif args.output_xml:
        export_results(args.output_xml, "X")
    elif args.output_all:
        export_results(args.output_all, "A")