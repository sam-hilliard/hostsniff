# HostSniff

A simple passive network scanner that detects live hosts on the local network by sniffing ARP and IP traffic.

## Setup

```bash
git clone https://github.com/sam-hilliard/hostsniff
cd hostsniff
./install.sh
```

## Usage

```bash
./host_sniff [options]
```

### Options

- `-i <interface>`: Network interface to listen on (default: auto)
- `-c <count>`: Stop after N packets
- `-t <minutes>`: Stop after N minutes
- `-o <file>`: Export to plaintext
- `-oJ <file>`: Export to JSON
- `-oX <file>`: Export to Nmap-style XML
- `-oA <file>`: Export all formats

### Example


```bash
./host_sniff -i wlan0 -t 2 -oA results
```