# Port Scan Detector

Detect real-time port scans against your machine.

## Overview
This tool monitors incoming TCP SYN packets and detects when a remote IP rapidly probes many ports, indicating a potential port scan (e.g. from nmap). Alerts are logged and displayed.

## Prerequisites
- Python 3.10+
- [scapy](https://scapy.net/) (install via pip)
- Run with administrative/root privileges (for packet sniffing)

## Setup & Install
```sh
pip install -r requirements.txt
```

## Usage
```sh
# Run on all interfaces (root required):
sudo python3 src/main.py
# Specify interface:
sudo python3 src/main.py -i eth0
```

## Testing with nmap
On another machine, run:
```sh
nmap -p 1-1000 <target-ip>
```
Watch for console alerts and check `data/logs/alerts.log` for details.
