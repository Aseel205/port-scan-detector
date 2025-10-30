# Port Scan Detector

A real-time tool for detecting port scans against your machine using Python and Scapy.

## Features
- Captures TCP SYN packets
- Detects vertical, horizontal, and slow/stealth port scans
- Alerts are logged with:
    - Source IP
    - Port count/sample ports
    - Scan classification
    - Country/city (GeoIP, for public IPs)
    - Reverse DNS hostname (if available)
- All alerts go to both console and `data/logs/alerts.log`
- Lightweight and privacy-respecting: no PCAP or DB files generated

## Prerequisites
- Python 3.10+
- [scapy](https://scapy.net/) (network packet library)
- [requests](https://requests.readthedocs.io/) (for GeoIP lookup)
- [dnspython](https://www.dnspython.org/) (for reverse DNS lookup)
- Administrative or root privileges (for packet capture)

Install requirements:
```sh
pip install -r requirements.txt
```

## How to Run
```sh
# Run on all network interfaces (needs Administrator/root):
python -m src.main
# Or specify interface (e.g. eth0, enp0s3):
python -m src.main -i eth0
```

## How to Test
- Simulate a scan from another computer (or VM) on the network using nmap:
    ```sh
    nmap -Pn -p 1-1000 <target-ip>
    ```
- Monitor the command prompt and `data/logs/alerts.log` for alerts.
- For LAN/private IPs (`10.x.x.x`, etc), GeoIP will display `Local/LAN`.
- For public internet IPs, country/city will display (if not blocked by a firewall).
- If you want to manually test the GeoIP lookup:
    ```sh
    python -c "import requests; print(requests.get('http://ip-api.com/json/8.8.8.8').json())"
    ```
  You should see U.S./Mountain View info for this Google DNS public IP.

## Notes
- Reverse DNS may return `?` if the IP has no PTR record.
- No persistent packet backups or alert DB are created for privacy and simplicity.
- All code is modular and fully commented for educational use.

## Troubleshooting
- If you see `GeoIP: Local/LAN` on all alerts, you are monitoring private/LAN sources—expected for local-only testing.
- If your machine/firewall blocks outgoing HTTP requests, GeoIP lookups for public IPs may fail (showing `? / ?`).
- For public IP scan simulation, try using a VPS or ask a friend on a different home network to scan your address.

---

Happy scanning! If you need further customization, see the `docs-technical.md` for design notes and extension ideas.
