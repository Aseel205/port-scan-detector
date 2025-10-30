"""
alert_manager.py: Alert logging and printing for Port Scan Detector
"""

import logging
import os
import socket
from datetime import datetime
import requests

try:
    import dns.reversename, dns.resolver
except ImportError:
    dns = None

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs', 'alerts.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def geoip_lookup(ip):
    # Return (country, city) for an IP using ip-api.com (no local database required). If private IP, label as Local/LAN.
    parts = ip.split('.')
    if ip.startswith('10.') or ip.startswith('192.168.') or (ip.startswith('172.') and 16 <= int(parts[1]) <= 31):
        return 'Local/LAN', 'PrivateNet'
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        if data.get('status') == 'success':
            return data.get('country'), data.get('city')
    except Exception:
        pass
    return '?', '?'

def reverse_dns(ip):
    if not dns:
        return '?'
    try:
        rev_name = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(rev_name, 'PTR', lifetime=2)
        return str(result[0]) if result else '?'
    except Exception:
        return '?'

def classify_scan(ports, time_span):
    if time_span > 20:
        return 'slow/stealth'
    port_count = len(ports)
    if port_count > 20:
        return 'vertical'
    return 'horizontal'

def alert(ip, ports, first_ts, last_ts):
    country, city = geoip_lookup(ip)
    ptr = reverse_dns(ip)
    classification = classify_scan(ports, last_ts - first_ts)
    alert_msg = (f"[PORT SCAN DETECTED] IP {ip}\n"
                 f"  Ports: {len(ports)} ({sorted(list(ports))[:10]}{'...' if len(ports)>10 else ''})\n"
                 f"  Window: {int(first_ts)}-{int(last_ts)} ({int(last_ts-first_ts)}s)\n"
                 f"  Classification: {classification}\n"
                 f"  GeoIP: {country} / {city}\n"
                 f"  RDNS: {ptr}")
    logging.info(alert_msg)
