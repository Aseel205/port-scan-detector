"""
alert_manager.py: Alert logging, printing, enrichment, and pcap saving for Port Scan Detector
"""

import logging
import os
import socket
from datetime import datetime
from src.db import insert_alert
import requests  # <-- WEB API based lookup

try:
    import dns.reversename, dns.resolver
except ImportError:
    dns = None

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs', 'alerts.log')
PCAP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'pcaps')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def geoip_lookup(ip):
    """Return (country, city) for an IP using ip-api.com (no local database required)."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        if data.get('status') == 'success':
            return data.get('country'), data.get('city')
    except Exception:
        pass
    return None, None

def reverse_dns(ip):
    """Return the PTR record for an IP if available."""
    if not dns:
        return None
    try:
        rev_name = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(rev_name, 'PTR', lifetime=2)
        return str(result[0]) if result else None
    except Exception:
        return None

def classify_scan(ports, time_span):
    """Label vertical/horizontal/slow scan based on port set and timing."""
    # Simple demo logic:
    if time_span > 20:  # Window >20s, treat as slow/stealth
        return 'slow/stealth'
    port_count = len(ports)
    if port_count > 20:
        return 'vertical'  # likely vertical: many ports same host
    return 'horizontal'  # same port many hosts (not used here)

def alert(ip, ports, first_ts, last_ts):
    from src.packet_sniffer import export_recent_packets  # moved inside to fix circular import
    country, city = geoip_lookup(ip)
    ptr = reverse_dns(ip)
    classification = classify_scan(ports, last_ts - first_ts)

    # Save last 1000 relevant packets to PCAP
    timestamp_str = datetime.utcfromtimestamp(last_ts).strftime('%Y%m%d-%H%M%S')
    pcap_name = f"alert-{timestamp_str}-{ip.replace('.', '-')}.pcap"
    pcap_path = os.path.join(PCAP_DIR, pcap_name)
    export_recent_packets(pcap_path, filter_ip=ip)

    alert_msg = (f"[PORT SCAN DETECTED] IP {ip}\n"
                 f"  Ports: {len(ports)} ({sorted(list(ports))[:10]}{'...' if len(ports)>10 else ''})\n"
                 f"  Window: {int(first_ts)}-{int(last_ts)} ({int(last_ts-first_ts)}s)\n"
                 f"  Classification: {classification}\n"
                 f"  GeoIP: {country or '?'} / {city or '?'}\n"
                 f"  RDNS: {ptr or '?'}\n"
                 f"  PCAP: {pcap_path}")
    logging.info(alert_msg)

    # Write to SQLite DB
    insert_alert({
        'timestamp': int(last_ts),
        'source_ip': ip,
        'ports_count': len(ports),
        'sample_ports': ','.join(map(str, sorted(list(ports))[:10])),
        'classification': classification,
        'geoip_country': country or '',
        'geoip_city': city or '',
        'rdns': ptr or '',
        'pcap_path': pcap_path
    })
