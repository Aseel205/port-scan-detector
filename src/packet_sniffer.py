"""
packet_sniffer.py: Sniffs TCP SYN packets using scapy and buffers packets
"""
from scapy.all import sniff, TCP, IP, wrpcap
from src.scanner_detector import process_syn
from collections import deque
import threading

# --- Rolling buffer for recent packets ---
BUFFER_SIZE = 1000
recent_packets = deque(maxlen=BUFFER_SIZE)
lock = threading.Lock()  # For thread safety with wrpcap

def syn_filter(pkt):
    """Return True if packet is a TCP SYN (not ACK), else False."""
    return pkt.haslayer(TCP) and pkt[TCP].flags == 'S'

def handle_pkt(pkt):
    """Extract src IP, dst port, record to buffer, then pass to scanner detector."""
    with lock:
        recent_packets.append(pkt)
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dport = pkt[TCP].dport
        process_syn(src_ip, dport)

def export_recent_packets(filename, filter_ip=None):
    """
    Export the latest BUFFER_SIZE packets to a PCAP file.
    If filter_ip is given, only packets with src==filter_ip or dst==filter_ip are included.
    """
    with lock:
        pkts = list(recent_packets)
    if filter_ip:
        pkts = [p for p in pkts if p.haslayer(IP) and (p[IP].src == filter_ip or p[IP].dst == filter_ip)]
    wrpcap(filename, pkts)

def start_sniff(interface=None):
    """
    Start sniffing packets on given network interface using scapy (may need root).
    Args:
        interface (str): Optional network interface to sniff on.
    """
    sniff(filter="tcp", prn=handle_pkt, lfilter=syn_filter, store=0, iface=interface)
