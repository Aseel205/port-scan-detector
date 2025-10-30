"""
packet_sniffer.py: Sniffs TCP SYN packets using scapy
"""
from scapy.all import sniff, TCP, IP
from src.scanner_detector import process_syn

def syn_filter(pkt):
    """Return True if packet is a TCP SYN (and not ACK), else False."""
    return pkt.haslayer(TCP) and pkt[TCP].flags == 'S'

def handle_pkt(pkt):
    """Extract src IP and dst port then pass to scanner detector."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dport = pkt[TCP].dport
        process_syn(src_ip, dport)

def start_sniff(interface=None):
    """
    Start sniffing packets on given network interface using scapy (may need root).
    Args:
        interface (str): Optional network interface to sniff on.
    """
    sniff(filter="tcp", prn=handle_pkt, lfilter=syn_filter, store=0, iface=interface)
