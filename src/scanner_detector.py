"""
scanner_detector.py: Detect port scan patterns
"""
from collections import defaultdict, deque
from src.alert_manager import alert
from src.utils import current_time

# Detector parameters
WINDOW_SECONDS = 30  # Time window in seconds
PORT_THRESHOLD = 20  # Unique port count to trigger alert

# Data structure: {src_ip: deque[(timestamp, port)]}
connections = defaultdict(lambda: deque())

def process_syn(src_ip, dport):
    """
    Process observed SYN packet. Detect port scan if triggered.
    Args:
        src_ip (str): Source IP address
        dport (int): Destination port number
    """
    now = current_time()
    q = connections[src_ip]
    q.append((now, dport))
    
    # Remove stale entries (older than WINDOW_SECONDS)
    while q and now - q[0][0] > WINDOW_SECONDS:
        q.popleft()

    # Get unique ports in sliding window
    unique_ports = set([p for _, p in q])
    if len(unique_ports) > PORT_THRESHOLD:
        alert(src_ip, unique_ports, q[0][0], now)
        # Clear out connections for this IP to avoid duplicate/flooded alerts
        connections[src_ip].clear()
