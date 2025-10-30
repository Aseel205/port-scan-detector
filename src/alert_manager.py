"""
alert_manager.py: Alert logging and printing for Port Scan Detector
"""

import logging
import os

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs', 'alerts.log')

# Configure logging. Log file will collect all alerts.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def alert(ip, ports, first_ts, last_ts):
    """
    Log and print a port scan alert.
    Args:
        ip (str): Source IP address triggering the alert
        ports (set): Ports scanned
        first_ts (float): Start time (timestamp)
        last_ts (float): End time (timestamp)
    """
    alert_msg = (f"[Port Scan Detected] IP {ip} scanned {len(ports)} unique ports "
                 f"between {first_ts:.0f} and {last_ts:.0f}.")
    logging.info(alert_msg)
