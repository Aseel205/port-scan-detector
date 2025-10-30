"""
utils.py: Helper functions for Port Scan Detector
"""

import datetime

def current_time():
    """Return current UTC time as timestamp (float)."""
    return datetime.datetime.utcnow().timestamp()
