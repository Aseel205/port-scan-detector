# Design Notes: Port Scan Detector

- **Packet Sniffing**: Uses scapy to sniff TCP SYN packets (the first step of a TCP connect). Only SYN (not ACK) packets are tracked for accuracy.
- **Sliding Window Detection**: Tracks port probe history per source IP via a deque, trimming entries older than 30s. If an IP accesses >20 unique ports in that window, it's likely a scan.
- **Alert System**: Logging system prints alerts to console and logs file for forensics.
- **Extensibility**: Add more sophisticated heuristics in `scanner_detector.py` and more alerting options in `alert_manager.py` as exercises.
- **Performance**: Suitable for light desktop/server use. For high-speed networks or production, consider optimized libraries and asynchronous/concurrent processing.
