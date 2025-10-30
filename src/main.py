"""
main.py: Entry point to run Port Scan Detector
"""
import argparse
from src.packet_sniffer import start_sniff

def main():
    parser = argparse.ArgumentParser(description="Port Scan Detector")
    parser.add_argument('-i', '--interface', help='Network interface to sniff on (default: all)')
    args = parser.parse_args()
    print("[+] Port Scan Detector started. Press Ctrl+C to stop.")
    try:
        start_sniff(args.interface)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user. Exiting...")

if __name__ == "__main__":
    main()
