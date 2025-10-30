# Technical Enhancements in Port Scan Detector

## 1. Rolling PCAP Buffer and Save-on-Alert
- Captured packets are stored in a memory-deque (buffer).
- When a port scan is detected, the last N packets (default 1000, filtered for the attacker IP) are automatically saved as a PCAP file in `data/pcaps/alert-<timestamp>-<ip>.pcap`.
- Useful for post-mortem analysis in Wireshark.

## 2. GeoIP and Reverse DNS Enrichment
- Alerts are enriched with:
  - Country and city from public GeoIP lookup (needs MaxMind GeoLite2-City.mmdb file).
  - Hostname using reverse DNS lookup.
- This info is recorded in logs and the database.

## 3. Scan Classification
- Each alert is tagged as:
  - **vertical:** many ports, one host (classic scan).
  - **horizontal:** one port, many hosts (not currently generated in TCP SYN-only mode).
  - **slow/stealth:** scan spread over >20 seconds.

## 4. SQLite Alert Database
- All alerts are stored in `data/alerts.db`.
- The schema includes:
  - Timestamp, Source IP, Port Count, Sample Ports, Scan Type, GeoIP, Reverse DNS, PCAP Path
- Includes code to query top source IPs for producing statistics.

---
## How to Test
- Trigger a scan (e.g. nmap as before).
- Upon detection, check:
  - 1) A new `.pcap` file is created in `data/pcaps/`.
  - 2) Alert log and database have new enriched entries.
  - 3) Classification and geo enrichment fields show in logs and DB.
- Use a database browser (e.g. DB Browser for SQLite) to examine `alerts.db` for all alerts.
- Open alert PCAPs with Wireshark for full packet detail.

**NOTE:** To enable GeoIP lookups, download a recent [GeoLite2 City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database and place as `GeoLite2-City.mmdb` in your project root or `data/` folder.
