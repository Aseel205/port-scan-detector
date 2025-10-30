"""
db.py: SQLite utility for Port Scan Detector alerts
"""
import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'alerts.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    source_ip TEXT,
    ports_count INTEGER,
    sample_ports TEXT,
    classification TEXT,
    geoip_country TEXT,
    geoip_city TEXT,
    rdns TEXT,
    pcap_path TEXT
);
"""

def create_db_and_table():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(SCHEMA)
    conn.commit()
    conn.close()

def insert_alert(alert_dict):
    create_db_and_table()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO alerts (timestamp, source_ip, ports_count, sample_ports, classification, geoip_country, geoip_city, rdns, pcap_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        alert_dict['timestamp'],
        alert_dict['source_ip'],
        alert_dict['ports_count'],
        alert_dict['sample_ports'],
        alert_dict['classification'],
        alert_dict['geoip_country'],
        alert_dict['geoip_city'],
        alert_dict['rdns'],
        alert_dict['pcap_path'],
    ])
    conn.commit()
    conn.close()

def get_top_ips(limit=5):
    create_db_and_table()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    SELECT source_ip, COUNT(*) as alerts FROM alerts GROUP BY source_ip ORDER BY alerts DESC LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows
