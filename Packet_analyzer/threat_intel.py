import os
import sqlite3
import requests
import json
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")

class ThreatIntel:
    def __init__(self, db_path="intel_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                score INTEGER,
                provider TEXT,
                last_updated REAL,
                raw_data TEXT
            )
        """)
        conn.commit()
        conn.close()

    def get_ip_reputation(self, ip):
        # 1. Check Cache first
        cache_hit = self._get_cached_ip(ip)
        if cache_hit:
            # If cache is less than 24 hours old, return it
            if time.time() - cache_hit['last_updated'] < 86400:
                print(f"[Intel] Cache HIT for {ip}: Score {cache_hit['score']}")
                return cache_hit['score'], cache_hit['raw_data']

        # 2. Call AbuseIPDB
        abuse_score = self._query_abuseipdb(ip)
        
        # 3. Cache and return
        self._cache_ip(ip, abuse_score, "AbuseIPDB", {"abuse_score": abuse_score})
        return abuse_score, {"abuse_score": abuse_score}

    def _get_cached_ip(self, ip):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM ip_cache WHERE ip = ?", (ip,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def _cache_ip(self, ip, score, provider, raw_data):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO ip_cache (ip, score, provider, last_updated, raw_data)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, score, provider, time.time(), json.dumps(raw_data)))
        conn.commit()
        conn.close()

    def get_history(self, limit=100):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM ip_cache ORDER BY last_updated DESC LIMIT ?", (limit,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            print(f"[Intel] History fetch failed: {e}")
            return []

    def _query_abuseipdb(self, ip):
        if not ABUSEIPDB_KEY:
            return 0
            
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_KEY
        }

        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data['data']['abuseConfidenceScore']
            else:
                print(f"[Intel] AbuseIPDB Error: {response.status_code}")
                return 0
        except Exception as e:
            print(f"[Intel] Request failed: {e}")
            return 0

# Test Singleton
intel_engine = ThreatIntel()

if __name__ == "__main__":
    # Simple Test
    score, data = intel_engine.get_ip_reputation("8.8.8.8")
    print(f"IP: 8.8.8.8 | Score: {score}")
