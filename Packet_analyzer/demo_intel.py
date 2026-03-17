import sqlite3
import time
import json
import os

# --- Step 1: Force a Malicious IP into the Cache ---
# We will use 1.2.3.4 as our "Demonstration Malware IP"
DEMO_IP = "1.2.3.4"
DEMO_SCORE = 98

def prepare_cache():
    db_path = "intel_cache.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""
        INSERT OR REPLACE INTO ip_cache (ip, score, provider, last_updated, raw_data)
        VALUES (?, ?, ?, ?, ?)
    """, (DEMO_IP, DEMO_SCORE, "AbuseIPDB (Demo Mode)", time.time(), json.dumps({"abuse_score": DEMO_SCORE})))
    conn.commit()
    conn.close()
    print(f"✅ Demo IP {DEMO_IP} injected into cache with score {DEMO_SCORE}%")

# --- Step 2: Simulate Traffic to that IP ---
# This uses a simple socket to send a tiny bit of data so the packet analyzer catches it
def trigger_traffic():
    import socket
    print(f"📡 Sending signal to {DEMO_IP}...")
    try:
        # We don't need a real connection, just a packet attempt
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        # Random port 4444 typical for C2
        s.connect_ex((DEMO_IP, 4444))
        s.close()
        print(f"🚀 Packet sent! Check your dashboard for: {DEMO_IP}")
    except:
        pass

if __name__ == "__main__":
    prepare_cache()
    # Briefly wait and trigger
    time.sleep(1)
    trigger_traffic()
