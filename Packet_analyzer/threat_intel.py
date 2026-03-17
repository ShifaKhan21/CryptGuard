import os
import sqlite3
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
CACHE_DB = "threat_intel_cache.db"
CACHE_EXPIRY_H = 24

# Pre-load top 1000 domains (simplified)
CLEAN_DOMAINS = {"google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com", "twitter.com", "linkedin.com"}

def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    curr = conn.cursor()
    curr.execute('''CREATE TABLE IF NOT EXISTS intel_cache 
                    (target TEXT PRIMARY KEY, verdict TEXT, confidence INTEGER, source TEXT, timestamp REAL)''')
    conn.commit()
    conn.close()

init_cache()

def is_private_ip(ip):
    # Simple check for private IP ranges
    if not ip or ":" in ip: return False # Skip IPv6 for now or handle later
    parts = ip.split(".")
    if len(parts) != 4: return False
    
    p1, p2 = int(parts[0]), int(parts[1])
    if p1 == 10: return True
    if p1 == 192 and p2 == 168: return True
    if p1 == 172 and (16 <= p2 <= 31): return True
    if p1 == 127: return True
    return False

def get_cached_intel(target):
    conn = sqlite3.connect(CACHE_DB)
    curr = conn.cursor()
    curr.execute("SELECT verdict, confidence, source, timestamp FROM intel_cache WHERE target=?", (target,))
    row = curr.fetchone()
    conn.close()
    
    if row:
        verdict, confidence, source, ts = row
        if (time.time() - ts) < (CACHE_EXPIRY_H * 3600):
            return {"verdict": verdict, "confidence": confidence, "source": source, "cached": True}
        else:
            # Expired
            pass
    return None

def save_to_cache(target, verdict, confidence, source):
    conn = sqlite3.connect(CACHE_DB)
    curr = conn.cursor()
    curr.execute("INSERT OR REPLACE INTO intel_cache VALUES (?, ?, ?, ?, ?)", 
                 (target, verdict, confidence, source, time.time()))
    conn.commit()
    conn.close()

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY: return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data["data"]["abuseConfidenceScore"]
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
    return None

def check_virustotal(ip):
    if not VT_API_KEY: return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            positives = stats["malicious"] + stats["suspicious"]
            total = sum(stats.values())
            return (positives / total) * 100 if total > 0 else 0
    except Exception as e:
        print(f"VT error: {e}")
    return None

def check_threat_intel(target):
    # 1. Check local top domains
    if target.lower() in CLEAN_DOMAINS:
        return {"ip": target, "verdict": "CLEAN", "confidence": 0, "source": "static_list", "cached": True}

    # 2. Check private IP
    if is_private_ip(target):
        return {"ip": target, "verdict": "CLEAN", "confidence": 0, "source": "private_range", "cached": True}

    # 3. Check Cache
    cached = get_cached_intel(target)
    if cached: return {**cached, "ip": target}

    # 4. API Calls
    intel_score = 0
    sources_used = []
    
    # AbuseIPDB (60%)
    score_abuse = check_abuseipdb(target)
    if score_abuse is not None:
        intel_score += score_abuse * 0.6
        sources_used.append("abuseipdb")
    
    # VirusTotal (40%)
    score_vt = check_virustotal(target)
    if score_vt is not None:
        intel_score += score_vt * 0.4
        sources_used.append("virustotal")
    
    if not sources_used:
        return {"ip": target, "verdict": "UNKNOWN", "confidence": 0, "source": "none", "cached": False}

    # Normalize if only one source was available
    if len(sources_used) == 1:
        if sources_used[0] == "abuseipdb": intel_score = score_abuse
        else: intel_score = score_vt

    # Result
    verdict = "CLEAN"
    if intel_score > 75: verdict = "MALICIOUS"
    elif intel_score > 40: verdict = "SUSPICIOUS"

    source_str = "/".join(sources_used)
    save_to_cache(target, verdict, int(intel_score), source_str)
    
    return {
        "ip": target,
        "verdict": verdict,
        "confidence": int(intel_score),
        "source": source_str,
        "cached": False
    }
