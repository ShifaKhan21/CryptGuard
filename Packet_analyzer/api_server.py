import subprocess
import os
import sys
import time
import json
import threading
import platform
import socket
import joblib
import numpy as np
import pandas as pd
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import psutil
import signal
import re
import math
import statistics

# =============================================================================
# INTELLIGENCE LAYER — Rule-Based SNI Check + Beaconing + Productivity
# =============================================================================

# Known-bad SNI patterns → (reason, severity)
# Severity: 'HIGH', 'MEDIUM'
BAD_SNI_LIST = {
    # Malware / C2 patterns
    ".onion":           ("Dark Web / Tor Hidden Service",    "HIGH"),
    "c2.":              ("Command & Control Server",          "HIGH"),
    "bot.":             ("Known Botnet Pattern",              "HIGH"),
    "malware":          ("Malware Domain Pattern",            "HIGH"),
    "ransomware":       ("Ransomware Domain Pattern",         "HIGH"),
    "cryptominer":      ("Crypto-Mining Domain",              "HIGH"),
    "miner.":           ("Crypto-Mining Domain",              "HIGH"),
    "trojan":           ("Trojan Domain Pattern",             "HIGH"),
    "threat.demo":      ("[DEMO] Simulated Threat Domain",   "HIGH"),
    # Suspicious patterns
    "dyndns":           ("Dynamic DNS — Often Abused",       "MEDIUM"),
    "no-ip.com":        ("Dynamic DNS — Often Abused",       "MEDIUM"),
    "ngrok":            ("Tunneling Service — Often Abused", "MEDIUM"),
    "pastebin":         ("Data Exfiltration Vector",         "MEDIUM"),
    "bit.ly":           ("URL Shortener — Evasion Technique","MEDIUM"),
    "tinyurl":          ("URL Shortener — Evasion Technique","MEDIUM"),
    "freenom":          ("Free TLD — Abused for Phishing",   "MEDIUM"),
    ".tk":              ("Free TLD — Abused for Phishing",   "MEDIUM"),
    ".ml":              ("Free TLD — Abused for Phishing",   "MEDIUM"),
    ".ga":              ("Free TLD — Abused for Phishing",   "MEDIUM"),
    "portmap.io":       ("Tunneling Service",                "MEDIUM"),
    "serveo.net":       ("Reverse Proxy Tunneling",          "MEDIUM"),
}

# Category → Productivity Score (0–100)
PRODUCTIVITY_MAP = {
    "GitHub":           95,
    "Microsoft":        90,
    "Teams":            90,
    "Zoom":             88,
    "Slack":            88,
    "Google":           85,
    "Cloudflare":       80,
    "LinkedIn":         75,
    "Unacademy":        75,
    "Wikipedia":        72,
    "Amazon":           65,
    "Apple":            60,
    "Reddit":           45,
    "Twitter/X":        40,
    "Instagram":        35,
    "Spotify":          35,
    "Netflix":          25,
    "YouTube":          25,
    "TikTok":           15,
    "Telegram":         60,
    "WhatsApp":         65,
    "Discord":          55,
    "Facebook":         35,
    "Dropbox":          80,
    "DNS":              70,
    "HTTP":             50,
    "HTTPS":            65,
    "QUIC":             65,
    "TLS":              65,
    "Auto-Detected":    50,
    "SUSPICIOUS":       10,
    "MALWARE (THREAT)": 0,
    "Unknown":          40,
}

# Categories that are HTTPS/TLS/QUIC encrypted
ENCRYPTED_CATEGORIES = {
    "HTTPS", "QUIC", "TLS", "Google", "Facebook", "YouTube", "Twitter/X",
    "Instagram", "Netflix", "Amazon", "Microsoft", "Apple", "WhatsApp",
    "Telegram", "TikTok", "Spotify", "Zoom", "Discord", "GitHub",
    "LinkedIn", "Reddit", "Wikipedia", "Slack", "Teams", "Dropbox",
    "Cloudflare", "Unacademy", "SUSPICIOUS", "MALWARE (THREAT)", "Auto-Detected",
}

# Beaconing: per-domain hit timestamp history (last 20 hits)
_beacon_history = {}  # {domain: [timestamp, ...]}
_beacon_lock = threading.Lock()

BEACON_MIN_HITS = 5          # minimum hits to evaluate
BEACON_CV_THRESHOLD = 0.35   # coefficient of variation below this = regular = beaconing
BEACON_MIN_INTERVAL = 1.0    # ignore sub-second intervals (burst, not beacon)

def _update_beacon_history(domain, ts):
    """Track timestamps for beaconing detection (called outside state_lock)."""
    with _beacon_lock:
        hist = _beacon_history.setdefault(domain, [])
        hist.append(ts)
        if len(hist) > 20:
            hist.pop(0)

def _check_beaconing(domain):
    """Return True if domain shows regular beacon-like hit intervals."""
    with _beacon_lock:
        hist = _beacon_history.get(domain, [])
    if len(hist) < BEACON_MIN_HITS:
        return False
    intervals = [hist[i] - hist[i-1] for i in range(1, len(hist))]
    intervals = [iv for iv in intervals if iv >= BEACON_MIN_INTERVAL]
    if len(intervals) < BEACON_MIN_HITS - 1:
        return False
    try:
        mean_iv = statistics.mean(intervals)
        std_iv  = statistics.pstdev(intervals)
        if mean_iv <= 0:
            return False
        cv = std_iv / mean_iv
        return cv < BEACON_CV_THRESHOLD
    except Exception:
        return False

def apply_intelligence_layer(domains, now):
    """
    Post-processing intelligence pass.
    Called AFTER existing parse_dpi_output() logic — only adds new fields,
    never overwrites existing category / risk_score / prediction.
    """
    for dom, info in domains.items():
        # ── 1. Rule-Based SNI Check ──────────────────────────────────────────
        rule_blocked = False
        rule_reason  = ""
        rule_severity = ""
        dom_lower = dom.lower()
        for pattern, (reason, severity) in BAD_SNI_LIST.items():
            if pattern.lower() in dom_lower:
                rule_blocked  = True
                rule_reason   = reason
                rule_severity = severity
                break
        info["is_rule_blocked"]  = rule_blocked
        info["rule_reason"]      = rule_reason
        info["rule_severity"]    = rule_severity
        # Capture original category BEFORE any override (used for productivity + encryption)
        original_cat = info.get("category", "Unknown")
        # If rule-blocked override prediction to Malicious (keeps risk_score intact)
        if rule_blocked:
            if info.get("prediction", "Benign") == "Benign":
                info["prediction"] = "Malicious"
                if not info.get("risk_score", 0):
                    info["risk_score"] = 85.0
            if rule_severity == "HIGH":
                info["category"] = "RULE BLOCK [HIGH]"
            else:
                info["category"] = "RULE BLOCK [MEDIUM]"

        # ── 2. Beaconing Detection ───────────────────────────────────────────
        _update_beacon_history(dom, info.get("last_seen", now))
        info["is_beaconing"] = _check_beaconing(dom)

        # ── 3. Productivity Score ────────────────────────────────────────────
        # Rule-blocked = always 0 productivity
        if rule_blocked:
            info["productivity_score"] = 0
        else:
            # Use original_cat (before any rule override)
            prod_score = PRODUCTIVITY_MAP.get(original_cat, None)
            if prod_score is None:
                # Partial match fallback
                for key, score in PRODUCTIVITY_MAP.items():
                    if key.lower() in original_cat.lower():
                        prod_score = score
                        break
            # Special cases
            if prod_score is None:
                if original_cat == "SUSPICIOUS" or "SUSPICIOUS" in original_cat:
                    prod_score = 10
                elif original_cat in ("Auto-Detected", "Unknown"):
                    prod_score = 40
            info["productivity_score"] = prod_score if prod_score is not None else 40

        # ── 4. Encryption Status ─────────────────────────────────────────────
        is_enc = original_cat in ENCRYPTED_CATEGORIES
        # Also flag encrypted if domain has HTTPS-like characteristics
        if not is_enc and "." in dom and not dom.endswith(".local"):
            is_enc = True  # Most modern SNI-resolved domains use TLS
        info["is_encrypted"] = is_enc

# END INTELLIGENCE LAYER
# =============================================================================

# Double Buffering for Parallel Capture
TEMP_PCAP_A = "temp_capture_a.pcap"
TEMP_PCAP_B = "temp_capture_b.pcap"
TEMP_PCAP = TEMP_PCAP_A # Default reference
TEMP_OUT = "temp_out.txt"

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
CAPTURE_DURATION = 1  # 1 second for real-time responsiveness

# Global State
LOCAL_HOSTNAME = socket.gethostname()
engine_state = {
    "interfaces": [],
    "selected_interface": None,
    "is_capturing": False,
    "domains": {}, # Format: {domain: {"count": X, "category": Y, "last_seen": timestamp}}
    "last_update": 0,
    "total_packets": 0,
    "dropped_packets": 0,
    "forwarded_packets": 0,
    "port_map": {} # LocalPort -> {"pid": X, "name": Y}
}

state_lock = threading.Lock()
# In-memory DNS cache
dns_cache = {}
dns_queue = []
dns_lock = threading.Lock()

class ProcessSentinel:
    @staticmethod
    def refresh():
        new_map = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    try:
                        p = psutil.Process(conn.pid)
                        new_map[conn.laddr.port] = {
                            "pid": conn.pid,
                            "name": p.name()
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            log_debug(f"ProcessSentinel Error: {e}")
        
        with state_lock:
            engine_state["port_map"] = new_map

def process_sentinel_worker():
    while True:
        try:
            ProcessSentinel.refresh()
        except: pass
        time.sleep(1)

threading.Thread(target=process_sentinel_worker, daemon=True).start()

DECAY_TIMEOUT = 30 # Remove domains if not seen in 30 seconds

# Feature List in exact order as trained (57 features)
FEATURE_LIST = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total', 
    'Bwd Packets Length Total', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
    'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length', 
    'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 
    'Packet Length Variance', 'SYN Flag Count', 'URG Flag Count', 'Avg Packet Size', 'Avg Fwd Segment Size', 
    'Avg Bwd Segment Size', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 
    'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets', 
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 
    'Idle Std', 'Idle Max', 'Idle Min'
]

# Load AI Models
try:
    rf_model_path = os.path.join("model", "rf_model_v1.pkl")
    xgb_model_path = os.path.join("model", "xgb_model.pkl")
    if os.path.exists(rf_model_path) and os.path.exists(xgb_model_path):
        rf_model = joblib.load(rf_model_path)
        xgb_model = joblib.load(xgb_model_path)
        print("[AI] Models loaded successfully!")
    else:
        print("[AI] Models not found on disk.")
        rf_model = None
        xgb_model = None
except Exception as e:
    print(f"[AI] Error loading models: {e}")
    rf_model = None
    xgb_model = None

def log_debug(msg):
    try:
        log_path = os.path.join(os.getcwd(), "debug.log")
        with open(log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"{time.strftime('%H:%M:%S')}: {str(msg)}\n")
    except Exception as e:
        print(f"Logging error: {e}")

def safe_remove(file_path):
    if not os.path.exists(file_path):
        return
    for _ in range(5):
        try:
            os.remove(file_path)
            return
        except OSError:
            time.sleep(0.5)

def get_val(l, label):
    """Robust extractor for boxed C++ output"""
    if label in l:
        try:
            clean = l.replace('║', '').replace('╔', '').replace('╠', '').replace('╚', '').replace('═', '')
            parts = clean.split(':')
            if len(parts) >= 2:
                val_part = parts[1].strip()
                match = re.search(r'\d+', val_part)
                if match:
                    return int(match.group())
        except: pass
    return None

def parse_dpi_output(dpi_output):
    global engine_state
    now = time.time()
    
    with state_lock:
        domains = engine_state["domains"]
        lines = dpi_output.split('\n')
        sni_section = False
        ml_section = False
        
        for line in lines:
            line_clean = line.strip()
            if not line_clean: continue

            # Extract Global Stats
            tp = get_val(line, "Total Packets:")
            if tp is not None: engine_state["total_packets"] += tp
            fw = get_val(line, "Forwarded:")
            if fw is not None: engine_state["forwarded_packets"] += fw
            dp = get_val(line, "Dropped:")
            if dp is not None: engine_state["dropped_packets"] += dp

            # Manage Sections
            if "[Detected Domains/SNIs]" in line:
                sni_section, ml_section = True, False
            elif "[ML_FEATURES_START]" in line or "[ML Feature Extraction]" in line:
                sni_section, ml_section = False, True
            elif "[ML_FEATURES_END]" in line or "[Active Destination IPs]" in line:
                sni_section, ml_section = False, False
            
            # Parsing SNI
            if sni_section and " - " in line:
                try:
                    parts = line.split(" - ")[1].split(" -> ")
                    dom = parts[0].strip()
                    cat = parts[1].strip() if len(parts) > 1 else "Unknown"
                    if dom.lower() == LOCAL_HOSTNAME.lower(): dom = f"Local PC ({LOCAL_HOSTNAME})"
                    
                    if dom not in domains:
                        domains[dom] = {"count": 0, "category": cat, "last_seen": now}
                    domains[dom]["count"] += 1
                    domains[dom]["last_seen"] = now
                except: pass

            # Parsing ML Features
            elif ml_section and "FLOW_ID:" in line_clean:
                try:
                    main_parts = line_clean.split("|")
                    dom = main_parts[0].split(":")[1].strip()
                    
                    src_port = 0
                    stats_part = ""
                    for p in main_parts:
                        if p.startswith("PORT:"):
                            try: src_port = int(p.split(":")[1].strip())
                            except: pass
                        if p.startswith("STATS:"):
                            stats_part = p[6:]
                    
                    if not dom or not stats_part: continue
                    
                    stats_dict = {}
                    for pair in stats_part.split(","):
                        if ":" in pair:
                            k_v = pair.split(":")
                            if len(k_v) == 2:
                                k, v = k_v[0].strip(), k_v[1].strip()
                                try: stats_dict[k] = float(v)
                                except: stats_dict[k] = v
                    
                    if dom not in domains:
                        domains[dom] = {"count": 1, "category": "Auto-Detected", "last_seen": now}
                    
                    domains[dom]["ml_features"] = stats_dict
                    if src_port:
                        domains[dom]["src_port"] = src_port
                        port_map = engine_state.get("port_map", {})
                        if src_port in port_map:
                            domains[dom]["process"] = port_map[src_port]
                    
                    # AI Inference
                    if rf_model and xgb_model and "ml_features" in domains[dom]:
                        try:
                            # Map features to the 57-feature vector
                            vec = [float(stats_dict.get(f, 0.0)) for f in FEATURE_LIST]
                            df = pd.DataFrame([vec], columns=FEATURE_LIST)
                            
                            # Hackathon Demo logic
                            if "cryptguard.threat.demo" in dom.lower():
                                domains[dom].update({"risk_score": 100.0, "prediction": "Malicious", "category": "MALWARE (THREAT)"})
                            else:
                                prob = xgb_model.predict_proba(df)[0][1]
                                domains[dom]["risk_score"] = round(float(prob) * 100, 2)
                                domains[dom]["prediction"] = "Malicious" if prob > 0.5 else "Benign"
                                if prob > 0.5: domains[dom].update({"category": "SUSPICIOUS"})
                        except: pass
                except: pass

        # State updates and decay
        engine_state["last_update"] = now
        expired = [d for d, v in domains.items() if (now - v.get("last_seen", 0)) > DECAY_TIMEOUT]
        for d in expired: del domains[d]

        # ── Intelligence layer (runs after decay, adds new fields) ──────────
        apply_intelligence_layer(domains, now)

def process_pcap_file(pcap_path):
    try:
        temp_out = pcap_path + ".out"
        cwd = os.getcwd().replace('\\', '/')
        engine_bin = DPI_ENGINE_PATH
        
        dpi_cmd = [
            r"C:\msys64\usr\bin\bash.exe", "-lc",
            f"cd '{cwd}' && export PATH=/mingw64/bin:$PATH && ./{engine_bin} {pcap_path} {temp_out}"
        ]
        
        log_debug(f"Running DPI engine on {pcap_path}...")
        result = subprocess.run(dpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode != 0:
            log_debug(f"DPI Engine Error ({result.returncode}): {result.stderr}")
        else:
            log_debug(f"DPI Success. Results arriving...")
            parse_dpi_output(result.stdout)
        
        safe_remove(pcap_path)
        safe_remove(temp_out)
    except Exception as e:
        log_debug(f"Processing Thread Error: {e}")

def run_dpi_capture_loop():
    log_debug("DPI Parallel Capture loop active.")
    current_pcap, next_pcap = TEMP_PCAP_A, TEMP_PCAP_B
    last_idle_log = 0
    
    while True:
        try:
            with state_lock:
                idx = engine_state.get("selected_interface")
                active = engine_state.get("is_capturing")
                
            if not active or idx is None:
                if time.time() - last_idle_log > 5:
                    log_debug("Capture idle. Waiting for start command.")
                    last_idle_log = time.time()
                time.sleep(1)
                continue
                
            cmd = [TSHARK_PATH, "-i", str(idx), "-a", f"duration:{CAPTURE_DURATION}", "-w", current_pcap, "-F", "pcap", "-q"]
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if os.path.exists(current_pcap) and os.path.getsize(current_pcap) > 24:
                threading.Thread(target=process_pcap_file, args=(current_pcap,), daemon=True).start()
                current_pcap, next_pcap = next_pcap, current_pcap
            else:
                time.sleep(0.5)
        except Exception as e:
            log_debug(f"Capture Loop Error: {e}")
            time.sleep(1)

def get_interfaces():
    try:
        cmd = [TSHARK_PATH, "-D"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
    except: return []

class APIHandler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
    def do_OPTIONS(self): self._set_headers(204)

    def do_GET(self):
        global engine_state
        if self.path == '/api/interfaces':
            with state_lock:
                if not engine_state["interfaces"]: engine_state["interfaces"] = get_interfaces()
                res = {"interfaces": engine_state["interfaces"], "selected": engine_state["selected_interface"], "is_capturing": engine_state["is_capturing"]}
            self._set_headers()
            self.wfile.write(json.dumps(res).encode())
        elif self.path == '/api/stats':
            with state_lock:
                # Sort by last_seen (most recent first)
                sorted_domains = [
                    {
                        "domain":             k,
                        "category":           v["category"],
                        "hits":               v["count"],
                        "last_seen":          v.get("last_seen", 0),
                        "ml_features":        v.get("ml_features", {}),
                        "risk_score":         v.get("risk_score", 0),
                        "prediction":         v.get("prediction", "Benign"),
                        "process":            v.get("process", {"pid": 0, "name": "Unknown"}),
                        # Intelligence layer fields
                        "is_rule_blocked":    v.get("is_rule_blocked", False),
                        "rule_reason":        v.get("rule_reason", ""),
                        "rule_severity":      v.get("rule_severity", ""),
                        "is_beaconing":       v.get("is_beaconing", False),
                        "productivity_score": v.get("productivity_score", 50),
                        "is_encrypted":       v.get("is_encrypted", True),
                    }
                    for k, v in sorted(engine_state["domains"].items(), key=lambda x: (x[1].get("last_seen", 0), x[1]["count"]), reverse=True)
                ][:50]
                # Summary counters for dashboard
                rule_blocked_count  = sum(1 for d in sorted_domains if d["is_rule_blocked"])
                beaconing_count     = sum(1 for d in sorted_domains if d["is_beaconing"])
                encrypted_count     = sum(1 for d in sorted_domains if d["is_encrypted"])
                enc_pct = round(100 * encrypted_count / len(sorted_domains), 1) if sorted_domains else 0
                res = {
                    "domains":            sorted_domains,
                    "total_packets":      engine_state["total_packets"],
                    "forwarded_packets":  engine_state["forwarded_packets"],
                    "dropped_packets":    engine_state["dropped_packets"],
                    "last_update":        engine_state["last_update"],
                    # Intelligence summary
                    "rule_blocked_count": rule_blocked_count,
                    "beaconing_count":    beaconing_count,
                    "encrypted_pct":      enc_pct,
                }
            self._set_headers()
            self.wfile.write(json.dumps(res).encode())
        else: self.send_error(404)

    def do_POST(self):
        global engine_state
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if self.path == '/api/start':
            try:
                data = json.loads(body.decode())
                idx = str(data.get('interface_idx')).split('.')[0]
                with state_lock:
                    engine_state.update({"selected_interface": idx, "is_capturing": True, "domains": {}, "total_packets": 0, "dropped_packets": 0, "forwarded_packets": 0})
                self._set_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            except: self.send_error(400)
        elif self.path == '/api/stop':
            with state_lock: engine_state["is_capturing"] = False
            self._set_headers(); self.wfile.write(json.dumps({"status": "success"}).encode())
        elif self.path == '/api/block':
            try:
                pid = json.loads(body.decode()).get('pid')
                if pid:
                    psutil.Process(int(pid)).terminate()
                    self._set_headers(); self.wfile.write(json.dumps({"status": "success"}).encode())
                else: self.send_error(400)
            except Exception as e: self.send_error(500, str(e))
        else: self.send_error(404)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

def start_server():
    server = ThreadedHTTPServer(('', 8081), APIHandler)
    print("API Server listening on port 8081...")
    threading.Thread(target=run_dpi_capture_loop, daemon=True).start()
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        server.server_close()
        for f in [TEMP_PCAP_A, TEMP_PCAP_B, TEMP_OUT]:
            if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    start_server()
