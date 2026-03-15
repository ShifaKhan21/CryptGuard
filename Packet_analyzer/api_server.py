import subprocess
import os
import sys
import time
import json
import threading
import platform
import socket
import pickle
import pandas as pd
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# Try loading XGBoost model
ML_MODEL = None
EXPECTED_FEATURES = None
try:
    with open('model/xgb_model.pkl', 'rb') as f:
        ML_MODEL = pickle.load(f)
        if hasattr(ML_MODEL, 'feature_names_in_'):
            EXPECTED_FEATURES = list(ML_MODEL.feature_names_in_)
            print(f"✅ Loaded XGBoost Model with {len(EXPECTED_FEATURES)} features.")
        else:
            print("⚠️ Loaded XGBoost Model but it's missing 'feature_names_in_' metadata.")
except Exception as e:
    print(f"❌ Failed to load ML Model: {e}")

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
TEMP_PCAP = "api_temp_capture.pcap"
TEMP_OUT = "api_temp_output.pcap"
CAPTURE_DURATION = 1.0  # Reduced for faster detection (within 1-2 seconds)
DECAY_TIMEOUT = 30 # Keep traffic visible for 30s for better dashboard experience

# Global State
LOCAL_HOSTNAME = socket.gethostname()
engine_state = {
    "interfaces": [],
    "selected_interface": None,
    "is_capturing": False,
    "domains": {}, # Format: {domain: {"count": X, "category": Y, "last_seen": timestamp, "last_seen_time": str, "ml_prediction": str, "ml_confidence": str}}
    "last_update": 0,
    "total_packets": 0,
    "dropped_packets": 0,
    "forwarded_packets": 0
}

state_lock = threading.Lock()
dns_cache = {}
dns_queue = []
dns_lock = threading.Lock()

ip_to_domain_cache = {} # Persistent IP -> Domain mapping

def dns_resolve_worker():
    """Background thread to resolve IPs without stalling the main loop"""
    while True:
        ip = None
        with dns_lock:
            if dns_queue:
                ip = dns_queue.pop(0)
        
        if ip:
            if ip not in dns_cache:
                try:
                    host = socket.gethostbyaddr(ip)[0]
                    if host:
                        # Clean up names
                        if host.lower() == LOCAL_HOSTNAME.lower():
                            dns_cache[ip] = "Local PC (" + LOCAL_HOSTNAME + ")"
                        else:
                            parts = host.split('.')
                            clean_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host
                            dns_cache[ip] = clean_domain
                except:
                    dns_cache[ip] = None
        else:
            time.sleep(0.5)

# Start DNS worker
threading.Thread(target=dns_resolve_worker, daemon=True).start()


def get_interfaces():
    try:
        cmd = [TSHARK_PATH, "-D"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                interfaces.append(line)
        return interfaces
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        return []


def log_debug(msg):
    with open("debug.log", "a") as f:
        f.write(f"{time.time()}: {msg}\n")

def run_ml_inference(pcap_file, features_csv, results_list):
    """Parallel worker for ML inference"""
    if not ML_MODEL or not EXPECTED_FEATURES:
        return

    try:
         # Run cicflowmeter
         cf_cmd = [sys.executable, "-m", "cicflowmeter.sniffer", "-f", pcap_file, "-c", features_csv]
         subprocess.run(cf_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
         
         if os.path.exists(features_csv):
             df = pd.read_csv(features_csv)
             available_features = [col for col in EXPECTED_FEATURES if col in df.columns]
             
             if len(available_features) == len(EXPECTED_FEATURES):
                 X_pred = df[EXPECTED_FEATURES]
                 preds = ML_MODEL.predict(X_pred)
                 probs = ML_MODEL.predict_proba(X_pred) if hasattr(ML_MODEL, "predict_proba") else []
                 
                 for idx, ((_, row), pred, prob) in enumerate(zip(df.iterrows(), preds, probs if len(probs) > 0 else [[0, 0]] * len(preds))):
                     src_ip = row.get('Src IP')
                     dst_ip = row.get('Dst IP')
                     pred_class = "MALWARE" if pred == 1 else "BENIGN"
                     confidence = round(float(prob.max() if hasattr(prob, 'max') else max(prob)) * 100, 1) if prob is not None else "--"
                     
                     raw_features = {feat: str(row.get(feat, "")) for feat in EXPECTED_FEATURES}
                     
                     results_list.append({
                         "ip1": src_ip, 
                         "ip2": dst_ip, 
                         "class": pred_class, 
                         "conf": confidence,
                         "features": raw_features
                     })
    except Exception as e:
        log_debug(f"ML Parallel Error: {e}")
    finally:
        try:
            if os.path.exists(features_csv): os.remove(features_csv)
        except: pass

def run_dpi_capture_loop():
    global engine_state
    
    log_debug("DPI Capture loop started...")
    
    while True:
        with state_lock:
            interface_idx = engine_state.get("selected_interface")
            is_capturing = engine_state.get("is_capturing")
            
        if not is_capturing or interface_idx is None:
            time.sleep(1)
            continue
            
        # 1. Capture traffic using tshark
        try:
            cmd = [TSHARK_PATH, "-i", str(interface_idx), "-a", f"duration:{CAPTURE_DURATION}", "-w", TEMP_PCAP, "-F", "pcap", "-q"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception as e:
            print(f"Error during packet capture: {e}")
            time.sleep(1)
            continue

        if not os.path.exists(TEMP_PCAP):
            cont        # 2. Parallel Processing: ML Inference & DPI Engine
        flow_predictions = []
        features_csv = f"live_features_{int(time.time())}.csv"
        
        ml_thread = threading.Thread(target=run_ml_inference, args=(TEMP_PCAP, features_csv, flow_predictions))
        ml_thread.start()

        dpi_output = ""
        try:
            cwd = os.getcwd().replace('\\', '/')
            dpi_cmd = [
                r"C:\msys64\usr\bin\bash.exe", "-lc",
                f"cd '{cwd}' && export PATH=/mingw64/bin:$PATH && ./{DPI_ENGINE_PATH} {TEMP_PCAP} {TEMP_OUT}"
            ]
            result = subprocess.run(dpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            dpi_output = result.stdout
        except Exception as e:
            log_debug(f"DPI Engine Error: {e}")

        # Wait for ML to finish (with short timeout to keep UI snappy)
        ml_thread.join(timeout=2.0)

        # 3. Parse and aggregate output
        now = time.time()
        now_time = time.strftime('%H:%M:%S', time.localtime(now))
        with state_lock:
            # PRUNING: Remove stale domains (not seen in DECAY_TIMEOUT seconds)
            stale_keys = [k for k, v in engine_state["domains"].items() if now - v.get("last_seen", 0) > DECAY_TIMEOUT]
            for k in stale_keys:
                del engine_state["domains"][k]
            
            # Parse packet stats
            lines = dpi_output.split('\n')
            sni_section = False
            active_ip_section = False
            
            for line in lines:
                line = line.replace("║", "").strip()
                if not line: continue

                if line.startswith("Total Packets:"):
                     parts = line.split()
                     if len(parts) >= 3:
                         try: engine_state["total_packets"] += int(parts[2])
                         except: pass
                elif line.startswith("Forwarded:"):
                     parts = line.split()
                     if len(parts) >= 2:
                         try: engine_state["forwarded_packets"] += int(parts[1])
                         except: pass
                elif line.startswith("Dropped:"):
                     parts = line.split()
                     if len(parts) >= 2:
                         try: engine_state["dropped_packets"] += int(parts[1])
                         except: pass
                          
                if "[Detected Domains/SNIs]" in line or "[Detected Applications/Domains]" in line:
                    sni_section = True
                    active_ip_section = False
                    continue
                
                if "[Active Destination IPs]" in line:
                    sni_section = False
                    active_ip_section = True
                    continue

                if sni_section:
                    if line.startswith("- "):
                        parts = line[2:].split(" -> ")
                        if len(parts) >= 2:
                            domain = parts[0]
                            category = parts[1]
                            if domain.lower() == LOCAL_HOSTNAME.lower():
                                domain = "Local PC (" + LOCAL_HOSTNAME + ")"

                            if domain not in engine_state["domains"]:
                                engine_state["domains"][domain] = {
                                    "count": 0, "category": category, "last_seen": now, "last_seen_time": now_time, "ml_prediction": "BENIGN", "ml_confidence": "--", "extended_features": {}
                                }
                            engine_state["domains"][domain]["count"] += 1
                            engine_state["domains"][domain]["last_seen"] = now
                            engine_state["domains"][domain]["last_seen_time"] = now_time
                    elif not line.startswith("║"):
                        sni_section = False

                if active_ip_section:
                    if line.startswith("- IP: "):
                        ip_addr = line[6:].strip()
                        resolved = dns_cache.get(ip_addr) or ip_to_domain_cache.get(ip_addr)
                        
                        if resolved:
                            if resolved not in engine_state["domains"]:
                                engine_state["domains"][resolved] = {
                                    "count": 0, "category": "Active Connection", "last_seen": now, "last_seen_time": now_time, "ml_prediction": "BENIGN", "ml_confidence": "--", "extended_features": {}
                                }
                            
                            # Correlate flow predictions
                            for f_pred in flow_predictions:
                                 if ip_addr == f_pred['ip1'] or ip_addr == f_pred['ip2']:
                                     engine_state["domains"][resolved]["extended_features"] = f_pred['features']
                                     if f_pred['class'] == 'MALWARE':
                                          engine_state["domains"][resolved]["ml_prediction"] = "MALWARE"
                                          engine_state["domains"][resolved]["ml_confidence"] = f_pred['conf']
                                          break
                                     else:
                                          if engine_state["domains"][resolved].get("ml_prediction") != "MALWARE":
                                              engine_state["domains"][resolved]["ml_prediction"] = f_pred['class']
                                              engine_state["domains"][resolved]["ml_confidence"] = f_pred['conf']
                                              
                            engine_state["domains"][resolved]["count"] += 1
                            engine_state["domains"][resolved]["last_seen"] = now
                            engine_state["domains"][resolved]["last_seen_time"] = now_time
                            ip_to_domain_cache[ip_addr] = resolved
                        else:
                            # Add to resolution queue if unknown
                            with dns_lock:
                                if ip_addr not in dns_queue:
                                    dns_queue.append(ip_addr)
                                    
                            # Fallback to IP as domain for visibility
                            if ip_addr not in engine_state["domains"]:
                                engine_state["domains"][ip_addr] = {
                                    "count": 0, "category": "Active Connection (IP)", "last_seen": now, "last_seen_time": now_time, "ml_prediction": "BENIGN", "ml_confidence": "--", "extended_features": {}
                                }
                            engine_state["domains"][ip_addr]["count"] += 1
                            engine_state["domains"][ip_addr]["last_seen"] = now
                            engine_state["domains"][ip_addr]["last_seen_time"] = now_time
                    elif not line.startswith("║"):
                        active_ip_section = False

            engine_state["last_update"] = now
            
        # Cleanup
        except: pass

    except Exception as e:
            print(f"Error running DPI engine: {e}")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    allow_reuse_address = True

class APIHandler(BaseHTTPRequestHandler):
    
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        global engine_state
        
        if self.path == '/api/interfaces':
            with state_lock:
                if not engine_state["interfaces"]:
                    engine_state["interfaces"] = get_interfaces()
                
                response = {
                    "interfaces": engine_state["interfaces"],
                    "selected": engine_state["selected_interface"],
                    "is_capturing": engine_state["is_capturing"]
                }
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            
        elif self.path == '/api/stats':
            with state_lock:
                # Sort by last_seen (most recent first), then by hits
                sorted_domains = [
                    {
                        "domain": k, 
                        "category": v["category"], 
                        "hits": v["count"], 
                        "last_seen": v.get("last_seen", 0),
                        "last_seen_time": v.get("last_seen_time", "--:--:--"),
                        "ml_prediction": v.get("ml_prediction", "BENIGN"),
                        "ml_confidence": v.get("ml_confidence", "--"),
                        "extended_features": v.get("extended_features", {})
                    }
                    for k, v in sorted(engine_state["domains"].items(), key=lambda item: (item[1].get("last_seen", 0), item[1]["count"]), reverse=True)
                ][:50]
                
                response = {
                    "domains": sorted_domains,
                    "total_packets": engine_state["total_packets"],
                    "forwarded_packets": engine_state["forwarded_packets"],
                    "dropped_packets": engine_state["dropped_packets"],
                    "last_update": engine_state["last_update"]
                }
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        global engine_state
        
        if self.path == '/api/start':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                interface_idx = data.get('interface_idx')
                
                if interface_idx is None:
                    self.send_error(400, "Missing interface_idx")
                    return
                if isinstance(interface_idx, str) and '. ' in interface_idx:
                    interface_idx = interface_idx.split('.')[0]
                    
                with state_lock:
                    engine_state["selected_interface"] = str(interface_idx)
                    engine_state["is_capturing"] = True
                    engine_state["domains"] = {}
                    engine_state["total_packets"] = 0
                    engine_state["dropped_packets"] = 0
                    engine_state["forwarded_packets"] = 0
                    
                self._set_headers()
                self.wfile.write(json.dumps({"status": "success", "message": "Capture started"}).encode())
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON data")
                
        elif self.path == '/api/stop':
             with state_lock:
                 engine_state["is_capturing"] = False
             self._set_headers()
             self.wfile.write(json.dumps({"status": "success", "message": "Capture stopped"}).encode())
        else:
            self.send_error(404, "Not Found")

def start_server():
    server_address = ('', 8081)
    httpd = ThreadedHTTPServer(server_address, APIHandler)
    print(f"API Server listening on port 8081...")
    
    capture_thread = threading.Thread(target=run_dpi_capture_loop, daemon=True)
    capture_thread.start()
    
    try:
        httpd.serve_forever()
    except Exception as e:
        print(f'CRASH: {e}')
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down API server...")
        httpd.server_close()
        
        if os.path.exists(TEMP_PCAP): os.remove(TEMP_PCAP)
        if os.path.exists(TEMP_OUT): os.remove(TEMP_OUT)

if __name__ == "__main__":
    start_server()
