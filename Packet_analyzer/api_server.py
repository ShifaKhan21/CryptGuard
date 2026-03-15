import subprocess
import os
import sys
import time
import json
import threading
import platform
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
TEMP_PCAP = "api_temp_capture.pcap"
TEMP_OUT = "api_temp_output.pcap"
CAPTURE_DURATION = 2  # Reduced for faster updates

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
    "forwarded_packets": 0
}

state_lock = threading.Lock()
dns_cache = {}
dns_queue = []
dns_lock = threading.Lock()

DECAY_TIMEOUT = 30 # Remove domains if not seen in 30 seconds

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
    try:
        with open("debug.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')}: {msg}\n")
    except Exception as e:
        print(f"Logging error: {e}")

def safe_remove(file_path):
    """Safely remove a file with retries for Windows file locks"""
    if not os.path.exists(file_path):
        return
    for _ in range(5):
        try:
            os.remove(file_path)
            return
        except OSError:
            time.sleep(0.5)

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
            
        # 0. Pre-cleanup
        safe_remove(TEMP_PCAP)
        safe_remove(TEMP_OUT)

        # 1. Capture traffic using tshark
        try:
            cmd = [TSHARK_PATH, "-i", str(interface_idx), "-a", f"duration:{CAPTURE_DURATION}", "-w", TEMP_PCAP, "-F", "pcap", "-q"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception as e:
            print(f"Error during packet capture: {e}")
            time.sleep(1)
            continue

        if not os.path.exists(TEMP_PCAP):
            continue

        # 2. Run C++ DPI engine
        try:
            cwd = os.getcwd().replace('\\', '/')
            dpi_cmd = [
                r"C:\msys64\usr\bin\bash.exe", "-lc",
                f"cd '{cwd}' && export PATH=/mingw64/bin:$PATH && ./{DPI_ENGINE_PATH} {TEMP_PCAP} {TEMP_OUT}"
            ]
            result = subprocess.run(dpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            dpi_output = result.stdout
            
            # 3. Parse and aggregate output
            now = time.time()
            with state_lock:
                # Use local references with explicit casts for Pyre
                domains = engine_state["domains"]
                total_packets = int(engine_state.get("total_packets", 0))
                forwarded_packets = int(engine_state.get("forwarded_packets", 0))
                dropped_packets = int(engine_state.get("dropped_packets", 0))
                
                # Parse packet stats
                lines = dpi_output.split('\n')
                sni_section = False
                active_ip_section = False
                ml_section = False
                
                for line in lines:
                    line = line.strip()
                    if not line: continue

                    if line.startswith("║ Total Packets:"):
                         parts = line.split()
                         if len(parts) >= 4:
                             try: total_packets += int(parts[3])
                             except: pass
                    elif line.startswith("║ Forwarded:"):
                         parts = line.split()
                         if len(parts) >= 3:
                             try: forwarded_packets += int(parts[2])
                             except: pass
                    elif line.startswith("║ Dropped:"):
                         parts = line.split()
                         if len(parts) >= 3:
                             try: dropped_packets += int(parts[2])
                             except: pass
                             
                    # Section detection
                    if "[Detected Domains/SNIs]" in line:
                        sni_section = True
                        active_ip_section = False
                        continue
                    
                    if "[Active Destination IPs]" in line:
                        sni_section = False
                        active_ip_section = True
                        ml_section = False
                        continue

                    if "[ML_FEATURES_START]" in line:
                        sni_section = False
                        active_ip_section = False
                        ml_section = True
                        continue
                        
                    if "[ML_FEATURES_END]" in line:
                        ml_section = False
                        continue

                    # Parse data lines
                    if sni_section:
                        if line.startswith("- "):
                            parts = line[2:].split(" -> ")
                            if len(parts) >= 2:
                                domain = parts[0]
                                category = parts[1]
                                
                                # Filter local hostname
                                if domain.lower() == LOCAL_HOSTNAME.lower():
                                    domain = "Local PC (" + LOCAL_HOSTNAME + ")"

                                if domain not in domains:
                                    domains[domain] = {"count": 0, "category": category, "last_seen": now}
                                
                                if domain in domains:
                                    domains[domain]["count"] += 1
                                    domains[domain]["last_seen"] = now
                        elif not line.startswith("║"):
                            sni_section = False

                    if active_ip_section:
                        if not line.startswith("║") and "[" in line:
                            active_ip_section = False
                        continue

                    if ml_section:
                        if line.startswith("FLOW_ID:"):
                            # Format: FLOW_ID:domain|IP:123|STATS:Key:Val,Key:Val...
                            try:
                                main_parts = line.split("|")
                                domain = main_parts[0].split(":")[1]
                                if not domain: continue # Only track SNI/Known domains for now
                                
                                stats_str = main_parts[2].split(":", 1)[1]
                                stats_dict = {}
                                for pair in stats_str.split(","):
                                    if ":" in pair:
                                        k, v = pair.split(":")
                                        try:
                                            stats_dict[k] = float(v)
                                        except:
                                            stats_dict[k] = v
                                    
                                if domain in domains:
                                    domains[domain]["ml_features"] = stats_dict
                            except Exception as e:
                                log_debug(f"ML Parse Error: {e} on line: {line}")

                # Update state back from local vars
                engine_state["total_packets"] = total_packets
                engine_state["forwarded_packets"] = forwarded_packets
                engine_state["dropped_packets"] = dropped_packets
                engine_state["last_update"] = now
                
                # Prune old domains (Decay mechanism)
                expired_domains = [
                    d for d, data in domains.items() 
                    if now - data.get("last_seen", 0) > DECAY_TIMEOUT
                ]
                for d in expired_domains:
                    del domains[d]

            # Cleanup temp files for this iteration
            safe_remove(TEMP_PCAP)
            safe_remove(TEMP_OUT)



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
                        "ml_features": v.get("ml_features", {})
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
