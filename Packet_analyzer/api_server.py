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
from concurrent.futures import ThreadPoolExecutor

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
TEMP_PCAP = "api_temp_capture.pcap"
TEMP_OUT = "api_temp_output.pcap"
CAPTURE_DURATION = 2  # Reduced for faster updates

# Global State
LOCAL_HOSTNAME = socket.gethostname()

def debug_log(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    try:
        with open("debug.log", "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    except:
        pass

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

def get_friendly_name(ip):
    """Returns a friendly name for common network addresses or internal IPs"""
    try:
        # Exact matches
        exact_matches = {
            "255.255.255.255": "Broadcast",
            "0.0.0.0": "Any Interface",
            "1.1.1.1": "Cloudflare DNS",
            "8.8.8.8": "Google DNS",
            "8.8.4.4": "Google DNS",
        }
        if ip in exact_matches: return exact_matches[ip]
        
        # Ranges and Patterns
        if ip.startswith("224.") or ip.startswith("239."): return "Multicast/Discovery"
        
        # Google Services (Broad check)
        google_prefixes = ["142.250", "142.251", "172.217", "172.253", "216.58", "216.239", "74.125"]
        if any(ip.startswith(p) for p in google_prefixes): return "Google Service"
        
        # Cloudflare
        cf_prefixes = ["104.16", "104.17", "104.18", "104.19", "104.20", "172.64", "172.67", "162.159"]
        if any(ip.startswith(p) for p in cf_prefixes): return "Cloudflare CDN"

        # AWS (Highly variable, but some common ones)
        aws_prefixes = ["52.216", "52.217", "54.231", "54.239", "3.5", "18.160", "13.224"]
        if any(ip.startswith(p) for p in aws_prefixes): return "AWS Service"

        # Private ranges
        parts = list(map(int, ip.split('.')))
        if parts[0] == 10: return "Internal Network (10.x)"
        if parts[0] == 172 and 16 <= parts[1] <= 31: return "Internal Network (172.x)"
        if parts[0] == 192 and parts[1] == 168: return "Local Network (192.x)"
        
        return None
    except:
        return None

DECAY_TIMEOUT = 30 # Remove domains if not seen in 30 seconds

def resolve_single_ip(ip):
    """Thread function to resolve a single IP"""
    try:
        host = socket.gethostbyaddr(ip)[0]
        if host:
            if host.lower() == LOCAL_HOSTNAME.lower():
                res = "Local PC (" + LOCAL_HOSTNAME + ")"
            else:
                parts = host.split('.')
                res = '.'.join(parts[-2:]) if len(parts) >= 2 else host
            with dns_lock:
                dns_cache[ip] = res
            debug_log(f"Thread Resolved {ip} -> {res}")
    except Exception as e:
        if isinstance(e, socket.herror) and e.errno == 11004:
            with dns_lock:
                dns_cache[ip] = "" # Cache negative result
        else:
            # Silent fail for transient errors
            pass

def dns_manager_worker():
    """Manages a pool of DNS resolution threads"""
    debug_log("DNS Thread Manager started")
    with ThreadPoolExecutor(max_workers=20) as executor:
        while True:
            ip_to_resolve = None
            with dns_lock:
                if dns_queue:
                    # Resolve in REVERSE order (most recent first)
                    ip_to_resolve = dns_queue.pop(-1)
            
            if ip_to_resolve:
                 executor.submit(resolve_single_ip, ip_to_resolve)
            else:
                 time.sleep(0.5)

# Start DNS manager
threading.Thread(target=dns_manager_worker, daemon=True).start()

def dns_monitor_worker(interface_name):
    """Sniffs DNS traffic in the background to build a real-time IP-to-domain map"""
    try:
        # Extract interface index (e.g., "5. Wi-Fi" -> "5")
        idx = interface_name.split('.')[0]
        debug_log(f"Starting DNS monitor on interface {idx}")
        
        # tshark command to sniff DNS queries and answers
        # -f "udp port 53" captures only DNS traffic
        # -T fields -e dns.qry.name -e dns.a extracts domain and resolved IPs
        cmd = [
            TSHARK_PATH, "-i", idx, 
            "-f", "udp port 53", 
            "-T", "fields", 
            "-e", "dns.qry.name", 
            "-e", "dns.a",
            "-l" # Unbuffered line-by-line output
        ]
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        for line in iter(proc.stdout.readline, ""):
            line = line.strip()
            if not line: continue
            
            parts = line.split('\t')
            if len(parts) >= 2:
                domain = parts[0]
                ips = parts[1].split(',')
                for ip in ips:
                    ip = ip.strip()
                    if ip and ip not in dns_cache:
                        # Clean domain name
                        clean_domain = domain
                        if '.' in domain:
                            d_parts = domain.split('.')
                            if len(d_parts) >= 2:
                                clean_domain = '.'.join(d_parts[-2:])
                        
                        with dns_lock:
                            dns_cache[ip] = clean_domain
                        debug_log(f"Live DNS: {ip} -> {clean_domain}")
    except Exception as e:
        debug_log(f"DNS Monitor Error: {str(e)}")

def start_dns_monitor():
    """Starts the DNS monitor thread if an interface is selected"""
    if engine_state["selected_interface"]:
        threading.Thread(target=dns_monitor_worker, args=(engine_state["selected_interface"],), daemon=True).start()


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
    
    # Start real-time DNS monitoring
    start_dns_monitor()
    
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
            # Convert Windows path to MSYS2 format safely
            abs_cwd = os.path.abspath(os.getcwd())
            msys_cwd = abs_cwd.replace('\\', '/')
            if ':' in msys_cwd:
                drive, rest = msys_cwd.split(':', 1)
                msys_cwd = f"/{drive.lower()}{rest}"
            
            dpi_cmd = [
                r"C:\msys64\usr\bin\bash.exe", "-lc",
                f"cd '{msys_cwd}' && export PATH=/mingw64/bin:$PATH && ./{DPI_ENGINE_PATH} {TEMP_PCAP} {TEMP_OUT}"
            ]
            result = subprocess.run(dpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            dpi_output = result.stdout
            dpi_stderr = result.stderr
            
            # FORCE LOGGING to a dedicated file for this run
            with open("capture_trace.log", "a", encoding="utf-8") as f:
                f.write(f"\n--- {time.ctime()} ---\n")
                f.write(f"DPI CMD: {' '.join(dpi_cmd)}\n")
                f.write(f"DPI EXIT CODE: {result.returncode}\n")
                if dpi_stderr:
                    f.write(f"DPI STDERR: {dpi_stderr[:500]}\n")
                f.write(f"DPI OUTPUT (first 500 chars): {dpi_output[:500]}\n")
                f.write(f"DPI OUTPUT LENGTH: {len(dpi_output)}\n")
            
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

                    if "Total Packets:" in line:
                         parts = line.strip("║").strip().split(":")
                         if len(parts) >= 2:
                             try:
                                 val = "".join(filter(str.isdigit, parts[1]))
                                 total_packets += int(val)
                             except: pass
                    elif "Forwarded:" in line:
                         parts = line.strip("║").strip().split(":")
                         if len(parts) >= 2:
                             try:
                                 val = "".join(filter(str.isdigit, parts[1]))
                                 forwarded_packets += int(val)
                             except: pass
                    elif "Dropped:" in line:
                         parts = line.strip("║").strip().split(":")
                         if len(parts) >= 2:
                             try:
                                 val = "".join(filter(str.isdigit, parts[1]))
                                 dropped_packets += int(val)
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
                        if " -> " in line:
                            parts = line.strip("║").strip("- ").split(" -> ")
                            if len(parts) >= 2:
                                domain = parts[0].strip()
                                category = parts[1].strip()
                                
                                # Filter local hostname
                                if domain.lower() == LOCAL_HOSTNAME.lower():
                                    domain = "Local PC (" + LOCAL_HOSTNAME + ")"

                                if domain not in domains:
                                    domains[domain] = {"count": 0, "category": category, "last_seen": now}
                                
                                domains[domain]["count"] += 1
                                domains[domain]["last_seen"] = now
                        elif not line.startswith("║") and "[" in line:
                            sni_section = False

                    if active_ip_section:
                        if "IP:" in line:
                            parts = line.split("IP:")
                            if len(parts) > 1:
                                ip = parts[1].split()[0].strip("║() ")
                                if ip:
                                    # Add to DNS queue for resolution
                                    with dns_lock:
                                        if ip not in dns_cache and ip not in dns_queue:
                                            dns_queue.append(ip)
                                    
                                    # Check resolving cache
                                    resolved = dns_cache.get(ip)
                                    domain_key = resolved if resolved else ip
                                    
                                    if domain_key not in domains:
                                        domains[domain_key] = {"count": 0, "category": "General Traffic", "last_seen": now}
                                    
                                    domains[domain_key]["count"] += 1
                                    domains[domain_key]["last_seen"] = now
                                    
                        elif not line.startswith("║") and "[" in line:
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
                # Resolve names for display and aggregate
                aggregated_stats = {}
                for k, v in engine_state["domains"].items():
                    # Standardize raw key
                    lookup_key = k.lower().strip('.')
                    is_ip = False
                    try:
                        socket.inet_aton(lookup_key)
                        is_ip = True
                    except:
                        pass
                    
                    display_name = lookup_key
                    if is_ip:
                         # 1. Try Cache
                         with dns_lock:
                             resolved = dns_cache.get(lookup_key)
                         
                         if resolved and resolved != "":
                             display_name = resolved.lower().strip('.')
                         else:
                             # 2. Try Friendly Names (Multicast, Broadcast, etc.)
                             friendly = get_friendly_name(lookup_key)
                             if friendly:
                                 display_name = friendly
                             else:
                                 # 3. Queue for worker if unknown
                                 with dns_lock:
                                     if lookup_key not in dns_queue:
                                         dns_queue.append(lookup_key)
                    
                    if display_name not in aggregated_stats:
                        aggregated_stats[display_name] = {
                            "domain": display_name,
                            "category": v.get("category", "General Traffic"),
                            "hits": 0,
                            "last_seen": 0,
                            "ml_features": {}
                        }
                    
                    stats_ref = aggregated_stats[display_name]
                    # Update hits and last_seen
                    stats_ref["hits"] += v.get("count", 0)
                    stats_ref["last_seen"] = max(stats_ref["last_seen"], v.get("last_seen", 0))
                    
                    # Merge ML features if available
                    if v.get("ml_features"):
                        stats_ref["ml_features"].update(v["ml_features"])
                
                # Sort by last_seen then by hits
                sorted_domains = sorted(
                    list(aggregated_stats.values()), 
                    key=lambda x: (x.get("last_seen", 0), x["hits"]), 
                    reverse=True
                )[:50]
                
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
