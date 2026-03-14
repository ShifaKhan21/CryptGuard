import http.server
import socketserver
import threading
import time
import subprocess
import os
import json

# Configuration
PORT = 5000
DPI_ENGINE = os.path.join("Packet_analyzer", "dpi_engine.exe")
GENERATE_SCRIPT = os.path.join("Packet_analyzer", "generate_test_pcap.py")
INPUT_PCAP = "live_temp.pcap"
OUTPUT_PCAP = "live_out.pcap"
JSON_REPORT = "live_report.json"

class LiveHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        return super().end_headers()

    def do_GET(self):
        if self.path == '/api/stats':
            if os.path.exists(JSON_REPORT):
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                with open(JSON_REPORT, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Report not ready")
        else:
            self.send_error(404)

def run_dpi_loop():
    print("[Bridge] Starting DPI simulation loop...")
    while True:
        try:
            # 1. Generate fresh packets
            subprocess.run(["python", GENERATE_SCRIPT, INPUT_PCAP], check=True, capture_output=True)
            
            # 2. Run DPI Engine (ensure MSYS2 DLLs are in path)
            env = os.environ.copy()
            env["PATH"] = env["PATH"] + ";C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin"
            
            subprocess.run([
                DPI_ENGINE, 
                INPUT_PCAP, 
                OUTPUT_PCAP, 
                "--json", JSON_REPORT
            ], env=env, check=True, capture_output=True)
            
            print(f"[Bridge] report updated at {time.ctime()}")
        except Exception as e:
            print(f"[Bridge] Error: {e}")
        
        time.sleep(3)

if __name__ == "__main__":
    # Start DPI loop in background
    threading.Thread(target=run_dpi_loop, daemon=True).start()
    
    # Start HTTP server
    with socketserver.TCPServer(("", PORT), LiveHandler) as httpd:
        print(f"[Bridge] Serving dashboard data at http://localhost:{PORT}/api/stats")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[Bridge] Shutting down...")
            httpd.shutdown()
