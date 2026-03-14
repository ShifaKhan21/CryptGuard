"""
CryptGuard – Python Bridge Server
Supports TWO modes:
  1. REAL mode  – runs DPI engine against a real .pcap file you captured
  2. SIM mode   – generates synthetic traffic (fallback)
"""
import http.server
import socketserver
import threading
import time
import subprocess
import os
import struct
import random
import json

PORT       = 5000
DPI_ENGINE = os.path.join("Packet_analyzer", "dpi_engine.exe")
OUTPUT_PCAP = "live_out.pcap"
JSON_REPORT = "live_report.json"

# ── Real PCAP mode ─────────────────────────────────────────────────────────────
# Drop your .pcap file in the project root OR the Packet_analyzer folder.
# The server will auto-detect it.
REAL_PCAP_CANDIDATES = [
    "ana.pcap",
    os.path.join("Packet_analyzer", "ana.pcap"),
    "my_capture.pcap",
    os.path.join("Packet_analyzer", "my_capture.pcap"),
]

def find_real_pcap():
    for p in REAL_PCAP_CANDIDATES:
        if os.path.exists(p):
            return p
    return None

# ── Simulated PCAP helpers (fallback) ─────────────────────────────────────────
GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_record(payload):
    ts = int(time.time())
    return struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload

def eth_ip_tcp(src_ip, dst_ip, dst_port, tcp_payload=b""):
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00"
    ip_len = 20 + 20 + len(tcp_payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len,
                     random.randint(1,65535), 0, 64, 6, 0,
                     bytes(map(int, src_ip.split("."))),
                     bytes(map(int, dst_ip.split("."))))
    tcp = struct.pack("!HHIIBBHHH",
                      random.randint(1024,65535), dst_port,
                      random.randint(0,2**32-1), 0,
                      0x50, 0x18, 8192, 0, 0)
    return eth + ip + tcp + tcp_payload

def tls_client_hello(sni):
    name = sni.encode()
    sni_ext_data = struct.pack("!HBH", len(name)+3, 0, len(name)) + name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    exts = sni_ext
    random_bytes = os.urandom(32)
    ch_body = (b"\x03\x03" + random_bytes + b"\x00"
               + struct.pack("!H", 2) + b"\xc0\x2b"
               + b"\x01\x00"
               + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

DOMAINS = [
    ("google.com","8.8.8.8"), ("youtube.com","142.250.1.1"),
    ("facebook.com","31.13.64.35"), ("instagram.com","157.240.2.13"),
    ("netflix.com","54.74.50.50"), ("discord.com","162.159.130.234"),
    ("github.com","140.82.114.4"), ("twitter.com","104.244.42.1"),
    ("spotify.com","35.186.224.25"), ("zoom.us","170.114.52.2"),
]

def generate_sim_pcap(path, num=60):
    with open(path, "wb") as f:
        f.write(GLOBAL_HEADER)
        for _ in range(num):
            src = f"192.168.1.{random.randint(2,254)}"
            domain, dst = random.choice(DOMAINS)
            pkt = eth_ip_tcp(src, dst, 443, tls_client_hello(domain))
            f.write(pcap_record(pkt))
        for _ in range(10):
            src = f"192.168.1.{random.randint(2,254)}"
            pkt = eth_ip_tcp(src, "1.1.1.1", 80)
            f.write(pcap_record(pkt))

# ── HTTP Handler ───────────────────────────────────────────────────────────────
class LiveHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()

    def do_GET(self):
        if self.path == "/api/stats":
            if os.path.exists(JSON_REPORT):
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                with open(JSON_REPORT, "rb") as fh:
                    self.wfile.write(fh.read())
            else:
                self.send_error(404, "Report not ready")
        elif self.path == "/api/mode":
            # Let the UI know if we are using a real PCAP
            real = find_real_pcap()
            payload = json.dumps({"mode": "real" if real else "sim",
                                   "pcap": real or "simulation"}).encode()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(404)

# ── DPI loop ───────────────────────────────────────────────────────────────────
def run_dpi_loop():
    env = os.environ.copy()
    env["PATH"] = env.get("PATH","") + ";C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin"

    while True:
        real_pcap = find_real_pcap()

        if real_pcap:
            input_pcap = real_pcap
            print(f"[Bridge] REAL PCAP mode  →  {real_pcap}")
        else:
            input_pcap = "live_temp.pcap"
            generate_sim_pcap(input_pcap)
            print(f"[Bridge] SIM mode  →  generated {input_pcap}")

        result = subprocess.run(
            [DPI_ENGINE, input_pcap, OUTPUT_PCAP, "--json", JSON_REPORT],
            env=env, capture_output=True, text=True
        )

        if result.returncode == 0:
            print(f"[Bridge] ✓ Report ready  ({time.strftime('%H:%M:%S')}) — "
                  f"{'REAL traffic' if real_pcap else 'simulated traffic'}")
        else:
            print(f"[Bridge] ✗ Engine error (code {result.returncode})")
            if result.stderr:
                print(result.stderr[:300])

        time.sleep(3)

# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    real = find_real_pcap()
    if real:
        print(f"[Bridge] 🟢 Found REAL PCAP: {real}")
    else:
        print("[Bridge] 🔵 No real PCAP found — using simulation mode")

    threading.Thread(target=run_dpi_loop, daemon=True).start()
    print(f"[Bridge] HTTP API  →  http://localhost:{PORT}/api/stats")

    with socketserver.TCPServer(("", PORT), LiveHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()
