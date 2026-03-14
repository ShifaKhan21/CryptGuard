"""
CryptGuard – Python Bridge Server
Generates a minimal test PCAP, runs dpi_engine.exe, serves JSON to the dashboard.
No external dependencies beyond Python stdlib.
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

PORT = 5000
DPI_ENGINE   = os.path.join("Packet_analyzer", "dpi_engine.exe")
INPUT_PCAP   = "live_temp.pcap"
OUTPUT_PCAP  = "live_out.pcap"
JSON_REPORT  = "live_report.json"

# ── PCAP helpers ──────────────────────────────────────────────────────────────
GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_record(payload: bytes) -> bytes:
    ts = int(time.time())
    return struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload

def eth_ip_tcp(src_ip, dst_ip, dst_port, tcp_payload=b""):
    # Ethernet header (dest=ff:ff..., src=00:00..., type=IPv4)
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00"
    ip_len = 20 + 20 + len(tcp_payload)
    # IP header (no options, ttl=64, proto=6/TCP)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_len, random.randint(1,65535), 0,
        64, 6, 0,
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split("."))))
    # TCP header (src_port random, dst_port given, no options)
    tcp = struct.pack("!HHIIBBHHH",
        random.randint(1024,65535), dst_port,
        random.randint(0,2**32-1), 0,
        0x50, 0x18, 8192, 0, 0)
    return eth + ip + tcp + tcp_payload

def tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS Client Hello with a given SNI."""
    name  = sni.encode()
    # SNI extension
    sni_ext_data = struct.pack("!HBH", len(name)+3, 0, len(name)) + name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    exts = sni_ext  # only one extension for simplicity
    # ClientHello body
    random_bytes = os.urandom(32)
    ch_body = (
        b"\x03\x03"      # TLS 1.2
        + random_bytes   # random
        + b"\x00"        # session id length
        + struct.pack("!H", 2) + b"\xc0\x2b"  # 1 cipher suite
        + b"\x01\x00"    # compression
        + struct.pack("!H", len(exts)) + exts
    )
    # Handshake record
    hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
    # TLS record
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

DOMAINS = [
    ("google.com",    "8.8.8.8"),
    ("youtube.com",   "142.250.1.1"),
    ("facebook.com",  "31.13.64.35"),
    ("instagram.com", "157.240.2.13"),
    ("netflix.com",   "54.74.50.50"),
    ("discord.com",   "162.159.130.234"),
    ("github.com",    "140.82.114.4"),
    ("twitter.com",   "104.244.42.1"),
    ("spotify.com",   "35.186.224.25"),
    ("zoom.us",       "170.114.52.2"),
]

def generate_test_pcap(path: str, num_packets: int = 60):
    with open(path, "wb") as f:
        f.write(GLOBAL_HEADER)
        for _ in range(num_packets):
            src_ip = f"192.168.1.{random.randint(2,254)}"
            domain, dst_ip = random.choice(DOMAINS)
            payload = tls_client_hello(domain)
            pkt = eth_ip_tcp(src_ip, dst_ip, 443, payload)
            f.write(pcap_record(pkt))
        # a few plain HTTP and DNS
        for _ in range(10):
            src_ip = f"192.168.1.{random.randint(2,254)}"
            pkt = eth_ip_tcp(src_ip, "1.1.1.1", 80)
            f.write(pcap_record(pkt))

# ── HTTP Handler ───────────────────────────────────────────────────────────────
class LiveHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass  # suppress access logs

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
        else:
            self.send_error(404)

# ── DPI loop ───────────────────────────────────────────────────────────────────
def run_dpi_loop():
    print("[Bridge] DPI simulation loop started.")
    env = os.environ.copy()
    env["PATH"] = env.get("PATH", "") + ";C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin"

    while True:
        try:
            generate_test_pcap(INPUT_PCAP)
            result = subprocess.run(
                [DPI_ENGINE, INPUT_PCAP, OUTPUT_PCAP, "--json", JSON_REPORT],
                env=env, capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"[Bridge] Report updated ({time.strftime('%H:%M:%S')})")
            else:
                print(f"[Bridge] Engine error (code {result.returncode}):")
                print(result.stderr[:400])
        except Exception as exc:
            print(f"[Bridge] Exception: {exc}")
        time.sleep(3)

# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    threading.Thread(target=run_dpi_loop, daemon=True).start()
    print(f"[Bridge] HTTP API on http://localhost:{PORT}/api/stats")
    with socketserver.TCPServer(("", PORT), LiveHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[Bridge] Shutdown.")
            httpd.shutdown()
