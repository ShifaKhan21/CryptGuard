"""
simulate_c2_beacon.py — C2 Beacon Simulator for CryptGuard Testing
====================================================================
Simulates 4 types of C2 beacon behaviour to trigger detection signals.

Run this WHILE api_server.py is running:
    python simulate_c2_beacon.py

Then check results at:
    http://localhost:8081/api/beacon-history
    http://localhost:8081/api/threat-cache
"""

import time
import json
import urllib.request
import urllib.error
from datetime import datetime

API_BASE = "http://localhost:8081/api"

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║         CryptGuard — C2 Beacon Simulator                     ║
║  This tool directly feeds beacon_detector.py via its API     ║
╚══════════════════════════════════════════════════════════════╝
""")

def api_get(path):
    try:
        with urllib.request.urlopen(f"{API_BASE}{path}", timeout=3) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def print_beacon_history():
    """Show current beacon alerts from SQLite"""
    result = api_get("/beacon-history")
    alerts = result.get("alerts", [])
    if not alerts:
        print("  [No beacon alerts yet — keep waiting...]")
        return

    print(f"\n  {'PROCESS':<20} {'DEST IP':<25} {'SCORE':>5}  {'VERDICT':<12} SIGNALS")
    print("  " + "─" * 85)
    for a in alerts[:10]:
        signals = ", ".join(a.get("signals", []))
        print(f"  {a['process_name']:<20} {a['destination_ip']:<25} {a['beacon_score']:>5}  {a['verdict']:<12} {signals}")

def print_db_stats():
    s = api_get("/threat-cache")
    print(f"\n  📊 DB Stats → Records: {s.get('total_records', 0)}  |  "
          f"Alerts: {s.get('total_alerts', 0)}  |  "
          f"Beacons: {s.get('beacon_count', 0)}  |  "
          f"Suspicious: {s.get('suspicious_count', 0)}")


# ════════════════════════════════════════════════════════════════
# SIMULATION MODE 1 — Direct SQLite Injection (FASTEST, no tshark)
# Bypasses tshark - directly feeds the beacon_detector database
# This is the BEST way to test because it doesn't need packets
# ════════════════════════════════════════════════════════════════

def simulate_via_python_directly():
    """
    Imports beacon_detector directly and feeds it test data.
    This is the FASTEST way to trigger all 4 signals.
    """
    print("\n" + "═" * 60)
    print("  MODE 1: Direct Python Simulation (Instant, No Network Needed)")
    print("═" * 60)

    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from beacon_detector import analyze_beacon
        from datetime import datetime, timedelta
        import time

        # ── SCENARIO A: Perfect C2 Beacon (All 4 signals) ──
        print("\n  🔴 Scenario A: Perfect C2 Beacon — svchost_fake.exe → 185.220.101.1")
        print("     Sending 15 connections at exact 30-second intervals at 2AM...")
        
        # Simulate at 2AM (night) with perfect timing
        base_time = datetime.now().replace(hour=2, minute=0, second=0)
        
        for i in range(15):
            ts = base_time + timedelta(seconds=i * 30)  # Perfect 30s interval
            result = analyze_beacon(
                process="svchost_fake.exe",
                destination_ip="185.220.101.1",   # Known Tor exit node IP
                packet_size=512,                   # Exact same size every time
                timestamp=ts,
                port=443
            )
            score = result['beacon_score']
            verdict = result['verdict']
            signals = result['signals_triggered']
            print(f"     Hit {i+1:2d}/15 | Score: {score:3d} | {verdict:<12} | Signals: {signals}")
            time.sleep(0.2)  # Small delay for readability

        # ── SCENARIO B: Suspicious Beacon (2 signals) ──
        print("\n  🟡 Scenario B: Suspicious Beacon — python.exe → 192.168.1.100")
        print("     Sending 8 connections at regular intervals (daytime)...")
        
        base_time2 = datetime.now()
        for i in range(8):
            ts = base_time2 + timedelta(seconds=i * 60)  # 1-minute intervals
            result = analyze_beacon(
                process="python.exe",
                destination_ip="192.168.1.100",
                packet_size=256 + (i % 3) * 5,  # Slight size variation
                timestamp=ts,
                port=8080
            )
            score = result['beacon_score']
            verdict = result['verdict']
            print(f"     Hit {i+1:2d}/8  | Score: {score:3d} | {verdict:<12} | Signals: {result['signals_triggered']}")
            time.sleep(0.1)

        # ── SCENARIO C: Normal traffic (should not trigger) ──
        print("\n  🟢 Scenario C: Normal Browser Traffic — chrome.exe → random IPs")
        destinations = ["8.8.8.8", "1.1.1.1", "142.250.80.46", "104.18.23.45", 
                        "13.107.42.12", "151.101.65.69", "192.0.2.1", "52.216.131.27"]
        for i, dest in enumerate(destinations):
            result = analyze_beacon(
                process="chrome.exe",
                destination_ip=dest,              # Different IP every time
                packet_size=100 + i * 150,        # Varying sizes
                timestamp=datetime.now(),
                port=443
            )
            score = result['beacon_score']
            verdict = result['verdict']
            print(f"     Con {i+1}/8   | Score: {score:3d} | {verdict:<12} | → {dest}")
            time.sleep(0.05)

        print("\n  ✅ Simulation complete! Checking beacon-history API...")
        time.sleep(0.5)
        print_beacon_history()
        print_db_stats()

    except ImportError as e:
        print(f"  ❌ Could not import beacon_detector: {e}")
        print("     Make sure you're in the Packet_analyzer directory!")


# ════════════════════════════════════════════════════════════════
# SIMULATION MODE 2 — Real Network Simulation (via HTTP beaconing)
# Actually sends HTTP requests to an external server at fixed intervals
# This goes through tshark → DPI → Python → beacon_detector
# ════════════════════════════════════════════════════════════════

def simulate_via_real_network(interval_sec=5, count=12):
    """
    Actually sends real HTTP requests at fixed intervals.
    tshark will capture these → DPI → beacon_detector analyzes them.
    
    Best endpoint to hit: httpbin.org/get (stable, free service)
    """
    print("\n" + "═" * 60)
    print("  MODE 2: Real Network Simulation (tshark captures these)")
    print(f"  Sending {count} HTTP requests to httpbin.org every {interval_sec}s")
    print("  Watch your CryptGuard dashboard for 'httpbin.org' to appear!")
    print("═" * 60)

    for i in range(count):
        try:
            start = time.time()
            with urllib.request.urlopen("http://httpbin.org/get?beacon=test", timeout=5) as r:
                status = r.status
            elapsed = time.time() - start
            now = datetime.now().strftime("%H:%M:%S")
            print(f"  [{now}] Beacon {i+1:2d}/{count} → httpbin.org | Status: {status} | {elapsed:.2f}s")
        except Exception as e:
            now = datetime.now().strftime("%H:%M:%S")
            print(f"  [{now}] Beacon {i+1:2d}/{count} → FAILED: {e}")
        
        if i < count - 1:
            print(f"           Waiting {interval_sec}s before next beacon...")
            time.sleep(interval_sec)

    print(f"\n  ✅ {count} beacons sent! After {count * interval_sec}s your dashboard should flag 'httpbin.org'")


# ════════════════════════════════════════════════════════════════
# MAIN MENU
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print_banner()
    
    print("  Choose simulation mode:")
    print("  [1] Direct Python Simulation ← FASTEST, instant results")
    print("  [2] Real Network Simulation  ← Slower, goes through tshark (5 min)")
    print("  [3] Check beacon history only")
    print("  [4] Clear all records and start fresh")
    print()
    
    choice = input("  Enter choice (1/2/3/4): ").strip()
    
    if choice == "1":
        simulate_via_python_directly()
    
    elif choice == "2":
        print("\n  Real network mode settings:")
        try:
            interval = int(input("  Interval between beacons in seconds [default 5]: ").strip() or "5")
            count = int(input("  Number of beacons to send [default 12]: ").strip() or "12")
        except ValueError:
            interval, count = 5, 12
        simulate_via_real_network(interval, count)
    
    elif choice == "3":
        print("\n  📋 Current Beacon History:")
        print_beacon_history()
        print_db_stats()
    
    elif choice == "4":
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(f"{API_BASE}/clear-cache", method="POST", data=b"{}")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=3) as r:
                res = json.loads(r.read())
            print(f"\n  ✅ Cleared! Deleted {res.get('deleted', 0)} records.")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    else:
        print("  Running default: Direct simulation...")
        simulate_via_python_directly()
    
    print("\n  ─────────────────────────────────────────────────────")
    print("  📌 Check results at:")
    print("     http://localhost:8081/api/beacon-history")
    print("     http://localhost:8081/api/threat-cache")
    print("     http://localhost:5173  ← Your dashboard")
    print("  ─────────────────────────────────────────────────────\n")
