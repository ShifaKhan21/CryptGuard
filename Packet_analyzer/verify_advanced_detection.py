import time
import requests
import socket
import os
from dotenv import load_dotenv
import threat_intel
import beacon_detector

load_dotenv()

def test_threat_intel():
    print("\n--- Testing Module 1: Threat Intelligence ---")
    # Test 1: Private IP (Should be CLEAN)
    print("Testing Private IP (192.168.1.1)...")
    res = threat_intel.check_threat_intel("192.168.1.1")
    print(f"Result: {res['verdict']} (Source: {res['source']})")

    # Test 2: Known Clean Domain
    print("\nTesting google.com...")
    res = threat_intel.check_threat_intel("google.com")
    print(f"Result: {res['verdict']} (Source: {res['source']})")

    # Test 3: Manual IP Check (Triggering API if KEY exists)
    # We'll use a known "frequently reported" IP example from AbuseIPDB (e.g., a common scanner)
    test_ip = "118.25.6.34" 
    print(f"\nTesting Malicious IP Lookup ({test_ip})...")
    res = threat_intel.check_threat_intel(test_ip)
    print(f"Result: {res['verdict']} (Score: {res['confidence']}, Source: {res['source']})")
    print(f"Cached: {res['cached']}")

def simulate_c2_beacon():
    print("\n--- Testing Module 2: C2 Beacon Detection ---")
    print("Simulating 20 periodic connections (one every 2 seconds)...")
    
    test_process = "TesterApp.exe"
    test_dest = "10.99.99.99"
    test_port = 8080
    
    for i in range(21):
        # We manually call the detector to simulate the backend loop finding this
        res = beacon_detector.analyze_beacon(test_process, test_dest, 128, test_port)
        print(f"[{i+1}/21] Score: {res['beacon_score']} | Verdict: {res['verdict']} | Signals: {res['signals_triggered']}")
        if res['verdict'] == "BEACON":
            print("!!! SUCCESS: C2 BEACON DETECTED !!!")
            break
        time.sleep(0.1) # Accelerated for testing; in real life interval would be constant

if __name__ == "__main__":
    print("=== CryptGuard Advanced Detection Stress Test ===")
    
    # 1. Test Threat Intel Logic
    test_threat_intel()
    
    # 2. Test Beacon Logic
    simulate_c2_beacon()
    
    print("\n=== Test Complete ===")
    print("Now run 'python api_server.py' and check the dashboard to see live detection results!")
