import subprocess
import time
import requests
import sys

print("==================================================")
print("🚀 CryptGuard Real-Time Extension Test Initialized")
print("==================================================")

extension_path = r"z:\Hacknova Hackathon\new\CryptGuard\extension"
chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

# 1. Launch Chrome with the extension loaded and go to some websites to generate real traffic
print(f"[*] Launching Chrome to load real websites...")
try:
    process = subprocess.Popen([
        chrome_path,
        f"--user-data-dir=C:\\Temp\\CryptGuardTestProfile",
        f"--load-extension={extension_path}",
        "--no-first-run",
        "--no-default-browser-check",
        "--new-window",
        "https://www.wikipedia.org",
        "https://github.com/microsoft"
    ])
except Exception as e:
    print(f"[!] Failed to launch Chrome: {e}")
    sys.exit(1)

print("[*] Browsing real websites to generate live HTTP requests tracking...")
# Give browser time to load pages, make requests, and for the extension to push stats to API server
for i in range(15):
    time.sleep(1)
    print(f"    - Monitoring traffic ({15-i}s)...")

print("\n[*] Querying CryptGuard API Server for live Extension Stats (/api/extension-stats)...")
try:
    response = requests.get("http://localhost:8081/api/extension-stats")
    if response.status_code == 200:
        data = response.json()
        domains = data.get("domains", [])
        print("\n✅ Real-Time Extension Stats Received!\n")
        print(f"Total Requests Analyzed: {data.get('total_packets', 'N/A')}")
        print(f"API Online: {data.get('api_online')}")
        print(f"\nTop Domains Monitored by Extension in Real Time:")
        print("-" * 65)
        print(f"{'DOMAIN':<35} | {'HITS':<10} | {'RISK SCORE':<10}")
        print("-" * 65)
        
        if not domains:
            print("No domains recorded yet. Ensure the API server is up and listening on POST /api/extension-report.")
        
        for d in domains:
            print(f"{d.get('domain', 'Unknown'):<35} | {d.get('hits', 0):<10} | {d.get('risk_score', 0):<10}")
    else:
        print(f"[-] API returned status code: {response.status_code}")
except Exception as e:
    print(f"\n[!] Could not connect to API server. Is it running? Error: {e}")
    print("\n💡 Make sure 'python api_server.py' is restarted and running!")

print("\n==================================================")
print("Test Complete. You can close the Chrome window.")
print("==================================================")
