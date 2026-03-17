# CryptGuard Advanced Detection Testing Protocol 🛡️🔬

Use this guide to verify that yours API integrations and behavioral detection modules are working perfectly.

## 1. Automated Unit Test
Run the verification script provided in the main directory. This will test the Threat Intel API logic and simulate a behavioral C2 beacon in isolation.

```powershell
# Open terminal in the Packet_analyzer folder
python verify_advanced_detection.py
```

**Check for:**
- `Result: MALICIOUS` for the testing IP.
- `!!! SUCCESS: C2 BEACON DETECTED !!!` at the end of the simulation.

---

## 2. Real-Time API Verification (Manual)
To see the system fetch live data from AbuseIPDB and VirusTotal during actual traffic:

1.  Start the dashboard: `.\run_app.bat`
2.  Open your browser and search for a known "blacklisted IP" list (like [AbuseIPDB Top 100](https://www.abuseipdb.com/statistics)).
3.  **DO NOT visit the malicious sites.** Just try to `ping` one of the IPs from that list in your terminal:
    ```powershell
    ping 123.123.123.123  # Replace with a real malicious IP from the list
    ```
4.  In the CryptGuard Dashboard, look for the IP in the table.
5.  Click **"Details"**.
6.  Verify under **"External Reputation"** that it shows:
    - **Verdict**: MALICIOUS or SUSPICIOUS
    - **Confidence Score**: > 0%
    - **Source**: abuseipdb/virustotal

---

## 3. Behavioral Beacon Simulation (Dashboard Check)
To see the **FFT (Fourier Transform)** and **Uniformity** signals trigger in the UI:

1.  Run the following PowerShell script to create a "noisy" heartbeat pattern:
    ```powershell
    # This will send 25 pings to a specific IP with exact 2-second intervals
    for ($i=1; $i -le 25; $i++) {
        Write-Host "Sending Heartbeat $i..."
        Test-Connection -ComputerName 1.2.3.4 -Count 1
        Start-Sleep -Seconds 2
    }
    ```
2.  Watch the dashboard. Once 20 heartbeats are captured, CryptGuard will analyze the intervals.
3.  Open **"Details"** for the IP `1.2.3.4`.
4.  Verify under **"Behavioral Signals"**:
    - **Verdict**: BEACON
    - **Beacon Score**: > 75
    - **Signals**: `FFT_PERIODICITY`, `SIZE_UNIFORMITY`, `SINGLE_DEST_CONSISTENCY`.

---

## 4. Cache Verification
1.  Check the file `threat_intel_cache.db` in your folder.
2.  Visit the API endpoint directly in your browser: `http://localhost:8081/api/threat-cache`
3.  Verify it returns `{"status": "active", "provider": "AbuseIPDB/VirusTotal"}`.

---

## 5. C2 Beacon History
1.  Visit: `http://localhost:8081/api/beacon-history`
2.  Verify you see the log of recent connections that were analyzed for beaconing.

---

**Bhai, agar ye saare checks pass ho rahe hain, to aapka system state-of-the-art security level par hai!** 🚀🔥
