import sqlite3, time, math, json, os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'beacon_history.db')

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

conn.execute("""CREATE TABLE IF NOT EXISTS beacon_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    packet_size INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    port INTEGER DEFAULT 0
)""")
conn.execute("""CREATE TABLE IF NOT EXISTS beacon_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    process_name TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    beacon_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    signals TEXT NOT NULL,
    should_block INTEGER NOT NULL
)""")
conn.execute("CREATE INDEX IF NOT EXISTS idx1 ON beacon_history(process_name, destination_ip)")
conn.execute("CREATE INDEX IF NOT EXISTS idx2 ON beacon_history(timestamp)")
conn.commit()


def insert(proc, ip, size, ts, port=443):
    conn.execute(
        'INSERT INTO beacon_history(process_name,destination_ip,packet_size,timestamp,port) VALUES(?,?,?,?,?)',
        (proc, ip, size, ts, port)
    )
    conn.commit()


def insert_alert(proc, ip, score, verdict, sigs, block):
    conn.execute(
        'INSERT INTO beacon_alerts(timestamp,process_name,destination_ip,beacon_score,verdict,signals,should_block) VALUES(?,?,?,?,?,?,?)',
        (time.time(), proc, ip, score, verdict, json.dumps(sigs), int(block))
    )
    conn.commit()


def analyze(proc, ip):
    cutoff = time.time() - 1800
    rows = conn.execute(
        'SELECT timestamp FROM beacon_history WHERE process_name=? AND destination_ip=? AND timestamp>=? ORDER BY timestamp',
        (proc, ip, cutoff)
    ).fetchall()
    ts_list = [r[0] for r in rows]

    sizes = [r[0] for r in conn.execute(
        'SELECT packet_size FROM beacon_history WHERE process_name=? AND destination_ip=? ORDER BY timestamp DESC LIMIT 20',
        (proc, ip)
    ).fetchall()]

    unique = conn.execute(
        'SELECT COUNT(DISTINCT destination_ip) FROM beacon_history WHERE process_name=? AND timestamp>=?',
        (proc, cutoff)
    ).fetchone()[0]

    score = 0
    signals = []

    # Signal 1: FFT Periodicity (Frequency Peak OR Low Jitter)
    if len(ts_list) >= 6:
        intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
        big = [d for d in intervals if d >= 3.0]
        if len(big) >= 3:
            n = len(big)
            mags = []
            for k in range(1, n//2 + 1):
                re = sum(big[j] * math.cos(2 * math.pi * k * j / n) for j in range(n))
                im = sum(big[j] * math.sin(2 * math.pi * k * j / n) for j in range(n))
                mags.append(math.sqrt(re**2 + im**2))
            
            is_periodic = False
            if mags:
                dom = max(mags)
                avg = sum(mags) / len(mags)
                if avg > 0 and dom / avg >= 3.0:
                    is_periodic = True
            
            # Low Jitter Check
            std_val = math.sqrt(sum((x - sum(big)/len(big))**2 for x in big)/len(big))
            mean_val = sum(big)/len(big)
            if mean_val > 0 and (std_val / mean_val) < 0.05:
                is_periodic = True

            if is_periodic:
                score += 25
                signals.append('FFT_PERIODICITY')


    # Signal 2: Destination Consistency
    if unique == 1 and len(ts_list) > 0:
        score += 25
        signals.append('DESTINATION_CONSISTENCY')

    # Signal 3: Packet Size Uniformity
    if len(sizes) >= 5:
        mean = sum(sizes) / len(sizes)
        std = math.sqrt(sum((x - mean)**2 for x in sizes) / len(sizes))
        if std < 15:
            score += 25
            signals.append('PACKET_SIZE_UNIFORMITY')

    # Signal 4: Night Activity (00:00-06:00)
    if 0 <= datetime.now().hour < 6:
        score += 25
        signals.append('NIGHT_ACTIVITY')

    verdict = 'BEACON' if score >= 75 else ('SUSPICIOUS' if score >= 50 else 'NORMAL')
    block = score >= 75
    if score >= 50:
        insert_alert(proc, ip, score, verdict, signals, block)
    return score, verdict, signals, block


# ═══════════════════════════════════════════════════════════
print()
print('=' * 68)
print('  CryptGuard C2 Beacon Simulation — Starting...')
print('=' * 68)

# SCENARIO A: Perfect C2 Beacon — 30s intervals
print('\n  SCENARIO A: malware.exe -> 185.220.101.1 (30s intervals, current time)\n')
base = datetime.now() - timedelta(minutes=15)
for i in range(20): # Increased hits to ensure FFT coverage
    ts = (base + timedelta(seconds=i * 30)).timestamp()
    insert('malware.exe', '185.220.101.1', 512, ts, 443)
    if i >= 10:
        sc, vd, sg, bl = analyze('malware.exe', '185.220.101.1')
        icon = '🔴 [BEACON]' if vd == 'BEACON' else ('🟡 [SUSPICIOUS]' if vd == 'SUSPICIOUS' else '🟢 [NORMAL]')
        print(f'  Hit {i+1:2d}/20 | Score {sc:3d}/100 | {icon:<15} | Block={bl} | {sg}')

# SCENARIO B: Suspicious — 60s intervals
print('\n  SCENARIO B: python.exe -> 10.0.0.5 (60s intervals, current time)\n')
base2 = datetime.now() - timedelta(minutes=10)
for i in range(8):
    ts = (base2 + timedelta(seconds=i * 60)).timestamp()
    insert('python.exe', '10.0.0.5', 256 + (i % 3) * 4, ts, 8080)
    if i >= 5:
        sc, vd, sg, bl = analyze('python.exe', '10.0.0.5')
        print(f'  Hit {i+1}/8   | Score {sc:3d}/100 | {vd:<12} | {sg}')


# SCENARIO C: Normal browser traffic — many IPs
print('\n  SCENARIO C: chrome.exe -> 6 different IPs (should be NORMAL)\n')
for i, dest in enumerate(['8.8.8.8', '1.1.1.1', '142.250.80.46', '104.18.23.45', '13.107.42.12', '151.101.65.69']):
    insert('chrome.exe', dest, 100 + i * 150, time.time() - i * 10, 443)
sc, vd, sg, bl = analyze('chrome.exe', '8.8.8.8')
print(f'  chrome.exe varied IPs   | Score {sc:3d}/100 | {vd}')

# SCENARIO D: AbuseIPDB Detection — Threat Intelligence
print('\n  SCENARIO D: powershell.exe -> 185.33.22.11 (Known Malicious IP)\n')
INTEL_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'intel_cache.db')
try:
    intel_conn = sqlite3.connect(INTEL_DB)
    # Inject 185.33.22.11 as a high-risk IP (95%)
    intel_conn.execute("""
        INSERT OR REPLACE INTO ip_cache (ip, score, provider, last_updated, raw_data)
        VALUES (?, ?, ?, ?, ?)
    """, ("185.33.22.11", 95, "AbuseIPDB (Simulation)", time.time(), '{"abuse_score": 95}'))
    intel_conn.commit()
    intel_conn.close()
    print('  ✅ Malicious IP (185.33.22.11) injected into Intel Cache.')
    
    # Send a burst to ensure it's visible
    for _ in range(10):
        insert('powershell.exe', '185.33.22.11', 1200, time.time(), 443)
        time.sleep(0.1)
    print('  🚀 10x Traffic burst sent to Malicious IP. It will appear on the dashboard table as SUSPICIOUS.')
except Exception as e:
    print(f'  ❌ Intel Injection failed: {e}')

# ═══ FINAL RESULTS ═══
print()
print('=' * 68)
print('  ALERTS IN DATABASE (last 10):')
print('=' * 68)
alerts = conn.execute(
    'SELECT process_name, destination_ip, beacon_score, verdict, signals FROM beacon_alerts ORDER BY timestamp DESC LIMIT 10'
).fetchall()
if not alerts:
    print('  No alerts stored yet.')
else:
    print(f'  {"PROCESS":<22} {"IP":<20} SCORE  VERDICT')
    print('  ' + '-' * 60)
    for a in alerts:
        print(f'  {a[0]:<22} {a[1]:<20} {a[2]:>3}    {a[3]}')

total = conn.execute('SELECT COUNT(*) FROM beacon_history').fetchone()[0]
total_alerts = conn.execute('SELECT COUNT(*) FROM beacon_alerts').fetchone()[0]
beacons = conn.execute("SELECT COUNT(*) FROM beacon_alerts WHERE verdict='BEACON'").fetchone()[0]
print()
print(f'  DB records     : {total}')
print(f'  Total alerts   : {total_alerts}')
print(f'  BEACON verdicts: {beacons}')
print()
print('  Now check your dashboard -> C2 Beacon Alerts tab!')
print('  Or visit: http://localhost:8081/api/beacon-history')
conn.close()
