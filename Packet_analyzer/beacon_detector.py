import sqlite3
import numpy as np
import time
from datetime import datetime
from scipy.fft import fft

# Configuration
BEACON_DB = "beacon_history.db"
HISTORY_LIMIT = 20  # Number of packets for FFT/StdDev
IDLE_THRESHOLD_MIN = 30  # Minutes for consistency check

def init_db():
    conn = sqlite3.connect(BEACON_DB)
    curr = conn.cursor()
    curr.execute('''CREATE TABLE IF NOT EXISTS beacon_history 
                    (process_name TEXT, dest_ip TEXT, packet_size INTEGER, timestamp REAL, port INTEGER)''')
    curr.execute("CREATE INDEX IF NOT EXISTS idx_proc_dest ON beacon_history (process_name, dest_ip)")
    conn.commit()
    conn.close()

init_db()

def analyze_beacon(process_name, dest_ip, packet_size, port):
    timestamp = time.time()
    conn = sqlite3.connect(BEACON_DB)
    curr = conn.cursor()
    
    # Insert new record
    curr.execute("INSERT INTO beacon_history VALUES (?, ?, ?, ?, ?)", 
                 (process_name, dest_ip, packet_size, timestamp, port))
    conn.commit()
    
    # Fetch last HISTORY_LIMIT records for this process and destination
    curr.execute("""SELECT timestamp, packet_size FROM beacon_history 
                    WHERE process_name=? AND dest_ip=? 
                    ORDER BY timestamp DESC LIMIT ?""", 
                 (process_name, dest_ip, HISTORY_LIMIT))
    rows = curr.fetchall()
    
    signals_triggered = []
    beacon_score = 0
    
    if len(rows) >= HISTORY_LIMIT:
        timestamps = [r[0] for r in reversed(rows)]
        sizes = [r[1] for r in rows]
        
        # SIGNAL 1: FFT Periodicity
        intervals = np.diff(timestamps)
        if len(intervals) >= 2:
            # Simple FFT on intervals to find dominant frequency
            yf = fft(intervals)
            # Find peaks in power spectrum (simplified)
            power = np.abs(yf[:len(intervals)//2])
            if np.max(power) > (np.mean(power) * 5): # Sharp peak detection
                beacon_score += 25
                signals_triggered.append("FFT_PERIODICITY")
        
        # SIGNAL 3: Packet Size Uniformity
        std_dev = np.std(sizes)
        if std_dev < 15:
            beacon_score += 25
            signals_triggered.append("SIZE_UNIFORMITY")

    # SIGNAL 2: Destination Consistency
    # Check if this process has connected to other IPs in the last 30 minutes
    thirty_mins_ago = timestamp - (IDLE_THRESHOLD_MIN * 60)
    curr.execute("""SELECT COUNT(DISTINCT dest_ip) FROM beacon_history 
                    WHERE process_name=? AND timestamp > ?""", 
                 (process_name, thirty_mins_ago))
    unique_ips = curr.fetchone()[0]
    if unique_ips == 1:
        beacon_score += 25
        signals_triggered.append("SINGLE_DEST_CONSISTENCY")

    # SIGNAL 4: Night Activity (00:00 - 06:00 local time)
    curr_hour = datetime.now().hour
    if 0 <= curr_hour <= 6:
        beacon_score += 25
        signals_triggered.append("NIGHT_ACTIVITY")

    conn.close()

    verdict = "NORMAL"
    if beacon_score >= 75: verdict = "BEACON"
    elif beacon_score >= 50: verdict = "SUSPICIOUS"

    return {
        "process": process_name,
        "dest_ip": dest_ip,
        "beacon_score": beacon_score,
        "verdict": verdict,
        "signals_triggered": signals_triggered,
        "should_block": beacon_score >= 75
    }

def get_beacon_history(limit=50):
    conn = sqlite3.connect(BEACON_DB)
    curr = conn.cursor()
    curr.execute("SELECT * FROM beacon_history ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = curr.fetchall()
    conn.close()
    return rows
