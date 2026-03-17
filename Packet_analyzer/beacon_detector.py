"""
beacon_detector.py — C2 Beacon Detection Engine for CryptGuard
===============================================================
Detects Command-and-Control beaconing via 4 independent statistical signals:

  SIGNAL 1 — FFT Periodicity Analysis       (25 points)
  SIGNAL 2 — Destination Consistency        (25 points)
  SIGNAL 3 — Packet Size Uniformity         (25 points)
  SIGNAL 4 — Night Activity (00:00 - 06:00) (25 points)

Verdict:
  score >= 75 → BEACON DETECTED (should_block = True)
  score >= 50 → SUSPICIOUS (alert)
  score <  50 → NORMAL

Usage:
    from beacon_detector import analyze_beacon, get_beacon_history, clear_old_records
    result = analyze_beacon("chrome.exe", "1.2.3.4", 512, datetime.now())
"""

import sqlite3
import threading
import numpy as np
import os
import time
from datetime import datetime, timedelta
from typing import Optional

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon_history.db")

HISTORY_WINDOW_MINUTES = 30      # Look-back window for analysis
MIN_SAMPLES_FFT = 6              # Minimum data points required for FFT
MIN_SAMPLES_SIZE = 5             # Minimum size samples for uniformity check
PACKET_SIZE_STD_THRESHOLD = 15   # bytes std_dev below = uniform
NIGHT_HOURS = (0, 6)             # Local time hours considered "night"
MAX_HISTORY_ROWS = 10000         # Global cap to prevent unbounded DB growth
FFT_DOMINANT_RATIO = 3.0         # Dominant freq must be N× stronger than mean

SCORE_BEACON = 75
SCORE_SUSPICIOUS = 50

# ─────────────────────────────────────────────────────────────────
# DATABASE LAYER
# ─────────────────────────────────────────────────────────────────
_db_lock = threading.Lock()
_conn_cache: dict[int, sqlite3.Connection] = {}  # Thread-local connections


def _get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection (thread-safe)."""
    tid = threading.get_ident()
    if tid not in _conn_cache:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")    # Better concurrent writes
        conn.execute("PRAGMA synchronous=NORMAL")
        _conn_cache[tid] = conn
    return _conn_cache[tid]


def _init_db():
    """Create tables if they don't exist."""
    with _db_lock:
        conn = _get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS beacon_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name    TEXT    NOT NULL,
                destination_ip  TEXT    NOT NULL,
                packet_size     INTEGER NOT NULL,
                timestamp       REAL    NOT NULL,   -- Unix epoch (float)
                port            INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_process_dest
                ON beacon_history(process_name, destination_ip);

            CREATE INDEX IF NOT EXISTS idx_timestamp
                ON beacon_history(timestamp);

            CREATE TABLE IF NOT EXISTS beacon_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       REAL    NOT NULL,
                process_name    TEXT    NOT NULL,
                destination_ip  TEXT    NOT NULL,
                beacon_score    INTEGER NOT NULL,
                verdict         TEXT    NOT NULL,
                signals         TEXT    NOT NULL,   -- JSON list
                should_block    INTEGER NOT NULL
            );
        """)
        conn.commit()


def _insert_record(process_name: str, destination_ip: str,
                   packet_size: int, timestamp: float, port: int = 0):
    """Insert a new connection record into the history table."""
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO beacon_history "
            "(process_name, destination_ip, packet_size, timestamp, port) "
            "VALUES (?, ?, ?, ?, ?)",
            (process_name, destination_ip, packet_size, timestamp, port)
        )
        conn.commit()


def _insert_alert(process_name: str, destination_ip: str,
                  beacon_score: int, verdict: str,
                  signals: list, should_block: bool):
    """Persist a beacon alert result."""
    import json
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO beacon_alerts "
            "(timestamp, process_name, destination_ip, beacon_score, verdict, signals, should_block) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), process_name, destination_ip,
             beacon_score, verdict, json.dumps(signals), int(should_block))
        )
        conn.commit()


def _fetch_recent_timestamps(process_name: str, destination_ip: str,
                              window_minutes: int = HISTORY_WINDOW_MINUTES,
                              limit: int = 20) -> list[float]:
    """Fetch the last N timestamps for a process→dest pair within window."""
    cutoff = time.time() - window_minutes * 60
    conn = _get_conn()
    rows = conn.execute(
        "SELECT timestamp FROM beacon_history "
        "WHERE process_name=? AND destination_ip=? AND timestamp>=? "
        "ORDER BY timestamp DESC LIMIT ?",
        (process_name, destination_ip, cutoff, limit)
    ).fetchall()
    return sorted([r["timestamp"] for r in rows])


def _fetch_unique_destinations(process_name: str,
                                window_minutes: int = HISTORY_WINDOW_MINUTES) -> int:
    """Count how many unique destination IPs a process contacted recently."""
    cutoff = time.time() - window_minutes * 60
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(DISTINCT destination_ip) as cnt FROM beacon_history "
        "WHERE process_name=? AND timestamp>=?",
        (process_name, cutoff)
    ).fetchone()
    return row["cnt"] if row else 0


def _fetch_recent_packet_sizes(process_name: str, destination_ip: str,
                                limit: int = 20) -> list[int]:
    """Fetch the last N packet sizes for process→dest pair."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT packet_size FROM beacon_history "
        "WHERE process_name=? AND destination_ip=? "
        "ORDER BY timestamp DESC LIMIT ?",
        (process_name, destination_ip, limit)
    ).fetchall()
    return [r["packet_size"] for r in rows]


# ─────────────────────────────────────────────────────────────────
# DETECTION SIGNALS
# ─────────────────────────────────────────────────────────────────

def _signal_fft_periodicity(timestamps: list[float]) -> tuple[bool, dict]:
    """
    SIGNAL 1: FFT Periodicity Analysis (weight: 25 points)

    Real C2 beacons sleep for a fixed interval then call home again.
    This creates a dominant frequency in an FFT of the inter-arrival
    intervals — just like a clock signal.

    Returns (triggered: bool, info: dict)
    """
    if len(timestamps) < MIN_SAMPLES_FFT:
        return False, {"reason": f"Insufficient samples ({len(timestamps)}/{MIN_SAMPLES_FFT})"}

    intervals = np.diff(timestamps)
    if len(intervals) < 3:
        return False, {"reason": "Too few intervals"}

    # Remove obvious outliers (> 10× median) before FFT
    median_interval = float(np.median(intervals))
    intervals_clean = intervals[intervals <= median_interval * 10]
    if len(intervals_clean) < 3:
        intervals_clean = intervals

    fft_result = np.abs(np.fft.fft(intervals_clean))
    # Remove DC component (index 0) — it's just the mean
    fft_magnitudes = fft_result[1:len(fft_result)//2 + 1]
    if len(fft_magnitudes) == 0:
        return False, {"reason": "FFT result empty"}

    dominant_mag = float(np.max(fft_magnitudes))
    mean_mag = float(np.mean(fft_magnitudes))

    if mean_mag == 0:
        return False, {"reason": "Flat FFT spectrum"}

    ratio = dominant_mag / mean_mag

    triggered = ratio >= FFT_DOMINANT_RATIO
    info = {
        "dominant_magnitude": round(dominant_mag, 3),
        "mean_magnitude": round(mean_mag, 3),
        "dominance_ratio": round(ratio, 3),
        "threshold": FFT_DOMINANT_RATIO,
        "mean_interval_sec": round(median_interval, 2),
        "samples": len(timestamps)
    }
    return triggered, info


def _signal_destination_consistency(process_name: str) -> tuple[bool, dict]:
    """
    SIGNAL 2: Destination Consistency (weight: 25 points)

    A C2 implant typically phones home to ONE fixed IP/domain.
    If a process connects to only 1 unique destination in 30 minutes,
    that matches beacon behaviour (vs a browser which connects to hundreds).

    Returns (triggered: bool, info: dict)
    """
    unique_count = _fetch_unique_destinations(process_name)
    triggered = unique_count == 1 and unique_count > 0
    info = {
        "unique_destinations_30min": unique_count,
        "threshold": "== 1"
    }
    return triggered, info


def _signal_packet_size_uniformity(sizes: list[int]) -> tuple[bool, dict]:
    """
    SIGNAL 3: Packet Size Uniformity (weight: 25 points)

    C2 beacons send fixed-format heartbeat messages — the same command
    structure every interval. This results in very consistent payload sizes
    with near-zero standard deviation.

    Returns (triggered: bool, info: dict)
    """
    if len(sizes) < MIN_SAMPLES_SIZE:
        return False, {"reason": f"Insufficient samples ({len(sizes)}/{MIN_SAMPLES_SIZE})"}

    std_dev = float(np.std(sizes))
    mean_size = float(np.mean(sizes))
    triggered = std_dev < PACKET_SIZE_STD_THRESHOLD

    info = {
        "std_dev_bytes": round(std_dev, 2),
        "mean_size_bytes": round(mean_size, 1),
        "threshold_bytes": PACKET_SIZE_STD_THRESHOLD,
        "samples": len(sizes)
    }
    return triggered, info


def _signal_night_activity(ts: Optional[datetime] = None) -> tuple[bool, dict]:
    """
    SIGNAL 4: Night/Off-Hours Activity (weight: 25 points)

    C2 malware often beacons during off-hours (midnight to 6AM local time)
    to blend into low-traffic periods and avoid detection by human analysts.

    Returns (triggered: bool, info: dict)
    """
    if ts is None:
        ts = datetime.now()

    hour = ts.hour
    start_hour, end_hour = NIGHT_HOURS
    triggered = start_hour <= hour < end_hour

    info = {
        "current_hour": hour,
        "night_window": f"{start_hour:02d}:00 - {end_hour:02d}:00",
        "is_night_hours": triggered
    }
    return triggered, info


# ─────────────────────────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────────────────────────

def analyze_beacon(process: str,
                   destination_ip: str,
                   packet_size: int,
                   timestamp: Optional[datetime] = None,
                   port: int = 0) -> dict:
    """
    Run all 4 beacon detection signals and return a combined verdict.

    Parameters
    ----------
    process       : process name (e.g. "chrome.exe", "python.exe")
    destination_ip: remote IPv4/IPv6 address
    packet_size   : size of the packet/flow in bytes
    timestamp     : datetime of the connection (defaults to now)
    port          : destination port (optional, stored for analysis)

    Returns
    -------
    {
        "process":           str,
        "destination_ip":    str,
        "beacon_score":      int (0-100),
        "verdict":           "BEACON" | "SUSPICIOUS" | "NORMAL",
        "signals_triggered": list[str],
        "signal_details":    dict,
        "should_block":      bool,
        "timestamp":         str (ISO format)
    }
    """
    if timestamp is None:
        timestamp = datetime.now()

    ts_epoch = timestamp.timestamp()

    # 1. Store this record first
    _insert_record(process, destination_ip, packet_size, ts_epoch, port)

    # 2. Fetch history for analysis
    recent_timestamps = _fetch_recent_timestamps(process, destination_ip)
    recent_sizes = _fetch_recent_packet_sizes(process, destination_ip)

    # 3. Run all 4 signals
    fft_triggered, fft_info = _signal_fft_periodicity(recent_timestamps)
    dest_triggered, dest_info = _signal_destination_consistency(process)
    size_triggered, size_info = _signal_packet_size_uniformity(recent_sizes)
    night_triggered, night_info = _signal_night_activity(timestamp)

    # 4. Score aggregation (each signal = 25 points)
    score = 0
    signals_triggered = []

    if fft_triggered:
        score += 25
        signals_triggered.append("FFT_PERIODICITY")

    if dest_triggered:
        score += 25
        signals_triggered.append("DESTINATION_CONSISTENCY")

    if size_triggered:
        score += 25
        signals_triggered.append("PACKET_SIZE_UNIFORMITY")

    if night_triggered:
        score += 25
        signals_triggered.append("NIGHT_ACTIVITY")

    # 5. Verdict decision
    if score >= SCORE_BEACON:
        verdict = "BEACON"
        should_block = True
    elif score >= SCORE_SUSPICIOUS:
        verdict = "SUSPICIOUS"
        should_block = False
    else:
        verdict = "NORMAL"
        should_block = False

    # 6. Persist alert if suspicious or above
    if score >= SCORE_SUSPICIOUS:
        _insert_alert(process, destination_ip, score, verdict,
                      signals_triggered, should_block)

    return {
        "process": process,
        "destination_ip": destination_ip,
        "beacon_score": score,
        "verdict": verdict,
        "signals_triggered": signals_triggered,
        "signal_details": {
            "fft_periodicity": {"triggered": fft_triggered, **fft_info},
            "destination_consistency": {"triggered": dest_triggered, **dest_info},
            "packet_size_uniformity": {"triggered": size_triggered, **size_info},
            "night_activity": {"triggered": night_triggered, **night_info}
        },
        "should_block": should_block,
        "timestamp": timestamp.isoformat()
    }


# ─────────────────────────────────────────────────────────────────
# HISTORY & MAINTENANCE FUNCTIONS
# ─────────────────────────────────────────────────────────────────

def get_beacon_history(limit: int = 50) -> list[dict]:
    """
    Return the last N beacon alerts (SUSPICIOUS or BEACON verdicts).
    Used by the /api/beacon-history endpoint.
    """
    import json
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM beacon_alerts ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()

    return [
        {
            "id": r["id"],
            "timestamp": datetime.fromtimestamp(r["timestamp"]).isoformat(),
            "process_name": r["process_name"],
            "destination_ip": r["destination_ip"],
            "beacon_score": r["beacon_score"],
            "verdict": r["verdict"],
            "signals": json.loads(r["signals"]),
            "should_block": bool(r["should_block"])
        }
        for r in rows
    ]


def get_db_stats() -> dict:
    """
    Return current database statistics.
    Used by the /api/threat-cache endpoint.
    """
    conn = _get_conn()
    history_count = conn.execute("SELECT COUNT(*) as c FROM beacon_history").fetchone()["c"]
    alert_count = conn.execute("SELECT COUNT(*) as c FROM beacon_alerts").fetchone()["c"]
    beacon_count = conn.execute(
        "SELECT COUNT(*) as c FROM beacon_alerts WHERE verdict='BEACON'"
    ).fetchone()["c"]
    suspicious_count = conn.execute(
        "SELECT COUNT(*) as c FROM beacon_alerts WHERE verdict='SUSPICIOUS'"
    ).fetchone()["c"]
    oldest = conn.execute("SELECT MIN(timestamp) as t FROM beacon_history").fetchone()["t"]

    return {
        "total_records": history_count,
        "total_alerts": alert_count,
        "beacon_count": beacon_count,
        "suspicious_count": suspicious_count,
        "db_path": DB_PATH,
        "oldest_record": datetime.fromtimestamp(oldest).isoformat() if oldest else None,
        "max_capacity": MAX_HISTORY_ROWS
    }


def clear_old_records(older_than_hours: int = 24) -> int:
    """
    Delete records older than N hours. Returns number of rows deleted.
    Used by the /api/clear-cache endpoint.
    """
    cutoff = time.time() - older_than_hours * 3600
    with _db_lock:
        conn = _get_conn()
        cursor = conn.execute(
            "DELETE FROM beacon_history WHERE timestamp < ?", (cutoff,)
        )
        conn.execute(
            "DELETE FROM beacon_alerts WHERE timestamp < ?", (cutoff,)
        )
        conn.commit()
    return cursor.rowcount


def _auto_prune():
    """Background pruner — runs every 5 minutes, removes records > 24h old."""
    while True:
        time.sleep(300)
        try:
            deleted = clear_old_records(older_than_hours=24)
            if deleted > 0:
                print(f"[BeaconDB] Pruned {deleted} old records")
        except Exception as e:
            print(f"[BeaconDB] Prune error: {e}")


# ─────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ─────────────────────────────────────────────────────────────────

# Initialize DB and start background pruner on import
_init_db()
import threading as _th
_pruner_thread = _th.Thread(target=_auto_prune, daemon=True, name="BeaconDBPruner")
_pruner_thread.start()

print("[BeaconDetector] Initialized — SQLite DB ready, 4 signals active")
