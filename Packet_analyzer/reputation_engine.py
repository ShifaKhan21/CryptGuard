import collections
import time
import sqlite3
import os

# Process Reputation metrics:
# - Malicious connection count
# - Beaconing consistency score
# - Duration of suspicious activity
# - Multi-PID correlation

class ReputationEngine:
    def __init__(self, db_path="reputation.db"):
        self.db_path = db_path
        self.process_stats = {} # PID -> { score, risk_level, detections, last_updated }
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS process_reputation
                     (pid INTEGER PRIMARY KEY, process_name TEXT, score INTEGER, 
                      risk_level TEXT, detection_count INTEGER, last_seen TIMESTAMP)''')
        conn.commit()
        conn.close()

    def update_score(self, pid, process_name, connection_verdict, connection_score):
        """
        Updates the holistic reputation of a process based on a single connection event.
        """
        if pid not in self.process_stats:
            self.process_stats[pid] = {
                "name": process_name,
                "score": 0,
                "events": 0,
                "malicious_count": 0,
                "last_updated": time.time()
            }
        
        stats = self.process_stats[pid]
        stats["events"] += 1
        
        # Scoring logic:
        # Malicious verdict: +30 points
        # Suspicious verdict: +10 points
        # High confidence score (>80): +10 bonus points
        
        if connection_verdict == "MALICIOUS":
            stats["score"] += 30
            stats["malicious_count"] += 1
        elif connection_verdict == "SUSPICIOUS":
            stats["score"] += 10
            
        if connection_score > 80:
            stats["score"] += 10
            
        # Cap score at 100
        stats["score"] = min(stats["score"], 100)
        stats["last_updated"] = time.time()
        
        # Determine Holistic Risk Level
        risk = "CLEAN"
        if stats["score"] >= 75: risk = "HIGH_RISK"
        elif stats["score"] >= 40: risk = "SUSPICIOUS"
        
        self._persist_to_db(pid, process_name, stats["score"], risk, stats["events"])
        return {"score": stats["score"], "risk_level": risk}

    def _persist_to_db(self, pid, name, score, risk, count):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO process_reputation 
                     (pid, process_name, score, risk_level, detection_count, last_seen)
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                  (pid, name, score, risk, count, time.time()))
        conn.commit()
        conn.close()

    def get_top_offenders(self, limit=10):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM process_reputation ORDER BY score DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        
        results = []
        for r in rows:
            results.append({
                "pid": r[0],
                "name": r[1],
                "score": r[2],
                "risk": r[3],
                "events": r[4]
            })
        return results

engine = ReputationEngine()

def calculate_reputation(pid, name, verdict, score):
    return engine.update_score(pid, name, verdict, score)

def get_process_stats():
    return engine.get_top_offenders()
