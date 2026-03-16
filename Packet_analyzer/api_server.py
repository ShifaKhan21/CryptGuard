import subprocess
import os
import sys
import time
import json
import threading
import platform
import socket
import pickle
import asyncio
import re
from typing import List, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import random
import pandas as pd

# Try loading XGBoost model
ML_MODEL = None
EXPECTED_FEATURES = None
try:
    with open('model/xgb_model.pkl', 'rb') as f:
        ML_MODEL = pickle.load(f)
        if hasattr(ML_MODEL, 'feature_names_in_'):
            EXPECTED_FEATURES = list(ML_MODEL.feature_names_in_)
            print(f"✅ Loaded XGBoost Model with {len(EXPECTED_FEATURES)} features.")
        else:
            print("⚠️ Loaded XGBoost Model but it's missing 'feature_names_in_' metadata.")
except Exception as e:
    print(f"❌ Failed to load ML Model: {e}")

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
DECAY_TIMEOUT = 30 

# Global State
LOCAL_HOSTNAME = socket.gethostname()
# --- ML CLASSIFICATION HELPERS ---
FEATURE_NAMES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total',
    'Bwd Packets Length Total', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'SYN Flag Count', 'URG Flag Count', 'Avg Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]

def synthesize_features(domain: str, hits: int, category: str):
    """
    Synthesize 57 flow features for the XGBoost model based on available data.
    Since the current engine doesn't export per-flow features, we map domain types
    to 'typical' feature patterns expected by the IDS model.
    """
    random.seed(hash(domain)) # Deterministic for same domain
    
    # Base pattern (Benign by default)
    feats = {name: 0.0 for name in FEATURE_NAMES}
    
    # Packets correlate with hits
    feats['Total Fwd Packets'] = float(hits)
    feats['Total Backward Packets'] = float(hits * 0.8)
    feats['Flow Duration'] = float(hits * 1000) # Microseconds
    
    # Lengths
    avg_len = 1200 if category == "HTTPS" else 400
    feats['Fwd Packets Length Total'] = float(hits * avg_len)
    feats['Bwd Packets Length Total'] = float(hits * avg_len * 0.5)
    feats['Fwd Packet Length Mean'] = float(avg_len)
    feats['Packet Length Mean'] = float(avg_len * 0.9)
    
    # IATs (Inter-arrival times)
    feats['Flow IAT Mean'] = 50.0 + random.random() * 50
    feats['Flow IAT Max'] = 200.0
    
    # Rates
    feats['Flow Bytes/s'] = (feats['Fwd Packets Length Total'] + feats['Bwd Packets Length Total']) / ((feats['Flow Duration'] + 1) / 1000000)
    feats['Flow Packets/s'] = (feats['Total Fwd Packets'] + feats['Total Backward Packets']) / ((feats['Flow Duration'] + 1) / 1000000)
    
    # If the domain is common background noise or known safe, keep features 'Benign-like'
    # If it's something suspicious or generating massive sudden hits, jitter them towards 'Malicious-like'
    suspicious_keywords = ['malware', 'attack', 'hack', 'spy', 'c2', 'beacon', 'exploit']
    is_suspicious = any(kw in domain.lower() for kw in suspicious_keywords) or (hits > 5000)
    
    if is_suspicious:
        # Malware often has high IAT variance or very fixed small packets
        feats['Flow IAT Std'] = 500.0
        feats['Packet Length Std'] = 10.0 # Small, repetitive
        feats['Avg Packet Size'] = 64.0
        feats['SYN Flag Count'] = 1.0 # Simulate connection attempts
    else:
        feats['Flow IAT Std'] = 10.0
        feats['Packet Length Std'] = 300.0
        feats['Avg Packet Size'] = float(avg_len)

    return feats

def classify_domain(domain: str, hits: int, category: str):
    if ML_MODEL is None: # Changed from XGB_MODEL to ML_MODEL
        return "N/A", 0, {}
    
    try:
        feats_dict = synthesize_features(domain, hits, category)
        # Convert to DataFrame with correct column order
        df = pd.DataFrame([list(feats_dict.values())], columns=FEATURE_NAMES)
        
        # Predict
        pred_idx = ML_MODEL.predict(df)[0] # Changed from XGB_MODEL to ML_MODEL
        # Label mapping (assuming 0=Benign, 1=Malware based on standard IDS datasets)
        # We might need to adjust based on the model's actual training
        label = "MALWARE" if pred_idx == 1 else "BENIGN"
        
        # Probabilities
        probs = ML_MODEL.predict_proba(df)[0]
        confidence_val = float(max(probs)) * 100
        # Bypass Pyre's weirdness with round() overflow/overload
        confidence = float(int(confidence_val * 10)) / 10.0
        
        return label, confidence, feats_dict
    except Exception as e:
        print(f"❌ ML Error for {domain}: {e}")
        return "UNKNOWN", 0, {}

# --- WEB SERVER STATE ---
engine_state = {
    "interfaces": [],
    "selected_interface": None,
    "is_capturing": False,
    "domains": {}, 
    "last_update": 0,
    "total_packets": 0,
    "dropped_packets": 0,
    "forwarded_packets": 0,
    "applications": {}
}

state_lock = threading.Lock()
connected_clients: List[WebSocket] = []

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Broadcaster:
    def __init__(self):
        self.clients: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.clients.append(websocket)
        print(f"📡 New client connected. Total clients: {len(self.clients)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.clients:
            self.clients.remove(websocket)
            print(f"📡 Client disconnected. Total clients: {len(self.clients)}")

    async def broadcast(self, message: str):
        # Use a copy for safe iteration during removals
        for client in self.clients[:]:
            try:
                await client.send_text(message)
            except Exception as e:
                # Silently remove stale clients
                if client in self.clients:
                    self.clients.remove(client)

broadcaster = Broadcaster()

def get_interfaces():
    try:
        cmd = [TSHARK_PATH, "-D"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        return []

@app.get("/api/interfaces")
async def api_interfaces():
    global engine_state
    if not engine_state["interfaces"]:
        engine_state["interfaces"] = get_interfaces()
    return {
        "interfaces": engine_state["interfaces"],
        "selected": engine_state["selected_interface"],
        "is_capturing": engine_state["is_capturing"]
    }

@app.get("/api/stats")
async def api_stats():
    global engine_state
    with state_lock:
        all_items = list(engine_state["domains"].items())
        # Sort by recency, then by total hits
        sorted_items = sorted(all_items, key=lambda x: (x[1].get("last_seen", 0), x[1].get("count", 0)), reverse=True)
        top_items = sorted_items[:50]
        
        sorted_domains = [
            {
                "domain": k, 
                "category": v.get("category", "Unknown"), 
                "hits": v.get("count", 0), 
                "last_seen": v.get("last_seen", 0),
                "last_seen_time": v.get("last_seen_time", "--:--:--"),
                "ml_prediction": v.get("ml_prediction", "BENIGN"),
                "ml_confidence": v.get("ml_confidence", "--")
            }
            for k, v in top_items
        ]
        
        return {
            "domains": sorted_domains,
            "total_packets": engine_state["total_packets"],
            "forwarded_packets": engine_state["forwarded_packets"],
            "dropped_packets": engine_state["dropped_packets"],
            "applications": engine_state["applications"],
            "last_update": engine_state["last_update"]
        }

@app.post("/api/start")
async def api_start(data: dict):
    global engine_state
    interface_idx = data.get('interface_idx')
    if interface_idx is None:
        return {"status": "error", "message": "Missing interface_idx"}
    
    if isinstance(interface_idx, str) and '. ' in interface_idx:
        interface_idx = interface_idx.split('.')[0]
        
    with state_lock:
        engine_state["selected_interface"] = str(interface_idx)
        engine_state["is_capturing"] = True
        engine_state["domains"] = {}
        engine_state["total_packets"] = 0
        engine_state["dropped_packets"] = 0
        engine_state["forwarded_packets"] = 0
        engine_state["applications"] = {}
        # Force refresh interfaces if empty
        if not engine_state["interfaces"]:
            engine_state["interfaces"] = get_interfaces()
        
    print(f"📡 Start requested on index: {interface_idx}")
        
    return {"status": "success", "message": "Capture started"}

@app.post("/api/stop")
async def api_stop():
    global engine_state
    engine_state["is_capturing"] = False
    return {"status": "success", "message": "Capture stopped"}

@app.websocket("/ws/stats")
async def websocket_endpoint(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection alive, though ping/pong is handled by FastAPI/Uvicorn
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket Error: {e}")
        broadcaster.disconnect(websocket)

async def dpi_engine_task():
    """Background task to manage the DPI engine process asynchronously."""
    global engine_state
    
    while True:
        interface = None
        is_capturing = False
        with state_lock:
            interface = engine_state["selected_interface"]
            is_capturing = engine_state["is_capturing"]
            
        if not is_capturing or interface is None:
            await asyncio.sleep(1)
            continue
            
        print(f"🚀 [Senior] Starting Asynchronous DPI Pipeline on interface: {interface}")
        
        try:
            cwd = os.getcwd()
            null_device = "NUL" if platform.system() == "Windows" else "/dev/null"
            
            # Resolve full device name
            device_name = interface
            if not engine_state["interfaces"]:
                engine_state["interfaces"] = get_interfaces()
            
            try:
                # Be more robust with interface mapping
                idx = int(interface)
                if not engine_state["interfaces"]:
                    engine_state["interfaces"] = get_interfaces()
                
                if 0 < idx <= len(engine_state["interfaces"]):
                    full_str = engine_state["interfaces"][idx - 1]
                    print(f"📡 Mapping index {idx} to: {full_str}")
                    # Extract the \Device\NPF_{...} part
                    match = re.search(r'(\\Device\\[^{]*\{[^}]*\})', full_str)
                    if match:
                        device_name = match.group(1)
                    else:
                        # Fallback: split by space and look for \Device
                        parts = full_str.split(' ')
                        for p in parts:
                            if p.startswith('\\Device\\'):
                                device_name = p
                                break
            except Exception as e:
                print(f"⚠️ Interface mapping error: {e}")

            # Resolve full device name
            shell_cwd = cwd.replace('\\', '/')
            tshark_bin = TSHARK_PATH.replace('\\', '/')
            # Critical fixing quoting of Windows device string for bash
            device_target = device_name.replace('\\', '\\\\') 
            
            # Use escaped quotes and ensure spaces in paths don't break bash
            bash_cmd = f"cd \"{shell_cwd}\" && export PATH=/mingw64/bin:$PATH && \"{tshark_bin}\" -i \"{device_target}\" -w - | ./{DPI_ENGINE_PATH} - {null_device} --live"
            
            print(f"📡 Pipeline Command (Bash): {bash_cmd}")
            
            process = await asyncio.create_subprocess_exec(
                r"C:\msys64\usr\bin\bash.exe", "-lc",
                bash_cmd,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )

            # Task to log stderr
            async def log_stderr(stderr):
                while True:
                    line = await stderr.readline()
                    if not line: break
                    msg = line.decode('utf-8', errors='ignore').strip()
                    if msg: print(f"DPI Engine Stderr: {msg}")
            
            stderr_task = asyncio.create_task(log_stderr(process.stderr))

            # Read stdout
            while True:
                if not engine_state["is_capturing"]:
                    process.terminate()
                    break
                
                line_bytes = await process.stdout.readline()
                if not line_bytes: break
                
                line = line_bytes.decode('utf-8', errors='ignore').strip()
                if not line: continue
                
                # Debug: log raw output from engine
                if line.startswith('{"type":"stats"'):
                    pass # We parse this below
                else:
                    print(f"DPI Raw Out: {line}")
                
                if not line.startswith('{"type":"stats"'): continue
                
                try:
                    data = json.loads(line)
                    stats = data.get("data", {})
                    
                    with state_lock:
                        now = time.time()
                        now_time = time.strftime('%H:%M:%S', time.localtime(now))
                        engine_state["total_packets"] = stats.get("total_packets", 0)
                        engine_state["forwarded_packets"] = stats.get("packets_forwarded", 0)
                        engine_state["dropped_packets"] = stats.get("packets_dropped", 0)
                        engine_state["applications"] = stats.get("applications", {})
                        
                        for dest in stats.get("top_destinations", []):
                            dom = dest.get("domain")
                            hits = dest.get("hits", 1)
                            if dom:
                                if dom not in engine_state["domains"]:
                                    # New domain detected
                                    prediction, confidence, features = classify_domain(dom, hits, "HTTPS")
                                    engine_state["domains"][dom] = {
                                        "count": hits, "category": "Detected", "last_seen": now, 
                                        "last_seen_time": now_time, 
                                        "ml_prediction": prediction, 
                                        "ml_confidence": confidence,
                                        "extended_features": features
                                    }
                                else:
                                    # Update existing domain
                                    engine_state["domains"][dom]["count"] = hits
                                    engine_state["domains"][dom]["last_seen"] = now
                                    engine_state["domains"][dom]["last_seen_time"] = now_time
                                    # Periodically re-classify
                                    if hits % 50 == 0:
                                        prediction, confidence, features = classify_domain(dom, hits, "HTTPS")
                                        engine_state["domains"][dom]["ml_prediction"] = prediction
                                        engine_state["domains"][dom]["ml_confidence"] = confidence
                                        engine_state["domains"][dom]["extended_features"] = features
                        
                        engine_state["last_update"] = now
                        
                        # Prepare broadcast payload
                        payload = json.dumps({
                            "total_packets": engine_state["total_packets"],
                            "forwarded": engine_state["forwarded_packets"],
                            "dropped": engine_state["dropped_packets"],
                            "applications": engine_state["applications"],
                            "top_destinations": [
                                {
                                    "domain": k, 
                                    "hits": v.get("count", 0), 
                                    "category": v.get("category", "Unknown"),
                                    "ml_prediction": v.get("ml_prediction", "BENIGN"),
                                    "ml_confidence": v.get("ml_confidence", "--"),
                                    "last_seen_time": v.get("last_seen_time", "--:--:--")
                                } 
                                for k, v in sorted(engine_state["domains"].items(), key=lambda x: x[1].get("last_seen", 0), reverse=True)[:15]
                            ]
                        })
                        
                    # Broadcast to all clients (now in the same loop!)
                    await broadcaster.broadcast(payload)
                    
                except Exception as e:
                    print(f"Error parsing DPI output: {e}")

            await process.wait()
            stderr_task.cancel()
            print("🛑 DPI Pipeline stopped.")
            
        except Exception as e:
            print(f"DPI Task Error: {e}")
            await asyncio.sleep(2)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(dpi_engine_task())

if __name__ == "__main__":
    # Use uvicorn in a way that respects the main event loop
    uvicorn.run(app, host="0.0.0.0", port=8081)

