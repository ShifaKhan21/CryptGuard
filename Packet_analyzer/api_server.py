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
from typing import List, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

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
            for k, v in sorted(engine_state["domains"].items(), key=lambda item: (item[1].get("last_seen", 0), item[1].get("count", 0)), reverse=True)
        ][:50]
        
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
                idx = int(interface)
                if 0 < idx <= len(engine_state["interfaces"]):
                    full_str = engine_state["interfaces"][idx - 1]
                    parts = full_str.split(' ')
                    for p in parts:
                        if p.startswith('\\Device\\'):
                            device_name = p
                            break
            except: pass

            # Resolve full device name
            shell_cwd = cwd.replace('\\', '/')
            tshark_bin = TSHARK_PATH.replace('\\', '/')
            device_target = device_name
            
            # Format the bash command string carefully
            # We use double quotes for the bash command to handle spaces in paths
            bash_cmd = f"cd '{shell_cwd}' && export PATH=/mingw64/bin:$PATH && \"{tshark_bin}\" -i '{device_target}' -w - | ./{DPI_ENGINE_PATH} - {null_device} --live"
            
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
                if not line or not line.startswith('{"type":"stats"'): continue
                
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
                            if dom:
                                if dom not in engine_state["domains"]:
                                    engine_state["domains"][dom] = {
                                        "count": 0, "category": "Detected", "last_seen": now, 
                                        "last_seen_time": now_time, "ml_prediction": "BENIGN", "ml_confidence": "--"
                                    }
                                engine_state["domains"][dom]["count"] += dest.get("hits", 1)
                                engine_state["domains"][dom]["last_seen"] = now
                                engine_state["domains"][dom]["last_seen_time"] = now_time
                        
                        engine_state["last_update"] = now
                        
                        # Prepare broadcast payload
                        payload = json.dumps({
                            "total_packets": engine_state["total_packets"],
                            "forwarded": engine_state["forwarded_packets"],
                            "dropped": engine_state["dropped_packets"],
                            "applications": engine_state["applications"],
                            "top_destinations": [
                                {"domain": k, "hits": v["count"], "category": v["category"]} 
                                for k, v in sorted(engine_state["domains"].items(), key=lambda x: x[1]["last_seen"], reverse=True)[:10]
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

