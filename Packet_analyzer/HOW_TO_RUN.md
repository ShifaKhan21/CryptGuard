# How to Run CryptGuard DPI System

## Prerequisites
- **MSYS2** installed at `C:\msys64`
- **Python 3** installed and in PATH
- **Node.js** installed (for frontend)
- **Wireshark/tshark** installed at `C:\Program Files\Wireshark\tshark.exe`

---

## Step 1 — Compile the C++ DPI Engine

Open **PowerShell** and navigate to the project directory:

```
cd "c:\Users\Muhammad Mitkar\Desktop\PROJECTS\OOOOCryptGuardad\Packet_analyzer"
```

Run the compiler using MSYS2/MinGW bash:

```
C:\msys64\usr\bin\bash.exe -lc "cd 'c:/Users/Muhammad Mitkar/Desktop/PROJECTS/OOOOCryptGuardad/Packet_analyzer' && export PATH=/mingw64/bin:$PATH && g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp 2>&1"
```

✅ You should see no errors and `dpi_engine.exe` will appear in the folder.

---

## Step 2 — Start the Python API Server

In the **same PowerShell window** (still in `Packet_analyzer/`):

```
python api_server.py
```

✅ You should see:
```
[AI] Models loaded successfully!
API Server listening on port 8081...
```

> ⚠️ Run as **Administrator** if you get a `PermissionError: [WinError 10013]`

---

## Step 3 — Start the React Frontend

Open a **new PowerShell window** and run:

```
cd "c:\Users\Muhammad Mitkar\Desktop\PROJECTS\OOOOCryptGuardad\Packet_analyzer\web_ui"
npm run dev
```

✅ You should see:
```
Local: http://localhost:5173/
```

---

## Step 4 — Use the Dashboard

1. Open your browser and go to **http://localhost:5173**
2. Select a **Network Interface** from the dropdown
3. Click **Start Inspection**
4. Browse the web — domains will appear in real-time with AI threat scores

---

## Summary — All 3 Services

| Service | Command | Port |
|---------|---------|------|
| **DPI Engine** | `g++` compile command above | (CLI tool, no port) |
| **API Server** | `python api_server.py` | `8081` |
| **Frontend** | `npm run dev` (in `web_ui/`) | `5173` |
