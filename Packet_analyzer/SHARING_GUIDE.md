# CryptGuard Sharing Guide 🛡️

Follow these steps to set up and run CryptGuard on your laptop.

## 1. Prerequisites
You need the following installed on your system:

### A. Network Capture
*   **Wireshark**: [Download and Install Wireshark](https://www.wireshark.org/download.html).
    *   **CRITICAL**: During installation, ensure `tshark` is included.
    *   Make sure `C:\Program Files\Wireshark\` is in your System PATH (usually done automatically).

### B. Python Environment
*   **Python 3.8+**: [Download Python](https://www.python.org/downloads/).
*   Install required libraries:
    ```bash
    pip install -r requirements.txt
    ```
    *(Specifically: psutil, pandas, numpy, scipy, joblib, scikit-learn, xgboost, requests, python-dotenv)*

### C. UI Environment
*   **Node.js**: [Download Node.js](https://nodejs.org/).
*   Run `npm install` inside the `web_ui` folder.

### D. API Keys (.env)
*   Rename `.env.example` to `.env`.
*   Add your `ABUSEIPDB_API_KEY` and `VT_API_KEY` for real-time threat intelligence.

---

## 2. Running CryptGuard
We have provided a one-click launcher for convenience.

1.  **Extract** the `CryptGuard` folder.
2.  Double-click **`run_app.bat`**.
    *   This will automatically start the **AI API Server** and the **Dashboard UI**.
3.  Open your browser to: `http://localhost:5173`

---

## 3. How to Use
1.  Once the dashboard loads, click **"Refresh Interfaces"**.
2.  Select your active network (usually the one with "Wi-Fi" or "Ethernet" in the name).
3.  Click **"Start Monitoring"**.
4.  Browse the web and watch the system detect real-time traffic and assign AI Risk Scores!

---

## 4. Troubleshooting
*   **"tshark not found"**: Ensure Wireshark is installed and the path `C:\Program Files\Wireshark\tshark.exe` exists.
*   **"Models not found"**: Ensure the `model/` folder contains `rf_model_v1.pkl` and `xgb_model.pkl`.
*   **"DPI Engine Error"**: Ensure `dpi_engine.exe` is present. If you need to recompile, use:
    ```bash
    cmd /c "set PATH=C:\msys64\mingw64\bin;%PATH% && g++ -O3 -std=c++17 src/dpi_mt.cpp src/packet_parser.cpp src/sni_extractor.cpp src/pcap_reader.cpp src/types.cpp src/md5.cpp -Iinclude -lws2_32 -o dpi_engine.exe"
    ```
    *(Note: Replace the path to MinGW if installed elsewhere).*
