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
*   Install required libraries by running this in your terminal:
    ```bash
    pip install psutil pandas numpy joblib joblib scikit-learn
    ```

### C. UI Environment
*   **Node.js**: [Download Node.js](https://nodejs.org/). This is needed to run the dashboard.

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
*   **"DPI Engine Error"**: Ensure `dpi_engine.exe` is in the `Packet_analyzer` folder.
