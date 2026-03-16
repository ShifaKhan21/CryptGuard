
import joblib
import os
import sys

# Try loading with joblib
try:
    rf_model = joblib.load(r"z:\Hacknova Hackathon\new\CryptGuard\Packet_analyzer\model\rf_model_v1.pkl")
    print("RF Model loaded successfully with joblib")
    print(f"Model type: {type(rf_model)}")
except Exception as e:
    print(f"RF Model load failed with joblib: {e}")

try:
    xgb_model = joblib.load(r"z:\Hacknova Hackathon\new\CryptGuard\Packet_analyzer\model\xgb_model.pkl")
    print("XGB Model loaded successfully with joblib")
    print(f"Model type: {type(xgb_model)}")
except Exception as e:
    print(f"XGB Model load failed with joblib: {e}")
