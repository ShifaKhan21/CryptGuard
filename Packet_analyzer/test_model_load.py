
import pickle
import os
import sys

# Try loading with pickle
try:
    with open(r"z:\Hacknova Hackathon\new\CryptGuard\Packet_analyzer\model\rf_model_v1.pkl", "rb") as f:
        rf_model = pickle.load(f)
    print("RF Model loaded successfully with pickle")
    print(f"Model type: {type(rf_model)}")
except Exception as e:
    print(f"RF Model load failed: {e}")

try:
    with open(r"z:\Hacknova Hackathon\new\CryptGuard\Packet_analyzer\model\xgb_model.pkl", "rb") as f:
        xgb_model = pickle.load(f)
    print("XGB Model loaded successfully with pickle")
    print(f"Model type: {type(xgb_model)}")
except Exception as e:
    print(f"XGB Model load failed: {e}")

# If they use XGBoost or RandomForest, we might need sklearn/xgboost libraries
try:
    import sklearn
    print(f"Scikit-learn version: {sklearn.__version__}")
except:
    print("Scikit-learn not installed")

try:
    import xgboost
    print(f"XGBoost version: {xgboost.__version__}")
except:
    print("XGBoost not installed")
