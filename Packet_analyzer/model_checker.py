import pickle
import pandas as pd
try:
    with open('model/xgb_model.pkl', 'rb') as f:
        xgb_model = pickle.load(f)
    print("XGBoost Model loaded.")
    if hasattr(xgb_model, 'feature_names_in_'):
        print(f"XGB Explict Features: {list(xgb_model.feature_names_in_)}")
    else:
        print("XGB Model doesn't have feature_names_in_ attribute.")
except Exception as e:
    print(f"Failed to load XGB Model: {e}")

try:
    with open('model/rf_model_v1.pkl', 'rb') as f:
        rf_model = pickle.load(f)
    print("\nRandom Forest Model loaded.")
    if hasattr(rf_model, 'feature_names_in_'):
         print(f"RF Explict Features: {list(rf_model.feature_names_in_)}")
    else:
         print("RF Model doesn't have feature_names_in_ attribute.")
except Exception as e:
    print(f"Failed to load RF Model: {e}")
