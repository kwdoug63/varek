# examples/integrations/arize-observability/scripts/inference.py
import json
import time
import random

def run_batch_inference(batch_uri):
    print(f"[Compute Node] Loading data from {batch_uri} and running model...")
    
    mock_records = []
    for i in range(5):
        # We rely on VAREK to ensure these float types are never coerced to strings dynamically
        record = {
            "prediction_id": f"pred_{random.randint(10000, 99999)}",
            "feature_age": round(random.uniform(35.0, 85.0), 1),
            "feature_bmi": round(random.uniform(18.5, 40.0), 1),
            "feature_blood_pressure": round(random.uniform(90.0, 180.0), 1),
            "predicted_risk_score": round(random.uniform(0.1, 0.9), 3),
            "timestamp_ms": int(time.time() * 1000)
        }
        mock_records.append(record)
        
    return mock_records
