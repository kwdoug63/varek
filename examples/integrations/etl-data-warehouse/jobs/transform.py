# examples/integrations/etl-data-warehouse/jobs/transform.py
import json

def engineer_features(raw_data):
    features = []
    MAX_AGE = 120.0
    
    for row in raw_data:
        # We can trust these types implicitly because VAREK guaranteed them
        age_norm = row["age"] / MAX_AGE
        
        # Simple risk calculation
        map_risk = (row["bp_systolic"] + (2 * row["bp_diastolic"])) / 3
        risk_score = round(min(map_risk / 120.0, 1.0), 3)
        
        features.append({
            "patient_id": row["patient_id"],
            "age_normalized": age_norm,
            "hypertension_risk": risk_score
        })
        
    print(f"[Transform Engine] Engineered {len(features)} feature rows.")
    return features
