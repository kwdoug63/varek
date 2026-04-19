# examples/integrations/data-lineage-marquez/src/anonymize.py
import hashlib

def mask_phi(raw_data):
    """
    Notice what is missing here: NO tracking code, NO Marquez imports, NO Atlas API calls.
    The Data Scientist only focuses on the math/logic. 
    VAREK handles the execution state and lineage emission automatically.
    """
    print(f"[Compute Node] Processing {len(raw_data)} records for PHI masking...")
    
    safe_features = []
    
    for row in raw_data:
        # One-way hash of the patient ID and drop the SSN entirely
        patient_hash = hashlib.sha256(row["patient_id"].encode()).hexdigest()
        
        # We implicitly trust these types because VAREK's compile-time contract guarantees them
        safe_features.append({
            "patient_hash": patient_hash[:12],
            "diagnosis_code": row["diagnosis_code"],
            "lab_value": row["lab_value"]
        })
        
    print("[Compute Node] Anonymization complete.")
    return safe_features
