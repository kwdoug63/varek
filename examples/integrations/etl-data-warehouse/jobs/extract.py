# examples/integrations/etl-data-warehouse/jobs/extract.py
import json

def pull_from_postgres(query):
    # Simulated database fetch
    print(f"[Postgres Engine] Executing query: {query}")
    
    # Notice this schema matches 'RawRecord' in VAREK.
    # If a DBA changes 'bp_systolic' to 'systolic_bp' in the DB query, 
    # VAREK traps the mismatch at the extraction boundary, preventing downstream corruption.
    mock_data = [
        {"patient_id": "PT-1029", "age": 45, "bp_systolic": 130, "bp_diastolic": 85},
        {"patient_id": "PT-3392", "age": 62, "bp_systolic": 155, "bp_diastolic": 95}
    ]
    
    return mock_data
