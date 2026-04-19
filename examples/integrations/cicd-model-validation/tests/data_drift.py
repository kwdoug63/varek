# examples/integrations/cicd-model-validation/tests/data_drift.py
import json

def check_distribution(reference_data, pr_data):
    # Simulated statistical test (e.g., Kolmogorov-Smirnov)
    # If this script randomly output 'drift_detected' instead of 'is_drifted',
    # VAREK's compile-time checks would catch the schema violation instantly.
    
    mock_result = {
        "feature_name": "bp_systolic",
        "p_value": 0.45, 
        "is_drifted": False # Change to True to simulate a CI failure
    }
    
    return mock_result
