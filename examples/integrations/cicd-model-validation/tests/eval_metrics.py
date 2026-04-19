# examples/integrations/cicd-model-validation/tests/eval_metrics.py
import json

def run_eval(model_path, test_data):
    # Simulated model inference and scoring
    # VAREK guarantees these float types won't be silently coerced to strings
    mock_metrics = {
        "model_version": "v2.1.0-rc1",
        "f1_score": 0.945,
        "p99_latency_ms": 112.4 
    }
    
    return mock_metrics
