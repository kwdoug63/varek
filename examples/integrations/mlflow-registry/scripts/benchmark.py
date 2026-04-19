# examples/integrations/mlflow-registry/scripts/benchmark.py

def run_eval(artifact_uri, test_data_path):
    # Simulated model loading and dataset scoring
    print(f"[Compute Node] Loading model from {artifact_uri}...")
    print(f"[Compute Node] Running inference on {test_data_path}...")
    
    # We rely on VAREK to ensure these float types are enforced
    mock_metrics = {
        "accuracy": 0.885,
        "log_loss": 0.312,
        "inference_time_ms": 42.8
    }
    
    return mock_metrics
