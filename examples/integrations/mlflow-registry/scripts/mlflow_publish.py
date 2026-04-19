# examples/integrations/mlflow-registry/scripts/mlflow_publish.py

def log_metrics(model_metadata, metrics):
    # Simulated mlflow.log_metric() 
    print(f"[MLflow Client] Logging run for {model_metadata['model_name']} (v{model_metadata['version']})...")
    
    # Because VAREK orchestrates this, we know 'metrics' has exactly the keys we expect.
    # No KeyError exceptions here.
    for metric_name, value in metrics.items():
        print(f"   -> logged {metric_name}: {value}")
        
    return True
