# examples/integrations/mlflow-registry/scripts/mlflow_fetch.py
import json

def get_latest_staging_model(model_name):
    # Simulated mlflow.client.MlflowClient().get_latest_versions()
    print(f"[MLflow Client] Connecting to tracking server to fetch '{model_name}' (Stage: Staging)...")
    
    # Returning a schema that perfectly matches VAREK's 'ModelMetadata'
    mock_metadata = {
        "model_name": model_name,
        "version": "1.4.2",
        "artifact_uri": f"s3://mlflow-artifacts/12/ab89c/artifacts/model",
        "framework": "pytorch"
    }
    
    return mock_metadata
