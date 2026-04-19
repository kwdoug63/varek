# examples/integrations/kubernetes-job-dispatch/src/train_resnet.py
import json
import sys

def train():
    # In a standard K8s Job, passing args via YAML is a string-parsing nightmare.
    # VAREK passes the strictly typed payload directly to the script via standard IO.
    raw_input = sys.stdin.read()
    payload = json.loads(raw_input)
    
    params = payload["params"]
    dataset_path = payload["dataset_s3_path"]
    
    print(f"[Training Container] Initializing PyTorch on {dataset_path}...")
    
    # We can rely on these types because VAREK enforced them before the pod was even scheduled.
    print(f"[Training Container] Config: LR={params['learning_rate']}, Batch={params['batch_size']}, Epochs={params['epochs']}")
    
    # Simulated 8-hour GPU training loop...
    mock_final_loss = 0.042
    mock_model_uri = f"s3://model-registry/resnet50_{params['epochs']}ep.pt"
    
    # VAREK structurally expects this JSON shape to match `TrainingResult`
    result = {
        "final_loss": mock_final_loss,
        "model_uri": mock_model_uri
    }
    
    print(json.dumps(result))

if __name__ == "__main__":
    train()
