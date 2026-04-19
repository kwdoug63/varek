# pods/preprocess.py
import numpy as np
import sys
import json

def run():
    # Simulating data extraction
    raw_path = sys.argv[1]
    
    # Generate mock processed features (Batch size 32, 256 features)
    # If a developer accidentally changed this to (64, 256), 
    # VAREK's compiler would catch the mismatch against the pipeline.vrk spec.
    features = np.random.rand(32, 256).astype(np.float32)
    
    output = {
        "batch_id": f"processed_{raw_path.split('/')[-1]}",
        "features": features.tolist()
    }
    
    # Write to stdout or shared volume for the next pod
    print(json.dumps(output))

if __name__ == "__main__":
    run()
