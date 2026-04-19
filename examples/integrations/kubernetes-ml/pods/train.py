# pods/train.py
import numpy as np
import sys
import json

def run():
    # Read the data contract passed from the previous pod
    input_data = sys.stdin.read()
    payload = json.loads(input_data)
    
    features = np.array(payload["features"])
    
    # The script blindly assumes the shape is (32, 256)
    # Thanks to VAREK, we know this assumption is structurally guaranteed
    assert features.shape == (32, 256), "Runtime shape mismatch!"
    
    # Mock training loop
    loss = 0.42 - (features.mean() * 0.1)
    
    print(json.dumps({"loss": round(loss, 4)}))

if __name__ == "__main__":
    run()
