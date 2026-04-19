# examples/integrations/inference-serving/backend/image_utils.py
import numpy as np

def decode_and_resize(b64_string):
    # Simulated decoding and resizing of a base64 image
    # If this step returns a (1, 4, 224, 224) tensor by mistake (e.g., RGBA instead of RGB),
    # VAREK's runtime catches it before it crashes the GPU model runner.
    return np.random.rand(1, 3, 224, 224).astype(np.float32)

def get_top_class(logits):
    # Simulated argmax and label lookup
    return {
        "label": "n01440764 tench, Tinca tinca",
        "conf": float(np.max(logits))
    }
