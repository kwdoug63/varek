# examples/integrations/inference-serving/server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import varek_runtime  # Simulated VAREK FFI bindings

app = FastAPI(title="VAREK Inference Server")

# Load the compiled, type-safe pipeline into memory
pipeline = varek_runtime.load("pipeline.vrk.bin")

class InferenceRequest(BaseModel):
    request_id: str
    image_b64: str

@app.post("/predict")
def predict(req: InferenceRequest):
    try:
        # FastAPI handles the HTTP layer, VAREK handles the deterministic execution graph.
        # If the image is malformed, VAREK traps the error gracefully at the execution boundary.
        result = pipeline.serve_inference(req.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
