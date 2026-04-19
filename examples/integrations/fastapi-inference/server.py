# examples/integrations/fastapi-inference/server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class ClinicalData(BaseModel):
    patient_id: str
    feature_vector: list[float]

@app.post("/predict")
def predict_risk(data: ClinicalData):
    # Simulate a model inference failure if data is malformed
    if len(data.feature_vector) != 3:
        raise HTTPException(status_code=400, detail="Invalid tensor shape")
    
    # Mock inference logic
    risk_score = sum(data.feature_vector) * 0.15
    return {"patient_id": data.patient_id, "risk_score": round(risk_score, 3)}
