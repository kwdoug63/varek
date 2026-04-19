# examples/integrations/rag-pipeline/services/llm_client.py
import json
import sys

def generate():
    # Read the assembled prompt and context from the pipeline
    payload = sys.stdin.read()
    data = json.loads(payload)
    
    # Simulating an LLM returning a structured JSON string
    # If the LLM hallucinated a key here (e.g., "condition" instead of "patient_condition"),
    # the VAREK runtime would trap it securely at the boundary, preventing downstream corruption.
    llm_response = {
        "patient_condition": "Suspected Acute Myocardial Infarction",
        "recommended_action": "Administer aspirin, order immediate ECG, consult cardiology.",
        "requires_escalation": True
    }
    
    print(json.dumps(llm_response))

if __name__ == "__main__":
    generate()
