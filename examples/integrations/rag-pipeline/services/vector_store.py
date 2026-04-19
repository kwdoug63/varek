# examples/integrations/rag-pipeline/services/vector_store.py
import json
import sys

def search():
    # Simulating reading the query from the pipeline
    query = sys.stdin.read().strip()
    
    # Mock retrieval from a vector database
    # Notice this perfectly matches the `RetrievedContext` type in VAREK
    mock_results = [
        {
            "doc_id": "guideline_cardio_104",
            "text_chunk": "Elevated troponin with chest pain indicates NSTEMI or STEMI.",
            "confidence_score": 0.94
        },
        {
            "doc_id": "history_pt_882",
            "text_chunk": "Patient has a history of hypertension and smoking.",
            "confidence_score": 0.88
        }
    ]
    
    print(json.dumps(mock_results))

if __name__ == "__main__":
    search()
