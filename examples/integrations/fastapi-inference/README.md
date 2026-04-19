# VAREK + FastAPI Integration

This example demonstrates how VAREK can safely orchestrate existing Python-based ML microservices. 

By defining the `PatientData` type with a strict tensor shape (`Tensor<Float32, [3]>`) in VAREK, we eliminate the risk of silent runtime failures when passing data to the dynamically typed FastAPI endpoint.

### How to run:
1. Start the Python inference server:
   `pip install -r requirements.txt`
   `uvicorn server:app --reload`
2. In a new terminal, compile and run the VAREK pipeline:
   `varek run pipeline.vrk`
