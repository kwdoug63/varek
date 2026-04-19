# VAREK: Type-Safe Inference Serving

This example demonstrates how to serve a machine learning model safely using VAREK as the orchestration engine behind a standard FastAPI endpoint.

### The Problem with Python Inference
In traditional ML serving, preprocessing, model execution, and postprocessing are chained together in standard Python scripts. If the preprocessing script accidentally returns an RGBA image `(1, 4, 224, 224)` instead of RGB `(1, 3, 224, 224)`, the Python API will pass it to the GPU, causing a hard crash or memory spike at runtime. 

### The VAREK Solution
VAREK acts as a strictly typed middleware between your web framework (FastAPI/gRPC) and your ML logic. 
By defining the tensor shapes in `pipeline.vrk`, VAREK mathematically guarantees that the output of the preprocessing step perfectly matches the input requirements of the model runner.

### Architecture
* `server.py` - The FastAPI server that handles HTTP and calls the compiled VAREK binary.
* `pipeline.vrk` - The strictly typed inference graph.
* `backend/` - The existing, untyped Python logic that VAREK safely wraps and executes.
