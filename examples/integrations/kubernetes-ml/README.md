# VAREK + Kubernetes ML Pipeline

This repository demonstrates how VAREK solves the "YAML impedance mismatch" in Kubernetes-based machine learning pipelines.

### The Problem
Traditional tools like Kubeflow or Argo rely on YAML for orchestration. YAML has no type system. If Pod A outputs a tensor of shape `[32, 128]` but Pod B expects `[64, 256]`, Kubernetes will deploy the pipeline anyway, resulting in a silent failure or a runtime crash hours into a training job.

### The VAREK Solution
VAREK elevates the pipeline to a compiled language. By defining the `ProcessedBatch` type with a strict tensor shape (`Tensor<Float32, [32, 256]>`), VAREK verifies the pod-to-pod data contract at **compile time**. If the steps do not align, the pipeline refuses to compile, preventing the YAML from ever being generated.

### Architecture
* `pipeline.vrk` - The strictly typed orchestration logic.
* `pods/preprocess.py` - The simulated data extraction container.
* `pods/train.py` - The simulated GPU training container.
