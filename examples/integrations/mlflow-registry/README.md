# VAREK: Existing Model Registry Integration

This example demonstrates how VAREK orchestrates type-safe evaluation pipelines while integrating cleanly with your existing Model Registry (e.g., MLflow, Weights & Biases, or Comet ML).

### No Rip-and-Replace
Adopting VAREK does not mean abandoning your MLOps stack. MLflow is excellent at tracking artifacts and metrics, but the Python scripts used to tie the fetch, evaluate, and publish steps together are fundamentally untyped and prone to silent failures.

### The VAREK Solution
VAREK acts as the **strictly typed orchestration glue** between your existing tools.
By defining `ModelMetadata` and `EvalMetrics` in `pipeline.vrk`, VAREK guarantees the data contracts between your MLflow scripts and your heavy compute scripts. 

If your evaluation script accidentally outputs `acc` instead of `accuracy`, VAREK traps the mismatch at the execution boundary *before* it logs corrupted data back to your central MLflow tracking server.

### Architecture
* `pipeline.vrk` - The compiled orchestrator enforcing the contracts.
* `scripts/mlflow_fetch.py` - Wraps the MLflow API to pull the staging model.
* `scripts/benchmark.py` - Runs the heavy inference evaluation.
* `scripts/mlflow_publish.py` - Wraps the MLflow API to log the results back.
