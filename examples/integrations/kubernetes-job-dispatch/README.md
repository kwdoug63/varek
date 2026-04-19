# VAREK: Type-Safe Kubernetes Job Orchestration

This example demonstrates how VAREK replaces the complex stack of Dockerfiles, Helm charts, Job YAMLs, and Bash scripts required to run a machine learning job on Kubernetes.

### The Problem with Kubernetes ML Jobs
To run a Python script on a GPU cluster today, a data scientist must step out of their code and write infrastructure configurations. YAML has no type system. If the data scientist changes a hyperparameter name in their Python script but forgets to update the bash entrypoint in the Helm chart, the Kubernetes cluster will happily provision a massive GPU pod, run the code, and crash instantly. 

### The VAREK Solution
VAREK elevates cluster dispatch to a native, compiled language feature. By using the `@kubernetes` decorator, VAREK binds the infrastructure requirements directly to the strongly typed execution boundary.
* **No YAML:** VAREK communicates directly with the Kubernetes API.
* **Type-Safe Hyperparameters:** The `HyperParams` type guarantees that the configuration sent to the cluster perfectly matches what the Python script expects.
* **Fail Fast:** If the struct shapes are wrong, VAREK refuses to compile. You find out your code is broken in 10 milliseconds locally, rather than 10 minutes later in a cluster queue.

### Architecture
* `pipeline.vrk` - The compiled orchestrator that defines the cluster resources and dispatches the job.
* `src/train_resnet.py` - The raw PyTorch training script, entirely unaware of K8s.
