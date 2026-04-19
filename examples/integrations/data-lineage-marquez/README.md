# VAREK: Automated Data Lineage & Compliance

This example demonstrates how VAREK automatically emits data lineage events (e.g., OpenLineage format to Marquez or Apache Atlas) without polluting your Python compute code.

### The Problem with Python Lineage Tracking
In regulated industries (Healthcare, Finance), tracking the exact origin and transformations of data is legally required. Usually, this means forcing Data Scientists to wrap every Python function in `openlineage` decorators or API calls. This tightly couples your compliance layer to your math layer. If a developer forgets the decorator, or if a dynamic Python type silently changes, the lineage graph breaks and compliance is violated.

### The VAREK Solution
VAREK cleanly separates **governance** from **compute**. 
Because VAREK acts as the compiled orchestration layer, it already knows the entire execution graph, the exact input/output URIs, and the structural types of the data. 

By simply tagging an execution boundary with `@openlineage`, VAREK automatically handles the Start, Complete, and Fail telemetry at the compiler level. 
* **Zero-Touch Python:** Your data scientists write raw, clean Python. No tracking SDKs required.
* **Deterministic Tracking:** Because VAREK guarantees the data contracts, the lineage metadata emitted to Marquez is guaranteed to perfectly reflect the actual data schemas flowing through the system.

### Architecture
* `pipeline.vrk` - The compiled orchestrator enforcing types and emitting lineage telemetry.
* `src/anonymize.py` - The raw, untracked Python logic that VAREK safely wraps.
