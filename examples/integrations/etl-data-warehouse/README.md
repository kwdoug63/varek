# VAREK: Type-Safe ETL into Data Warehouses

This example demonstrates how VAREK replaces fragile Airflow DAGs and untyped Python scripts with a compiled, structurally verified data pipeline.

### The Problem with Airflow + Python ETL
Traditional orchestrators like Airflow verify task *execution*, not data *contracts*. If Task A (Extract) pulls a column named `bp_systolic` as a string instead of an integer, Airflow will mark Task A as successful. Task B (Transform) will then crash with a Python `TypeError`, or worse, Task C (Load) will write corrupted data into Snowflake or BigQuery. 

### The VAREK Solution
VAREK elevates the DAG to a strictly typed, compiled orchestration layer. By defining `RawRecord` and `FeatureRow` in `pipeline.vrk`, VAREK guarantees that the input and output schemas of every Python script align perfectly.
* **Compile-Time Safety:** If the output of the Transform step does not match the exact schema expected by the Load step, the pipeline refuses to compile.
* **Boundary Trapping:** If the external Postgres database returns an unexpected schema at runtime, VAREK traps the error at the execution boundary *before* the corrupted data is passed to the transform logic.

### Architecture
* `pipeline.vrk` - The strictly typed DAG and data contract definition.
* `jobs/extract.py` - Simulates reading from Postgres.
* `jobs/transform.py` - Simulates feature engineering.
* `jobs/load.py` - Simulates writing to Snowflake.
