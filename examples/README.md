# VAREK Integration Examples

VAREK is designed to solve the semantic impedance mismatch across the entire ML infrastructure stack. 

Instead of relying on dynamically typed Python scripts, brittle YAML files, and untyped REST APIs, VAREK acts as a strictly typed, compiled orchestration layer.

Below is an index of self-contained examples demonstrating how VAREK securely wraps and orchestrates existing tools and frameworks.

## 🔌 API & Microservices
* **[FastAPI Inference Serving](./integrations/inference-serving/)** — VAREK handling pre/post-processing tensor shapes behind a FastAPI endpoint, before hitting PyTorch/ONNX.
* **[External REST Boundaries](./integrations/fastapi-inference/)** — VAREK enforcing strict data contracts before sending payloads to dynamically typed Python microservices.

## ⚙️ Orchestration & ETL
* **[Airflow/Snowflake ETL Pipeline](./integrations/etl-data-warehouse/)** — A type-safe alternative to Airflow DAGs. VAREK guarantees data schemas between extraction, transformation, and warehouse loading.
* **[Kubernetes Pod-to-Pod Pipeline](./integrations/kubernetes-pipeline/)** — Eliminating YAML mismatch. VAREK verifies tensor shapes moving between disparate K8s pods at compile time.
* **[Kubernetes Job Dispatch](./integrations/kubernetes-job-dispatch/)** — Abstracting away Dockerfiles and Helm charts. VAREK natively dispatches heavily-typed ML training jobs to a cluster.

## 🌊 Streaming & Compute
* **[Kafka Streaming Pipeline](./integrations/kafka-pipeline/)** — VAREK acting as a compile-time schema registry between streaming producers and ML consumers.
* **[High-Speed Native Streaming](./integrations/fast-streaming-anomaly-detection/)** — Bypassing the Python GIL. VAREK compiled via LLVM for microsecond-latency IoT anomaly detection directly off a Kafka topic.

## 🤖 LLMs & Agents
* **[Type-Safe RAG Pipeline](./integrations/rag-pipeline/)** — A compiled alternative to LangChain. VAREK strictly typing the data contracts between Vector Databases and LLM JSON generation.
* **[LangChain Circuit Breaker](./03-langchain-circuit-breaker) — Stopping the infinite retry loop. Wrapping LangChain agent executors in a deterministic LLVM gateway to physically snap the circuit when a model hallucinates malformed JSON.

## 🔒 DevOps & Compliance
* **[Type-Safe ML Observability (Arize AI)](./integrations/arize-observability/)** — VAREK acting as a compile-time telemetry contract, guaranteeing that feature and prediction logs sent to Arize are structurally perfect before ingestion.
* **[CI/CD Model Validation](./integrations/cicd-model-validation/)** — VAREK as a deterministic GitHub Actions gatekeeper, replacing brittle Bash/Regex model evaluation scripts.
* **[Existing MLflow Registry](./integrations/mlflow-registry/)** — "No Rip-and-Replace." VAREK safely typing the staging, fetching, and logging of metrics to an existing MLflow tracking server.
* **[Automated Data Lineage](./integrations/data-lineage-marquez/)** — VAREK automatically emitting OpenLineage events to Marquez/Atlas natively from the compiler, keeping Python compute code clean.
* **[Type-Safe Secrets Management](./integrations/secrets-management/)** — VAREK dynamically injecting AWS/Vault credentials into memory safely, preventing leaked keys in logs or YAML.
