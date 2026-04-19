# VAREK: Type-Safe RAG Pipeline

This example demonstrates how VAREK replaces fragile LangChain/LlamaIndex scripts with a compiled, structurally verified orchestration layer for Retrieval-Augmented Generation (RAG).

### The Problem with Python RAG
In standard Python RAG applications, the orchestration layer relies on deep, dynamically typed abstractions. If the Vector DB returns unexpected metadata, or if the LLM hallucinates a JSON key (e.g., returning `{"condition": "..."}` instead of `{"patient_condition": "..."}`), the pipeline fails silently or throws an obscure Python runtime error deep in an execution chain.

### The VAREK Solution
VAREK acts as a strictly typed orchestrator. By defining the `RetrievedContext` and `ClinicalExtraction` types, VAREK guarantees the data contracts between the database, the prompt assembly, and the LLM execution boundary.
* **Compile-Time Safety:** If the downstream consumer expects `patient_condition` to be a string, VAREK ensures the pipeline cannot compile unless the execution boundaries agree.
* **No Abstraction Magic:** VAREK gives you a flat, transparent dependency graph, entirely eliminating the need for heavy orchestrator libraries.

### Architecture
* `pipeline.vrk` - The strictly typed RAG orchestration logic.
* `services/vector_store.py` - Simulates the Pinecone/Weaviate retrieval.
* `services/llm_client.py` - Simulates the LLM structured JSON generation.
