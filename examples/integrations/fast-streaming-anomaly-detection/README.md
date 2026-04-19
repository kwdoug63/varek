# VAREK: High-Performance Event Stream Processing

This example demonstrates VAREK's LLVM compilation backend for latency-sensitive streaming workloads, such as real-time anomaly detection or fraud evaluation.

### The Problem with Python Stream Processing
Tools like Faust, Celery, or standard `kafka-python` are severely bottlenecked by the Python Global Interpreter Lock (GIL) and dynamic type checking. When processing thousands of events per second, Python's overhead and Garbage Collection (GC) pauses introduce unpredictable latency spikes (milliseconds to seconds), which is unacceptable for high-frequency trading or critical IoT monitoring.

### The VAREK Solution
For critical stream processing, VAREK bypasses Python entirely.
* **Native Execution:** The `pipeline.vrk` file compiles down to native machine code via LLVM. The `detect_anomaly` function executes with C/Rust-level microsecond latency.
* **Zero-Cost Deserialization:** Because VAREK strictly types the `SensorReading` struct, it reads the byte stream from Kafka directly into memory with zero dynamic type-checking overhead.
* **Memory Determinism:** VAREK does not suffer from unpredictable GC pauses, guaranteeing flat, consistent latency percentiles.

### Architecture
* `pipeline.vrk` - The compiled, native stream processor.
* `tools/mock_sensor_pump.py` - A utility script to generate mock JSON payloads for local testing.

### Local Simulation
You can pipe the mock data directly into the compiled VAREK binary to test throughput:
`python tools/mock_sensor_pump.py | varek run pipeline.vrk`
