# VAREK + Kafka Streaming Pipeline

This example demonstrates how VAREK enforces streaming data contracts between producers and ML inference consumers.

### The Problem
In streaming ML pipelines, data is typically serialized as JSON. If the upstream data engineering team changes a field name or type (e.g., changing `amount` from a float to a string), the downstream ML model will either crash or, worse, make silent, inaccurate predictions in real-time. 

### The VAREK Solution
VAREK acts as a compile-time schema enforcer. By defining the `TransactionEvent` type, VAREK ensures that the `Stream` output of the producer strictly matches the `Stream` input of the consumer. Any structural deviation fails at compile time, long before the bad data hits the live Kafka topic.

### To simulate this pipeline locally:
`python streaming/producer.py | python streaming/consumer.py`

*(Note: VAREK compiles this logic down to ensure boundary safety before allowing execution).*
