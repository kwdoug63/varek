# examples/integrations/kafka-pipeline/streaming/producer.py
import json
import time
import random

def emit_events():
    print("Starting transaction producer...")
    while True:
        # If a dev renames 'amount' to 'tx_amount' here, 
        # VAREK catches the schema violation at compile time.
        event = {
            "tx_id": f"tx_{random.randint(1000, 9999)}",
            "amount": round(random.uniform(5.0, 1500.0), 2),
            "merchant_category": random.choice([5411, 5812, 5912]),
            "timestamp": int(time.time())
        }
        
        # Simulate producing to Kafka topic
        print(f"PRODUCING: {json.dumps(event)}")
        time.sleep(1)

if __name__ == "__main__":
    emit_events()
