# examples/integrations/kafka-pipeline/streaming/consumer.py
import json
import sys

def run_inference():
    print("Listening for transactions on 'live-transactions' topic...")
    # Simulating consuming from standard in for the demo
    for line in sys.stdin:
        try:
            event = json.loads(line)
            
            # The ML model expects a float amount.
            # VAREK structurally guarantees this data type won't silently change to a string.
            amount = float(event["amount"]) 
            
            # Mock inference logic
            risk_score = min(amount / 1000.0, 1.0)
            status = "FLAGGED" if risk_score > 0.8 else "CLEARED"
            
            print(f"CONSUMED: tx_id={event['tx_id']} | risk_score={risk_score:.2f} | status={status}")
            
        except KeyError as e:
            print(f"CRITICAL ERROR: Missing schema key {e}")

if __name__ == "__main__":
    run_inference()
