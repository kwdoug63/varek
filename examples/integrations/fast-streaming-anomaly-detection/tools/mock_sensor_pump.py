# examples/integrations/fast-streaming-anomaly-detection/tools/mock_sensor_pump.py
import json
import time
import random
import sys

def pump_data():
    print("Pumping mock sensor data into standard out (Simulating Kafka 'iot-raw-sensors')...")
    
    try:
        while True:
            # Simulate high-frequency IoT data
            payload = {
                "sensor_id": f"turbine_{random.randint(1, 10)}",
                "temperature_c": round(random.uniform(60.0, 115.0), 2),
                "vibration_hz": round(random.uniform(40.0, 95.0), 2),
                "timestamp_ms": int(time.time() * 1000)
            }
            
            # Print to stdout so it can be piped into VAREK for local testing
            print(json.dumps(payload))
            sys.stdout.flush()
            time.sleep(0.01) # 100 messages per second
            
    except KeyboardInterrupt:
        print("\nPump stopped.")

if __name__ == "__main__":
    pump_data()
