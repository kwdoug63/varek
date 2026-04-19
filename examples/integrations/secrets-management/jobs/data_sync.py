# examples/integrations/secrets-management/jobs/data_sync.py
import json
import sys

def run_secure_sync():
    """
    In a standard setup, developers rely on os.environ.get("DB_PASSWORD"), 
    leading to environment variable sprawl and leaked keys in crash logs.
    
    Here, VAREK passes the strictly typed payload directly via secure IPC.
    """
    # Read the securely injected payload from VAREK
    payload = json.loads(sys.stdin.read())
    
    db_config = payload["db"]
    api_creds = payload["api"]
    
    print(f"[Sync Node] Connecting to database at {db_config['host']}:{db_config['port']} as {db_config['username']}...")
    
    # We implicitly trust these credentials exist and are the correct data types 
    # because VAREK enforced the contract at the Vault/AWS boundary.
    print(f"[Sync Node] Initializing API client for {api_creds['provider']}...")
    
    # Simulated workload...
    # (Notice we never log the db_config['password'] or api_creds['token'])
    
    print("[Sync Node] Workload complete. VAREK will purge credentials from memory.")
    
    return {"status": "success"}

if __name__ == "__main__":
    run_secure_sync()
