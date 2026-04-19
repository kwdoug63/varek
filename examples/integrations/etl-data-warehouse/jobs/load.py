# examples/integrations/etl-data-warehouse/jobs/load.py

def write_to_snowflake(features, table_name):
    # Simulated Snowflake write
    print(f"[Snowflake Engine] Connecting to destination table: {table_name}")
    
    # In a standard Airflow job, if the upstream transform script started outputting 
    # 'age_norm' as a string by accident, Snowflake would reject the batch and crash.
    # Because VAREK orchestrates this, we have a structural guarantee that 'features'
    # exactly matches the expected schema.
    
    print(f"[Snowflake Engine] Successfully wrote {len(features)} strictly typed rows.")
    return True
