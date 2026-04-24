import json
import time
import random
import uuid
from datetime import datetime
from confluent_kafka import Producer
from faker import Faker
import sqlite3

fake = Faker()

# --- AIVEN KAFKA CONFIGURATION ---
# Replace <YOUR_AIVEN_SERVICE_URI> with your actual Aiven Service URI (e.g., kafka-xxxx.aivencloud.com:28925)
AIVEN_URI = "kafka-mas-social-spark.k.aivencloud.com:10409" 

conf = {
    'bootstrap.servers': AIVEN_URI,
    'security.protocol': 'SSL',
    'ssl.ca.location': 'ca.pem',
    'ssl.certificate.location': 'service.cert',
    'ssl.key.location': 'service.key',
    'client.id': 'core_banking_producer'
}

producer = Producer(conf)
topic = 'incoming_transactions'

def generate_live_transaction():
    """Generates a realistic transaction payload."""
    db_path = r"D:\All-Things-Python\Projects\Autonomous-Finance-Forensics-Agent\Autonomous-Finance-Forensics-Agent - Copy (2)\organization_vault\data\core_banking_ledger.db"
    
    query = """
    SELECT * FROM transactions
    """

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    if rows:
        transaction = random.choice(rows)
    else:
        transaction = None

    return transaction

def delivery_report(err, msg):
    """Callback triggered on successful/failed delivery."""
    if err is not None:
        print(f"[!] Message delivery failed: {err}")
    else:
        try:
            payload = json.loads(msg.value().decode('utf-8'))
            print(f"[>] Streamed to {msg.topic()}: TX {payload['tx_id']} for {payload['amount']} {payload['currency']}")
        except:
            print(f"[>] Streamed to {msg.topic()}")

print(f"Starting Core Banking Stream to Aiven Kafka topic '{topic}'...")
# print(f"Ensure you have replaced '<YOUR_AIVEN_SERVICE_URI>:<PORT>' with your actual Aiven URI.")

try:
    while True:
        tx_data = generate_live_transaction()
        
        # Send the data to Kafka
        producer.produce(
            topic, 
            key=tx_data['customer_id'].encode('utf-8'), # Grouping by customer ensures sequential processing
            value=json.dumps(tx_data).encode('utf-8'),
            callback=delivery_report
        )
        
        producer.poll(0) # Serve delivery callbacks
        time.sleep(random.uniform(20.0, 25.0)) # Delay between 20 to 25 seconds
except KeyboardInterrupt:
    print("\nStopping producer...")
finally:
    producer.flush()
