import json
from confluent_kafka import Consumer, KafkaError

# --- CONFIGURATION ---
AIVEN_URI = "kafka-mas-social-spark.k.aivencloud.com:10409"

conf = {
    'bootstrap.servers': AIVEN_URI,
    'security.protocol': 'SSL',
    'ssl.ca.location': 'ca.pem',
    'ssl.certificate.location': 'service.cert',
    'ssl.key.location': 'service.key',
    'group.id': 'peek_group_temp',  # Unique group ID to avoid affecting the main consumer
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False      # Don't mark messages as read
}

consumer = Consumer(conf)
topic = 'incoming_transactions'
consumer.subscribe([topic])

print(f"Peeking into topic '{topic}'... (Waiting for connection)")

retry_count = 0
max_retries = 10 # Give it ~10 seconds to find data before giving up

try:
    while True:
        msg = consumer.poll(1.0)
        
        if msg is None:
            retry_count += 1
            if retry_count > max_retries:
                print("\nNo more messages found in backlog after waiting.")
                break
            print(".", end="", flush=True) # Show progress while waiting
            continue
        
        # Reset retry count once we start getting data
        retry_count = 0
        
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                print("\nReached end of partition.")
                break
            else:
                print(f"\nError: {msg.error()}")
                break

        # Simply print the raw payload
        raw_tx = json.loads(msg.value().decode('utf-8'))
        print(f"[Backlog] TX: {raw_tx['tx_id']} | Amount: {raw_tx['amount']} | Customer: {raw_tx['customer_id']} | TS: {raw_tx['timestamp']}")

except KeyboardInterrupt:
    pass
finally:
    consumer.close()
