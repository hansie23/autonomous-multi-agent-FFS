import json
import time
from confluent_kafka import Consumer, KafkaError
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import sys

# Import your existing workflow builder
from src.main import build_workflow, get_customer_from_db

# --- AIVEN KAFKA CONFIGURATION ---
# Replace <YOUR_AIVEN_SERVICE_URI> with your actual Aiven Service URI (e.g., kafka-xxxx.aivencloud.com:28925)
AIVEN_URI = "kafka-mas-social-spark.k.aivencloud.com:10409"

conf = {
    'bootstrap.servers': AIVEN_URI,
    'security.protocol': 'SSL',
    'ssl.ca.location': 'ca.pem',
    'ssl.certificate.location': 'service.cert',
    'ssl.key.location': 'service.key',
    'group.id': 'fraud_agent_group_1', # All consumers in this group share the load
    'auto.offset.reset': 'earliest'  # Start reading from the beginning if no offset is found
}
consumer = Consumer(conf)
topic = 'incoming_transactions'

print("Initializing LangGraph Multi-Agent Workflow...")
app = build_workflow()

consumer.subscribe([topic])
print(f"Fraud System listening on Aiven Kafka topic '{topic}'...")
# print(f"Ensure you have replaced '<YOUR_AIVEN_SERVICE_URI>:<PORT>' with your actual Aiven URI.")

# Global flag to signal threads to stop processing
shutdown_flag = threading.Event()

def process_message(raw_tx, worker_id, kafka_msg):
    if shutdown_flag.is_set():
        print("[System] Shutdown signal received.")
        return
    
    print(f"\n" + "="*60)
    print(f"[Worker-{worker_id}] TX {raw_tx['tx_id']} | Amount: {raw_tx['amount']} {raw_tx['currency']} | Customer: {raw_tx['customer_id']}")
    print("="*60)

    # 1. DB Lookup (or Mock if it's a random user from the stream)
    customer_data = get_customer_from_db(raw_tx['customer_id'])

    # 2. Initialize State for the Multi-Agent Workflow
    initial_state = {
        "raw_transaction": raw_tx,
        "customer_data": customer_data,
        "anonymized_metadata": "",
        "pii_map": {},
        "next_step": "supervisor",
        "investigation_log": {},
        "pending_experts": [],
        "regulatory_findings": [],
        "ato_findings": None,
        "aml_findings": None,
        "synthetic_id_findings": None,
        "cnp_findings": None,
        "app_findings": None,
        "velocity_findings": None,
        "shared_evidence": {},
        "timeline": [],
        "final_status": "PENDING",
        "sar_report": "",
        "evidence_trail": []
    }

    # 3. Trigger the LangGraph Workflow
    print(f"[Worker-{worker_id}] Triggering Agentic Workflow for TX {raw_tx['tx_id']}...")
    start_time = time.time()

    try:
        final_state = app.invoke(initial_state)
        verdict = final_state.get('final_status', 'UNKNOWN')
        tx_id = raw_tx['tx_id']

        print(f" [Worker-{worker_id}] Case Closed in {time.time() - start_time:.2f}s | TX: {tx_id} | VERDICT: {verdict}")

        # Only save a SAR if the system found something suspicious or fraudulent
        if final_state.get('sar_report'):
            sar_dir = "generated_sars"
            os.makedirs(sar_dir, exist_ok=True)

            # Create a unique file for this specific transaction
            filepath = os.path.join(sar_dir, f"{tx_id}_SAR.md")
            with open(filepath, "w") as f:
                f.write(final_state.get('sar_report'))
            print(f" [Worker-{worker_id}] SAR saved to {filepath}")

            if not shutdown_flag.is_set():
                consumer.commit(kafka_msg)

    except Exception as e:
        if not shutdown_flag.is_set():
            print(f"[!] Error during workflow execution for TX {raw_tx['tx_id']}: {e}")

# Parallel processing with ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=1)
worker_counter = 0

try:
    while not shutdown_flag.is_set():
        # Wait for a new message
        msg = consumer.poll(1.0)

        if msg is None:
            print(".", end="", flush=True) # Show progress while waiting
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            else:
                print(f"[!] Consumer Error: {msg.error()}")
                break

        # Parse the incoming transaction
        raw_tx = json.loads(msg.value().decode('utf-8'))

        worker_id = (worker_counter % 2) + 1

        # Submit to the thread pool instead of blocking
        executor.submit(process_message, raw_tx, worker_id, msg)

except KeyboardInterrupt:
    print("\nShutting down consumer. Waiting for ongoing tasks to finish...\n")
    shutdown_flag.set()  # Signal threads to stop processing
    executor.shutdown(wait=True, cancel_futures=True)  # Wait for all threads to finish

finally:
    print("\nClosing Kafka consumer...")
    consumer.close()
    sys.exit(0)