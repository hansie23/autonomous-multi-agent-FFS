import sqlite3
import random
import uuid
import json
import os
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# -------------- INSTRUCTIONS --------------
# Before running this script, ensure to delete the following folders/files;
# - "organization_vault/data/core_banking_ledger.db"
# - "organization_vault/biometric_data/biometric_iam_vault.json"
# - "ground_truth_labels.json"
# - "incoming_stepup_challenges.json"
# - "injected_frauds.md"
#
# Following folder/file might be present. Delete if exists;
# - "system/visuals/"  (delete all contents)
# - "workflow_graph.png"
#
# DO NO DELETE ANYTHING ELSE
# -------------------------------------------


# PERSONAS
PERSONAS = [
    {"name": "Sarah King", "gender": "F", "scenario": "Impossible Travel", "img": "0f87482f_ID.png", "ext": "png"},
    {"name": "David Adams", "gender": "M", "scenario": "Frequency Burst", "img": "5c8cd38a_ID.png", "ext": "png"},
    {"name": "Gregory Gould", "gender": "M", "scenario": "Night Owl", "img": "a1b2c3d4_ID.png", "ext": "png"},
    {"name": "Cynthia Bennett", "gender": "F", "scenario": "APP Fraud", "img": "e5f6g7h8_ID.png", "ext": "png"},
    {"name": "Amanda Henry", "gender": "F", "scenario": "CNP Fraud", "img": "i9j0k1l2_ID.png", "ext": "png"},
    {"name": "Shane Jones", "gender": "M", "scenario": "Mule Activity", "img": "m3n4o5p6_ID.png", "ext": "png"},
    {"name": "Denise Bryant", "gender": "F", "scenario": "Account Takeover", "img": "q7r8s9t0_ID.png", "ext": "png"},
    {"name": "Steven Franco", "gender": "M", "scenario": "Multimodal Verification", "img": "u1v2w3x4_ID.png", "ext": "png"},
    {"name": "Haley Lopez", "gender": "F", "scenario": "Normal Baseline", "img": "y5z6a7b8_ID.png", "ext": "png"},
    {"name": "Elena Petrova", "gender": "F", "scenario": "Russian Laundromat", "img": "0f87482f_ID.png", "ext": "png"} # Multi-hop target
]

DB_PATH = "organization_vault/data/core_banking_ledger.db"
VAULT_PATH = "organization_vault/biometric_data/biometric_iam_vault.json"
ALERTS_PATH = "incoming_stepup_challenges.json"
TRUTH_PATH = "ground_truth_labels.json"
INJECTED_FRAUDS = "injected_frauds.md"

def setup_database():
    """Initializes the Core Banking Ledger."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE customers (
        customer_id TEXT PRIMARY KEY, 
        full_name TEXT, 
        email TEXT, 
        account_number TEXT UNIQUE, 
        kyc_risk_level TEXT, 
        residency_country TEXT, 
        account_opened DATE, 
        ssn_masked TEXT,
        dob DATE,
        address TEXT
    )''')
    cursor.execute('''CREATE TABLE transactions (tx_id TEXT PRIMARY KEY, customer_id TEXT, amount REAL, currency TEXT, timestamp DATETIME, transaction_type TEXT, destination_account TEXT, destination_jurisdiction TEXT, ip_address TEXT, location_city TEXT, FOREIGN KEY (customer_id) REFERENCES customers (customer_id))''')
    conn.commit()
    return conn

def generate_neutral_transaction(customer_id, amount=None, ts=None, city=None, country=None, ip=None, dest_acc=None):
    tx_id = f"TX-{uuid.uuid4().hex[:10].upper()}"
    cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Online", "Online", "Online"]
    origin_city = city if city else random.choice(cities)
    dest_country = country if country else "USA"
    if dest_country == "USA":
        types = ["Internal Transfer", "ACH Transfer", "P2P Payment", "External Wire"]
    else:
        types = ["International SWIFT", "External Wire"]
    selected_type = random.choice(types)
    return (tx_id, customer_id, amount if amount else round(random.uniform(10, 1000), 2), "USD", ts, selected_type, dest_acc if dest_acc else f"ACC-{fake.random_number(digits=8)}", dest_country, ip if ip else fake.ipv4(), origin_city)

def run_orchestrator():
    conn = setup_database()
    cursor = conn.cursor()
    all_tx = []
    iam_vault = {}
    alerts = {}
    ground_truth = {}
    
    END_DATE = datetime(2026, 3, 30)

    # Pre-generate Vladimir Kozlov (The Dirty Entity)
    kozlov_id = "CUST-999999"
    kozlov_acc = "ACC-99999999"
    cursor.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", 
                   (kozlov_id, "Vladimir Kozlov", "v.kozlov@shadow.net", kozlov_acc, "High", "Russia", "2020-01-01", "***-**-0000", "1975-06-15", "123 Red Sq, Moscow"))
    
    # GENERATE
    for i, p in enumerate(PERSONAS):
        c_id = f"CUST-{random.randint(100000, 899999)}"
        # Account opened at least 14 months ago to allow for 12 months of history
        open_date = (END_DATE - timedelta(days=random.randint(450, 600))).date()
        
        # Specific Data for Steven Franco (Multimodal)
        dob = "1974-08-24" if p['name'] == "Steven Franco" else fake.date_of_birth(minimum_age=18, maximum_age=80).isoformat()
        address = "742 Evergreen Terrace, Springfield" if p['name'] == "Steven Franco" else fake.address().replace("\n", ", ")

        cursor.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", 
                       (c_id, 
                        p['name'], 
                        fake.email(), 
                        f"ACC-{fake.random_number(digits=8)}", 
                        "Low", 
                        "USA", 
                        open_date.isoformat(), 
                        "***-**-9999",
                        dob,
                        address))
        
        iam_vault[c_id] = {"name": p['name'], "reference_id_path": f"organization_vault/biometric_data/profile_imgs/{p['img']}", "security_clearance": "standard"}
        
        # --- GENERATE 12 MONTHS OF NORMAL HISTORY FIRST ---
        for month in range(12, 0, -1):
            month_start = END_DATE - timedelta(days=30 * (month + 1))
            for _ in range(random.randint(2, 5)):
                ts = fake.date_time_between(start_date=month_start, end_date=month_start + timedelta(days=28))
                all_tx.append(generate_neutral_transaction(c_id, ts=ts))

        # --- GENERATE RECENT SCENARIO DATA ---
        def get_recent_ts(): 
            return fake.date_time_between(start_date=END_DATE-timedelta(days=2), end_date=END_DATE)
        
        base_ts = get_recent_ts()
        alert_id = f"ALRT-2026-{i+1:03d}"
        
        if p['scenario'] == "Impossible Travel":
            all_tx.append(generate_neutral_transaction(c_id, amount=12.50, ts=base_ts, city="New York"))
            fraud_tx = generate_neutral_transaction(c_id, amount=3400.00, ts=base_ts + timedelta(minutes=35), city="London", country="UK")
            all_tx.append(fraud_tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": True, "target_tx": fraud_tx[0]}
            
        elif p['scenario'] == "Frequency Burst":
            burst_ids = []
            for j in range(12):
                tx = generate_neutral_transaction(c_id, amount=round(random.uniform(50, 200), 2), ts=base_ts + timedelta(seconds=45*j))
                all_tx.append(tx)
                burst_ids.append(tx[0])
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": True, "target_tx": burst_ids}
            
        elif p['scenario'] == "Night Owl":
            ts = base_ts.replace(hour=3, minute=15)
            tx = generate_neutral_transaction(c_id, amount=50000.00, ts=ts, country="Republic of Aethelgard")
            all_tx.append(tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": True, "target_tx": tx[0]}
            
        elif p['scenario'] == "APP Fraud":
            tx = list(generate_neutral_transaction(c_id, amount=12400.00, ts=base_ts))
            tx[6] = "ACC-77441199" # Blacklisted
            all_tx.append(tuple(tx))
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": True, "target_tx": tx[0]}
            
        elif p['scenario'] == "CNP Fraud":
            for j in range(3): all_tx.append(generate_neutral_transaction(c_id, amount=round(random.uniform(1,5), 2), ts=base_ts + timedelta(seconds=40*j), city="Online"))
            tx = generate_neutral_transaction(c_id, amount=2500.00, ts=base_ts + timedelta(minutes=5), city="Online")
            all_tx.append(tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": tx[0]}
            
        elif p['scenario'] == "Mule Activity":
            mule_ids = []
            for j in range(5):
                tx = generate_neutral_transaction(c_id, amount=9500.00, ts=base_ts + timedelta(minutes=12*j), country="Shadow-Bank Archipelago", city="Online")
                all_tx.append(tx)
                mule_ids.append(tx[0])
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": mule_ids}
            
        elif p['scenario'] == "Account Takeover":
            for _ in range(3): all_tx.append(generate_neutral_transaction(c_id, ts=base_ts - timedelta(days=2), city="New York", ip="68.12.44.101"))
            tx = generate_neutral_transaction(c_id, amount=15000.00, ts=base_ts, city="Miami", ip="104.244.72.15")
            all_tx.append(tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": tx[0]}
            
        elif p['scenario'] == "Synthetic Identity":
            tx = generate_neutral_transaction(c_id, amount=round(random.uniform(5000, 10000), 2), ts=base_ts)
            all_tx.append(tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": tx[0]}
        
        elif p['scenario'] == "Russian Laundromat": # Multi-hop
            fraud_tx = generate_neutral_transaction(c_id, amount=15000.00, ts=base_ts, dest_acc=kozlov_acc, country="Russia")
            all_tx.append(fraud_tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": fraud_tx[0]}

        elif p['scenario'] == "Multimodal Verification": # Vision-to-Record
            tx = generate_neutral_transaction(c_id, amount=12000.00, ts=base_ts)
            all_tx.append(tx)
            ground_truth[alert_id] = {"scenario": p['scenario'], "is_genuine": False, "target_tx": tx[0]}
            
        else: # Normals
            for _ in range(10): all_tx.append(generate_neutral_transaction(c_id, ts=base_ts - timedelta(hours=random.randint(1,48))))
            ground_truth[alert_id] = {"scenario": "Normal Baseline", "is_genuine": True, "target_tx": "None"}

        # Create Step-Up Challenge Alert
        alerts[alert_id] = {"customer_id": c_id, "captured_selfie_path": f"system/bio_evidence/{c_id}/{p['img']}"}


        for folder in os.listdir("system/bio_evidence/"):
            for img in os.listdir(f"system/bio_evidence/{folder}/"):
                if img == p['img']:
                    os.rename(f"system/bio_evidence/{folder}", f"system/bio_evidence/{c_id}")

    # --- 2. BASELINE NOISE (50 Normal Users) ---
    for _ in range(50):
        c_id = f"CUST-{random.randint(100000, 999999)}"
        open_date = (END_DATE - timedelta(days=random.randint(450, 1800))).date()
        cursor.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", 
                       (c_id, 
                        fake.name(), 
                        fake.email(), 
                        f"ACC-{fake.random_number(digits=8)}", 
                        "Low", 
                        "USA", 
                        open_date.isoformat(), 
                        "***-**-4444",
                        fake.date_of_birth(minimum_age=18, maximum_age=80).isoformat(),
                        fake.address().replace("\n", ", ")))
        
        # 12-24 months of history for noise
        for _ in range(random.randint(30, 60)): 
            ts = fake.date_time_between(start_date=open_date, end_date=END_DATE)
            all_tx.append(generate_neutral_transaction(c_id, ts=ts))

    # --- 3. FINAL SORT & SYNC ---
    all_tx.sort(key=lambda x: x[4] if not isinstance(x[4], str) else datetime.strptime(x[4], '%Y-%m-%d %H:%M:%S'))
    sanitized_tx = [(t[0], t[1], t[2], t[3], t[4].isoformat() if hasattr(t[4], 'isoformat') else t[4], t[5], t[6], t[7], t[8], t[9]) for t in all_tx]
    
    cursor.executemany("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?)", sanitized_tx)
    conn.commit()

    print(f"Database Sync Complete: {len(all_tx)} transactions across {len(PERSONAS)+50} customers.")
    print(f"Database Path: {DB_PATH}")
    
    with open(VAULT_PATH, 'w') as f: json.dump(iam_vault, f, indent=4)
    print(f"\nIAM Vault Sync Complete: {len(iam_vault)} entries.")
    print(f"IAM Vault Path: {VAULT_PATH}")

    with open(ALERTS_PATH, 'w') as f: json.dump(alerts, f, indent=4)
    print(f"\nAlerts Sync Complete: {len(alerts)} alerts generated.")
    print(f"Alerts Path: {ALERTS_PATH}")
    
    # Use a lambda to convert datetimes to strings on the fly
    with open(TRUTH_PATH, 'w') as f: 
        json.dump(ground_truth, f, indent=4, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o))
    
    print(f"\nGround Truth Sync Complete: {len(ground_truth)} scenarios documented.")
    print(f"Ground Truth Path: {TRUTH_PATH}")
    
    # Update injected_frauds.md for cross-checking
    # os.makedirs(os.path.dirname(INJECTED_FRAUDS), exist_ok=True)
    with open(INJECTED_FRAUDS, "w") as f:
        f.write("# Injected Fraud Registry\n\n| Fraud Type | Transaction ID |\n| :--- | :--- |\n")
        for aid, data in ground_truth.items():
            if "Normal Baseline" in data['scenario']: continue
            f.write(f"| {data['scenario']} | {data['target_tx']} |\n")
    
    print(f"\nInjected Fraud Registry Sync Complete: {len(ground_truth)} entries documented.")
    print(f"Injected Fraud Registry Path: {INJECTED_FRAUDS}")
    
    print(f"\nOrchestration Complete: Sync successful across DB, 3 JSON systems, and Registry.")


if __name__ == "__main__":
    run_orchestrator()