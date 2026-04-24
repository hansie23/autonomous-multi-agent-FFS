import os
import random
import uuid
from faker import Faker

fake = Faker()

# PERSONAS (from 1_transaction_generator.py)
PERSONAS = [
    {"name": "Sarah King", "scenario": "Impossible Travel", "loc": "London/New York"},
    {"name": "David Adams", "scenario": "Frequency Burst", "detail": "high-velocity digital payouts"},
    {"name": "Gregory Gould", "scenario": "Night Owl", "loc": "Republic of Aethelgard"},
    {"name": "Cynthia Bennett", "scenario": "APP Fraud", "acc": "ACC-77441199"},
    {"name": "Amanda Henry", "scenario": "CNP Fraud", "detail": "card-not-present online gateway abuse"},
    {"name": "Shane Jones", "scenario": "Mule Activity", "loc": "Shadow-Bank Archipelago", "acc_suffix": "73936"},
    {"name": "Denise Bryant", "scenario": "Account Takeover", "loc": "Miami/New York"},
    {"name": "Steven Franco", "scenario": "Synthetic Identity", "detail": "low-risk initial scoring anomalies"},
    {"name": "Haley Lopez", "scenario": "Normal Baseline", "detail": "legitimate retail patterns"},
    {"name": "Vladimir Kozlov", "scenario": "Russian Laundromat", "loc": "Moscow/Global", "detail": "high-level money laundering syndicate lead"}
]

BASE_DIR = "organization_vault/regulatory/Adverse media/"

def generate_noise_doc(index):
    """Generates generic noise documents (Weather, Generic Finance, Sports)."""
    doc_type = random.choice(["Bulletin", "News", "List"])
    
    if doc_type == "Bulletin":
        length = random.randint(150, 300)
        title = f"Local Update: {fake.city()} {fake.word().capitalize()}"
        content = fake.paragraph(nb_sentences=15)
    elif doc_type == "News":
        length = random.randint(500, 1200)
        title = f"{fake.company()} Announces {fake.bs()}"
        content = "\n\n".join([fake.paragraph(nb_sentences=8) for _ in range(5)])
    else: # List
        length = random.randint(2000, 3000)
        title = f"Annual {fake.word().capitalize()} Index - 2026"
        items = [f"* {fake.name()}: {fake.job()} ({fake.country()})" for _ in range(50)]
        content = "\n".join(items)

    filename = f"noise_{index}_{uuid.uuid4().hex[:6]}.md"
    with open(os.path.join(BASE_DIR, filename), 'w') as f:
        f.write(f"# {title}\n\n{content}")

def generate_hit_doc(p):
    """Generates a 'Hit' document for a persona with a forensic hook and false friend."""
    name = p['name']
    scenario = p['scenario']
    
    # False Friend
    first, last = name.split(' ')
    false_friend = f"{first} {fake.first_name()[0]}. {last}"
    
    # Forensic Hook
    hook = ""
    if scenario == "Impossible Travel":
        hook = f"Investigators found that a login from New York occurred minutes after a high-value purchase in London, linked to {name}."
    elif scenario == "Frequency Burst":
        hook = f"The suspect, identified as {name}, performed 12 rapid digital transfers totaling over $2,000 in under 10 minutes."
    elif scenario == "Night Owl":
        hook = f"A wire transfer of $50,000 to the Republic of Aethelgard was traced back to {name}'s residential IP address."
    elif scenario == "APP Fraud":
        hook = f"Public warnings have been issued regarding account {p['acc']}, which was used to receive stolen funds from {name}."
    elif scenario == "CNP Fraud":
        hook = f"Law enforcement identified {name} as a victim of a credential-stuffing attack that led to multiple card-not-present fraud events."
    elif scenario == "Mule Activity":
        hook = f"A mule network operating in the Shadow-Bank Archipelago utilized several accounts, including one ending in {p['acc_suffix']} belonging to {name}."
    elif scenario == "Account Takeover":
        hook = f"Suspicious IP logins from Miami were detected on {name}'s account shortly before a total depletion of funds."
    elif scenario == "Synthetic Identity":
        hook = f"Federal agencies are investigating a case where {name}'s SSN was used to create a high-credit-limit synthetic persona."
    else: # Normal
        hook = f"{name} was praised for reporting a phishing attempt, confirming their legitimate status."

    title = f"Forensic Intelligence: {scenario} Investigation"
    content = f"""# {title}
## Metro-Central Authorities Report
The Metro-Central Police Department has released a bulletin regarding ongoing financial crimes. While many individuals like {false_friend} have been cleared of any wrongdoing, other leads remain active.

The lead investigator noted that {fake.sentence()}

{fake.paragraph(nb_sentences=10)}

### The Forensic Evidence
In a surprising turn of events, {hook} This has led to a major breakthrough in the case.

{fake.paragraph(nb_sentences=5)}
"""
    filename = f"hit_{name.replace(' ', '_')}_{uuid.uuid4().hex[:6]}.md"
    with open(os.path.join(BASE_DIR, filename), 'w') as f:
        f.write(content)

def main():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
        
    print(f"Generating 9 Hit documents for personas...")
    for p in PERSONAS:
        generate_hit_doc(p)
        
    print(f"Generating 250 Noise documents...")
    for i in range(250):
        generate_noise_doc(i)
        
    print("Generation complete.")

if __name__ == "__main__":
    main()
