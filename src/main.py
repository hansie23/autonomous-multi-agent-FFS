import json
import sqlite3
import time
import ollama
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Literal
from langgraph.graph import StateGraph, END

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# --- Modular Imports ---
from src.state import ForensicState
from src.privacy_proxy import PrivacyProxy
from src.tools import ForensicSQLTool, SemanticKYCTool, IdentityVisionTool, BehavioralHeatmapTool, RegulatoryTool
from src.agents.sar_generator import SARGenerator
from src.agents.ato_agent import ATOAgent
from src.agents.aml_agent import AMLAgent
from src.agents.synthetic_id_agent import SyntheticIDAgent
from src.agents.cnp_agent import CNPAgent
from src.agents.app_agent import APPAgent
from src.agents.velocity_agent import VelocityAgent

# --- Configuration ---
DB_PATH = "D:/All-Things-Python/Projects/Autonomous ITSM RCA Multi-Agent System/Autonomous-Finance-Forensics-Agent/organization_vault/data/core_banking_ledger.db"
CHROMA_PATH = "D:/All-Things-Python/Projects/Autonomous ITSM RCA Multi-Agent System/Autonomous-Finance-Forensics-Agent/system/chroma_db"
VISUALS_DIR = "D:/All-Things-Python/Projects/Autonomous ITSM RCA Multi-Agent System/Autonomous-Finance-Forensics-Agent/system/visuals"
SANCTIONS_PATH = "D:/All-Things-Python/Projects/Autonomous ITSM RCA Multi-Agent System/Autonomous-Finance-Forensics-Agent/organization_vault/regulatory/sanctions_list.md"
SUPERVISOR_MODEL = "qwen3:4b-instruct"

# --- Tool Initialization ---
sql_tool = ForensicSQLTool(DB_PATH)
kyc_tool = SemanticKYCTool(CHROMA_PATH)
bio_tool = IdentityVisionTool()
viz_tool = BehavioralHeatmapTool(VISUALS_DIR, DB_PATH)
reg_tool = RegulatoryTool(SANCTIONS_PATH)

# --- Agent Initialization ---
ato_agent = ATOAgent(sql_tool, bio_tool, viz_tool)
aml_agent = AMLAgent(sql_tool, kyc_tool)
synthetic_id_agent = SyntheticIDAgent(sql_tool, bio_tool, kyc_tool)
cnp_agent = CNPAgent(sql_tool, viz_tool, kyc_tool)
app_agent = APPAgent(sql_tool, kyc_tool)
velocity_agent = VelocityAgent(sql_tool, viz_tool)

# --- DB Helpers ---
def get_customer_from_db(customer_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers WHERE customer_id = ?", (customer_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}

def get_transaction_from_db(tx_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}

def get_recent_history(customer_id: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = f"SELECT * FROM transactions WHERE customer_id = '{customer_id}' ORDER BY timestamp DESC LIMIT 10"
    rows = cursor.execute(query).fetchall()
    conn.close()
    return [dict(row) for row in rows]

# --- Signal Extraction ---
def extract_signals(state: ForensicState) -> Dict[str, Any]:
    tx = state['raw_transaction']
    cust = state['customer_data']
    history = get_recent_history(cust['customer_id'])
    
    # Dynamic Sanctions Scan
    reg_lists = reg_tool.get_high_risk_lists()
    dest_jurisdiction = tx.get('destination_jurisdiction')
    dest_account = tx.get('destination_account')
    
    # Standardize 'New Account' to 90 days for better detection
    opened_date = datetime.strptime(cust.get('account_opened', '2000-01-01'), '%Y-%m-%d')
    account_age_days = (datetime.now() - opened_date).days

    signals = {
        "amount": tx.get('amount', 0),
        "near_threshold": 9000 <= tx.get('amount', 0) <= 10000,
        "is_blacklisted": dest_jurisdiction in reg_lists['blacklist'],
        "is_greylisted": dest_jurisdiction in reg_lists['greylist'],
        "is_mule_account": dest_account in reg_lists['mule_accounts'],
        "ip_change": history[0].get('ip_address') != tx.get('ip_address') if history else False,
        "new_account": account_age_days < 90,
        "account_age_days": account_age_days
    }
    
    # Capture specific regulatory text
    findings = []
    if signals['is_blacklisted']: findings.append(f"BLACKLIST_HIT: {dest_jurisdiction}")
    if signals['is_greylisted']: findings.append(f"GREYLIST_MONITORING: {dest_jurisdiction}")
    if signals['is_mule_account']: findings.append(f"KNOWN_MULE_ACCOUNT: {dest_account}")
    
    signals['findings'] = findings
    signals['high_risk_jurisdiction'] = signals['is_blacklisted'] or signals['is_greylisted']
    
    return signals

# --- Supervisor Node ---
def supervisor_node(state: ForensicState) -> Dict[str, Any]:
    print("\n[Supervisor] Orchestrating Investigation...")
    log = state.get('investigation_log', [])
    pending = state.get('pending_experts', [])
    signals = extract_signals(state)
    
    # Update Evidence Trail with any initial regulatory findings
    new_evidence = state.get('evidence_trail', [])
    for f in signals.get('findings', []):
        if f not in new_evidence:
            new_evidence.append(f)

    # --- Tier 1: Early Exit & Critical Shortcuts (Hard Rules) ---
    if log:
        latest_result = log[-1].get('results', {})
        if latest_result.get('verdict') == "FRAUD_DETECTED":
            print("  [!] Definitive Fraud detected. Short-circuiting investigation.")
            return {"next_step": "sar_generator", "pending_experts": [], "evidence_trail": new_evidence}

    # --- Tier 2: Plan Generation / Adaptation (Logic) ---
    if not log and not pending:
        print("  [>] Turn 1: Calculating expert queue based on signals...")
        triggered = []
        
        # Hard Rule Triggers
        if signals['amount'] > 10000 or signals['is_blacklisted']: triggered.append("aml_agent")
        if signals['is_mule_account']: triggered.append("app_agent")
        if signals['ip_change']: triggered.append("ato_agent")      # check how this is calculated
        if signals['new_account']: triggered.append("synthetic_id_agent")
        
        # --- Tier 3: LLM Escalation (The "Doctor" Triage) ---
        if not triggered:
            print("  [>] Signals weak. Escalating to LLM for expert mapping...")
            
            # Fetch and Anonymize Context (Record + History)
            history = get_recent_history(state['customer_data']['customer_id'])
            proxy = PrivacyProxy()
            anonymized_context = proxy.prepare_llm_prompt(
                state['raw_transaction'], 
                state['customer_data'],
                history=history
            )
            
            expert_map = """
            - aml_agent: Best for large sums, structuring, or high-risk jurisdictions.
            - ato_agent: Best for geo-shifts, IP changes, or behavioral deviations.
            - synthetic_id_agent: Best for NEW accounts (<90 days) with no history.
            - cnp_agent: Best for online/card-not-present bursts or location shifts.
            - app_agent: Best for first-time recipients or suspicious destinations.
            - velocity_agent: General baseline for transaction spikes.
            """
            
            system_instruction = f"""
            You are the Senior Forensic Triage Lead. Your goal is ZERO FALSE NEGATIVES.
            Review the extracted signals and the anonymized patient record (including recent history) to decide which experts should investigate.
            
            EXPERT CAPABILITIES:
            {expert_map}
            
            EXTRACTED SIGNALS:
            {json.dumps(signals, indent=2)}
            
            ANONYMIZED PATIENT RECORD & HISTORY:
            {anonymized_context}
            
            MANDATE: If signals are ambiguous but not perfectly normal, select at least 'velocity_agent' as a safety net.
            
            Your response MUST be in RAW JSON format:
            {{
              "trigger": ["agent_name_1", "agent_name_2"],
              "reasoning": "Contextual synthesis of signals, history, and record details"
            }}
            """
            try:
                resp = ollama.chat(model=SUPERVISOR_MODEL, messages=[{'role': 'system', 'content': system_instruction}], format='json')
                triage_decision = json.loads(resp['message']['content'])
                triggered = triage_decision.get('trigger', [])
                print(f"  [>] LLM Triage Reasoning: {triage_decision.get('reasoning')}")
                print(f"  [>] LLM Triggered Experts: {triggered}")
            except Exception as e:
                print(f"  [!] Triage Error: {e}")
                triggered = ["velocity_agent"]
        
        pending = list(dict.fromkeys(triggered))

    # 2. REACTIVE ROUTING (Turn 2+)
    # If AML found structuring, but we didn't plan Synthetic ID, add it now.
    if log and log[-1].get('agent') == "aml_agent":
        aml_findings = log[-1].get('results', {})
        if aml_findings.get('risk_score', 0) > 60 and "synthetic_id_agent" not in pending:
            print("  [>] AML findings highly suspicious. Adding Synthetic ID check to queue.")
            pending.append("synthetic_id_agent")

    # --- Tier 3: LLM Synthesis (Ambiguous multi-agent findings) ---
    if log and len(log) >= 2 and not pending:
        # Check if we need one last "expert" look before closing the case
        # all_clear = all(l.get('results', {}).get('verdict') == "CLEAR" for l in log if 'results' in l)

        # print(log)

        max_rounds = 3
        current_round = 0

        while log[-1].get('results', {}).get('verdict') == "SUSPICIOUS" and current_round < max_rounds:
            print("  [>] Mixed signals in log. Asking LLM if further investigation is needed...")
            
            valid_experts = ["ato_agent", "aml_agent", "synthetic_id_agent", "cnp_agent", "app_agent", "velocity_agent"]
            
            prompt = f"""
            Investigation Log: {json.dumps(log, indent=2)}

            Since the latest findings are SUSPICIOUS but not definitive, should we loop back in another expert for a deeper look to gather more evidence?
            
            Based on the findings above, is more evidence needed from another specialist?
            VALID EXPERTS: {', '.join(valid_experts)}
            
            Respond in RAW JSON format:
            {{
              "more_experts": true/false,
              "next": "agent_name_from_list_above" or null,
              "reasoning": "Why this expert is needed"
            }}
            """
            try:
                resp = ollama.chat(model=SUPERVISOR_MODEL, messages=[{'role': 'user', 'content': prompt}], format='json')
                decision = json.loads(resp['message']['content'])

                # print(decision)
                
                next_agent = decision.get('next')
                if decision.get('more_experts') and next_agent in valid_experts:
                
                    # Prevent circular loops: don't call the same agent twice in a row
                    if not any(l.get('agent') == next_agent for l in log[-1:]):
                        print(f"  [>] LLM synthesis requested additional look from: {next_agent}")
                        print(f"  [>] LLM Synthesis Reasoning: {decision.get('reasoning')}")

                        pending.append(next_agent)

                        break  # Exit the loop to dispatch the new expert
                elif decision.get('more_experts'):
                        print(f"  [!] LLM suggested invalid expert '{next_agent}'. Ignoring.")

                current_round += 1
            except Exception as e:
                print(f"  [!] Synthesis Error: {e}")

    # --- Dispatch Logic ---
    if pending:
        next_agent = pending.pop(0)
        print(f"  [>] Dispatching next expert: {next_agent}. Remaining queue: {', '.join(pending) if pending else 'None'}.")
        return {
            "next_step": next_agent,
            "pending_experts": pending,
            "evidence_trail": new_evidence,
            "investigation_log": log + [{"agent": "Supervisor", "action": f"Dispatched {next_agent}", "reasoning": "Reactive investigation planning"}]
        }

        # batch_size = 2
        # next_batch = pending[:batch_size]
        # pending = pending[batch_size:]

        # print(f"  [Supervisor] Dispatching batch: {', '.join(next_batch)}. Remaining queue: {', '.join(pending) if pending else 'None'}.")

        # next_batch = []
        # for _ in range(min(2, len(pending))):  # Dispatch up to 2 agents in parallel
        #     next_batch.append(pending.pop(0))

        # return {
        #     "next_step": next_batch,  # This will require the graph to handle lists of next steps
        #     "pending_experts": pending,
        #     "evidence_trail": new_evidence,
        #     "investigation_log": log + [{"agent": "Supervisor", "action": f"Dispatched {', '.join(next_batch)}", "reasoning": "Reactive investigation planning"}]
        # }
    

    print("[Supervisor] No pending experts. Moving to SAR generation.")

    return {"next_step": "sar_generator", "evidence_trail": new_evidence}

# --- Specialist Nodes (Now Using Tools) ---

def ato_agent_node(state: ForensicState) -> Dict[str, Any]:

    shared = state.get('shared_evidence', {})
    cached_heatmap = shared.get('heatmap')  # Check if any agent has

    history = get_recent_history(state['customer_data']['customer_id'])
    findings = ato_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction'], 
        history,
        existing_heatmap=cached_heatmap
    )
    
    return {
        "ato_findings": findings,
        "shared_evidence": {
            **shared,  # Preserve any existing shared evidence
            "heatmap": findings.get('heatmap')  # Update heatmap if ATO agent generated one
        },
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "ATOExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def aml_agent_node(state: ForensicState) -> Dict[str, Any]:
    findings = aml_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction']
    )
    
    return {
        "aml_findings": findings,
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "AMLExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def synthetic_id_agent_node(state: ForensicState) -> Dict[str, Any]:
    findings = synthetic_id_agent.analyze(
        state['customer_data']['customer_id'], 
        state['customer_data']
    )
    
    return {
        "synthetic_id_findings": findings,
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "SyntheticIDExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def cnp_agent_node(state: ForensicState) -> Dict[str, Any]:

    shared = state.get('shared_evidence', {})
    cached_heatmap = shared.get('heatmap')  # Check if any agent has already

    history = get_recent_history(state['customer_data']['customer_id'])
    findings = cnp_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction'],
        history,
        existing_heatmap=cached_heatmap
    )
    
    return {
        "cnp_findings": findings,
        "shared_evidence": {
            **shared,  # Preserve any existing shared evidence
            "heatmap": findings.get('heatmap')  # Update heatmap if CNP agent generated one
        },
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "CNPExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def app_agent_node(state: ForensicState) -> Dict[str, Any]:
    findings = app_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction']
    )
    
    return {
        "app_findings": findings,
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "APPExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def velocity_agent_node(state: ForensicState) -> Dict[str, Any]:

    shared = state.get('shared_evidence', {})
    cached_heatmap = shared.get('heatmap')  # Check if any agent has already generated a heatmap for this customer in this investigation
    
    history = get_recent_history(state['customer_data']['customer_id'])
    findings = velocity_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction'],
        history,
        existing_heatmap=cached_heatmap
    )
    
    return {
        "velocity_findings": findings,
        "shared_evidence": {
            **shared,  # Preserve any existing shared evidence
            "heatmap": findings.get('heatmap')  # Update heatmap if Velocity agent generated one
        },
        "investigation_log": state.get('investigation_log', []) + [{
            "agent": "VelocityExpert",
            "results": findings
        }],
        "next_step": "supervisor"
    }

def report_node(state: ForensicState) -> Dict[str, Any]:
    print("\n[System] Generating Final SAR...")
    generator = SARGenerator(model=SUPERVISOR_MODEL)
    report = generator.generate_report(state)
    return {"sar_report": report, "next_step": "FINISH"}

# --- Graph Construction ---
def build_workflow():
    workflow = StateGraph(ForensicState)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("ato_agent", ato_agent_node)
    workflow.add_node("aml_agent", aml_agent_node)
    workflow.add_node("synthetic_id_agent", synthetic_id_agent_node)
    workflow.add_node("cnp_agent", cnp_agent_node)
    workflow.add_node("app_agent", app_agent_node)
    workflow.add_node("velocity_agent", velocity_agent_node)
    workflow.add_node("sar_generator", report_node)
    
    workflow.set_entry_point("supervisor")

    def router(state):
        return state["next_step"] # This will be a string or a list of strings based on the supervisor's output
    
    workflow.add_conditional_edges(
        "supervisor",  
        # lambda x: x["next_step"], 
        router,     # This will require the graph execution engine to handle both single strings and lists of next steps
        {
            "ato_agent": "ato_agent",
            "aml_agent": "aml_agent",
            "synthetic_id_agent": "synthetic_id_agent",
            "cnp_agent": "cnp_agent",
            "app_agent": "app_agent",
            "velocity_agent": "velocity_agent",
            "sar_generator": "sar_generator",
            "FINISH": END
            })
    
    for agent in ["ato_agent", "aml_agent", "synthetic_id_agent", "cnp_agent", "app_agent", "velocity_agent"]:
        workflow.add_edge(agent, "supervisor")
    
    workflow.add_edge("sar_generator", END)

    return workflow.compile()

if __name__ == "__main__":
    # --- End-to-End Simulation ---
    print("\n" + "="*60)
    print("    AUTONOMOUS FRAUD FORENSICS: MULTI-AGENT SIMULATION")
    print("="*60)
    
    app = build_workflow()

    # Generate Langgraph Visualization
    png_bytes = app.get_graph().draw_mermaid_png()
    with open("workflow_graph.png", "wb") as f:
        f.write(png_bytes)
        print("Workflow graph visualization saved as 'workflow_graph.png'.")

    
    # Load Ground Truth to pick a test case
    with open("ground_truth_labels.json", "r") as f:
        truth = json.load(f)
    
    # Let's target the Account Takeover scenario (ALRT-2026-007)
    target_alert_id = "ALRT-2026-001"
    target_alert = truth.get(target_alert_id, {})
    tx_list = target_alert.get("target_tx", [])
    trigger_tx_id = tx_list[0] if isinstance(tx_list, list) else tx_list
    
    print(f"[Trigger] Alert: {target_alert_id} | Scenario: {target_alert.get('scenario')}")
    
    test_tx = get_transaction_from_db(trigger_tx_id)
    if not test_tx:
        print("Error: Test transaction not found in database.")
    else:
        customer = get_customer_from_db(test_tx['customer_id'])
        
        # Initialize Forensic State
        initial_state = {
            "raw_transaction": test_tx,
            "customer_data": customer,
            "anonymized_metadata": "",
            "pii_map": {},
            "next_step": "",
            "investigation_log": [],
            "ato_findings": None,
            "aml_findings": None,
            "synthetic_id_findings": None,
            "cnp_findings": None,
            "app_findings": None,
            "velocity_findings": None,
            "final_status": "PENDING",
            "sar_report": "",
            "evidence_trail": []
        }
        
        start_time = time.time()
        final_state = app.invoke(initial_state)

        print("\n" + "="*60)
        print("FINAL FORENSIC REPORT")
        print("="*60)
        print(final_state['sar_report'])
        print(f"\nExecution Time: {time.time() - start_time:.2f}s")
