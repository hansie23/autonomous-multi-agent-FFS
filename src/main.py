import json
import sqlite3
import time
import ollama
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Literal
from langgraph.graph import StateGraph, END
from pprint import pprint
from dotenv import load_dotenv
from langchain_ollama import ChatOllama

# Load environment variables for LangSmith tracing
load_dotenv()

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# --- Modular Imports ---
from src.state import ForensicState
from src.privacy_proxy import PrivacyProxy
from src.tools import ForensicSQLTool, SemanticKYCTool, IdentityVisionTool, BehavioralHeatmapTool, MultiHopRelationalTool
from src.agents.sar_generator import SARGenerator
from src.agents.ato_agent import ATOAgent
from src.agents.aml_agent import AMLAgent
from src.agents.synthetic_id_agent import SyntheticIDAgent
from src.agents.cnp_agent import CNPAgent
from src.agents.app_agent import APPAgent
from src.agents.velocity_agent import VelocityAgent

import transformers
transformers.logging.set_verbosity_error()

import re

# def extract_json_from_thinking_model(text: str) -> str:
#     """Extracts the final JSON block from a model that outputs internal thoughts before the answer."""
#     # Remove everything before and including the last </think> tag if it exists
#     if "</think>" in text:
#         text = text.split("</think>")[-1]

#     # Use regex to find the first balanced JSON object {...}
#     json_match = re.search(r'\{.*\}', text, re.DOTALL)
#     if json_match:
#         return json_match.group().strip()
#     return text.strip()

# --- Configuration ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "organization_vault/data/core_banking_ledger.db")
CHROMA_PATH = os.path.join(PROJECT_ROOT, "system/chroma_db")
VISUALS_DIR = os.path.join(PROJECT_ROOT, "system/visuals")

REASONING_MODEL = "qwen3-vl:2b-instruct-q4_K_M"
VISION_MODEL = "qwen3-vl:2b-instruct-q4_K_M"
SUPERVISOR_MODEL = REASONING_MODEL


def validate_environment():
    """Industry Standard Pre-flight Check: Ensures all local AI brains are present."""
    print("\n[System] Performing Pre-flight Validation...")
    
    # 1. Check Ollama Models
    try:
        models_info = ollama.list()
        # for model in (models_info.models):
        #     print(model.model)
        # Extract base names (e.g., 'qwen3' from 'qwen3:4b-instruct')
        available = [m.get('model') for m in models_info.get('models', [])]
        
        required = [REASONING_MODEL, VISION_MODEL]
        missing = [m for m in required if m not in available]
        
        if missing:
            print(f"  [!] CRITICAL ERROR: Required models missing from Ollama: {missing}")
            print(f"  [>] Action Required: Run 'ollama pull {missing[0]}'")
            sys.exit(1)
        print("  [OK] All required LLM models found.")
    except Exception as e:
        print(f"  [!] WARNING: Could not connect to Ollama: {e}")
        print("  [>] Ensure Ollama is running on localhost:11434")
        sys.exit(1)

    # 2. Check Database
    if not os.path.exists(DB_PATH):
        print(f"  [!] CRITICAL ERROR: Ledger database not found at {DB_PATH}")
        sys.exit(1)
    
    print("  [OK] Database and filesystem validated.\n")

# --- Startup ---
validate_environment()

# --- Tool Initialization ---
from src.tools import MultiHopRelationalTool, StreamingIntelligenceTool
sql_tool = ForensicSQLTool(DB_PATH)
kyc_tool = SemanticKYCTool(CHROMA_PATH, model=REASONING_MODEL)
bio_tool = IdentityVisionTool(model=VISION_MODEL)
viz_tool = BehavioralHeatmapTool(VISUALS_DIR, DB_PATH, model=VISION_MODEL)
graph_tool = MultiHopRelationalTool(sql_tool, kyc_tool)
stream_tool = StreamingIntelligenceTool(kyc_tool)

# --- Agent Initialization ---
# We inject the model name or object into the agents
ato_agent = ATOAgent(sql_tool, bio_tool, stream_tool, model=REASONING_MODEL)
aml_agent = AMLAgent(sql_tool, kyc_tool, graph_tool, stream_tool, model=REASONING_MODEL)
synthetic_id_agent = SyntheticIDAgent(sql_tool, bio_tool, stream_tool, model=REASONING_MODEL)
cnp_agent = CNPAgent(sql_tool, stream_tool, model=REASONING_MODEL)
app_agent = APPAgent(sql_tool, stream_tool, model=REASONING_MODEL)
velocity_agent = VelocityAgent(sql_tool, viz_tool, stream_tool, model=REASONING_MODEL)

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
    query = f"SELECT * FROM transactions WHERE customer_id = '{customer_id}' ORDER BY timestamp DESC LIMIT 10"
    result = sql_tool.execute_query(query)
    return json.loads(result)

# --- Signal Extraction ---
def extract_signals(state: ForensicState) -> Dict[str, Any]:
    tx = state['raw_transaction']
    cust = state['customer_data']
    history = get_recent_history(cust['customer_id'])
    
    # Standardize 'New Account' to 90 days for better detection
    opened_date = datetime.strptime(cust.get('account_opened', '2000-01-01'), '%Y-%m-%d')
    account_age_days = (datetime.now() - opened_date).days

    # --- Behavioral Summary (Low-Token Consumption) ---
    recent_amounts = [h['amount'] for h in history]
    avg_amount = sum(recent_amounts)/len(recent_amounts) if recent_amounts else 0
    max_amount = max(recent_amounts) if recent_amounts else 0
    
    signals = {
        "amount": tx.get('amount', 0),
        "near_threshold": 9000 <= tx.get('amount', 0) <= 10000,
        "ip_change": history[0].get('ip_address') != tx.get('ip_address') if history else False,
        "new_account": account_age_days < 90,
        "account_age_days": account_age_days,
        "behavioral_summary": {
            "avg_history_amount": round(avg_amount, 2),
            "max_history_amount": max_amount,
            "tx_count_history": len(history),
            "is_significant_deviation": tx.get('amount', 0) > (avg_amount * 3) if avg_amount > 0 else False
        }
    }
    
    return signals

# --- Log Summarization Utility ---
def get_summarized_investigation_log(log: dict) -> str:
    """Converts raw investigation JSON into a concise, high-signal summary for the LLM."""
    if not log:
        return "Initial investigation phase. No experts consulted yet."
    
    summary = []
    for agent, data in log.items():
        verdict = data.get("verdict", "UNKNOWN")
        reasoning = data.get("reasoning", "No reasoning provided.")
        # Extract high-signal findings from tools if they exist
        hunch = ""
        if data.get("hunch_evidence"):
            hunch = f" | Tool Findings: Found indicators in {len(data['hunch_evidence'])} queries."
        
        summary.append(f"- {reasoning}{hunch} [{verdict}]")
    
    return "\n".join(summary)

# --- Supervisor Node ---
def supervisor_node(state: ForensicState) -> Dict[str, Any]:
    print("\n[Supervisor] Orchestrating Investigation...")

    log = state.get('investigation_log', {})
    pending = state.get('pending_experts', [])
    new_evidence = state.get('evidence_trail', [])

    # --- Tier 1: Early Exit (Hard Rules) ---
    if log:
        for v in log.values():
            if v.get("verdict") == "FRAUD_DETECTED":
                print("  [!] Definitive Fraud detected. Short-circuiting investigation.")
                return {"next_step": "sar_generator", "pending_experts": [], "evidence_trail": new_evidence}

    # --- Tier 2: State Compression (Context Optimization) ---
    summarized_log = get_summarized_investigation_log(log)

    expert_map = """
            - aml_agent: Sanctions, Adverse Media (RAG), and Layering patterns.
            - ato_agent: Account Takeover, IP/Device shifts, and Biometrics.
            - synthetic_id_agent: Identity Authenticity, Deepfake ID detection (Vision).
            - cnp_agent: Card probing (BIN attacks), Merchant risk.
            - app_agent: Destination account risk, Mule detection.
            - velocity_agent: Statistical bursts and Visual spend heatmaps.
            """
    
    if not log and not pending:
        signals = extract_signals(state)
        print("  [>] Turn 1: Calculating expert queue based on signals...")
        triggered = []
        
        # Surgical Deterministic Triggers (Reduce unnecessary agent calls)
        if signals['amount'] > 10000: triggered.append("aml_agent")
        if signals['ip_change']: triggered.append("ato_agent")
        if signals['new_account'] and signals['amount'] > 1000: triggered.append("synthetic_id_agent")
        
        # --- Tier 3: LLM Escalation (Layer 2: Agentic Triage) ---
        print("  [>] Consulting LLM for surgical triage mapping...")
        
        # proxy = PrivacyProxy()
        # anonymized_context = proxy.prepare_llm_prompt(
        #     state['raw_transaction'], 
        #     state['customer_data'],
        #     history=None 
        # )
        
        system_instruction = f"""
        You are the Senior Forensic Triage Lead. 
        
        DETERMINISTICALLY TRIGGERED: {triggered}
        
        CASE SIGNALS:
        - Account Age: {signals['account_age_days']} days
        - Near Threshold: {signals['near_threshold']}
        - IP Change: {signals['ip_change']}
        - Behavior: {json.dumps(signals['behavioral_summary'])}
        
        EXPERT CAPABILITIES:
        {expert_map}
        
        TASK:
        Add ONLY essential agents to the list based on specific risk indicators. 
        Example: If 'is_significant_deviation' is true, add 'velocity_agent'.
        If signals are normal, return empty.
        
        Response MUST be RAW JSON:
        {{
            "additional_trigger": ["agent_name"],
            "reasoning": "Brief risk synthesis"
        }}
        """
        try:
            # Industry Standard: Low-latency triage
            llm = ChatOllama(
                model=SUPERVISOR_MODEL,
                temperature=0, 
                num_predict=200,
                )
            resp = llm.invoke(system_instruction)
            content = resp.content.strip()
            
            # Robust JSON Extraction
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group()
            
            triage_decision = json.loads(content.strip())
            triggered.extend(triage_decision.get('additional_trigger', []))
            print(f"  [>] Triage Reasoning: {triage_decision.get('reasoning')}")
        except Exception as e:
            print(f"  [!] Triage Error: {e} | Raw Content: {content[:100]}...")
        
        pending = list(dict.fromkeys(triggered))

    # --- Tier 4: Reactive Synthesis ---
    if log and not pending:
        agents = ['ato_agent', 'aml_agent', 'synthetic_id_agent', 'cnp_agent', 'app_agent', 'velocity_agent']
        consulted_agents = [k for k in log.keys() if k in agents]
        valid_agents = [a for a in agents if a not in consulted_agents]

        if not valid_agents:
            return {"next_step": "sar_generator", "evidence_trail": new_evidence}

        print("  [>] Reviewing summarized logs for secondary triggers...")
        prompt = f"""
        Case Summary so far:
        {summarized_log}

        EXPERT CAPABILITIES:
        {expert_map}

        AVAILABLE EXPERTS: {', '.join(valid_agents)}
        
        Analyze findings. If evidence suggests a new angle for investigation, request it.
        Otherwise, close the case.

        
        RAW JSON:
        {{
            "more_experts": true/false,
            "next": "agent_name" or null,
            "reasoning": "very brief synthesis of why further investigation is or isn't needed"
        }}
        """
        try:
            llm = ChatOllama(
                model=SUPERVISOR_MODEL,
                temperature=0,
                # top_p=1,
                num_predict=200,
                # stop=["}", "}\n", "```"] # Stop generating immediately when JSON closes
                )
            resp = llm.invoke(prompt)
            content = resp.content.strip()
            if content.startswith('```json'): content = content[7:]
            if content.endswith('```'): content = content[:-3]
            
            decision = json.loads(content.strip())
            next_agent = decision.get('next')
            if decision.get('more_experts') and next_agent in valid_agents:
                pending.append(next_agent)
                print(f"  [>] Synthesis requested look from: {next_agent}")
            else:
                print(f"  [>] Synthesis: No further investigation required.")
                print(f"  [>] Synthesis Reasoning: {decision.get('reasoning')}")
        except Exception:
            print(f"  [!] Synthesis Error. Closing case with current findings.")
            return {"next_step": "sar_generator", "evidence_trail": new_evidence}

    # --- Dispatch ---
    if pending:
        next_agent = pending.pop(0)
        return {
            "next_step": next_agent,
            "pending_experts": pending,
            "evidence_trail": new_evidence,
            "timestamp": f"{datetime.now().isoformat()} - Supervisor: Dispatching {next_agent}"
        }

    return {"next_step": "sar_generator", "evidence_trail": new_evidence}


# --- Specialist Nodes (Now Using Tools) ---

def ato_agent_node(state: ForensicState) -> Dict[str, Any]:

    log = state.get('investigation_log', {})

    findings = ato_agent.analyze(
        state['customer_data'], 
        state['raw_transaction'], 
        investigation_log=log
    )
    print(f"  [ATO] Verdict: {findings.get('verdict')}")
    
    return {
        "ato_findings": findings,
        "investigation_log": {
            "ato_agent": findings
        },
        "timeline": [f"{datetime.now().isoformat()} - ATO Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def aml_agent_node(state: ForensicState) -> Dict[str, Any]:

    shared = state.get('shared_evidence', {})
    log = state.get('investigation_log', {})
    cached_kyc = state.get("shared_evidence").get("kyc_findings") if state.get("shared_evidence") else None

    findings = aml_agent.analyze(
        state['customer_data'], 
        state['raw_transaction'],
        existing_kyc=cached_kyc,
        investigation_log=log        
    )
    
    print(f"  [AML] Verdict: {findings.get('verdict')}")

    return {
        "aml_findings": findings,
        "investigation_log": {
            "aml_agent": findings
        },
        "shared_evidence": {
            **shared,
            "kyc_findings": findings.get("kyc_result")
        },
        "timeline": [f"{datetime.now().isoformat()} - AML Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def synthetic_id_agent_node(state: ForensicState) -> Dict[str, Any]:

    log = state.get('investigation_log', {})

    findings = synthetic_id_agent.analyze(
        state['customer_data'],
        investigation_log=log
    )
    
    print(f"  [SyntheticID] Verdict: {findings.get('verdict')}")

    return {
        "synthetic_id_findings": findings,
        "investigation_log": {
            "synthetic_id_agent": findings
        },
        "timeline": [f"{datetime.now().isoformat()} - SyntheticID Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def cnp_agent_node(state: ForensicState) -> Dict[str, Any]:

    log = state.get('investigation_log', {})

    findings = cnp_agent.analyze(
        state['customer_data'],
        investigation_log=log
    )

    print(f"  [CNP] Verdict: {findings.get('verdict')}")
    
    return {
        "cnp_findings": findings,
        "investigation_log": {
            "cnp_agent": findings
        },
        "timeline": [f"{datetime.now().isoformat()} - CNP Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def app_agent_node(state: ForensicState) -> Dict[str, Any]:

    log = state.get('investigation_log', {})

    findings = app_agent.analyze(
        state['customer_data'], 
        state['raw_transaction'],
        investigation_log=log
    )

    print(f"  [APP] Verdict: {findings.get('verdict')}")
    
    return {
        "app_findings": findings,
        "investigation_log": {
            "app_agent": findings
        },
        "timeline": [f"{datetime.now().isoformat()} - APP Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def velocity_agent_node(state: ForensicState) -> Dict[str, Any]:

    shared = state.get('shared_evidence', {})
    log = state.get('investigation_log', {})
    cached_heatmap = state.get("shared_evidence").get("heatmap") if state.get("shared_evidence") else None

    history = get_recent_history(state['customer_data']['customer_id'])
    findings = velocity_agent.analyze(
        state['customer_data']['customer_id'], 
        state['raw_transaction'],
        history,
        existing_heatmap=cached_heatmap,
        investigation_log=log
    )

    print(f"  [Velocity] Verdict: {findings.get('verdict')}")
    
    return {
        "velocity_findings": findings,
        "shared_evidence": {
            **shared,
            "heatmap": findings.get('heatmap_path')
        },
        "investigation_log": {
            "velocity_agent": findings
        },
        "timeline": [f"{datetime.now().isoformat()} - Velocity Agent: {findings.get('verdict')}"],
        "next_step": "supervisor"
    }

def report_node(state: ForensicState) -> Dict[str, Any]:
    from pprint import pprint
    print("Final log:")
    pprint(state.get("investigation_log"), width=150, compact=False, sort_dicts=False)
    print("\n[System] Generating Final SAR...")
    generator = SARGenerator(model=REASONING_MODEL)
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
    target_alert_id = "ALRT-2026-008"
    target_alert = truth.get(target_alert_id, {})
    tx_list = target_alert.get("target_tx", [])
    trigger_tx_id = tx_list[0] if isinstance(tx_list, list) else tx_list
     
    print(f"[Trigger] Alert: {target_alert_id} | Scenario: {target_alert.get('scenario')}")

    test_tx = get_transaction_from_db(trigger_tx_id)
    if not test_tx:
        print(f"Error: Test transaction {trigger_tx_id} not found in database.")
    else:
        customer = get_customer_from_db(test_tx['customer_id'])
        
        # Initialize Forensic State
        initial_state = {
            "raw_transaction": test_tx,
            "customer_data": customer,
            "anonymized_metadata": "",
            "pii_map": {},
            "next_step": "supervisor",
            "investigation_log": {}, # Must be a dict for ior operator
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
        
        start_time = time.time()
        final_state = app.invoke(initial_state)

        print("\n" + "="*60)
        print("FINAL FORENSIC REPORT")
        print("="*60)
        print(final_state['sar_report'])
        print(f"\nExecution Time: {time.time() - start_time:.2f}s")
