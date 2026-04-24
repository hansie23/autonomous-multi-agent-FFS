import json
from typing import Dict, Any, Optional
from src.tools import ForensicSQLTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class APPAgent:
    """
    Expert Agent: APP (Authorized Push Payment) / Social Engineering.
    Hybrid Model: FTR/Mule (Deterministic) + LLM Destination Audit (Agentic).
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, stream_tool: Any, model: str):
        self.sql_tool = sql_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer: dict, trigger_tx: dict, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs the APP investigative playbook.
        SHARPENED ROLE: Primary owner of Destination Account forensics (FTR, Mule Diversity).
        """
        print(f"\n  [APP] Analyzing social engineering risk for {customer['customer_id']}...")
        
        # --- PHASE 1: DETERMINISTIC CHECKS (FTR & Mule) ---
        dest_account = trigger_tx.get('destination_account')
        history_query = f"SELECT COUNT(*) as prev_count FROM transactions WHERE customer_id = '{customer['customer_id']}' AND destination_account = '{dest_account}' AND timestamp < '{trigger_tx.get('timestamp')}'"
        history_stats = json.loads(self.sql_tool.execute_query(history_query))
        is_new_recipient = history_stats[0].get('prev_count', 0) == 0
        
        mule_query = f"SELECT COUNT(DISTINCT customer_id) as source_count FROM transactions WHERE destination_account = '{dest_account}' AND timestamp >= datetime('now', '-7 days')"
        mule_stats = json.loads(self.sql_tool.execute_query(mule_query))
        source_count = mule_stats[0].get('source_count', 0)
        is_potential_mule = source_count > 3

        # FAST PATH: If recipient is established and not a mule, skip LLM
        if not is_new_recipient and not is_potential_mule:
             print(f"  [APP] Destination account is trusted. Skipping agentic deep-dive.")
             return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": "Account is an established recipient with no mule indicators.",
                "hunch_evidence": []
            }

        # --- PHASE 2: AGENTIC \"HUNCH\" ---
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])

        db_schema = self.sql_tool.get_schema()

        @tool
        def run_scam_query(sql_query: str):
            """Investigate destination account patterns (diversity, total inflow)."""
            return self.sql_tool.execute_query(sql_query)

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=100
            )
        llm_with_tools = llm.bind_tools([run_scam_query])

        system_prompt = f"""
        You are a Senior APP Specialist.
        
        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer['customer_id']}
        Transaction ID: {trigger_tx['tx_id']}

        DESTINATION STATE ({dest_account}):
        - First-Time Recipient: {is_new_recipient}
        - Inbound Diversity: {source_count} unique sources
        
        TASK:
        Verify if this represents a social engineering scam or mule activity.
        """

        hunch_evidence = []
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                call = response.tool_calls[0]
                result = run_scam_query.invoke(call['args'])
                hunch_evidence.append({"query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 3: FINAL SYNTHESIS ---
        risk_score = 0
        if is_new_recipient: risk_score += 20
        if is_potential_mule: risk_score += 50
        if trigger_tx.get('amount', 0) > 15000: risk_score += 20
        if hunch_evidence: risk_score += 10

        return {
            "verdict": "SUSPICIOUS" if risk_score >= 50 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": f"APP: FTR={is_new_recipient}, Mule={is_potential_mule}.",
            "hunch_evidence": hunch_evidence
        }
