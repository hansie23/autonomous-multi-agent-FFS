import json
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, SemanticKYCTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class CNPAgent:
    """
    Expert Agent: CNP (Card Not Present) / Payment Fraud.
    Hybrid Model: Geo-Velocity (Deterministic) + LLM Merchant Audit (Agentic).
    """

    def __init__(self, sql_tool: ForensicSQLTool, stream_tool: Any, model: str):
        self.sql_tool = sql_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer: dict, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes the CNP (Card-Not-Present) forensic playbook.
        SHARPENED ROLE: Primary owner of Merchant Risk, Card Probing, and Geo-Velocity.
        """
        print(f"\n  [CNP] Analyzing payment risk for {customer['customer_id']}...")

        # --- PHASE 1: DETERMINISTIC CHECKS (Merchant & Geo) ---
        is_high_frequency, recent_count = self._check_high_frequency(customer['customer_id'])
        location_shift, is_frequent_traveler = self._check_geo_velocity(customer['customer_id'])

        # FAST PATH: If no frequency or location anomalies, skip LLM
        if not is_high_frequency and not location_shift:
             print(f"  [CNP] Payment baseline normal. Skipping agentic deep-dive.")
             return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": "No high-frequency probing or geo-velocity shifts detected.",
                "hunch_evidence": []
            }

        # --- PHASE 2: AGENTIC \"HUNCH\" ---
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])
        
        db_schema = self.sql_tool.get_schema()

        @tool
        def run_payment_query(sql_query: str):
            """Investigate merchant patterns or BIN-attack patterns."""
            return self.sql_tool.execute_query(sql_query)

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=150
        )
        llm_with_tools = llm.bind_tools([run_payment_query])

        system_prompt = f"""
        You are a Senior CNP Specialist.
        
        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer['customer_id']}

        CURRENT STATE:
        - Card Probing frequency: {recent_count} (last 1h)
        - Location Shift: {location_shift}
        
        TASK:
        Verify if these represent e-commerce fraud.
        """

        hunch_evidence = []
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                call = response.tool_calls[0]
                result = run_payment_query.invoke(call['args'])
                hunch_evidence.append({"query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 3: FINAL SYNTHESIS ---
        risk_score = 0
        if is_high_frequency: risk_score += 40
        if location_shift and not is_frequent_traveler: risk_score += 35
        if hunch_evidence: risk_score += 10

        return {
            "verdict": "SUSPICIOUS" if risk_score >= 50 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": f"CNP: Probing={is_high_frequency}, Geo={location_shift}.",
            "hunch_evidence": hunch_evidence
        }

    def _check_high_frequency(self, customer_id: str) -> tuple:
        query = f"SELECT COUNT(*) as recent_count FROM transactions WHERE customer_id = '{customer_id}' AND timestamp >= datetime('now', '-1 hour')"
        print(f"  [CNP] Checking high-frequency transactions...")
        stats = json.loads(self.sql_tool.execute_query(query))
        count = stats[0].get('recent_count', 0) if stats else 0
        return count > 3, count

    def _check_geo_velocity(self, customer_id: str) -> tuple:
        print(f"  [CNP] Checking geo-velocity...")
        geo_query = f"SELECT ip_address FROM transactions WHERE customer_id = '{customer_id}' ORDER BY timestamp DESC LIMIT 2"
        history = json.loads(self.sql_tool.execute_query(geo_query))
        travel_query = f"SELECT COUNT(DISTINCT location_city) as city_count FROM transactions WHERE customer_id = '{customer_id}'"
        travel_stats = json.loads(self.sql_tool.execute_query(travel_query))
        location_shift = len(history) > 1 and history[0]['ip_address'] != history[1]['ip_address']
        unique_cities = travel_stats[0].get('city_count', 0) if travel_stats else 0
        return location_shift, unique_cities > 3
