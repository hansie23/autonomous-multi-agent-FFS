import json
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, BehavioralHeatmapTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class VelocityAgent:
    """
    Expert Agent: Velocity (Behavioral Analytics).
    Hybrid Model: Statistical IQR (Deterministic) + LLM Pattern Recognition (Agentic).
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, viz_tool: BehavioralHeatmapTool, stream_tool: Any, model: str):
        self.sql_tool = sql_tool
        self.viz_tool = viz_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer_id: str, trigger_tx: dict, history: List[dict], existing_heatmap: Optional[str] = None, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes the Velocity forensic playbook.
        SHARPENED ROLE: Primary owner of Statistical Volatility (IQR) and Visual spend signatures.
        """
        print(f"\n  [Velocity] Analyzing behavioral volume for {customer_id}...")
        
        # --- PHASE 1: DETERMINISTIC STATS (IQR & Bursts) ---
        history_query = f"SELECT amount FROM transactions WHERE customer_id = '{customer_id}' ORDER BY timestamp DESC LIMIT 10"
        raw_history = json.loads(self.sql_tool.execute_query(history_query))
        amounts = sorted([row['amount'] for row in raw_history]) if raw_history else []
        
        is_iqr_spike = False
        if len(amounts) >= 4:
            q1, q3 = amounts[len(amounts)//4], amounts[(3*len(amounts))//4]
            upper_bound = q3 + (1.5 * (q3 - q1))
            if trigger_tx.get('amount', 0) > upper_bound: is_iqr_spike = True

        burst_query = f"SELECT COUNT(*) as burst_count FROM transactions WHERE customer_id = '{customer_id}' AND timestamp >= datetime('now', '-6 hours')"
        burst_stats = json.loads(self.sql_tool.execute_query(burst_query))
        burst_count = burst_stats[0].get('burst_count', 0)
        is_burst = burst_count > 4

        # FAST PATH: If stats are normal, skip vision and LLM
        if not is_iqr_spike and not is_burst:
            print(f"  [Velocity] Behavioral baseline normal. Skipping vision and LLM.")
            return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": "No IQR spikes or transaction bursts detected.",
                "hunch_evidence": [],
                "heatmap_path": None,
                "visual_anomaly": False
            }

        # Visual Analysis (Only if stats are triggered)
        print(f"  [Velocity] Volatility detected. Analyzing visual patterns in heatmap...")
        heatmap_path = existing_heatmap if existing_heatmap else self.viz_tool.generate(customer_id, history)
        visual_findings = self.viz_tool.analyze_visual_pattern(heatmap_path)

        # --- PHASE 2: AGENTIC \"HUNCH\" ---
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])

        db_schema = self.sql_tool.get_schema()

        @tool
        def run_velocity_query(sql_query: str):
            """Investigate transaction frequency or timing patterns."""
            return self.sql_tool.execute_query(sql_query)

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=150
        )
        llm_with_tools = llm.bind_tools([run_velocity_query])

        system_prompt = f"""
        You are a Senior Velocity Analyst.

        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer_id}
        Transaction ID: {trigger_tx['tx_id']}

        BEHAVIORAL STATE:
        - IQR Spike: {is_iqr_spike}
        - Burst Count (6h): {burst_count}
        - Visual Pattern: {visual_findings.get('pattern_type')}
        
        TASK:
        Verify if this represents automated 'testing' or 'cash-out' behavior.
        """

        hunch_evidence = []
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                call = response.tool_calls[0]
                result = run_velocity_query.invoke(call['args'])
                hunch_evidence.append({"query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 3: FINAL VERDICT ---
        risk_score = 0
        if is_iqr_spike: risk_score += 40
        if is_burst: risk_score += 30
        if visual_findings.get('visual_anomaly_detected'): risk_score += 30
        if hunch_evidence: risk_score += 10 

        return {
            "verdict": "SUSPICIOUS" if risk_score >= 50 else "CLEAR",
            "risk_score": min(int(risk_score), 100),
            "reasoning": f"Velocity: Spike={is_iqr_spike}, Burst={is_burst}. Visual: {visual_findings.get('pattern_type')}.",
            "hunch_evidence": hunch_evidence,
            "heatmap_path": heatmap_path,
            "visual_anomaly": visual_findings.get('visual_anomaly_detected')
        }
