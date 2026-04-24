import json
from typing import Dict, Any, Optional
from src.tools import ForensicSQLTool, SemanticKYCTool, StreamingIntelligenceTool, MultiHopRelationalTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class AMLAgent:
    """
    Expert Agent: Anti-Money Laundering (AML).
    Specializes in detecting Placement, Layering, and Integration patterns 
    via SQL forensics and global sanctions RAG.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, kyc_tool: SemanticKYCTool, graph_tool: MultiHopRelationalTool, stream_tool: StreamingIntelligenceTool, model: str):
        self.sql_tool = sql_tool
        self.kyc_tool = kyc_tool
        self.graph_tool = graph_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer: dict, trigger_tx: dict, existing_kyc: Optional[str] = None, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs the AML forensic playbook.
        SHARPENED ROLE: Primary owner of Money Laundering patterns and Reputation Intelligence (RAG).
        """
        print(f"\n  [AML] Investigating transaction patterns for {customer['customer_id']}...")

        # --- PHASE 1: DETERMINISTIC SCAN (Fast Compliance) ---
        smurfing_query = f"SELECT COUNT(*) as count FROM transactions WHERE customer_id = '{customer['customer_id']}' AND amount BETWEEN 9000 AND 9999 AND timestamp >= datetime('now', '-30 days')"
        structuring_stats = json.loads(self.sql_tool.execute_query(smurfing_query))
        
        layering_query = f"SELECT COUNT(*) as fast_moves FROM transactions WHERE customer_id = '{customer['customer_id']}' AND timestamp >= datetime('now', '-24 hours')"
        layering_stats = json.loads(self.sql_tool.execute_query(layering_query))
        
        kyc_result = existing_kyc if existing_kyc else self.kyc_tool.query_docs(
            tx_dest=trigger_tx["destination_jurisdiction"], 
            customer_name=customer["full_name"]
        )

        # COMPRESSION: Summarize RAG findings to save tokens
        kyc_summary = kyc_result.get('findings', 'No adverse media hits.')
        if len(kyc_summary) > 500:
             kyc_summary = kyc_summary[:500] + "... [Truncated for Token Efficiency]"

        # --- FAST PATH: Skip LLM if baseline is clearly normal ---
        if structuring_stats[0]['count'] == 0 and layering_stats[0]['fast_moves'] < 3 and kyc_result.get('total_hits', 0) == 0:
            print(f"  [AML] Deterministic checks clear. Skipping agentic deep-dive.")
            return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": "No structuring, layering, or KYC hits found in deterministic scan.",
                "kyc_result": kyc_result,
                "counterparty_hits": {"status": "SKIPPED"},
                "hunch_evidence": []
            }

        # --- PHASE 2: AGENTIC REASONING (Autonomous Tools) ---
        print(f"  [AML] Baseline anomalies found. Engaging LLM for autonomous investigation...")
        
        db_schema = self.sql_tool.get_schema()
        # Summarize log for LLM
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])

        @tool
        def run_aml_query(sql_query: str):
            """Executes a SQL query to investigate laundering indicators like structuring, layering, or integration."""
            return self.sql_tool.execute_query(sql_query)

        @tool
        def investigate_destination_reputation(destination_account: str):
            """
            Resolves owner and checks adverse media. Use for large/suspicious transfers.
            """
            return json.dumps(self.graph_tool.investigate_counterparty(destination_account))

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=150
            )
        llm_with_tools = llm.bind_tools([run_aml_query, investigate_destination_reputation])

        system_prompt = f"""
        You are a Senior AML Specialist. 

        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer['customer_id']}
        Transaction ID: {trigger_tx['tx_id']}

        CURRENT SCAN:
        - Structuring (9k-10k): {structuring_stats[0]['count']}
        - Rapid Moves (24h): {layering_stats[0]['fast_moves']}
        - KYC Hit Summary: {kyc_summary}

        MANDATE:
        Verify if these indicators represent true risk. If destination {trigger_tx.get('destination_account')} is suspicious, investigate reputation.
        """

        hunch_evidence = []
        counterparty_hits = {"status": "NOT_PERFORMED"}
        
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                for call in response.tool_calls:
                    if call['name'] == "investigate_destination_reputation":
                        result = investigate_destination_reputation.invoke(call['args'])
                        counterparty_hits = json.loads(result)
                        hunch_evidence.append({"type": "GRAPH", "result": counterparty_hits})
                    elif call['name'] == "run_aml_query":
                        result = run_aml_query.invoke(call['args'])
                        hunch_evidence.append({"type": "SQL", "query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 3: FINAL SYNTHESIS ---
        risk_score = 0
        if structuring_stats[0]['count'] > 2: risk_score += 40
        if layering_stats[0]['fast_moves'] > 5: risk_score += 30
        
        # Only add RAG risk if it's a true relevant HIT
        if kyc_result.get('total_hits', 0) > 0 and "No relevant findings" not in kyc_result.get('findings', ''):
             risk_score += 40
             
        if counterparty_hits.get('status') == 'HIT': 
            risk_score += 60
        
        # Final Verdict Logic
        verdict = "CLEAR"
        if risk_score >= 100 and counterparty_hits.get('status') == 'HIT':
             verdict = "FRAUD_DETECTED" # Only definitive if counterparty is confirmed high-risk
        elif risk_score >= 40: 
             verdict = "SUSPICIOUS"
        
        return {
            "verdict": verdict,
            "risk_score": min(risk_score, 100),
            "reasoning": f"AML scan complete. Counterparty: {counterparty_hits.get('status')}. Risk Score: {risk_score}",
            "kyc_result": kyc_result,
            "counterparty_hits": counterparty_hits,
            "hunch_evidence": hunch_evidence
        }
