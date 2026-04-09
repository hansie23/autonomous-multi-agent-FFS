import json
from typing import Dict, Any, List
from src.tools import ForensicSQLTool, SemanticKYCTool

class AMLAgent:
    """
    Expert Agent: Anti-Money Laundering (AML).
    Specializes in detecting Placement, Layering, and Integration patterns 
    via SQL forensics and global sanctions RAG.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, kyc_tool: SemanticKYCTool):
        self.sql_tool = sql_tool
        self.kyc_tool = kyc_tool

    def analyze(self, customer_id: str, trigger_tx: dict) -> Dict[str, Any]:
        """Runs the AML forensic playbook."""
        print(f"\n  [AML] Investigating transaction patterns for {customer_id}...")
        
        # 1. Sanctions & Adverse Media Pre-Scan (RAG)
        print(f"  [AML] KYC tool querying RAG for {customer_id}...")
        kyc_results = self.kyc_tool.query_docs(trigger_tx, {"full_name": "Unknown", "customer_id": customer_id})
        print(f"  [AML] KYC RAG results for {customer_id}: {kyc_results.get('findings', 'No findings')}")

        # 2. Structural Analysis (SQL - Smurfing/Structuring Check)
        # Look for multiple transactions just under $10,000 threshold
        smurfing_query = f"""
        SELECT COUNT(*) as count, SUM(amount) as total 
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND amount BETWEEN 9000 AND 9999
        AND timestamp >= datetime('now', '-30 days')
        """
        print(f"  [AML] SQL tool executing structuring check for {customer_id}...")
        structuring_stats = json.loads(self.sql_tool.execute_query(smurfing_query))
        
        # 3. Layering Check (Rapid Movement)
        layering_query = f"""
        SELECT COUNT(*) as fast_moves
        FROM transactions 
        WHERE customer_id = '{customer_id}'
        AND timestamp >= datetime('now', '-24 hours')
        """
        print(f"  [AML] SQL tool executing layering check for {customer_id}...")
        layering_stats = json.loads(self.sql_tool.execute_query(layering_query))

        # Decision Logic
        risk_score = 0
        if kyc_results.get('risk_level') == 'HIGH': risk_score += 50
        if structuring_stats and structuring_stats[0]['count'] > 2: risk_score += 40
        if layering_stats and layering_stats[0]['fast_moves'] > 5: risk_score += 30

        print(f"  [AML] Risk Score: {risk_score}")
        # print(f"  [AML] Findings: {kyc_results.get('findings', [])}")
        print(f"""  [AML] Reasoning: Structuring patterns: {structuring_stats[0]['count']}, Rapid moves: {layering_stats[0]['fast_moves']}, KYC Risk: {kyc_results.get('risk_level')}.""")
        
        return {
            "verdict": "SUSPICIOUS" if risk_score >= 40 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": f"AML scan found {structuring_stats[0]['count']} structuring patterns and {layering_stats[0]['fast_moves']} rapid moves. KYC Risk: {kyc_results.get('risk_level')}.",
            "kyc_hits": kyc_results.get('findings', []),
            "structuring_detected": structuring_stats[0]['count'] > 2
        }
