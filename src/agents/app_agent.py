import json
from typing import Dict, Any, List
from src.tools import ForensicSQLTool, SemanticKYCTool

class APPAgent:
    """
    Expert Agent: APP (Authorized Push Payment) / Social Engineering.
    
    ROLE:
    The APP Agent is the system's specialist for detecting "Scams" and "Mule Account" activity. 
    Unlike other agents that focus on the sender (ATO) or the volume (Velocity), the APP Agent 
    performs deep forensic analysis on the DESTINATION of the funds.

    FORENSIC PLAYBOOK:
    1. First-Time Recipient (FTR): Uses SQL to determine if this is a novel relationship. 
       Scammers often coerce victims into sending money to unfamiliar accounts.
    2. Mule Node Detection: Analyzes the destination account's "Inbound Diversity." 
       If an account receives rapid transfers from multiple unrelated customers, it is 
       flagged as a potential 'Mule' (a transit point for laundered money).
    3. Intelligence Cross-Referencing: Uses the SemanticKYCTool (RAG) to scan global 
       regulatory bulletins and scam databases for hits against the destination entity.

    OUTPUT:
    Returns a verdict (CLEAR/SUSPICIOUS) and a risk score weighted heavily toward 
    destination-based indicators.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, kyc_tool: SemanticKYCTool):
        self.sql_tool = sql_tool
        self.kyc_tool = kyc_tool

    def analyze(self, customer_id: str, trigger_tx: dict) -> Dict[str, Any]:
        """Runs the APP investigative playbook."""
        print(f"\n  [APP] Analyzing social engineering risk for {customer_id}...")
        
        dest_account = trigger_tx.get('destination_account')
        
        # 1. First-Time Recipient Check (SQL)
        # Check if the customer has ever sent money to this account before
        history_query = f"""
        SELECT COUNT(*) as prev_count
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND destination_account = '{dest_account}'
        AND timestamp < '{trigger_tx.get('timestamp')}'
        """
        history_stats = json.loads(self.sql_tool.execute_query(history_query))
        
        # 2. "Mule" Destination Check (SQL)
        # Check if this destination account is receiving bursts from multiple other customers
        mule_query = f"""
        SELECT COUNT(DISTINCT customer_id) as source_count, SUM(amount) as total_received
        FROM transactions 
        WHERE destination_account = '{dest_account}'
        AND timestamp >= datetime('now', '-7 days')
        """
        mule_stats = json.loads(self.sql_tool.execute_query(mule_query))
        
        # 3. Destination Risk Scan (RAG)
        kyc_results = self.kyc_tool.query_docs(trigger_tx, {"customer_id": "DEST_" + dest_account})

        # Decision Logic
        is_new_recipient = history_stats[0].get('prev_count', 0) == 0
        is_potential_mule = mule_stats[0].get('source_count', 0) > 3 # Received from >3 different people in a week
        
        risk_score = 0
        if is_new_recipient: risk_score += 20
        if is_potential_mule: risk_score += 50
        if trigger_tx.get('amount', 0) > 15000: risk_score += 20
        if kyc_results.get('risk_level') == 'HIGH': risk_score += 10

        return {
            "verdict": "SUSPICIOUS" if risk_score >= 50 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": f"APP analysis: New recipient: {is_new_recipient}. Potential mule account: {is_potential_mule} (Received from {mule_stats[0].get('source_count')} sources). Risk weighted score: {risk_score}.",
            "new_recipient": is_new_recipient,
            "mule_indicators": is_potential_mule,
            "source_diversity": mule_stats[0].get('source_count', 0)
        }
