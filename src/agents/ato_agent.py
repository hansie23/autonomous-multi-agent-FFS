import json
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, IdentityVisionTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class ATOAgent:
    """
    Expert Agent: Account Takeover (Identity & Access).
    Hybrid Model: IP/Biometric (Deterministic) + LLM Security Audit (Agentic).
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, bio_tool: IdentityVisionTool, stream_tool: Any, model: str):
        self.sql_tool = sql_tool
        self.bio_tool = bio_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer_data: dict, trigger_tx: dict, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs the ATO investigative playbook.
        SHARPENED ROLE: Primary owner of Security/Access anomalies (IP shifts, Device shifts, Biometrics).
        """
        customer_id = customer_data.get('customer_id')
        print(f"\n  [ATO] Analyzing access for {customer_id}...")
        
        # --- PHASE 1: DETERMINISTIC CHECKS (IP & Biometrics) ---
        current_ip = trigger_tx.get('ip_address')
        ip_query = f"SELECT COUNT(DISTINCT ip_address) as unique_ips FROM transactions WHERE customer_id = '{customer_id}' AND ip_address != '{current_ip}'"
        ip_stats = json.loads(self.sql_tool.execute_query(ip_query))
        unique_ips = ip_stats[0].get('unique_ips', 0) if ip_stats else 0

        # FAST PATH: If no IP shifts and amount is low, skip deep-dive
        if unique_ips == 0 and trigger_tx.get('amount', 0) < 5000:
             print(f"  [ATO] No security anomalies. Skipping biometric step-up and LLM.")
             return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": "No IP shifts or high-value triggers.",
                "hunch_evidence": [],
                "ip_anomalies": 0
            }

        # Biometric Verification (Step-Up Challenge)
        print(f"  [ATO] Access anomalies detected. Requesting Biometric Step-up...")
        ref_path, selfie_path = self.bio_tool.resolve_biometric_paths(customer_id)
        bio_result = self.bio_tool.compare_faces(ref_path, selfie_path)
        
        # OCR Verification Logic (Industry Standard)
        mismatch_findings = []
        ocr_data = bio_result.get("extracted_data", {})
        if ocr_data:
            if ocr_data.get("full_name") != customer_data.get("full_name"):
                mismatch_findings.append("NAME_MISMATCH_ON_LIVE_ID")
            if ocr_data.get("date_of_birth") != customer_data.get("dob"):
                mismatch_findings.append("DOB_MISMATCH_ON_LIVE_ID")
        
        print(f"  [ATO] Biometric result: {bio_result.get('status')} | OCR Mismatches: {len(mismatch_findings)}")

        # --- PHASE 2: AGENTIC \"HUNCH\" (Contextual Audit) ---
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])

        db_schema = self.sql_tool.get_schema()

        @tool
        def run_security_query(sql_query: str):
            """Executes a SQL query to investigate login patterns or device shifts."""
            return self.sql_tool.execute_query(sql_query)

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=200
            )
        llm_with_tools = llm.bind_tools([run_security_query])

        system_prompt = f"""
        You are a Senior ATO Investigator.

        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer_data['customer_id']}
        Transaction ID: {trigger_tx['tx_id']}

        SECURITY STATE:
        - IP shifts: {unique_ips}
        - Biometric Match: {bio_result.get('status')}
        - ID Verification Mismatches: {mismatch_findings}
        
        TASK:
        Verify if this access represents a takeover. If face failed or ID mismatched, it's fraud.
        """
        
        hunch_evidence = []
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                call = response.tool_calls[0]
                result = run_security_query.invoke(call['args'])
                hunch_evidence.append({"query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 3: FINAL SYNTHESIS ---
        risk_score = 0
        if unique_ips > 0: risk_score += 30
        
        if bio_result.get('status') == 'FAIL' or mismatch_findings: 
            risk_score = 100 # High-confidence fraud
        elif bio_result.get('status') in ['PENDING', 'UNKNOWN']: 
            risk_score += 20
            
        if hunch_evidence: risk_score += 10

        verdict = "CLEAR"
        if risk_score == 100: verdict = "FRAUD_DETECTED"
        elif risk_score >= 40: verdict = "SUSPICIOUS"

        return {
            "verdict": verdict,
            "risk_score": int(risk_score),
            "reasoning": f"ATO: IPs={unique_ips}, Bio={bio_result.get('status')}, OCR_Mismatch={len(mismatch_findings)}.",
            "hunch_evidence": hunch_evidence,
            "ip_anomalies": unique_ips
        }
