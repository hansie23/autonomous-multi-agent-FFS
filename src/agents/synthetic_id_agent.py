import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, IdentityVisionTool, SemanticKYCTool
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

class SyntheticIDAgent:
    """
    Expert Agent: Synthetic Identity Fraud.
    Hybrid Model: Vision/Footprint (Deterministic) + LLM Identity Audit (Agentic).
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, bio_tool: IdentityVisionTool, stream_tool: Any, model: str):
        self.sql_tool = sql_tool
        self.bio_tool = bio_tool
        self.stream_tool = stream_tool
        self.model_name = model

    def analyze(self, customer_data: dict, investigation_log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes the Synthetic Identity forensic playbook.
        SHARPENED ROLE: Primary owner of Persona Authenticity (Vision/GAN) and Footprint depth.
        """
        print(f"\n  [SyntheticID] Analyzing persona authenticity for {customer_data['customer_id']}...")
        
        # --- PHASE 1: DETERMINISTIC FOOTPRINT ---
        history_query = f"SELECT COUNT(*) as tx_count FROM transactions WHERE customer_id = '{customer_data['customer_id']}'"
        history_stats = json.loads(self.sql_tool.execute_query(history_query))
        tx_count = history_stats[0].get('tx_count', 0)
        
        account_opened_str = customer_data.get('account_opened', '2000-01-01')
        account_age_days = (datetime.now() - datetime.strptime(account_opened_str, '%Y-%m-%d')).days
        is_new_account = account_age_days < 90

        # --- FAST PATH: If account is aged and has history, skip deep-dive ---
        if not is_new_account and tx_count > 20:
            print(f"  [SyntheticID] Established account footprint. Skipping vision and LLM.")
            return {
                "verdict": "CLEAR",
                "risk_score": 0,
                "reasoning": f"Account is {account_age_days} days old with {tx_count} transactions.",
                "vision_results": {"status": "SKIPPED"},
                "mismatch_findings": [],
                "hunch_evidence": []
            }

        # --- PHASE 2: VISION EXTRACTION & CROSS-VERIFICATION ---
        ref_path, selfie_path = self.bio_tool.resolve_biometric_paths(customer_data["customer_id"])
        
        mismatch_findings = []
        vision_results = {}
        
        if selfie_path:
            print(f"  [SyntheticID] Live Selfie found. Performing OCR and deepfake analysis...")
            vision_results = self.bio_tool.compare_faces(ref_path, selfie_path)
            ocr_data = vision_results.get("extracted_data", {})
            
            if ocr_data:
                if ocr_data.get("full_name") != customer_data.get("full_name"):
                    mismatch_findings.append("NAME_MISMATCH")
                if ocr_data.get("date_of_birth") != customer_data.get("dob"):
                    mismatch_findings.append("DOB_MISMATCH")
        else:
            print(f"  [SyntheticID] No Selfie available. Analyzing static ID for GAN artifacts...")
            vision_results = self.bio_tool.analyze_document_authenticity(ref_path)
            # Cannot do OCR verification without selfie in the refactored architecture
            mismatch_findings.append("NO_LIVE_OCR_POSSIBLE")

        # --- PHASE 3: AGENTIC REASONING ---
        log_summary = "No previous findings."
        if investigation_log:
            log_summary = "\n".join([f"{a}: {d.get('verdict')}" for a, d in investigation_log.items()])

        db_schema = self.sql_tool.get_schema()

        @tool
        def run_identity_query(sql_query: str):
            """Investigate shared attributes between different IDs."""
            return self.sql_tool.execute_query(sql_query)

        llm = ChatOllama(
            model=self.model_name,
            temperature=0.1,
            top_p=1,
            num_predict=150
        )
        llm_with_tools = llm.bind_tools([run_identity_query])

        system_prompt = f"""
        You are a Senior Synthetic Identity Investigator.

        PREVIOUS FINDINGS:
        {log_summary}

        DATABASE SCHEMA:
        {db_schema}

        Customer ID: {customer_data['customer_id']}

        IDENTITY STATE:
        - GAN Artifacts: {vision_results.get('artifact_detected')}
        - Discrepancies: {mismatch_findings}
        - Account Age: {account_age_days} days
        
        TASK:
        Verify if this is a 'Frankenstein' identity.
        """

        hunch_evidence = []
        try:
            response = llm_with_tools.invoke(system_prompt)
            if response.tool_calls:
                call = response.tool_calls[0]
                result = run_identity_query.invoke(call['args'])
                hunch_evidence.append({"query": call['args'].get('sql_query'), "result": result})
        except Exception:
            pass

        # --- PHASE 4: FINAL SYNTHESIS ---
        risk_score = 0
        if vision_results.get('artifact_detected'): risk_score += 80
        if "NAME_MISMATCH" in mismatch_findings or "DOB_MISMATCH" in mismatch_findings: risk_score += 40
        if is_new_account or tx_count < 5: risk_score += 20

        verdict = "CLEAR"
        if risk_score >= 100: verdict = "FRAUD_DETECTED"
        elif risk_score >= 60: verdict = "SUSPICIOUS"

        return {
            "verdict": verdict,
            "risk_score": min(risk_score, 100),
            "reasoning": f"SyntheticID check found {len(mismatch_findings)} record mismatches and GAN artifacts: {vision_results.get('artifact_detected')}.",
            "vision_results": vision_results,
            "mismatch_findings": mismatch_findings,
            "hunch_evidence": hunch_evidence
        }
