import json
import os
from datetime import datetime
from typing import Dict, Any, List
from src.tools import ForensicSQLTool, IdentityVisionTool, SemanticKYCTool

class SyntheticIDAgent:
    """
    Expert Agent: Synthetic Identity Fraud.
    
    This agent specializes in detecting "Frankenstein" identities (real data mixed with 
    fake attributes) through three forensic pillars:
    1. Independent Document Verification: Scans the 'Golden Reference' ID for GAN-generated 
       artifacts, compositing halos, or font-plane mismatches without requiring a selfie.
    2. Digital Footprint Depth: Analyzes the ledger for 'shallow' histories (e.g., <5 tx) 
       and recent account openings (<90 days) which are typical of synthetic setups.
    3. RAG-Driven KYC Footprint: Cross-references the residency and personal data 
       against adverse media to detect 'recycled' or compromised identity components.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, bio_tool: IdentityVisionTool, kyc_tool: SemanticKYCTool):
        self.sql_tool = sql_tool
        self.bio_tool = bio_tool
        self.kyc_tool = kyc_tool

    def analyze(self, customer_id: str, customer_data: dict) -> Dict[str, Any]:
        """
        Executes the Synthetic Identity forensic playbook.
        
        Args:
            customer_id: The unique identifier for the customer.
            customer_data: Metadata containing residency, account age, and name.

        Returns:
            A dictionary containing the fraud verdict, risk score, and detailed forensic 
            reasoning regarding GAN artifacts and footprint depth.
        """
        print(f"\n  [SyntheticID] Analyzing persona authenticity for {customer_id}...")
        
        # 1. GAN/Deepfake Analysis (Independent Vision Scan)
        ref_path, _ = self.bio_tool.resolve_biometric_paths(customer_id)
        print(f"  [SyntheticID] Resolved reference document path: {ref_path}")
        vision_results = {"status": "SKIPPED", "artifact_detected": False}
        if ref_path:
            # Use the new independent authenticity scan instead of a self-comparison
            print(f"  [SyntheticID] Performing independent document authenticity scan...")
            vision_results = self.bio_tool.analyze_document_authenticity(ref_path)
        
        # 2. Digital Footprint Depth (SQL)
        history_query = f"""
        SELECT COUNT(*) as tx_count
        FROM transactions 
        WHERE customer_id = '{customer_id}'
        """
        print(f"  [SyntheticID] SQL tool executing footprint depth check for {customer_id}...")
        history_stats = json.loads(self.sql_tool.execute_query(history_query))
        
        # 3. KYC Inconsistency (RAG)
        print(f"  [SyntheticID] KYC tool querying RAG for {customer_id}...")
        kyc_results = self.kyc_tool.query_docs({"destination_jurisdiction": customer_data.get('residency_country')}, customer_data)

        # Decision Logic
        account_opened_str = customer_data.get('account_opened', '2000-01-01')
        account_age_days = (datetime.now() - datetime.strptime(account_opened_str, '%Y-%m-%d')).days
        is_new_account = account_age_days < 90
        
        gan_detected = vision_results.get('artifact_detected', False)
        tx_count = history_stats[0].get('tx_count', 0) if history_stats else 0
        shallow_history = tx_count < 5
        
        risk_score = 0
        if gan_detected: risk_score += 80
        if is_new_account and shallow_history: risk_score += 30
        if kyc_results.get('risk_level') == 'HIGH': risk_score += 20

        reasoning = (
            f"Synthetic ID Forensic Scan: GAN Artifacts: {gan_detected}. "
            f"Account Status: {'NEW' if is_new_account else 'ESTABLISHED'} ({account_age_days} days). "
            f"Footprint Depth: {'SHALLOW' if shallow_history else 'DEEP'} ({tx_count} transactions). "
            f"KYC Footprint: {kyc_results.get('risk_level', 'LOW')}."
        )

        print(f"  [SyntheticID] Risk Score: {risk_score}")
        print(f"  [SyntheticID] Reasoning: {reasoning}")

        return {
            "verdict": "FRAUD_DETECTED" if risk_score >= 80 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": reasoning,
            "gan_artifacts": gan_detected,
            "footprint_depth": tx_count
        }
