import json
import os
import ollama
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, IdentityVisionTool, BehavioralHeatmapTool

class ATOAgent:
    """
    Expert Agent: Account Takeover (Identity & Access).
    Specializes in detecting unauthorized access via IP shifts, 
    behavioral anomalies, and identity verification.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, bio_tool: IdentityVisionTool, viz_tool: BehavioralHeatmapTool, model: str = "gemma4:e2b-it-q4_K_M"):
        self.sql_tool = sql_tool
        self.bio_tool = bio_tool
        self.viz_tool = viz_tool
        self.model = model

    def _analyze_visual_pattern(self, heatmap_path: str) -> Dict[str, Any]:
        """Performs VLM analysis on the generated behavioral heatmap."""
        print(f"  [ATO] Performing VLM visual analysis via {self.model}...")
        
        system_instruction = """
        You are a Senior Forensic Visual Analyst. Analyze the provided 'Behavioral Velocity Heatmap' (a chart of transaction amounts over time) to identify anomalies that might suggest an Account Takeover.
        
        Look for:
        1. SAWTOOTH PATTERN: Rapid, alternating high and low values suggesting automated testing.
        2. PARABOLIC SPIKE: A sudden, nearly vertical increase in transaction magnitude.
        3. DENSITY SHIFT: A sudden cluster of transactions after a long period of dormancy.
        
        Your response MUST be in RAW JSON format:
        {
            "visual_anomaly_detected": true/false,
            "pattern_type": "SAWTOOTH" | "SPIKE" | "DENSITY_SHIFT" | "NORMAL",
            "reasoning": "Specific visual evidence from the chart",
            "confidence_score": 0.0-1.0
        }
        """

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system', 
                    'content': system_instruction
                }, {
                    'role': 'user', 
                    'content': "Analyze this behavioral heatmap for visual anomalies.",
                    'images': [heatmap_path]
                }],
                format='json'
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            return {
                "visual_anomaly_detected": False, 
                "pattern_type": "ERROR", 
                "reasoning": f"Vision error: {e}", 
                "confidence_score": 0.0
            }

    def analyze(self, customer_id: str, trigger_tx: dict, history: List[dict], existing_heatmap: Optional[str] = None) -> Dict[str, Any]:
        """Runs the ATO investigative playbook."""
        print(f"\n  [ATO] Analyzing access for {customer_id}...")
        
        # 1. IP & Location Forensic Analysis (SQL)
        current_ip = trigger_tx.get('ip_address')
        ip_query = f"""
        SELECT COUNT(DISTINCT ip_address) as unique_ips, 
               COUNT(*) as total_tx 
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND ip_address != '{current_ip}'
        """
        print(f"  [ATO] SQL tool executing IP check for {customer_id}...")
        ip_stats = json.loads(self.sql_tool.execute_query(ip_query))
        unique_ips = ip_stats[0].get('unique_ips', 0) if ip_stats else 0
        
        # 2. Behavioral Visual Analysis (Vision)
        if existing_heatmap:
            heatmap_path = existing_heatmap
            print(f"  [ATO] Using existing heatmap for {customer_id}.")
        else:
            heatmap_path = self.viz_tool.generate(customer_id, history)
        
        print(f"  [ATO] Analyzing visual pattern for {customer_id}...")
        visual_findings = self._analyze_visual_pattern(heatmap_path)
        
        # 3. Identity Verification (If anomalies detected)
        bio_result = {"status": "SKIPPED"}
        
        # Thresholds for Step-up
        is_visual_anomaly = visual_findings.get('visual_anomaly_detected', False)
        is_high_value = trigger_tx.get('amount', 0) > 10000
        is_ip_shift = unique_ips > 0

        risk_score = 0
        if is_ip_shift: risk_score += 40
        if is_high_value: risk_score += 20
        if is_visual_anomaly: risk_score += (30 * visual_findings.get('confidence_score', 0))

        risk_level = "LOW"
        if is_ip_shift or is_high_value or is_visual_anomaly:
            print("  [ATO] Access anomalies detected. Requesting Biometric Step-up...")
            ref_path, selfie_path = self.bio_tool.resolve_biometric_paths(customer_id)
            print(f"  [ATO] Resolved reference document path: {ref_path}")
            print(f"  [ATO] Resolved selfie path: {selfie_path}")
            print(f"  [ATO] Performing biometric comparison...")
            bio_result = self.bio_tool.compare_faces(ref_path, selfie_path)
            risk_level = "HIGH" if bio_result.get('status') == 'FAIL' else "MEDIUM"

        print(f"  [ATO] Biometric result received: {bio_result.get('status')}.")
        
        # Final Verdict Logic
        verdict = "CLEAR"
        if bio_result.get('status') == 'FAIL':
            verdict = "FRAUD_DETECTED"
            risk_score = 100
        elif risk_score >= 50:
            verdict = "SUSPICIOUS"

        reasoning = (
            f"ATO Analysis: {unique_ips} IP shifts detected. "
            f"Visual Analysis: {visual_findings.get('pattern_type')} detected ({visual_findings.get('reasoning')}). "
            f"Biometric check: {bio_result.get('status')}. {bio_result.get('reasoning', '')}"
        )

        return {
            "verdict": verdict,
            "risk_level": risk_level,
            "risk_score": int(risk_score),
            "reasoning": reasoning,
            "biometric_status": bio_result.get('status'),
            "ip_anomalies": unique_ips,
            "heatmap_path": heatmap_path,
            "visual_anomaly": is_visual_anomaly,
            "visual_reasoning": visual_findings.get('reasoning')
        }

