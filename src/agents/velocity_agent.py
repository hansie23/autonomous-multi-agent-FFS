import json
import ollama
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, BehavioralHeatmapTool
import numpy as np

class VelocityAgent:
    """
    Expert Agent: Velocity (Behavioral Analytics).
    
    This agent specializes in detecting anomalous transaction patterns through three distinct lenses:
    1. Statistical Volatility: Uses the Interquartile Range (IQR) method to identify transaction 
       amounts that deviate significantly from the customer's historical 10-transaction baseline.
    2. Temporal Bursts: Monitors the ledger for high-frequency activity (e.g., >4 transactions 
       in a 6-hour window).
    3. Visual Behavioral Context: Analyzes behavioral heatmaps using a VLM to confirm 
       if current activity aligns with long-term visual spending signatures.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, viz_tool: BehavioralHeatmapTool, model: str = "gemma4:e2b-it-q4_K_M"):
        self.sql_tool = sql_tool
        self.viz_tool = viz_tool
        self.model = model

    def _analyze_visual_pattern(self, heatmap_path: str) -> Dict[str, Any]:
        """Performs VLM analysis on the generated behavioral heatmap."""
        
        system_instruction = """
        You are a Senior Forensic Visual Analyst. Analyze the provided 'Behavioral Velocity Heatmap' (a chart of transaction amounts over time) to identify anomalies.
        
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
        """Executes the Velocity forensic playbook."""
        print(f"\n  [Velocity] Analyzing behavioral volume for {customer_id}...")
        
        # 1. Statistical Outlier Detection (IQR Method)
        history_query = f"""
        SELECT amount FROM transactions 
        WHERE customer_id = '{customer_id}' 
        ORDER BY timestamp DESC
        LIMIT 10
        """
        print(f"  [Velocity] SQL tool executing IQR query for {customer_id}...")
        raw_history = json.loads(self.sql_tool.execute_query(history_query))
        amounts = sorted([row['amount'] for row in raw_history]) if raw_history else []
        
        is_iqr_spike = False
        upper_bound = 0
        
        if len(amounts) >= 4:
            def get_percentile(data, p):
                size = len(data)
                index = int(size * p)
                return data[min(index, size - 1)]

            q1 = get_percentile(amounts, 0.25)
            q3 = get_percentile(amounts, 0.75)
            iqr = q3 - q1
            upper_bound = q3 + (1.5 * iqr)
            if trigger_tx.get('amount', 0) > upper_bound:
                is_iqr_spike = True
        else:
            avg_amt = sum(amounts)/len(amounts) if amounts else 0
            if trigger_tx.get('amount', 0) > (avg_amt * 10) and avg_amt > 0:
                is_iqr_spike = True

        # 2. Burst Detection (SQL)
        burst_query = f"""
        SELECT COUNT(*) as burst_count
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND timestamp >= datetime('now', '-6 hours')
        """
        print(f"  [Velocity] SQL tool executing burst query for {customer_id}...")
        burst_stats = json.loads(self.sql_tool.execute_query(burst_query))
        burst_count = burst_stats[0].get('burst_count', 0) if burst_stats else 0
        is_burst = burst_count > 4
        
        # 3. Visual Pattern Confirmation (Vision)
        if existing_heatmap:
            heatmap_path = existing_heatmap
            print(f"  [Velocity] Using existing heatmap for {customer_id}.")
        else:
            heatmap_path = self.viz_tool.generate(customer_id, history)
        print(f"  [Velocity] Generated heatmap for {customer_id}: {heatmap_path}")
        
        print(f"  [Velocity] Analyzing visual pattern for {customer_id}...")
        visual_findings = self._analyze_visual_pattern(heatmap_path)
        
        # Decision Logic
        risk_score = 0
        if is_iqr_spike: risk_score += 40
        if is_burst: risk_score += 30
        if visual_findings.get('visual_anomaly_detected'):
            # Weight the visual finding by confidence
            risk_score += (30 * visual_findings.get('confidence_score', 0))

        # Final Verdict
        verdict = "SUSPICIOUS" if risk_score >= 50 else "CLEAR"
        print(f"  [Velocity] Risk Score: {risk_score:.2f}")
        
        reasoning = f"Velocity (IQR): Spike: {is_iqr_spike}. Burst: {is_burst} ({burst_count} tx/6h). "
        reasoning += f"Visual Analysis: {visual_findings.get('pattern_type')} detected ({visual_findings.get('reasoning')})."
        
        return {
            "verdict": verdict,
            "risk_score": min(int(risk_score), 100),
            "reasoning": reasoning,
            "volume_spike": is_iqr_spike,
            "burst_detected": is_burst,
            "visual_anomaly": visual_findings.get('visual_anomaly_detected'),
            "heatmap_path": heatmap_path,
            "visual_reasoning": visual_findings.get('reasoning')
        }

