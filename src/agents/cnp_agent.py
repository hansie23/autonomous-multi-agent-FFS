import json
from typing import Dict, Any, List, Optional
from src.tools import ForensicSQLTool, BehavioralHeatmapTool, SemanticKYCTool
import ollama

class CNPAgent:
    """
    Expert Agent: CNP (Card Not Present) / Payment Fraud.
    
    This agent specializes in detecting e-commerce and digital payment anomalies through:
    1. BIN Attack Detection: Monitors for high-frequency, low-value 'probing' transactions 
       (e.g., >3 transactions in 1 hour) typical of automated card-testing scripts.
    2. Geographic Velocity ('Impossible Travel'): Uses SQL to identify rapid shifts in 
       transaction locations that exceed physical travel possibilities between timestamps.
    3. Multi-Modal Risk Synthesis: Integrates behavioral heatmaps with RAG-driven KYC 
       profiles to distinguish between legitimate travel and account compromise.
    4. Transaction Magnitude Analysis: Flags high-value digital purchases that deviate 
       from the customer's established baseline.
    """
    
    def __init__(self, sql_tool: ForensicSQLTool, viz_tool: BehavioralHeatmapTool, kyc_tool: SemanticKYCTool, model: str = "gemma4:e2b-it-q4_K_M"):
        self.sql_tool = sql_tool
        self.viz_tool = viz_tool
        self.kyc_tool = kyc_tool
        self.model = model

    def analyze(self, customer_id: str, trigger_tx: dict, history: List[dict], existing_heatmap: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes the CNP (Card-Not-Present) forensic playbook.
        """
        print(f"\n  [CNP] Analyzing payment risk for {customer_id}...")
        
        # 1. BIN Attack / High-Frequency Check
        is_high_frequency, recent_count = self._check_high_frequency(customer_id)
        
        # 2. Geo-Velocity & Travel History Check
        location_shift, is_frequent_traveler = self._check_geo_velocity(customer_id)
        
        # 3. Transaction Magnitude Baseline
        current_amount = trigger_tx.get('amount', 0)
        is_magnitude_spike, avg_baseline = self._check_magnitude_spike(customer_id, current_amount)
        
        # 4. Visual Velocity Analysis
        heatmap_path = self._get_analyze_heatmap(customer_id, history, existing_heatmap)
        
        
        # 5. KYC Consistency (RAG)
        kyc_risk = self._get_kyc_risk(customer_id, trigger_tx)

        # Decision Logic: Multi-Modal Synthesis
        risk_score = 0
        if is_high_frequency: risk_score += 40
        
        if location_shift:
            risk_score += 15 if is_frequent_traveler else 35
                
        if is_magnitude_spike: risk_score += 20
        if kyc_risk == 'HIGH': risk_score += 15

        reasoning = (
            f"CNP Forensic Analysis: High Frequency ({is_high_frequency}, count: {recent_count}). "
            f"Location Shift ({location_shift}, Frequent Traveler: {is_frequent_traveler}). "
            f"Magnitude Spike ({is_magnitude_spike}, Current: {current_amount:.2f}, Baseline: {avg_baseline:.2f}). "
            f"KYC Risk ({kyc_risk})."
        )

        print(f"  [CNP] Risk score: {risk_score}")
        print(f"  [CNP] Reasoning: {reasoning}")

        return {
            "verdict": "SUSPICIOUS" if risk_score >= 50 else "CLEAR",
            "risk_score": min(risk_score, 100),
            "reasoning": reasoning,
            "high_frequency": is_high_frequency,
            "location_shift": location_shift,
            "is_magnitude_spike": is_magnitude_spike,
            "heatmap_path": heatmap_path
        }

    def _check_high_frequency(self, customer_id: str) -> tuple:
        """Detects high-frequency probing / BIN attacks."""
        query = f"""
        SELECT COUNT(*) as recent_count
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND timestamp >= datetime('now', '-1 hour')
        """
        print(f"  [CNP] SQL tool executing high-frequency check for {customer_id}...")
        stats = json.loads(self.sql_tool.execute_query(query))
        count = stats[0].get('recent_count', 0) if stats else 0
        return count > 3, count

    def _check_geo_velocity(self, customer_id: str) -> tuple:
        """Analyzes location shifts vs. traveler profile."""
        geo_query = f"""
        SELECT ip_address, timestamp FROM transactions 
        WHERE customer_id = '{customer_id}' 
        ORDER BY timestamp DESC LIMIT 2
        """
        print(f"  [CNP] SQL tool executing geo-velocity check for {customer_id}...")
        history = json.loads(self.sql_tool.execute_query(geo_query))
        
        travel_query = f"""
        SELECT COUNT(DISTINCT location_city) as city_count
        FROM transactions WHERE customer_id = '{customer_id}'
        """
        travel_stats = json.loads(self.sql_tool.execute_query(travel_query))
        
        location_shift = False
        if len(history) > 1 and history[0]['ip_address'] != history[1]['ip_address']:
            location_shift = True
            
        unique_cities = travel_stats[0].get('city_count', 0) if travel_stats else 0
        return location_shift, unique_cities > 3

    def _check_magnitude_spike(self, customer_id: str, current_amount: float) -> tuple:
        """Compares current transaction against historical baseline."""
        query = f"SELECT amount FROM transactions WHERE customer_id = '{customer_id}' ORDER BY timestamp DESC"
        print(f"  [CNP] SQL tool executing magnitude spike check for {customer_id}...")
        stats = json.loads(self.sql_tool.execute_query(query))

        stats = [row['amount'] for row in stats]

        avg_baseline = sum(stats[1:]) / len(stats[1:]) if len(stats) > 1 else 0

        # avg_baseline = stats[0].get('avg_amount', 0) if stats else 0
        
        is_spike = (current_amount > avg_baseline * 3) and (current_amount > 500)
        return is_spike, avg_baseline

    def _get_kyc_risk(self, customer_id: str, trigger_tx: dict) -> str:
        """Queries RAG for adverse media and sanctions."""
        print(f"  [CNP] KYC tool querying RAG for {customer_id}...")
        results = self.kyc_tool.query_docs(trigger_tx, {"customer_id": customer_id})
        print(f"  [CNP] KYC RAG results for {customer_id}: {results.get("findings", "No findings")}")
        return results.get('risk_level', 'LOW')

    # def _get_heatmap(self, customer_id: str, history: List[dict], existing_heatmap: Optional[str]) -> str:
    #     """Resolves existing or generates new behavioral heatmap."""
    #     if existing_heatmap:
    #         return existing_heatmap
    #     return self.viz_tool.generate(customer_id, history)

    def _get_analyze_heatmap(self, customer_id: str, history: List[dict], existing_heatmap: Optional[str]) -> tuple:
        """Performs VLM analysis on the generated behavioral heatmap."""

        if existing_heatmap:
            print(f"  [CNP] Using existing heatmap for {customer_id}: {existing_heatmap}")
            heatmap_path =  existing_heatmap
        else:
            heatmap_path = self.viz_tool.generate(customer_id, history)
            print(f"  [CNP] Generated heatmap for {customer_id}: {heatmap_path}")

        print(f"  [CNP] Analyzing visual pattern for {customer_id}...")
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
            return heatmap_path, json.loads(response['message']['content'])
        except Exception as e:
            return heatmap_path, {
                "visual_anomaly_detected": False, 
                "pattern_type": "ERROR", 
                "reasoning": f"Vision error: {e}", 
                "confidence_score": 0.0,
                }