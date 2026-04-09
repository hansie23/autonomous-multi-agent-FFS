import json
import ollama
from typing import Dict, Any, List

class SARGenerator:
    """
    Final Stage: SAR Synthesis Agent.
    Aggregates findings from domain experts (ATO, AML, Synthetic ID, etc.) 
    to generate a formal forensic report and final risk verdict.
    """

    def __init__(self, model: str = "qwen3:4b-instruct"):
        self.model = model

    def _synthesize_narrative(self, log: List[Dict[str, Any]]) -> str:
        """
        NLP Narrative Synthesis: Performs abstractive summarization of the investigation log.
        Converts raw agent findings into a cohesive, chronological forensic story.
        """
        if not log:
            return "No investigation log available for narrative synthesis."

        print(f"  [SAR] Performing Abstractive Narrative Synthesis...")

        system_prompt = """
        You are a Senior Financial Crimes Forensic Investigator at FinCEN. 
        Your task is to review the raw 'Investigation Log' and synthesize a professional, 
        cohesive, and chronological Forensic Narrative for a Suspicious Activity Report (SAR).

        GUIDELINES:
        1. CHRONOLOGY: Start with the initial trigger and explain how the investigation evolved.
        2. COHESION: Use logical connectors (e.g., 'consequently', 'subsequently', 'furthermore').
        3. FACTUALITY: Strictly refer to details found in the log. Do not hallucinate data.
        4. TONE: Objective, professional, and dry. Avoid sensationalism.
        5. LINGUISTIC PRECISION: Use forensic terminology (e.g., 'structuring', 'velocity attack', 'synthetic identity').

        Structure the narrative as a single, multi-paragraph story that bridges the gap between different specialist findings.
        """

        prompt = f"Investigation Log to Synthesize:\n{json.dumps(log, indent=2)}"

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': prompt}
                ]
            )
            return response['message']['content']
        except Exception as e:
            return f"Error during narrative synthesis: {str(e)}"

    def generate_report(self, state: Dict[str, Any]) -> str:
        """
        Synthesizes findings from the domain-expert nodes.
        Calculates a weighted final risk score based on agent verdicts.
        """
        
        # 1. Collect findings from state
        experts = {
            "ATO": state.get('ato_findings'),
            "AML": state.get('aml_findings'),
            "SyntheticID": state.get('synthetic_id_findings'),
            "CNP": state.get('cnp_findings'),
            "APP": state.get('app_findings'),
            "Velocity": state.get('velocity_findings')
        }

        # 2. Risk Weighting & Status Logic
        final_risk = 0
        status = "CLEAR"
        verdicts = []
        
        # Expert Weights (Adjusted for reliability)
        weights = {
            "ATO": 0.2,
            "AML": 0.25,
            "SyntheticID": 0.25,
            "CNP": 0.1,
            "APP": 0.1,
            "Velocity": 0.1
        }

        for name, findings in experts.items():
            if findings:
                score = findings.get('risk_score', 0)
                # If agent has no score but detected fraud, force 100(ATO Agent)
                if findings.get('verdict') == "FRAUD_DETECTED":
                    score = 100
                
                final_risk += score * weights.get(name, 0)
                verdicts.append(f"{name}: {findings.get('verdict')} (Score: {score})")

        # Immediate Fail Rules
        if any(f.get('verdict') == "FRAUD_DETECTED" for f in experts.values() if f):
            final_risk = max(final_risk, 90)
            status = "FRAUD / SAR_FILED"
        elif final_risk > 70:
            status = "HIGH_RISK / SUSPEND_ACCOUNT"
        elif final_risk > 40:
            status = "SUSPICIOUS / MONITORING"
        else:
            status = "CLEAR"

        # 3. Identity Context
        cust = state['customer_data']
        cust_name = cust.get('full_name', "REDACTED")
        cust_id = cust.get('customer_id', "UNKNOWN")

        # 4. Generate Narrative Summary (NLP Enhancement)
        narrative = self._synthesize_narrative(state.get('investigation_log', []))

        # 5. Construct Report
        report = "=" * 60 + "\n"
        report += "    OFFICIAL SUSPICIOUS ACTIVITY REPORT (SAR) - AGENTIC CORE\n"
        report += "=" * 60 + "\n\n"
        
        report += f"SUBJECT: {cust_name} (ID: {cust_id})\n"
        report += f"RESIDENCY: {cust.get('residency_country', 'Unknown')}\n"
        report += f"FINAL VERDICT: {status}\n"
        report += f"AGGREGATED RISK SCORE: {final_risk:.2f}/100\n"
        
        # Add Regulatory Context
        reg_hits = state.get('regulatory_findings', [])
        if reg_hits:
            report += f"REGULATORY HITS: {', '.join(reg_hits)}\n"
            
        report += "-" * 40 + "\n\n"
        
        report += "FORENSIC NARRATIVE SUMMARY:\n"
        report += f"{narrative}\n\n"
        
        report += "-" * 40 + "\n\n"
        
        report += "EXPERT ANALYSIS DETAILS:\n"
        for name, findings in experts.items():
            if findings:
                report += f"\n[{name} Expert]:\n"
                report += f"  > Verdict: {findings.get('verdict')}\n"
                report += f"  > Reasoning: {findings.get('reasoning')}\n"
                if 'biometric_status' in findings:
                    report += f"  > Identity Check: {findings['biometric_status']}\n"
                if 'heatmap_path' in findings:
                    report += f"  > Behavioral Evidence: {findings['heatmap_path']}\n"
        
        report += "\n" + "-" * 40 + "\n"
        report += "INVESTIGATION AUDIT TRAIL:\n"
        # report += f"{state.get('investigation_log', [])}\n"

        for entry in state.get('investigation_log', []):
            agent = entry.get('agent', 'System')
            action = entry.get('action', 'Analyzed')
            reasoning = entry.get('reasoning', '')
            report += f"- [{agent}] {action}: {reasoning}\n"
        
        report += "\n" + "=" * 60 + "\n"
        report += "    FINANCIAL CRIMES ENFORCEMENT AGENT (AI)\n"
        report += "=" * 60 + "\n"
        
        return report

