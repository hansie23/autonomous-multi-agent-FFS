from typing import Annotated, List, TypedDict, Optional, Dict, Any, Union
from langgraph.graph import StateGraph, END

from operator import add, ior

def take_latest(old, new):
    return new


class ForensicState(TypedDict):
    # --- Input Data ---
    raw_transaction: dict
    customer_data: dict
    
    # --- Processing State ---
    anonymized_metadata: str
    pii_map: dict
    next_step: Annotated[Union[str, List[str]], take_latest]
    investigation_log: Annotated[Dict[str, Any], ior]
    pending_experts: List[str] # Queue of experts to run
    regulatory_findings: List[str] # Specific hits from sanctions/blacklist
    
    # --- Agent Findings (Verdicts & Reasoning) ---
    ato_findings: Optional[Dict[str, Any]]
    aml_findings: Optional[Dict[str, Any]]
    synthetic_id_findings: Optional[Dict[str, Any]]
    cnp_findings: Optional[Dict[str, Any]]
    app_findings: Optional[Dict[str, Any]]
    velocity_findings: Optional[Dict[str, Any]]
    
    # Shared Evidence (Cache for tool outputs)
    shared_evidence: Annotated[Dict[str, Any], take_latest]
    
    # --- Risk Assessment & Conclusion ---
    timeline: Annotated[List[str], add]
    final_status: str # "CLEAR", "DENIED", "FRAUD"
    sar_report: str
    evidence_trail: List[str]
