import hashlib
import json

class PrivacyProxy:
    """Anonymizes PII before sending it to the LLM for reasoning."""
    
    def __init__(self):
        # Maps raw value to anonymized token
        self.pii_map = {}
        # Maps anonymized token back to raw value (stored only locally)
        self.reverse_map = {}
        self.counter = 0

    def _get_hash(self, val: str, prefix: str = "HASH"):
        return f"[{prefix}_{hashlib.sha256(val.encode()).hexdigest()[:8].upper()}]"

    def mask_transaction(self, tx: dict) -> dict:
        """Masks a single transaction dictionary."""
        masked_tx = tx.copy()
        
        # Mask Account Number
        if "account_number" in masked_tx:
            masked_tx["account_number"] = self._get_hash(masked_tx["account_number"], "ACC")
        
        if "destination_account" in masked_tx:
            masked_tx["destination_account"] = self._get_hash(masked_tx["destination_account"], "ACC")
            
        # Keep Location/Amount/IP as is (forensic markers), but anonymize ID if present
        if "customer_id" in masked_tx:
            masked_tx["customer_id"] = self._get_hash(masked_tx["customer_id"], "CUST")
            
        return masked_tx

    def mask_customer(self, cust: dict) -> dict:
        """Masks sensitive customer identity fields."""
        masked_cust = cust.copy()
        
        # Identity PII
        if "full_name" in masked_cust:
            self.pii_map[masked_cust["full_name"]] = "[CUSTOMER_ALPHA]"
            self.reverse_map["[CUSTOMER_ALPHA]"] = masked_cust["full_name"]
            masked_cust["full_name"] = "[CUSTOMER_ALPHA]"
            
        if "ssn_masked" in masked_cust:
            masked_cust["ssn_masked"] = "[SSN_REDACTED]"
            
        if "email" in masked_cust:
            masked_cust["email"] = "[EMAIL_REDACTED]"
            
        if "customer_id" in masked_cust:
            masked_cust["customer_id"] = self._get_hash(masked_cust["customer_id"], "CUST")
            
        return masked_cust

    def prepare_llm_prompt(self, tx: dict, cust: dict, history: list = None, rag_findings: str = None) -> str:
        """Combines masked data into a safe forensic string for the LLM."""
        masked_tx = self.mask_transaction(tx)
        masked_cust = self.mask_customer(cust)

        history_str = ""
        if history:
            masked_history = [self.mask_transaction(h) for h in history[-5:]] # Last 5 only
            history_str = f"\n**Recent Transaction History (Last 5):** {json.dumps(masked_history)}"

        rag_str = ""
        if rag_findings:
            rag_str = f"\n### REGULATORY PRE-SCAN FINDINGS\n{rag_findings}"

        return f"""
    ### ANONYMIZED FORENSIC METADATA
    **Customer Profile:** {json.dumps(masked_cust)}
    **Trigger Transaction:** {json.dumps(masked_tx)}{history_str}{rag_str}
    """

