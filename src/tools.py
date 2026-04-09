import sqlite3
import json
import os
import ollama
from datetime import datetime
from typing import List, Dict, Any, Optional

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for image generation
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.figure import Figure

# --- Forensic SQL Tool ---
class ForensicSQLTool:
    """
    DOCSTRING:
    ForensicSQLTool provides a secure interface for executing read-only (DQL) SQL queries against the transactions database

    USAGE:
    sql_tool = ForensicSQLTool(db_path="path_to_transactions.db")

    OUTPUT:
    The execute_query method returns a JSON string of the query results, which can be parsed into Python data structures for further analysis by the agents.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path

    def execute_query(self, sql: str) -> str:
        """
        DOCSTRING:
        Executes a read-only (DQL) SQL query against the transactions database and returns results as a JSON string.
        
        USAGE:
        sql_tool = ForensicSQLTool(db_path="path_to_transactions.db")
        result_json = sql_tool.execute_query("SELECT * FROM transactions WHERE customer_id = '123")

        OUTPUT:
        A JSON string representing a list of rows, where each row is a dictionary of column names
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # print(f"  [SQL Tool] Executing query:\n{sql}")
            cursor.execute(sql)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return json.dumps(rows, indent=2)
        except Exception as e:
            return f"SQL ERROR: {str(e)}"

# --- Semantic KYC Tool (RAG) ---
class SemanticKYCTool:
    """
    DOCSTRING:
    Generates dynamic queries based on transaction and customer context, then performs semantic search against sanctions and adverse media collections. Returns a risk level and specific findings.

    USAGE:
    kyc_tool = SemanticKYCTool(chroma_path="path_to_chroma_db")

    METHODS:
    query_docs(tx: dict, customer: dict) -> Dict[str, Any]
        - tx: The transaction data that triggered the investigation
        - customer: The customer data associated with the transaction

    OUTPUT:
    A dictionary containing:
        risk_level: str
        findings: string list of specific hits from the sanctions and adverse media collections
        queries_used: list of the dynamic search queries that were generated and executed
    """
    def __init__(self, chroma_path: str, model: str = "qwen3:4b-instruct"):
        import chromadb
        from chromadb.utils import embedding_functions
        self.client = chromadb.PersistentClient(path=chroma_path)
        self.model = model
        
        # Initialize local BGE embedding function
        local_emb_path = os.path.abspath("local_bge_model")
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=local_emb_path,
            device="cpu",
            local_files_only=True
        )
        
        # Load collections
        try:
            self.sanctions_col = self.client.get_collection(name="regulatory_sanctions", embedding_function=self.emb_fn)
            self.adverse_col = self.client.get_collection(name="adverse_media", embedding_function=self.emb_fn)
        except:
            self.sanctions_col = None
            self.adverse_col = None

    def query_docs(self, tx: dict, customer: dict) -> Dict[str, Any]:
        """Generates dynamic queries and scans vector collections for sanctions/risk."""
        if not self.sanctions_col:
            return {"risk_level": "UNKNOWN", "findings": "Collections not initialized."}

        # 1. Generate dynamic search terms
        prompt = f"Identify 3-5 specific search terms for sanctions/fraud scans for customer {customer.get('full_name')} in {tx.get('destination_jurisdiction')}. Return as JSON list."
        try:
            # print(f"  [Semantic KYC] Generating search terms for {customer.get('customer_id')}...")
            resp = ollama.chat(model=self.model, messages=[{'role': 'user', 'content': prompt}], format='json')
            queries = json.loads(resp['message']['content'])
        except:
            queries = [customer.get('full_name'), tx.get('destination_jurisdiction')]

        # print(f"  [Semantic KYC] Generated queries: {queries}")

        # 2. Scan Collections
        findings = []
        for q in queries:
            # print(f"  [Semantic KYC] Scanning for {q}...")
            s_res = self.sanctions_col.query(query_texts=[q], n_results=1)
            a_res = self.adverse_col.query(query_texts=[q], n_results=1)
 
            if s_res['distances'][0] and s_res['distances'][0][0] < 1.1:
                findings.append(f"Sanctions Hit: {s_res['documents'][0][0]}")
            if a_res['distances'][0] and a_res['distances'][0][0] < 1.1:
                findings.append(f"Adverse Media: {a_res['documents'][0][0]}")

        return {
            "risk_level": "HIGH" if findings else "LOW",
            "findings": findings,
            "queries_used": queries
        }

# --- Identity Vision Tool (Biometrics) ---
class IdentityVisionTool:
    def __init__(self, model: str = "gemma4:e2b-it-q4_K_M"):
        self.model = model
        self.vault_path = "organization_vault/biometric_data/biometric_iam_vault.json"
        self.reference_base_path = "organization_vault/biometric_data/profile_imgs"
        self.selfie_base_path = "system/bio_evidence"

    def resolve_biometric_paths(self, customer_id: str) -> tuple:
        """Helper to resolve reference and selfie paths for a given customer."""
        try:
            if not os.path.exists(self.vault_path):
                print(f"  [Biometric Tool] Vault not found at {self.vault_path}.")
                return None, None
                
            with open(self.vault_path, 'r') as f:
                vault = json.load(f)
            
            if customer_id not in vault:
                print(f"  [Biometric Tool] Customer ID {customer_id} not found in vault.")
                return None, None
            
            ref_filename = os.path.basename(vault[customer_id]['reference_id_path'])
            reference_path = os.path.join(self.reference_base_path, ref_filename)
            
            # Search for selfie in bio_evidence/{customer_id}
            selfie_path = None
            customer_selfie_dir = os.path.join(self.selfie_base_path, customer_id)
            if os.path.exists(customer_selfie_dir):
                files = [f for f in os.listdir(customer_selfie_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
                if files:
                    selfie_path = os.path.join(customer_selfie_dir, files[0])

            # print(f"  [Biometric Tool] Reference path: {reference_path}.")
            # print(f"  [Biometric Tool] Selfie path: {selfie_path}.")
            
            return reference_path, selfie_path
        except Exception as e:
            print(f"  [!] Biometric Path Resolution Error: {e}")
            return None, None

    def compare_faces(self, reference_path: str, selfie_path: str) -> Dict[str, Any]:
        """Performs visual forensic comparison for deepfakes and facial consistency."""
        if not os.path.exists(reference_path) or not os.path.exists(selfie_path):
            return {
                "status": "FAIL", 
                "reasoning": f"Files missing. Reference: {os.path.exists(reference_path)}, Selfie: {os.path.exists(selfie_path)}",
                "confidence": 0.0
            }
        
        system_instruction = """
        You are a Senior Forensic Biometric Analyst. Compare the 'Bank ID' (Image 1) with the customer provided 'Live Selfie' (Image 2) to: 
        Analyze for:
        1. DEEPFAKE: GAN artifacts, unnatural skin/hair blending, double edges.
        2. PRESENTATION ATTACK: Screen moiré patterns, glare from a flat monitor, phone borders.
        3. FACIAL CONSISTENCY: Structural bone distance, ear shape, nose bridge.
        
        SKEPTICISM: 
        1. If digital manipulation or screen re-photography is detected, FAIL the comparison.
        2. If the customer provided 'Live Selfie' is visually a 1:1 replica of the 'Bank ID' with no natural variation, FAIL for potential deepfake.

        Your response MUST be in RAW JSON format:
        {
            "status": "PASS" or "FAIL",
            "reasoning": "Specific forensic detail on artifacts or matches",
            "artifact_detected": true/false,
            "confidence_score": 0.0-1.0
        }
        """

        try:
            # print(f"  [Biometric Tool] Performing forensic visual comparison...")
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system', 
                    'content': system_instruction
                }, {
                    'role': 'user', 
                    # 'content': "Perform forensic comparison between Image 1 (Reference) and Image 2 (Selfie).",
                    'images': [reference_path, selfie_path]
                }],
                format='json',
                # options={
                #     "temperature": 1.0,
                #     "top_p": 0.95,
                #     "top_k": 64
                # }
            )

            response = json.loads(response['message']['content'])

            # print(f"  [Biometric Tool] Status: {response.get('status', 'UNKNOWN')}.")
            # print(f"  [Biometric Tool] Reasoning: {response.get('reasoning', '')}")
            # print(f"  [Biometric Tool] Confidence: {response.get('confidence_score', 0.0)}")


            return response
        except Exception as e:
            return {"status": "FAIL", "reasoning": f"Vision error: {e}", "confidence": 0.0}

    def analyze_document_authenticity(self, image_path: str) -> Dict[str, Any]:
        """Analyzes a single document image for GAN artifacts, deepfakes, or tampering."""
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "FAIL", 
                "reasoning": "Document image missing.", 
                "artifact_detected": False,
                "confidence_score": 0.0
            }
        
        system_instruction = """
        You are a Senior Forensic Document Analyst. Analyze the provided 'Bank ID' for signs of synthetic creation or digital tampering.
        Analyze for:
        1. GAN ARTIFACTS: Check for 'melting' textures, unnatural symmetry in hair/eyes, or background warping.
        2. COMPOSITING: Look for 'pixel halos' around the subject, lighting mismatches, or unnatural blending.
        3. DATA TAMPERING: Inconsistent font weights, misaligned text fields, or digital 'stamps' that don't match the card's physical plane.
        
        SKEPTICISM: If you detect even subtle signs of AI generation (GAN) or photoshop manipulation, mark artifact_detected as true.
        Your response MUST be in RAW JSON format:
        {
            "status": "PASS" or "FAIL",
            "reasoning": "Specific forensic detail on detected artifacts or authenticity markers",
            "artifact_detected": true,
            "confidence_score": 0.95
        }
        """

        try:
            # print(f"  [Biometric Tool] Performing independent document authenticity scan...")
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system', 
                    'content': system_instruction
                }, {
                    'role': 'user', 
                    'content': "Analyze this document for GAN artifacts and authenticity.",
                    'images': [image_path]
                }],
                format='json'
            )

            parsed_response = json.loads(response['message']['content'])
            # print(f"  [Biometric Tool] Auth Scan Status: {parsed_response.get('status', 'UNKNOWN')}.")
            return parsed_response
        except Exception as e:
            return {
                "status": "FAIL", 
                "reasoning": f"Document Vision error: {e}", 
                "artifact_detected": False,
                "confidence_score": 0.0
            }

# --- Regulatory Scanner Tool ---
class RegulatoryTool:
    """Parses markdown-based sanctions lists using a structural state-machine."""
    def __init__(self, sanctions_path: str):
        self.sanctions_path = sanctions_path
        self._cache = self._load_and_parse()

    def _load_and_parse(self) -> Dict[str, List[str]]:
        lists = {"blacklist": [], "greylist": [], "mule_accounts": []}
        if not os.path.exists(self.sanctions_path):
            return lists

        current_section = None
        try:
            print(f"  [Regulatory Tool] Parsing sanctions list...")
            with open(self.sanctions_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    # Section Headers
                    if "## 1. Prohibited" in line: current_section = "blacklist"
                    elif "## 2. Monitored" in line: current_section = "greylist"
                    elif "## 3. High-Risk Account" in line: current_section = "mule_accounts"
                    elif line.startswith("##"): current_section = None # Reset on other headers

                    # List Extraction
                    if line.startswith("*") and current_section:
                        # Extract content between **...**
                        if "**" in line:
                            item = line.split("**")[1]
                            lists[current_section].append(item)
        except Exception as e:
            print(f"  [!] RegulatoryTool Parsing Error: {e}")
        
        return lists

    def get_high_risk_lists(self) -> Dict[str, List[str]]:
        """Returns the cached structured data for fast look-ups."""
        return self._cache

# --- Behavioral Heatmap Tool ---
class BehavioralHeatmapTool:
    def __init__(self, output_dir: str, db_path: str):
        self.output_dir = output_dir
        self.db_path = db_path
        os.makedirs(self.output_dir, exist_ok=True)

    # def generate(self, customer_id: str, history: List[Dict[str, Any]]) -> str:
    #     dpi = 100
    #     fig, ax = plt.subplots(figsize=(4.48, 4.48), dpi=dpi)
        
    #     if not history:
    #         ax.text(0.5, 0.5, "NO_DATA", ha='center', va='center')
    #     else:
    #         sorted_history = sorted(history, key=lambda x: x['timestamp'])
    #         dates = [datetime.fromisoformat(tx['timestamp']) for tx in sorted_history]
    #         amounts = [tx['amount'] for tx in sorted_history]
    #         ax.plot(dates, amounts, color='black', linewidth=3)

    #     ax.set_title(f"Velocity: {customer_id}")
    #     filename = os.path.join(self.output_dir, f"{customer_id}_velocity.png")
    #     plt.savefig(filename)
    #     plt.close()
    #     return filename
    
    def generate(self, customer_id: str, history: List[Dict[str, Any]]) -> str:
        """Generates a velocity chart using the thread-safe OO API."""
        # Use Figure directly instead of plt.subplots() to avoid thread collisions
        # print(f"  [Heatmap Tool] Generating behavioral heatmap for {customer_id}...")
        fig = Figure(figsize=(4.48, 4.48), dpi=100)
        ax = fig.add_subplot(111)
        
        if not history:
            ax.text(0.5, 0.5, "NO_DATA", ha='center', va='center')
        else:
            sorted_history = sorted(history, key=lambda x: x['timestamp'])
            dates = [datetime.fromisoformat(tx['timestamp']) for tx in sorted_history]
            amounts = [tx['amount'] for tx in sorted_history]
            ax.plot(dates, amounts, color='black', linewidth=3)
            
        ax.set_title(f"Velocity: {customer_id}")
        
        filename = os.path.join(self.output_dir, f"{customer_id}_velocity.png")
        fig.savefig(filename)
        
        return filename 
