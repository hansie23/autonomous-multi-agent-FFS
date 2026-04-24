from collections import defaultdict
import sqlite3
import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for image generation
import matplotlib.dates as mdates
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from sentence_transformers import SentenceTransformer

# --- Forensic SQL Tool ---
class ForensicSQLTool:
    """Provides a secure interface for executing read-only (DQL) SQL queries."""
    def __init__(self, db_path: str):
        self.db_path = db_path

    def execute_query(self, sql: str) -> str:
        """Executes a read-only (DQL) SQL query."""
        if not sql.strip().upper().startswith("SELECT"):
            return "SQL ERROR: Unauthorized query. Forensic tools only support read-only SELECT statements."

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return json.dumps(rows, indent=2)
        except Exception as e:
            return f"SQL ERROR: {str(e)}"

    def get_schema(self) -> str:
        """Retrieves the database schema (tables and columns) for LLM context."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            schema_info = []
            for table in tables:
                table_name = table[0]
                cursor.execute(f"PRAGMA table_info({table_name});")
                columns = [col[1] for col in cursor.fetchall()]
                schema_info.append(f"Table: {table_name} | Columns: [{', '.join(columns)}]")
            conn.close()
            return "\n".join(schema_info)
        except Exception as e:
            return f"Error retrieving schema: {e}"

# --- Semantic KYC Tool (RAG) ---
class SemanticKYCTool:
    """Performs semantic search against sanctions and adverse media using Instruction-Aware embeddings."""
    def __init__(self, chroma_path: str, model: str):
        import chromadb
        from chromadb.utils import embedding_functions
        self.client = chromadb.PersistentClient(path=chroma_path)
        self.model_name = model # Injected Reasoning Model
        self.llm = ChatOllama(model=self.model_name)
        
        # Industry Standard: Pair Qwen3 Reasoning with Qwen3 Embeddings
        # Using local path for Zero-Box Privacy and architectural consistency
        model_path = "models/qwen3_emb"
        if not os.path.exists(model_path) or not os.listdir(model_path):
            os.makedirs(model_path, exist_ok=True)
            print("Downloading Qwen3-Embedding-0.6B to local storage...")
            temp_model = SentenceTransformer("Qwen/Qwen3-Embedding-0.6B", trust_remote_code=True)
            temp_model.save(model_path)
            print(f"Model saved successfully to {model_path}")
        
        abs_model_path = os.path.abspath(model_path)
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=abs_model_path, # Use local path instead of HF name
            device="cuda",
            trust_remote_code=True,
            local_files_only=True      # FORCED local-only mode
        )
        
        try:
            self.adverse_col = self.client.get_collection(name="adverse_media", embedding_function=self.emb_fn)
        except:
            self.adverse_col = None

    def query_docs(self, tx_dest: str, customer_name: str) -> Dict[str, Any]:
        """Optimized One-Shot Retrieval: Combines search, evaluation, and summary in one turn."""
        if not self.adverse_col:
            return {"findings": "No database loaded.", "queries_used": [], "total_hits": 0}
        
        # 1. Instruction-Aware Query Formulation (Standard for Qwen3-Embedding)
        task_desc = "Given a search query, retrieve relevant passages that answer the query regarding criminal activity, fraud, or global sanctions."
        raw_query = f"{customer_name} fraud OR sanctions OR money laundering"
        
        # The exact format required for 1-5% accuracy boost
        current_query = f"Instruct: {task_desc}\nQuery: {raw_query}"
        
        print(f"  [RAG] One-Shot Forensic Scan for {customer_name}...")

        # 2. Retrieve top 3 chunks (wider net, single pull)
        res = self.adverse_col.query(query_texts=[current_query], n_results=3)
        
        if not res['documents'] or not res['documents'][0]:
            return {"findings": "No relevant adverse media found.", "queries_used": [current_query], "total_hits": 0}
            
        combined_text = "\n---\n".join(res['documents'][0])

        # 3. Combined Evaluation & Summary (Reduces LLM turns from 3 to 1)
        summary_instruction = f"""
        You are a Forensic Investigator.
        
        DATA SCRAPS:
        {combined_text}
        
        TASK:
        1. Evaluate if any of these scraps refer to '{customer_name}' committing crimes, fraud, or facing sanctions. 
        2. If YES, provide a 2-sentence summary of the risk.
        3. If NO or irrelevant, state 'No relevant findings.'
        
        Respond concisely.
        """
        
        try:
            # Industry Standard: Nesting parameters in 'options' for Ollama compatibility
            resp = self.llm.bind(
                options={
                    "temperature": 0.1, 
                    "num_predict": 150,
                    "stop": ["\n\n"]
                }
            ).invoke(summary_instruction)
            summary = resp.content.strip()
        except Exception:
            summary = "Search completed, analysis failed."

        return {"findings": summary, "queries_used": [current_query], "total_hits": len(res['documents'][0])}

# --- Multi-Hop Relational Tool (GraphRAG) ---
class MultiHopRelationalTool:
    """Performs multi-step 'Virtual Graph' traversal between SQL and Vector DBs."""
    def __init__(self, sql_tool: ForensicSQLTool, kyc_tool: SemanticKYCTool):
        self.sql_tool = sql_tool
        self.kyc_tool = kyc_tool

    def investigate_counterparty(self, destination_account: str) -> Dict[str, Any]:
        """
        Traverses the graph:
        1. SQL: Find owner of the destination account.
        2. Vector: Check if that owner has adverse media hits.
        3. Fallback: If not in SQL (External), search Vector DB for the account number directly.
        """
        print(f"  [GraphRAG] Investigating Counterparty: {destination_account}...")
        
        # Hop 1: SQL Lookup (Internal Check)
        query = f"SELECT full_name, residency_country FROM customers WHERE account_number = '{destination_account}'"
        res = json.loads(self.sql_tool.execute_query(query))
        
        if res:
            owner_name = res[0]['full_name']
            country = res[0]['residency_country']
            print(f"  [GraphRAG] Resolved Internal Owner: {owner_name} ({country})")
            
            # Hop 2: Vector Lookup (By Name)
            kyc_hits = self.kyc_tool.query_docs(tx_dest=country, customer_name=owner_name)
            
            # Industry Standard: Only flag as HIT if the LLM summary is NOT the 'No findings' fallback
            is_hit = kyc_hits['total_hits'] > 0 and "No relevant findings" not in kyc_hits['findings']
            
            return {
                "status": "HIT" if is_hit else "CLEAR",
                "counterparty_type": "INTERNAL",
                "counterparty_name": owner_name,
                "findings": kyc_hits['findings'],
                "total_hits": kyc_hits['total_hits']
            }
        else:
            # EXTERNAL BRANCH: Search Vector DB for the account number directly
            print(f"  [GraphRAG] Account {destination_account} is EXTERNAL. Searching RAG for ID blacklists...")
            kyc_hits = self.kyc_tool.query_docs(tx_dest="Global/External", customer_name=destination_account)
            
            is_hit = kyc_hits['total_hits'] > 0 and "No relevant findings" not in kyc_hits['findings']

            return {
                "status": "HIT" if is_hit else "CLEAR",
                "counterparty_type": "EXTERNAL",
                "counterparty_name": destination_account,
                "findings": kyc_hits['findings'],
                "total_hits": kyc_hits['total_hits']
            }

# --- Streaming Intelligence Tool (RAG 2.0 Memory) ---
class StreamingIntelligenceTool:
    """RAG 2.0: Enables real-time 'Streaming' updates to the knowledge base."""
    def __init__(self, kyc_tool: SemanticKYCTool):
        self.kyc_tool = kyc_tool # Uses the existing Chroma connection

    def ingest_new_finding(self, content: str, source_agent: str, metadata: dict = None) -> str:
        """Adds a live forensic finding to the Vector DB instantly."""
        if not self.kyc_tool.adverse_col:
            return "Error: Vector DB not connected."

        # 1. Create a unique ID for the finding
        finding_id = f"LIVE_{uuid.uuid4().hex[:8]}"
        
        # 2. Enrich metadata for traceability
        doc_metadata = {
            "source": f"Agent_{source_agent}",
            "timestamp": datetime.now().isoformat(),
            "type": "LIVE_INTELLIGENCE"
        }
        if metadata: doc_metadata.update(metadata)

        # 3. STREAM to ChromaDB (Incremental Upsert)
        print(f"  [StreamingRAG] Ingesting live intelligence from {source_agent} into Vector DB...")
        self.kyc_tool.adverse_col.add(
            documents=[content],
            metadatas=[doc_metadata],
            ids=[finding_id]
        )
        
        return f"Success: Intelligence {finding_id} is now searchable."

# --- Identity Vision Tool (Biometrics) ---
class IdentityVisionTool:
    """Performs visual forensic comparison for deepfakes."""
    def __init__(self, model: str):
        self.model_name = model # Injected Vision Model
        self.llm = ChatOllama(model=self.model_name)
        self.vault_path = "organization_vault/biometric_data/biometric_iam_vault.json"
        self.reference_base_path = "organization_vault/biometric_data/profile_imgs"
        self.selfie_base_path = "system/bio_evidence"

    def resolve_biometric_paths(self, customer_id: str) -> tuple:
        try:
            with open(self.vault_path, 'r') as f: vault = json.load(f)
            if customer_id not in vault: return None, None
            ref_path = os.path.join(self.reference_base_path, os.path.basename(vault[customer_id]['reference_id_path']))
            selfie_path = None
            customer_dir = os.path.join(self.selfie_base_path, customer_id)
            if os.path.exists(customer_dir):
                files = [f for f in os.listdir(customer_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
                if files: selfie_path = os.path.join(customer_dir, files[0])
            return ref_path, selfie_path
        except: return None, None

    def compare_faces(self, reference_path: str, selfie_path: str) -> Dict[str, Any]:
        if not selfie_path or not os.path.exists(reference_path) or not os.path.exists(selfie_path):
            return {"status": "PENDING", "reasoning": "Files missing."}
        
        instruction = """
        You are a Senior Forensic Biometric Analyst. 
        Compare the Registered ID (Image 1) with the Live Selfie holding an ID (Image 2). 
        
        TASK:
        1. Verify FACIAL CONSISTENCY between the two images.
        2. Check for DEEPFAKES or GAN artifacts in the Live Selfie.
        3. EXTRACT the text from the ID held in the Live Selfie:
           - full_name
           - date_of_birth
           - address
        4. If the ID held in the selfie contains an image of a person then compare that image too with the registered ID for consistency.
           
        Respond in RAW JSON: 
        {
            "status": "PASS/FAIL", 
            "reasoning": "...", 
            "artifact_detected": true/false, 
            "confidence_score": 0.0-1.0,
            "extracted_data": {
                "full_name": "...",
                "date_of_birth": "...",
                "address": "..."
            }
        }
        """
        try:
            from langchain_core.messages import HumanMessage
            import base64
            import re

            def encode_image(path):
                with open(path, "rb") as image_file:
                    return base64.b64encode(image_file.read()).decode('utf-8')

            ref_b64 = encode_image(reference_path)
            selfie_b64 = encode_image(selfie_path)

            message = HumanMessage(
                content=[
                    {"type": "text", "text": instruction},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{ref_b64}"}},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{selfie_b64}"}},
                ]
            )
            
            resp = self.llm.bind(
                options={
                    "temperature": 0.1, 
                    "num_predict": 300
                }
            ).invoke([message])
            
            content = resp.content.strip()
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return json.loads(content)
        except: return {"status": "UNKNOWN", "reasoning": "Vision comparison error"}

    def analyze_document_authenticity(self, image_path: str) -> Dict[str, Any]:
        if not image_path or not os.path.exists(image_path): return {"status": "PENDING", "reasoning": "File missing."}
        
        instruction = """
        You are a Senior Forensic Document Analyst. 
        Scan this registered ID image for GAN artifacts, deepfakes, or digital tampering (e.g., skin-smoothing, font misalignments).
        
        Respond in RAW JSON: 
        {
            "status": "PASS/FAIL", 
            "reasoning": "...", 
            "artifact_detected": true/false, 
            "confidence_score": 0.0-1.0
        }
        """
        try:
            import base64
            import re
            with open(image_path, "rb") as image_file:
                img_b64 = base64.b64encode(image_file.read()).decode('utf-8')

            message = HumanMessage(
                content=[
                    {"type": "text", "text": instruction},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"}},
                ]
            )
            
            resp = self.llm.bind(
                options={
                    "temperature": 0.1, 
                    "num_predict": 150
                }
            ).invoke([message])
            
            content = resp.content.strip()
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return json.loads(content)
        except: return {"status": "UNKNOWN", "reasoning": "Document analysis error"}

# --- Behavioral Heatmap Tool ---
class BehavioralHeatmapTool:
    """Generates and analyzes behavioral velocity heatmaps."""
    def __init__(self, output_dir: str, db_path: str, model: str):
        self.output_dir = output_dir
        self.db_path = db_path
        self.model_name = model # Injected Vision Model
        self.llm = ChatOllama(model=self.model_name)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, customer_id: str, history: List[Dict[str, Any]]) -> str:
        print(f"  [DEBUG] Generating heatmap for {customer_id} with {len(history)} items.")
        # Standardize size to 448x448 (Native Qwen3-VL resolution) for 2x speedup
        fig = Figure(figsize=(4.48, 4.48), dpi=100)
        ax = fig.add_subplot(111)
        if not history: ax.text(0.5, 0.5, "NO_DATA", ha='center', va='center')
        else:
            dates = [datetime.fromisoformat(tx['timestamp']) for tx in history]
            amounts = [tx['amount'] for tx in history]
            ax.plot(dates, amounts, color='black', linewidth=2)
        ax.set_title(f"Last 10 transactions: {customer_id}")
        ax.tick_params(axis='x', rotation=45)
        fig.tight_layout()
        filename = os.path.join(self.output_dir, f"{customer_id}_velocity.png")
        print(f"  [DEBUG] Attempting to save heatmap to: {filename}")
        fig.savefig(filename)
        print(f"  [DEBUG] Heatmap saved successfully: {os.path.exists(filename)}")
        return filename

    def analyze_visual_pattern(self, heatmap_path: str) -> Dict[str, Any]:
        instruction = "Analyze behavioral heatmap for anomalies: SAWTOOTH (testing), SPIKE (cash-out), DENSITY_SHIFT. Respond in RAW JSON: {'visual_anomaly_detected': true/false, 'pattern_type': 'SAWTOOTH/SPIKE/DENSITY_SHIFT/NORMAL', 'reasoning': '...', 'confidence_score': 0.0-1.0}"
        try:
            import base64
            import re
            with open(heatmap_path, "rb") as image_file:
                img_b64 = base64.b64encode(image_file.read()).decode('utf-8')

            message = HumanMessage(
                content=[
                    {"type": "text", "text": instruction},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"}},
                ]
            )
            
            resp = self.llm.bind(
                options={
                    "temperature": 0.1, 
                    "num_predict": 150
                }
            ).invoke([message])
            
            content = resp.content.strip()
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return json.loads(content)
        except: return {"visual_anomaly_detected": False, "pattern_type": "ERROR", "confidence": 0.0}
