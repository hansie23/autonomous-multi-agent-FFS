import os
import shutil
import chromadb
from sentence_transformers import SentenceTransformer
from chromadb.utils import embedding_functions
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

ADVERSE_DIR = "organization_vault/regulatory/Adverse media/"
CHROMA_DB_PATH = "system/chroma_db"
EMB_MODEL_PATH = "models/qwen3_emb"

def setup_rag(db_path=CHROMA_DB_PATH, source_dir=ADVERSE_DIR):
    # 1. Load and Split Documents
    loader = DirectoryLoader(source_dir, glob="**/*.md", loader_cls=TextLoader)
    documents = loader.load()
    print(f"Loaded {len(documents)} documents from {source_dir}")

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000, 
        chunk_overlap=100,
        separators=["##", "\n\n", "\n", " "]
    )
    chunks = text_splitter.split_documents(documents)
    print(f"Created {len(chunks)} chunks.")

    # 2. Local Embedding Setup (Zero-Box Privacy)
    os.makedirs(EMB_MODEL_PATH, exist_ok=True)
    if not os.listdir(EMB_MODEL_PATH):
        print("Downloading Qwen3-Embedding-0.6B to local storage...")
        model = SentenceTransformer("Qwen/Qwen3-Embedding-0.6B", trust_remote_code=True)
        model.save(EMB_MODEL_PATH)
        print(f"Model saved successfully to {EMB_MODEL_PATH}")
    
    # Absolute path required for local_files_only mode
    abs_model_path = os.path.abspath(EMB_MODEL_PATH)
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=abs_model_path,
        device="cuda",
        trust_remote_code=True,
        local_files_only=True
    )
    print("Embeddings ready (Local-Only).")

    # 3. Database Reset
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
        print(f"Deleted existing ChromaDB at {db_path}.")

    # 4. Native Chroma Indexing (MATCHES src/tools.py)
    client = chromadb.PersistentClient(path=db_path)
    collection = client.create_collection(
        name="adverse_media", 
        embedding_function=emb_fn
    )

    # Prepare data for native ingestion
    ids = [f"chunk_{i}" for i in range(len(chunks))]
    texts = [c.page_content for c in chunks]
    metadatas = [c.metadata for c in chunks]
    
    # Ingest in batches to optimize memory
    batch_size = 100
    for i in range(0, len(texts), batch_size):
        collection.add(
            ids=ids[i:i+batch_size],
            documents=texts[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size]
        )

    print(f"Successfully indexed {len(texts)} chunks into native ChromaDB.")

if __name__ == "__main__":
    setup_rag()
