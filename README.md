# Autonomous Finance Forensics Agent

[![Agentic Workflow](https://img.shields.io/badge/Orchestration-LangGraph-blue)](https://github.com/langchain-ai/langgraph)
[![Local AI](https://img.shields.io/badge/Local--AI-Ollama-orange)](https://ollama.com/)
[![Streaming](https://img.shields.io/badge/Streaming-Aiven--Kafka-red)](https://aiven.io/kafka)

An industrial-grade, multi-agent system designed for **Real-Time Forensic Streaming** and automated Root Cause Analysis (RCA) of financial crimes. By transitioning from batch processing to agentic orchestration, this system detects and investigates fraud in sub-20 seconds.

## 🚀 Key Features

*   **Real-Time Streaming:** Integrated with **Aiven Kafka** for high-throughput transaction ingestion.
*   **Multi-Agent Orchestration:** Powered by **LangGraph**, featuring a **Supervisor Node** that triages cases to specialized experts.
*   **Local-First AI:** Privacy-centric architecture executing **multimodal LLMs (Qwen3-VL)** locally via **Ollama**.
*   **Multimodal Forensics:** Specialized agents for **Biometric Identity Verification**, **Behavioral Heatmap Analysis**, and **Multi-Hop GraphRAG**.
*   **Automated SAR Generation:** Synthesizes complex investigation logs into professional **Suspicious Activity Reports (SARs)**.
*   **Observability:** Full tracing of every agent "hunch" and tool call via **LangSmith**.

## 🏗 System Architecture

The system operates across four distinct layers:
1.  **Ingestion:** Real-time data streaming via Aiven Kafka.
2.  **Orchestration:** State-driven agent workflows managed by LangGraph.
3.  **Intelligence:** Local LLM execution (Reasoning & Vision) via Ollama.
4.  **Observability:** Global tracing and performance monitoring via LangSmith.

## 👥 The Expert Agents

| Agent | Focus Area |
| :--- | :--- |
| **Supervisor** | The Triage Brain; dynamically routes cases and reflects on findings. |
| **AML Expert** | Investigates Sanctions and Adverse Media using Multi-hop GraphRAG. |
| **ATO Expert** | Detects Account Takeover via IP/Device shifts and Biometric Face Comparison. |
| **Synthetic ID** | Scans for Deepfakes and identity record mismatches using Multimodal Vision. |
| **Velocity** | Analyzes statistical IQR spikes and visual spend "signatures." |
| **CNP Expert** | Identifies Card Not Present (CNP) fraud and BIN attacks. |
| **APP Expert** | Profiles destination account risk and detects money mule activity. |

## 🛠 Advanced Toolset

*   **Forensic SQL Tool:** Secure, read-only access to the core banking ledger.
*   **Semantic KYC (Self-RAG):** Autonomous RAG loop that evaluates media hits in ChromaDB.
*   **Identity Vision:** Forensic ID scan for GAN artifacts and digital tampering.
*   **Behavioral Heatmap Tool:** Generates thread-safe transaction volatility visualizations.
*   **Streaming Intelligence:** RAG 2.0 implementation that updates the global vector memory in real-time.

## 🚦 Getting Started

### Prerequisites
*   **Ollama:** Installed and running.
    *   `ollama pull qwen3-vl:2b-instruct` (or your preferred reasoning/vision model)
*   **Python 3.10+**
*   **Kafka:** Aiven Kafka service (with `ca.pem`, `service.cert`, and `service.key` in the root).

### Installation
1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Configure your `.env` file (see `.env.example`).

### Data Initialization
Run the data factory scripts to set up your local forensics environment:
```bash
python 1_transaction_generator.py  # Generates SQLite ledger
python 2_generate_adverse_media.py # Generates adverse media documents
python 3_setup_rag.py              # Indexes documents into ChromaDB
```

### Running the App
**Option 1: Simulation (Single Case)**
```bash
python src/main.py
```

**Option 2: Real-Time Streaming (Kafka)**
```bash
# In one terminal, start the producer
python streaming_producer.py

# In another terminal, start the forensic consumer
python streaming_consumer.py
```

## 🔒 Security & Privacy
*   **Zero-Box Privacy:** No PII or transaction data ever leaves your local environment.
*   **SSL/TLS:** All Kafka traffic is encrypted.
*   **Read-Only:** Forensic tools are restricted to `SELECT` operations to prevent ledger tampering.

## 📊 Observability
This project uses **LangSmith** for deep trace analysis. You can view the internal "thought process" of each agent, including tool calls and internal monologues, by providing your `LANGCHAIN_API_KEY` in the `.env` file.

---
*Developed as a high-performance demonstration of Agentic Workflows in FinTech.*
