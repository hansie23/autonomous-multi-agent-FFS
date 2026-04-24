# Forensic Agent Playbooks: Sharpened Boundaries

This document outlines the specialized roles and ownership of forensic domains within the multi-agent system. Each agent acts as a domain expert, building upon the findings of others via the shared "Full Case File" (Investigation Log).

## 1. Velocity Agent (The Behavioral & Visual Engine)
*   **Primary Owner:** Statistical Volatility (IQR) and Visual Spend Signatures.
*   **Core Checks:** 
    *   **IQR Math:** Detects statistical outliers in transaction magnitude.
    *   **Temporal Bursts:** Monitors transaction frequency (6h window).
    *   **Visual Heatmaps:** Sole agent responsible for generating and analyzing behavioral heatmaps via VLM.
*   **Peer Context:** Interprets mathematical spikes in the context of security or identity red flags found by others.

## 2. AML Agent (The Reputation Bureau)
*   **Primary Owner:** Global Reputation Intelligence and Money Laundering patterns.
*   **Core Checks:**
    *   **Reputation RAG:** Sole owner of Semantic search against global sanctions and adverse media.
    *   **Distilled Intelligence:** Performs LLM-driven summarization of RAG hits to protect context window limits.
    *   **Structuring & Layering:** Detects smurfing patterns (last 30 days) and rapid fund movement (last 24h).
*   **Peer Context:** Correlates sanctions hits with persona authenticity (SyntheticID) or account access (ATO).

## 3. Synthetic ID Agent (The Identity Bureau)
*   **Primary Owner:** Persona Authenticity and ID Document Verification.
*   **Core Checks:**
    *   **Document Forensic Vision:** Sole owner of the scan for GAN artifacts, deepfakes, and digital tampering in Bank ID images.
    *   **Footprint Depth:** Analyzes account age (<90 days) and historical depth (<5 transactions).
*   **Peer Context:** Decides if a "Clear" reputational record (from AML) is actually a "New Persona" created by a fraud ring.

## 4. ATO Agent (The Security Agent)
*   **Primary Owner:** Account Takeover and unauthorized access detection.
*   **Core Checks:**
    *   **Access Forensics:** Monitors IP shifts and Device ID fingerprinting.
    *   **Biometric Step-up:** Triggers and analyzes forensic face-comparisons (Selfie vs ID).
*   **Peer Context:** Checks if statistical spikes (from Velocity) correlate with unauthorized access.

## 5. CNPAgent (The Merchant Agent)
*   **Primary Owner:** E-commerce fraud, Merchant risk, and Card Probing.
*   **Core Checks:**
    *   **BIN Attack Detection:** Detects high-frequency probing at merchants (1h window).
    *   **Geo-Velocity:** Identifies "Impossible Travel" based on IP location history.
*   **Peer Context:** Analyzes merchant category risk in the context of the customer's broader reputation (from AML).

## 6. APPAgent (The Network Agent)
*   **Primary Owner:** Destination Account forensics and Social Engineering.
*   **Core Checks:**
    *   **FTR Analysis:** Identifies First-Time Recipients.
    *   **Mule Detection:** Monitors destination accounts for "Inbound Diversity" (multiple unrelated senders).
*   **Peer Context:** Correlates suspicious outbound flows with "Account Takeover" flags to identify victim-based scams.

---

### Key Operational Rules:
1.  **Non-Redundancy:** Visual analysis (Heatmaps) is delegated to **Velocity**; Reputational analysis (RAG) is delegated to **AML**. All other agents consult their findings.
2.  **Full Case File Context:** Every agent LLM is provided the *entire* investigation log. They are expected to cross-reference peer findings to refine their own "Hunch" SQL queries.
3.  **Dynamic Discovery:** Every agent discovers the database schema at runtime to ensure SQL query accuracy.
