Cortex-Chain: AI-Powered SOC Automation and Compliance
An automated pipeline for smart threat analysis and tamper-resistant log archiving

Cortex-Chain: A security automation framework for turning raw SIEM alerts into useful, actionable intelligence. The framework uses a mix of local LLMs (Llama 3), cloud storage (AWS S3), and cryptographic ledgers (SHA-256) to solve the problems of alert fatigue and log tampering.

Key Features
- Intelligent Triage: Uses a local Llama 3 instance to analyze Windows Event Logs (ID: 4625) in real time, providing instant risk scores and incident response recommendations.
- Immutable Audit Trail: Uses SHA-256 hashing to generate a digital fingerprint for every log analysis, ensuring non-repudiation and integrity for legal or compliance audits.
- Hybrid Cloud Archiving: Automatically exports “Compliance Packages” (Raw Log + AI Verdict + Hash) to AWS S3 for long-term, cost-effective log retention.
- Privacy-First Design: Only runs on the local network using Ollama, ensuring security-sensitive information never leaves the organization to query public AI APIs.

Architecture
Modular ‘Detection-to-Ledger’ workflow:

- Ingestion: Splunk Enterprise identifies the brute force activity and initiates the webhook.
- Analysis: FastAPI receives the payload and directs it to the Llama 3 engine for processing.
- Hashing: The incident is given a unique hash to serve as the “seed” for the blockchain-based “chain of trust.”
- Archiving: The compiled package is then uploaded to AWS S3 using the Boto3 SDK.

**Tech Stack**
- **AI Engine**: Llama 3 via Ollama
- **Cloud Infrastructure**: AWS S3 and IAM
- **SIEM Integration**: Splunk Enterprise
- **Backend**: Python 3.11 and FastAPI
- **Cryptography**: SHA-256 Hashing

**Installation & Setup**
- Clone the repository:
  - `git clone https://github.com/Arjun7114/Cortex-Chain.git`
  - `cd Cortex-Chain`
- Install the required packages:
  - `pip install -r requirements.txt`
- Configure AWS:
  - Install and set up the AWS CLI with `aws configure`
- Start the FastAPI:
  - `python -m uvicorn cortex_api:app --reload`

**Business Benefits**
- **Reduced MTTR**: Automates the initial L1 analyst triage, reducing Mean Time to Respond.
- **Audit Readiness**: Provides a mathematical proof of log integrity, ensuring alignment with ISO 27001 and SOC2 regulations.
- Cost Optimization: Leverages AWS S3 for storage, significantly reducing SIEM data retention costs.
