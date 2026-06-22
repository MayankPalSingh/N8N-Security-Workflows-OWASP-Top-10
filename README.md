<p align="center">
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-red?style=for-the-badge&logo=owasp" alt="OWASP LLM Top 10"/>
  <img src="https://img.shields.io/badge/n8n-Workflows-orange?style=for-the-badge&logo=n8n" alt="n8n Workflows"/>
  <img src="https://img.shields.io/badge/ChromaDB-Vector%20DB-blue?style=for-the-badge" alt="ChromaDB"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"/>
  <img src="https://img.shields.io/github/stars/MayankPalSingh/N8N-Security-Workflows-OWASP-Top-10?style=for-the-badge" alt="Stars"/>
</p>

# 🛡️ N8N Security Workflows - OWASP Top 10 for LLM Applications

> **See it break. Understand why. Learn how to fix it.**

Hands-on n8n workflows that bring the [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) to life with **real attack simulations**, **vulnerable vs. mitigated comparisons**, and **interactive demos** - all built using visual workflow automation.

This isn't just documentation - it's a working security lab. Every vulnerability has a fully functional n8n workflow you can import, execute, and learn from. Attack it, defend it, and understand exactly how LLM security risks manifest in real-world applications.

<!-- Add a screenshot of your n8n canvas here -->
<!-- ![Workflow Overview](screenshots/workflow-overview.png) -->

---

## 📑 Table of Contents

- [Why This Exists](#-why-this-exists)
- [Who Is This For](#-who-is-this-for)
- [What's Inside](#-whats-inside)
- [Learning Outcomes](#-learning-outcomes)
- [Screenshots](#-screenshots)
- [Getting Started](#-getting-started)
- [Repository Structure](#-repository-structure)
- [Roadmap](#-roadmap)
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [License](#-license)
- [Author](#-author)

---

## 💡 Why This Exists

Reading about LLM vulnerabilities is one thing. **Watching an AI agent leak production database credentials, serve poisoned security policies, or expose customer SSNs in real-time** is something else entirely.

This project bridges the gap between theory and practice. Security professionals and AI developers can:

- **See vulnerabilities in action** - not just read about them in a PDF
- **Compare vulnerable vs. mitigated implementations** side-by-side in the same workflow
- **Understand the full attack chain** - from ingestion to exploitation to data exfiltration
- **Test their own defenses** - modify the workflows, add guardrails, and verify they hold
- **Train their teams** - use these as live demos in security awareness sessions and workshops

Every workflow is self-contained, documented on-canvas with sticky notes, and designed to run out of the box.

---

## 🎯 Who Is This For

| Role | How You'll Use This |
|------|-------------------|
| **AppSec Engineers** | Understand LLM-specific attack surfaces and validate RAG pipeline security controls |
| **Red Teamers / Pentesters** | Learn LLM exploitation techniques - prompt injection, data poisoning, system prompt extraction |
| **AI/ML Developers** | See how common architectural decisions (no metadata, no output filtering, shared vector DBs) create vulnerabilities |
| **Security Trainers** | Ready-made interactive demos for workshops, bootcamps, and security awareness sessions |
| **CTF Creators** | Adapt these workflows into capture-the-flag challenges for AI security competitions |
| **DevSecOps Teams** | Understand where security controls are needed in LLM deployment pipelines |
| **Engineering Leaders** | Visualize the risks of deploying LLMs without proper guardrails to drive security investment decisions |

---

## 📋 What's Inside

### OWASP LLM Top 10 (2025)

Each vulnerability maps to one or more n8n workflows with attack simulations and mitigations.

| # | Vulnerability | Workflow | Attack Demo | Mitigation Demo |
|---|--------------|----------|-------------|-----------------|
| **LLM01** | [Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Vulnerable vs. Defended branches | Direct override, role hijacking, indirect injection via documents | 3-layer defense: injection classifier → hardened prompt → output validator |
| **LLM02** | [Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) | RAG pipeline with PII-laden documents | Agent exposes SSNs, credentials, and financials from vector DB | Access controls, data masking, output filtering |
| **LLM03** | [Supply Chain Vulnerabilities](https://genai.owasp.org/llmrisk/llm032025-supply-chain-vulnerabilities/) | PyPI package vetting pipeline | Typosquats, vulnerable dependencies, unknown authors | Automated risk scoring using PyPI + OSV.dev + LLM analysis |
| **LLM04** | [Data Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-poisoning/) | RAG corpus poisoning | Poisoned document injection with manipulated pricing and competitor info | Source verification, content validation, trust scoring |
| **LLM05** | [Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) | Feedback processing pipeline | XSS, SQL injection, command injection payloads via LLM output | Output sanitization, encoding, validation before downstream use |
| **LLM06** | [Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | 4-scenario progression | Unrestricted delete, autonomous payments | Read-only tools, human-in-the-loop approval, full audit workflow |
| **LLM07** | [System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/) | Vulnerable agent with embedded secrets | Prompt extraction reveals database credentials | Credential management, prompt hardening |
| **LLM08** | [Vector & Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) | 3 sub-scenarios | Metadata bypass, cross-tenant leakage, data poisoning via RAG | Metadata access control, tenant isolation, input validation |
| **LLM09** | [Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/) | Grounded vs. ungrounded agents | LLM fabricates company policies with confident but false details | Knowledge base grounding, honest fallback responses |
| **LLM10** | [Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/) | Token exploitation demos | Input floods, denial of wallet, resource-intensive queries, model extraction | Rate limiting, token budgets, input validation |

### LLM08 Deep Dive - Three Sub-Scenarios

LLM08 (Vector & Embedding Weaknesses) is explored through three separate workflows to cover distinct attack patterns:

| Sub-Scenario | Workflow | What It Demonstrates |
|-------------|----------|---------------------|
| **Sensitive Data Leakage** | RAG Data Leakage Demo & Mitigation | Documents stored without metadata expose all data to any user. Metadata-based classification (public/confidential/restricted) enables role-based access control. |
| **Cross-Tenant Leakage** | Cross Tenant Data Leakage | Company A and Company B share one vector DB. Without tenant filtering, one company sees the other's confidential policies. Tenant metadata isolation prevents cross-context leaks. |
| **Data Poisoning** | Data Poison | Attacker uploads a poisoned API security policy via the same form as legitimate users. The RAG pipeline serves dangerous recommendations (basic auth, no logging, public admin endpoints) as official policy. |

---

## 🧠 Learning Outcomes

Beyond understanding the OWASP LLM Top 10, you'll gain practical experience with:

### RAG Pipeline Architecture
End-to-end understanding of document ingestion → text chunking → embedding generation → vector storage → semantic retrieval → LLM response generation. See exactly where security controls are needed at each stage.

### Vector Databases & Embeddings
Hands-on experience with ChromaDB - creating collections, generating embeddings via OpenAI's API, performing similarity search, and understanding how metadata filtering works at the database level.

### Human-in-the-Loop (HITL) Workflows
LLM06 demonstrates four levels of agent autonomy - from fully autonomous (dangerous) to human-approved (safe). Learn how to design approval workflows that prevent AI agents from executing destructive actions without oversight.

### Metadata-Based Access Control
LLM08 shows how tagging documents with classification metadata (public, confidential, restricted) and tenant identifiers enables fine-grained access control in vector databases, a critical pattern for multi-tenant AI applications.

### Prompt Injection Defense Layers
LLM01 implements a three-layer defense architecture, input classification, hardened system prompts, and deterministic output validation. Understand defense-in-depth for LLM applications.

### Supply Chain Vetting
LLM03 builds a complete package vetting pipeline combining PyPI metadata analysis, OSV.dev vulnerability checks, heuristic red/green flag scoring, and LLM-powered risk assessment, a practical blueprint for supply chain security.

### Workflow Automation for Security
All demos are built in n8n, showing how visual workflow automation can be used for security testing, red team simulations, and building security-aware AI pipelines.

---

## 📸 Screenshots

> Add your workflow screenshots to a `screenshots/` folder and uncomment the lines below.


### Workflows
![Workflows](llm-top-10/screenshots/screenshot-1.png)
![Workflows](llm-top-10/screenshots/screenshot-2.png)
<!--
### LLM01 - Prompt Injection (Vulnerable vs. Defended)
![LLM01 Workflow](screenshots/llm01-prompt-injection.png)

### LLM08 - RAG Data Leakage & Mitigation
![LLM08 Workflow](screenshots/llm08-rag-data-leakage.png)
 
### LLM08 - Cross-Tenant Data Leakage
![LLM08 Cross Tenant](screenshots/llm08-cross-tenant.png)

### LLM08 - Data Poisoning
![LLM08 Data Poison](screenshots/llm08-data-poison.png)

### LLM06 - Excessive Agency (4 Scenarios)
![LLM06 Workflow](screenshots/llm06-excessive-agency.png)

### LLM03 - Supply Chain Vetting Pipeline
![LLM03 Workflow](screenshots/llm03-supply-chain.png)
-->

---

## 🚀 Getting Started

### Prerequisites

| Tool | Purpose | Required |
|------|---------|----------|
| [n8n](https://n8n.io) | Workflow automation platform | ✅ Cloud or self-hosted |
| [ChromaDB](https://www.trychroma.com) | Vector database for RAG workflows | ✅ For LLM08 workflows |
| [ngrok](https://ngrok.com) | Tunnel local ChromaDB to n8n Cloud | ✅ If using n8n Cloud |
| [OpenAI API Key](https://platform.openai.com) | Embeddings and LLM inference | ✅ |
| [Groq API Key](https://groq.com) | Fast inference for LLM01, LLM03 | Optional |

### Setup (Estimated Time: 15–20 minutes)

**1. Clone the repository**
```bash
git clone https://github.com/MayankPalSingh/N8N-Security-Workflows-OWASP-Top-10.git
cd N8N-Security-Workflows-OWASP-Top-10
```

**2. Start ChromaDB (for LLM08 workflows)**
```bash
pip install chromadb
chroma run --host 0.0.0.0 --port 6333
```

**3. Expose ChromaDB via ngrok (if using n8n Cloud)**
```bash
ngrok http 6333
```
Copy the ngrok URL - you'll need to update it in the workflow HTTP Request nodes.

**4. Import workflows into n8n**
- Open n8n → Settings → Import from File
- Select the `.json` workflow files from the `llm-top-10/` directory
- Import sub-workflows first, then main workflows

**5. Configure credentials in n8n**
- **OpenAI:** Add as Predefined Credential (type: OpenAI)
- **Groq:** Add as HTTP Header Auth (Name: `Authorization`, Value: `Bearer YOUR_GROQ_KEY`)

**6. Update URLs**
- Replace ngrok URLs in HTTP Request nodes with your ngrok tunnel URL
- Update webhook URLs if using a different n8n instance

**7. Run and explore**
- Start with LLM07 (simplest, just a chat agent) and work your way up to LLM08 (most complex, RAG + ChromaDB)

---

## 📁 Repository Structure

```
N8N-Security-Workflows-OWASP-Top-10/
├── llm-top-10/
│   ├── docs/                                          # Sample documents for demos
│   │   ├── Valid_Document.txt                         # Legit API security policy
│   │   ├── Poisoned_Document.txt                      # Poisoned policy with prompt injection
│   │   ├── Attacker Provided Document.txt             # Attacker's document for LLM04
│   │   ├── Legit Document.txt                         # Legitimate document for LLM04
│   │   └── Sample_Sales_Report_Q1_2026.txt            # PII-laden sales report for LLM02
│   │
│   ├── server_llm_top_10/                             # Support server for LLM05
│   │   ├── server.py                                  # Flask server for feedback storage
│   │   ├── index.html                                 # Frontend for viewing stored feedback
│   │   └── feedback.csv                               # Stored feedback data
│   │
│   ├── OWASP LLM01 - Prompt Injection.json
│   ├── OWASP LLM02 - Sensitive Information Disclosure.json
│   ├── OWASP LLM03 - Supply Chain Vetting Pipeline.json
│   ├── OWASP LLM04 - RAG Poisoning.json
│   ├── OWASP LLM05 - Improper Output Handling Demo.json
│   ├── OWASP LLM06 - Excessive Agency Demonstration.json
│   ├── OWASP LLM07 - System Prompt Leakage.json
│   ├── OWASP LLM08 - RAG Data Leakage Demo & Mitigation.json
│   ├── OWASP LLM08 - Cross Tenant Data Leakage.json
│   ├── OWASP LLM08 - Data Poison.json
│   ├── OWASP LLM09 - Misinformation.json
│   ├── OWASP LLM10 - Unbounded Consumption.json
│   │
│   ├── My Sub-Workflow - Safe.json                    # Sub-workflow: metadata-filtered retrieval
│   ├── My Sub-Workflow - Unsafe.json                  # Sub-workflow: unfiltered retrieval
│   ├── My Sub-Workflow - Tenant.json                  # Sub-workflow: tenant-based retrieval
│   ├── My Sub-Workflow - Data Poison.json             # Sub-workflow: data poison retrieval
│   └── README.md
│
├── LICENSE
└── README.md
```

---

## 🗺️ Roadmap

This project is actively expanding to cover the full spectrum of AI security risks.

| Phase | Category | Status |
|-------|---------|--------|
| ✅ Phase 1 | **OWASP LLM Top 10 (2025)** | Complete - 10 vulnerabilities, 14 workflows |
| 🔜 Phase 2 | **OWASP MCP Top 10** | Coming Soon - Model Context Protocol security risks |
| 🔜 Phase 3 | **OWASP Agentic Security Top 10** | Coming Soon - Autonomous AI agent security risks |

Follow this repo or star it to get notified when new phases drop.

---

## ⚠️ Disclaimer

These workflows are designed for **educational and authorized security research purposes only**. They intentionally demonstrate vulnerabilities and attack techniques to help security professionals understand and defend against them.

- **Do not** use these against systems without explicit authorization
- **Do not** use the attack payloads outside of controlled lab environments
- All PII data in demo documents (SSNs, names, addresses, financials) is **entirely fictional**
- The vulnerable configurations are deliberately insecure for educational purposes - never replicate them in production

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Mayank Pal Singh** - Security Professional

[![GitHub](https://img.shields.io/badge/GitHub-MayankPalSingh-black?style=flat-square&logo=github)](https://github.com/MayankPalSingh)

---

<p align="center">
  <i>Built with 🛡️ for the AI security community</i>
</p>
