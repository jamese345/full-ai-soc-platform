# 🛡️ Full AI SOC Analyst Platform

An end-to-end **AI-powered Security Operations Center (SOC) platform** built with Python, machine learning, threat intelligence, MITRE ATT&CK, RAG, and LLM-based investigation.

The platform simulates a modern SOC workflow — from alert ingestion and detection to risk assessment, threat intelligence enrichment, investigation, case management, and automated reporting.

> **Goal:** Build a practical AI SOC system that helps security analysts detect, prioritize, investigate, and document security incidents.

---

## 🚀 Platform Overview

The Full AI SOC Analyst Platform combines the capabilities developed throughout my AI SOC learning journey into one integrated security operations pipeline.

```text
                    ┌─────────────────┐
                    │   Security      │
                    │     Alert       │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Alert Ingestion │
                    │ & Normalization │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │      Detection Layer         │
              │                              │
              │  Rule Detection + ML Anomaly │
              └──────────────┬───────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Risk Assessment │
                    │  & Prioritizing  │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Threat Intelligence     │
              │                              │
              │ IOC Extraction + Enrichment  │
              └──────────────┬───────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ MITRE ATT&CK   │
                    │     Mapping     │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │       Investigation          │
              │                              │
              │ RAG + Evidence + AI Agent    │
              └──────────────┬───────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  SOC Case       │
                    │   Management    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ SOC Reporting   │
                    └─────────────────┘
```

---

## 🔥 Key Capabilities

### Detection

- Rule-based security detections
- Brute-force detection
- Suspicious login detection
- Suspicious request detection
- Machine-learning anomaly detection
- Alert normalization and validation

### Risk & Triage

- Risk scoring
- Risk-level classification
- SOC priority assignment
- Analyst confidence
- Recommended SOC actions

### Threat Intelligence

- IP and domain IOC extraction
- IOC normalization
- Threat intelligence enrichment
- Internal/private IP classification
- IOC context for investigations

### MITRE ATT&CK

- Enterprise ATT&CK dataset integration
- Technique identification
- Tactic mapping
- Security alert → MITRE technique context

Current integrated dataset contains approximately **867 attack patterns**.

Examples:

| Detection | MITRE Technique |
| --- | --- |
| Brute Force | T1110 |
| Suspicious Login | T1078 |
| Suspicious Request | No direct mapping |

---

## 🧠 AI Investigation

The platform includes an AI investigation layer designed to assist analysts without replacing evidence-based investigation.

The AI investigation workflow combines:

```text
Alert
  ↓
Detection Results
  ↓
ML Analysis
  ↓
Risk Assessment
  ↓
IOC Intelligence
  ↓
MITRE ATT&CK
  ↓
RAG Evidence
  ↓
Investigation Context
  ↓
AI Investigation Agent
  ↓
LLM
```

The investigation agent is explicitly designed to:

- Use only available evidence
- Avoid inventing facts
- Distinguish evidence from inference
- Avoid claiming compromise without supporting evidence
- Identify missing evidence
- Recommend additional investigation steps

If the LLM is unavailable or fails, the platform safely falls back to the underlying SOC evidence instead of treating an AI response as authoritative.

---

## 📚 RAG Investigation Layer

The platform uses Retrieval-Augmented Generation (RAG) to provide investigation knowledge to the AI investigation agent.

Knowledge areas include:

- SOC investigation methodology
- Brute-force investigation
- Suspicious login investigation
- Phishing investigation
- Evidence interpretation
- Analyst reasoning
- Investigation recommendations

This helps ground AI-generated investigation output in security knowledge rather than relying only on the LLM's general knowledge.

---

## 📁 SOC Case Management

Security alerts can be converted into persistent SOC cases.

Cases support:

- Case creation
- Case retrieval
- Analyst assignment
- Status updates
- Evidence tracking
- Investigation notes
- Case closure
- Resolution tracking
- Persistent SQLite storage

Supported case statuses:

```text
OPEN
IN_PROGRESS
CONTAINED
RESOLVED
CLOSED
```

---

## 📊 SOC Reporting

The platform generates structured SOC investigation reports containing:

- Alert information
- Detection results
- ML anomaly results
- Risk assessment
- IOC information
- Threat intelligence
- MITRE ATT&CK context
- Investigation findings
- AI investigation results
- Recommended actions

Reports are generated as structured JSON for further automation and integration.

---

## 🖥️ SOC Dashboard

A Streamlit dashboard provides a security-operations-style interface for interacting with the platform.

Dashboard areas include:

### 📊 Overview

- Total alerts
- Risk distribution
- Detection summary
- Pipeline status
- SOC analysis results

### 🚨 Alert Queue

Allows analysts to review processed alerts and prioritize investigations.

### 🔎 Investigation

Provides investigation context including:

- Detection results
- ML anomaly analysis
- Risk assessment
- IOC intelligence
- MITRE ATT&CK mappings
- Investigation findings
- AI investigation output

### 📁 Cases & Reports

Provides access to:

- SOC cases
- Investigation reports
- Case information
- Generated reports

---

## 🧪 Testing

The platform has an extensive automated test suite covering the major components of the system.

Current baseline:

```text
Ran 148 tests
OK
```

Tests cover areas including:

- Alert ingestion
- Alert normalization
- Detection
- ML anomaly detection
- Risk assessment
- Threat intelligence
- MITRE mapping
- Investigation
- RAG
- LLM integration
- AI investigation
- Case management
- SQLite persistence
- Reporting
- End-to-end pipeline integration

The project is designed so that new capabilities are added together with automated tests.

---

## 🏗️ Project Structure

```text
full-ai-soc-platform/
│
├── app/
│   └── dashboard.py
│
├── src/
│   ├── ingestion/
│   ├── detection/
│   ├── anomaly/
│   ├── threat_intel/
│   ├── triage/
│   ├── mitre/
│   ├── rag/
│   ├── investigation/
│   ├── cases/
│   ├── reporting/
│   └── ai/
│
├── data/
│   ├── alerts/
│   ├── knowledge_base/
│   └── mitre/
│
├── models/
├── reports/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── end_to_end/
│
├── config/
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE
```

---

## ⚙️ Technology Stack

| Technology | Purpose |
| --- | --- |
| Python | Core platform |
| Pandas | Security data processing |
| Scikit-learn | ML anomaly detection |
| SQLite | SOC case persistence |
| Streamlit | SOC dashboard |
| OpenAI API | AI investigation |
| RAG | Evidence-grounded investigation |
| MITRE ATT&CK | Threat behavior mapping |
| Threat Intelligence APIs | IOC enrichment |
| Unittest | Automated testing |

---

## ▶️ Running the Platform

### 1. Clone the repository

```bash
git clone https://github.com/jamese345/full-ai-soc-platform.git
cd full-ai-soc-platform
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy:

```text
.env.example
```

to:

```text
.env
```

Configure the required API keys.

> API keys should never be committed to GitHub.

### 5. Run the platform

```powershell
python main.py
```

### 6. Launch the SOC dashboard

```powershell
streamlit run app/dashboard.py
```

The dashboard will open in your browser.

---

## 🧪 Run Tests

Run the complete test suite:

```powershell
python -m unittest discover -s tests -v
```

Expected baseline:

```text
Ran 148 tests
OK
```

---

## 🔐 Security Design Principles

This project intentionally follows several security engineering principles:

### Evidence First

AI output should be grounded in available SOC evidence.

### No Blind AI Trust

An LLM response is treated as an investigation aid, not as proof of compromise.

### Fail Safely

If the LLM is unavailable, the platform continues using deterministic SOC analysis.

### Secrets Protection

API credentials are loaded through environment variables and excluded from version control.

### Testable Components

The platform is divided into modular components with automated tests.

### Explainability

Risk scores, detections, MITRE mappings, investigation findings, and recommended actions are exposed to the analyst.

---

## 📈 Project Journey

This platform represents the culmination of a larger AI SOC engineering roadmap:

```text
01  SOC Log Analyzer
        ↓
02  Automated Alert Triage Engine
        ↓
03  ML-Based Anomaly Detector
        ↓
04  Threat Intelligence Enrichment Engine
        ↓
05  Cybersecurity RAG Assistant
        ↓
06  AI SOC Investigation Agent
        ↓
07  Full AI SOC Analyst Platform
```

Each project was built to introduce another capability required for an AI-assisted SOC workflow.

---

## 🎯 Future Improvements

Potential future development includes:

- Real-time SIEM ingestion
- Microsoft Sentinel integration
- Splunk integration
- Elastic integration
- Automated containment workflows
- SOAR integrations
- More ML detection models
- Advanced threat hunting
- Analyst authentication and RBAC
- Multi-user case management
- Docker deployment
- CI/CD security testing
- Cloud deployment
- LLM evaluation and benchmarking
- Agent tool-use expansion
- Production-grade observability

---

## 👨‍💻 About

Built as part of my journey toward becoming an **AI SOC Analyst**, combining:

### Cybersecurity + Python + Machine Learning + Threat Intelligence + RAG + AI Agents

The goal is to build practical security systems that can support real-world SOC workflows.

---

## ⭐ Feedback

If you work in:

- Cybersecurity
- SOC operations
- Detection engineering
- Threat intelligence
- AI security
- Security automation

I'd appreciate feedback on the architecture, investigation workflow, detection logic, and ideas for improving the platform.

⭐ If you find the project useful, consider giving the repository a star
