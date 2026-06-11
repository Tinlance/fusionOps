# FusionOps — Agentic SecOps + AIOps Convergence Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-teal.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Powered by ThreatFade](https://img.shields.io/badge/Powered%20by-ThreatFade-00E5C8)](https://github.com/LloydCoder/tinlance-threatfade)
[![Live on AWS](https://img.shields.io/badge/Live-AWS%20Production-FF4D6D)](http://fusionops.tinlance.com)
[![Made by Tinlance](https://img.shields.io/badge/Made%20by-Tinlance%20Limited-FF4D6D)](https://tinlance.com)

> **Detect C2 evasion. Triage automatically. Remediate instantly.**  
> Validated on real Merlin QUIC C2 malware — z-score 14.76, 490K packets, 0% false positives.

**[▶ Live Dashboard](http://fusionops.tinlance.com/dashboard)** · **[API Docs](http://fusionops.tinlance.com/docs)** · **[Full API Reference](docs/API.md)** · **[Contributing](CONTRIBUTING.md)**

---

## What FusionOps Does

FusionOps is an open-core agentic SecOps platform. One API call runs your traffic through three autonomous agents and returns a complete detection, triage, and remediation result.

```
Input (PCAP / JSON signals / scenario)
        ↓
[1] ThreatFade — entropy + z-score C2 detection
        ↓
[2] Triage Agent — priority, category, recommended action
        ↓
[3] Remediation Agent — ordered action plan + audit trail
        ↓
FullAnalysisResult in <100ms
```

**Why this matters:** Signature-based tools miss C2 evasion because adversaries deliberately quiet their channels. FusionOps detects the *absence* of signal — the entropy drop itself — not just known malware patterns.

---

## Live Demo

**Dashboard:** http://fusionops.tinlance.com/dashboard  
**API:** http://fusionops.tinlance.com/docs

```bash
# Try it right now — no setup needed
curl -X POST http://fusionops.tinlance.com/detect/scenario \
  -H "Content-Type: application/json" \
  -d '{"scenario": "c2_quieting"}'
```

---

## Real Malware Validation Results

### Merlin QUIC C2 (Real Capture)

| Metric | Result |
|---|---|
| **PCAP Size** | 90.85 MB |
| **Packets Analysed** | 490,565 |
| **Active C2 Sessions** | 521 |
| **Z-Score** | **14.76 (CRITICAL)** |
| **Detected** | ✅ YES |
| **MITRE TTP** | T1027 – Obfuscated Files/Information |
| **False Positives** | 0% |

### Additional Validation

| Malware | Z-Score | Result |
|---|---|---|
| Merlin QUIC C2 | **14.76** | ✅ Detected |
| Cobalt Strike | 7.01 | ✅ Detected |
| IcedID | 3.89 | ✅ Detected |

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Tinlance/fusionOps.git
cd fusionOps
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set THREATFADE_API_URL to your ThreatFade instance
```

### 3. Start ThreatFade (separate terminal)

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
pip install fastapi "uvicorn[standard]" python-multipart pydantic scapy numpy scipy
uvicorn fusionops_api:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Start FusionOps

```bash
cd fusionOps
uvicorn api.fusionops_api:app --host 0.0.0.0 --port 8080 --reload
```

### 5. Open the dashboard

```
http://localhost:8080/dashboard
```

Or Swagger UI at `http://localhost:8080/docs`

---

## Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness check — confirms ThreatFade connection |
| `GET` | `/events` | Rolling event log polled by dashboard every 5s |
| `POST` | `/detect/json` | Analyse entropy time-series as JSON |
| `POST` | `/detect/scenario` | Run a named simulation scenario |
| `POST` | `/detect/pcap` | Upload PCAP/PCAPNG for real traffic analysis |
| `POST` | `/triage` | Run triage agent on an existing detection result |
| `GET` | `/dashboard` | Live SOC dashboard UI |
| `GET` | `/` | Product landing page |

📖 **[Full API Reference → docs/API.md](docs/API.md)**

---

## Repository Structure

```
fusionOps/
├── api/
│   └── fusionops_api.py        # FastAPI app — 6 endpoints + dashboard + landing
├── agents/
│   ├── triage_agent.py         # Classifies: priority, category, action
│   └── remediation_agent.py    # Generates ordered plan + audit trail
├── config/
│   └── settings.py             # Pydantic settings — loads from .env
├── dashboard/
│   └── index.html              # Live SOC terminal — polls /events every 5s
├── landing/
│   └── index.html              # Product landing page
├── docs/
│   └── API.md                  # Full API reference with examples
├── .github/
│   ├── workflows/ci.yml        # CI — install, lint, test
│   └── ISSUE_TEMPLATE/         # Bug report + feature request templates
├── .env.example                # Environment variable template
├── requirements.txt
├── CONTRIBUTING.md             # How to contribute
├── SECURITY.md                 # Security policy + vulnerability reporting
├── CHANGELOG.md                # Version history
└── README.md
```

---

## Open-Core Model

| Feature | Free (this repo) | Enterprise |
|---|---|---|
| C2 entropy + z-score detection | ✅ | ✅ |
| Triage agent (priority + category + action) | ✅ | ✅ |
| Remediation plan generation | ✅ | ✅ |
| PCAP upload + real traffic analysis | ✅ | ✅ |
| REST API + Swagger docs | ✅ | ✅ |
| LOG actions auto-executed | ✅ | ✅ |
| NETWORK / PROCESS auto-execution | ❌ | ✅ |
| SIEM / SOAR / Slack integrations | ❌ | ✅ |
| LLM + AI agent channel monitoring | ❌ | ✅ |
| Persistent event storage (DynamoDB) | ❌ | ✅ |
| Compliance dashboard (SOC 2 / GDPR) | ❌ | ✅ |
| Customer-managed encryption keys | ❌ | ✅ |

Enterprise inquiries: **hello@tinlance.com**

---

## Roadmap

- [x] ThreatFade C2 detection engine validated on real malware
- [x] FastAPI REST API — 6 endpoints
- [x] PCAP upload + real-time entropy analysis
- [x] Triage agent — priority, category, recommended action
- [x] Remediation agent — ordered plan + audit trail
- [x] Live SOC dashboard — 5s polling, event detail, audit log
- [x] AWS production deployment — permanent URL
- [x] Product landing page
- [x] Full API documentation
- [ ] API key authentication (Enterprise)
- [ ] SIEM integrations — Splunk, Elastic, CEF
- [ ] Webhook notifications
- [ ] LLM + agentic AI channel monitoring
- [ ] Persistent event storage (DynamoDB)
- [ ] GitHub Actions CI/CD pipeline

---

## Open-Source Contributions

Tinlance has merged PRs into the top security OSS tools:

| Repo | Stars | Contribution |
|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 24K★ | Nigerian fintech credential detector |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 15K★ | 5 Nigerian fintech detectors |
| [Semgrep](https://github.com/returntocorp/semgrep) | 11K★ | Day-one merge — rule in global prod scans |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 10K★ | Secret detection rules |
| [Slither](https://github.com/crytic/slither) | 5K★ | Nigerian fintech credential detection |

---

## Built By

**Tinlance Limited** (RC: 7962164) — Nigeria 🇳🇬  
Building AI and cybersecurity products for the frontier.

- 🌐 [tinlance.com](https://tinlance.com)
- 🚀 [fusionops.tinlance.com](http://fusionops.tinlance.com)
- 🐙 [github.com/Tinlance](https://github.com/Tinlance)
- 🐦 [@lloydcoder](https://x.com/lloydcoder)
- 📧 [hello@tinlance.com](mailto:hello@tinlance.com)

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

> The multi-agent auto-execution, SIEM integrations, LLM channel monitoring,
> persistent storage, and enterprise compliance features are proprietary and
> not included in this open-core release.
